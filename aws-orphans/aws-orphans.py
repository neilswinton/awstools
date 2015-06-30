#!/usr/bin/env python
# coding: utf-8

# Copyright (c) 2014-2015 Cazena, Inc., as an unpublished work.
# This notice does not imply unrestricted or public access to these
# materials which are a trade secret of Cazena, Inc. or its 
# subsidiaries or affiliates (together referred to as "Cazena"), and 
# which may not be copied, reproduced, used, sold or transferred to any 
# third party without Cazena's prior written consent.
#
# All rights reserved.

import sys
from argparse import ArgumentParser
import json
import re

import boto3


class CustomerContainer:
    def __init__(self, case_sensitive=True):
        self.customer_to_resource = dict()
        self.case_sensitive = case_sensitive

    def __getitem__(self, customer):
        result = []
        customer = unicode(customer)
        if customer in self.customer_to_resource:
            result = self.customer_to_resource[customer]
        return result

    def customer_find_or_create(self, customer):
        customer = unicode(customer)
        if not customer in self.customer_to_resource:
            self.customer_to_resource[customer] = []
        return self.customer_to_resource[customer]

    def is_case_sensitive(self):
        return self.case_sensitive

    def keys(self):
        return self.customer_to_resource.keys()

    def print_customer_resources(self, customer, message):
        for resource in self[customer]:
            print message % customer


class NamedListBase(CustomerContainer):
    def __init__(self, lister):
        CustomerContainer.__init__(self, case_sensitive=False)
        self.lister = lister

    def load(self):
        for (customer, item) in self.lister():
            item_list = self.customer_find_or_create(customer)
            item_list.append(item)


class Policies(NamedListBase):
    customer_name_re = re.compile('(?P<customer>\S+)-(s3accessor|provisioner)')

    def __init__(self):
        NamedListBase.__init__(self, Policies.get_policy_list)

    @staticmethod
    def get_policy_list():
        iam = boto3.client("iam")
        policies = iam.list_policies()
        for policy in policies["Policies"]:
            policy_name = policy["PolicyName"]
            if policy_name.endswith("-s3accessor") or policy_name.endswith("-provisioner"):
                yield (Policies.policy_name_to_customer_name(policy_name), policy)

    @staticmethod
    def policy_name_to_customer_name(policy_name):
        match = Policies.customer_name_re.match(policy_name)
        return match.group("customer")

    def print_orphans(self, customer):
        for policy in self[customer]:
            print "\tOrphan IAM Policy: %s" % policy["PolicyName"]


class Roles(NamedListBase):
    customer_name_re = re.compile('(?P<customer>\S+)-(s3accessor|provisioner)')

    def __init__(self):
        NamedListBase.__init__(self, Roles.get_role_list)

    @staticmethod
    def get_role_list():
        iam = boto3.client("iam")
        roles = iam.list_roles()
        for role in roles["Roles"]:
            role_name = role["RoleName"]
            if role_name.endswith("-s3accessor") or role_name.endswith("-provisioner"):
                yield (Roles.role_name_to_customer_name(role_name), role)

    @staticmethod
    def role_name_to_customer_name(role_name):
        match = Roles.customer_name_re.match(role_name)
        return match.group("customer")

    def print_orphans(self, customer):
        for policy in self[customer]:
            print "\tOrphan IAM Role: %s" % policy["RoleName"]


class CryptoKeys(CustomerContainer):
    def __init__(self, region):
        CustomerContainer.__init__(self, case_sensitive=False)
        self.region = region

    def load(self):
        kms = boto3.client('kms')
        keys = kms.list_keys()

        for key in keys["Keys"]:
            arn = key['KeyArn']
            arnparts = arn.split(":")
            if arnparts[3].startswith(self.region):
                info = kms.describe_key(KeyId=arn)
                key_metadata = info['KeyMetadata']
                description = None

                try:
                    description = json.loads(key_metadata['Description'])
                except ValueError:
                    pass

                if description:
                    # value = ":".join([x for x in description.values() if type(x) in [str, unicode]])
                    customer = unicode(description['c'])
                    if customer and description['s'] == 'used':
                        key_list = self.customer_find_or_create(customer)
                        key_list.append(key)

    def print_orphans(self, customer):
        self.print_customer_resources(customer, "\tOrphan crypto key: %s")


class S3Buckets(NamedListBase):
    customer_bucket_re = re.compile(
        '^customer-(?P<customer>\S+)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')

    def __init__(self):
        NamedListBase.__init__(self, S3Buckets.get_bucket_list)

    @staticmethod
    def get_bucket_list():
        s3 = boto3.client("s3")
        bucketlisting = s3.list_buckets()
        buckets = bucketlisting["Buckets"]
        for bucket in buckets:
            bucketname = bucket["Name"]
            match = S3Buckets.customer_bucket_re.match(bucketname)
            if match and match.group("customer"):
                yield (match.group("customer"), bucketname)

    def print_orphans(self, customer):
        for bucketname in self[customer]:
            print "\tOrphan S3 bucket: %s" % bucketname


class Vpcs(NamedListBase):
    def __init__(self, region, pattern):
        NamedListBase.__init__(self, self.get_vpc_list)
        self.region = region
        self.pattern_re = re.compile(pattern)

        self.unowned_vpcs = []
        self.vpc_instance_count = dict()
        self.active_customers = set()

    def get_active_customers(self):
        return self.active_customers

    def get_vpc_list(self):
        ec2 = boto3.session.Session(region_name=self.region).client("ec2")
        vpcs = ec2.describe_vpcs()
        vpcs = vpcs["Vpcs"]
        for vpc in filter(self.is_pattern_match, vpcs):
            active = False
            vpcid = vpc["VpcId"]
            self.vpc_instance_count[vpcid] = 0
            instances = ec2.describe_instances(
                Filters=[{'Name': 'vpc-id', 'Values': [vpcid]}])
            reservations = instances["Reservations"]
            for reservation in reservations:
                for instance in reservation["Instances"]:
                    active = True
                    self.vpc_instance_count[vpcid] += 1
            tags = Resources.make_tags(vpc["Tags"])
            if not "customer" in tags:
                self.unowned_vpcs.append(vpc)
            else:
                customer = unicode(tags["customer"])
                if active and customer not in self.active_customers:
                    self.active_customers.add(customer)
                yield (customer, vpc)

    def is_pattern_match(self, vpc):
        result = False
        tags = Resources.make_tags(vpc["Tags"])
        if "customer" in tags:
            match = self.pattern_re.match(tags["customer"])
            result = match
        return result

    def print_orphans(self, customer):
        for vpc in self[customer]:
            print "\tOrphan VPC %s" % vpc["VpcId"]
            tags = Resources.make_tags(vpc["Tags"])
            for (key, value) in tags.iteritems():
                print "\t\t%s: %s" % (key, value)

    def print_unowned(self):
        print "Unowned VPCs:"
        for vpc in self.unowned_vpcs:
            print "\tUnowned VPC %s" % vpc["VpcId"]
            tags = Resources.make_tags(vpc["Tags"])
            for (key, value) in tags.iteritems():
                print "\t\t%s: %s" % (key, value)


class Resources:
    def __init__(self, region, pattern):
        self.region = region
        self.pattern = pattern
        self.customer_names = []
        self.vpcs = Vpcs(region, self.pattern)
        self.resources = [self.vpcs, S3Buckets(), CryptoKeys(region), Policies(), Roles()]

    def load(self):
        for resource in self.resources:
            resource.load()

        customer_found = set()

        for resource in self.resources:
            for customer in resource.keys():
                lc = customer.lower()

                if not customer in customer_found:
                    customer_found.add(unicode(customer))
                    self.customer_names.append(unicode(customer))
                    if resource.is_case_sensitive() and not lc in customer_found:
                        customer_found.add(unicode(lc))
        self.customer_names.sort(key=unicode.lower)

    def print_orphans(self):
        pattern_re = re.compile(self.pattern)
        for customer in filter(pattern_re.match, self.customer_names):
            if not customer in self.vpcs.get_active_customers():
                print customer
                for resource in self.resources:
                    resource.print_orphans(customer)
                print ""

    def print_unowned(self):
        self.vpcs.print_unowned()
        print ""

    @staticmethod
    def make_tags(taglist):
        result = dict()
        for d in taglist:
            result[d["Key"].lower()] = d["Value"]
        return result


def main():
    parser = ArgumentParser(description='Set EC2 instance tags based on the pattern of their names.')
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--match", default=".*")

    args = parser.parse_args()
    region = args.region
    pattern = args.match

    resources = Resources(region, pattern)
    resources.load()
    resources.print_unowned()
    resources.print_orphans()
    return 0


if __name__ == '__main__':
    sys.exit(main())

