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

    def keys(self):
        return self.customer_to_resource.keys()

    def print_customer_resources(self, customer, message):
        for resource in self[customer]:
            print message % customer


class NamedListBase(CustomerContainer):
    def __init__(self, lister, item_name_to_customer_name):
        CustomerContainer.__init__(self, case_sensitive=False)
        self.lister = lister
        self.item_name_to_customer_name = item_name_to_customer_name

    def load(self):
        for item in self.lister():
            name = self.item_name_to_customer_name(item)
            item_list = self.customer_find_or_create(name)
            item_list.append(item)

class Policies(NamedListBase):
    customer_name_re = re.compile('(?P<customer>\S+)-(s3accessor|provisioner)')

    def __init__(self):
        NamedListBase.__init__(self, Policies.get_policy_list, Policies.policy_name_to_customer_name)

    @staticmethod
    def get_policy_list():
        iam = boto3.client("iam")
        policies = iam.list_policies()
        for policy in policies["Policies"]:
            policy_name = policy["PolicyName"]
            if policy_name.endswith("-s3") or policy_name.endswith("-provisioner"):
                yield policy

    @staticmethod
    def policy_name_to_customer_name(item):
        match = Policies.customer_name_re.match(item["PolicyName"])
        return match.group("customer")

    def print_orphans(self, customer):
        for policy in self[customer]:
            print "\tOrphan IAM Policy: %s" % customer

class Roles(NamedListBase):
    customer_name_re = re.compile('(?P<customer>\S+)-(s3accessor|provisioner)')

    def __init__(self):
        NamedListBase.__init__(self, Roles.get_role_list, Roles.role_name_to_customer_name)

    @staticmethod
    def get_role_list():
        iam = boto3.client("iam")
        roles = iam.list_roles()
        for role in roles["Roles"]:
            role_name = role["RoleName"]
            if role_name.endswith("-s3") or role_name.endswith("-provisioner"):
                yield role

    @staticmethod
    def role_name_to_customer_name(item):
        match = Roles.customer_name_re.match(item["RoleName"])
        return match.group("customer")

    def print_orphans(self, customer):
        for policy in self[customer]:
            print "\tOrphan IAM Role: %s" % customer

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
        self.print_customer_resources(customer, "Orphan crypto key: %s")

class S3Buckets(NamedListBase):

    customer_bucket_re = re.compile(
        '^customer-(?P<customer>\w+)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')

    def __init__(self):
       NamedListBase.__init__(self, S3Buckets.get_bucket_list, S3Buckets.bucket_name_to_customer_name)

    @staticmethod
    def get_role_list():
        s3 = boto3.client("s3")
        bucketlisting = s3.list_buckets()
        buckets = bucketlisting["Buckets"]
        for bucket in buckets:
            bucketname = bucket["Name"]
            match = customer_bucket_re.match(bucketname)
            if match and match.group("customer"):
                yield

    @staticmethod
    def role_name_to_customer_name(item):
        match = Roles.customer_name_re.match(item["RoleName"])
        return match.group("customer")

    def print_orphans(self, customer):
        for policy in self[customer]:
            print "\tOrphan IAM Role: %s" % customer
       def load_s3_buckets(self):
        # customer-<customername>-f4eb065-9bf0-4ef3-a9bf-33e0c7d8da56
        customer_bucket_re = re.compile(
            '^customer-(?P<customer>\w+)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
        s3 = boto3.client("s3")
        bucketlisting = s3.list_buckets()
        buckets = bucketlisting["Buckets"]
        for bucket in buckets:
            bucketname = bucket["Name"]
            match = customer_bucket_re.match(bucketname)
            if match and match.group("customer"):
                customer = unicode(match.group('customer'))
                if not customer in self.customer_to_buckets:
                    self.customer_to_buckets[customer] = []
                self.customer_to_buckets[customer].append(bucketname)


class Resources:
    def __init__(self, region):
        self.region = region
        self.customer_to_vpc = dict()
        self.unowned_vpcs = []
        self.vpc_instance_count = dict()
        self.customer_to_buckets = dict()
        self.active_customers = set()
        self.customer_names = []
        self.policies = Policies()
        self.roles = Roles()
        self.crypto_keys = CryptoKeys(region)


    def load(self):
        self.policies.load()
        self.crypto_keys.load()
        self.roles.load()
        self.policies.load()
        self.load_s3_buckets()
        self.load_vpcs()

        customer_found = set()
        collections = [
            (self.customer_to_vpc, True),
            (self.customer_to_buckets, False),
            (self.policies, self.roles.case_sensitive),
            (self.roles, self.policies.case_sensitive),

            (self.crypto_keys, self.crypto_keys.case_sensitive)]

        for (collection, case_sensitive) in collections:
            for customer in collection.keys():
                lc = customer.lower()

                if not customer in customer_found:
                    customer_found.add(unicode(customer))
                    self.customer_names.append(unicode(customer))
                    if case_sensitive and not lc in customer_found:
                        customer_found.add(unicode(lc))

        self.customer_names.sort(key=unicode.lower)

    def load_vpcs(self):
        ec2 = boto3.client("ec2")
        vpcs = ec2.describe_vpcs()
        vpcs = vpcs["Vpcs"]
        for vpc in vpcs:
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
                if not customer in self.customer_to_vpc:
                    self.customer_to_vpc[customer] = []
                self.customer_to_vpc[customer].append(vpc)

                if active and customer not in self.active_customers:
                    self.active_customers.add(customer)

    def load_s3_buckets(self):
        # customer-<customername>-f4eb065-9bf0-4ef3-a9bf-33e0c7d8da56
        customer_bucket_re = re.compile(
            '^customer-(?P<customer>\w+)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
        s3 = boto3.client("s3")
        bucketlisting = s3.list_buckets()
        buckets = bucketlisting["Buckets"]
        for bucket in buckets:
            bucketname = bucket["Name"]
            match = customer_bucket_re.match(bucketname)
            if match and match.group("customer"):
                customer = unicode(match.group('customer'))
                if not customer in self.customer_to_buckets:
                    self.customer_to_buckets[customer] = []
                self.customer_to_buckets[customer].append(bucketname)

    def print_orphan_bucket(self, customer):
        if customer in self.customer_to_buckets:
            for bucket in self.customer_to_buckets[customer]:
                print "\tS3 orphan bucket: %s" % bucket

    def print_orphan_vpcs(self, customer):
        if customer in self.customer_to_vpc:
            for vpc in self.customer_to_vpc[customer]:
                print "\tOrphan VPC %s" % vpc["VpcId"]
                tags = Resources.make_tags(vpc["Tags"])
                for (key, value) in tags.iteritems():
                    print "\t\t%s: %s" % (key, value)

    def print_orphans(self):
        for customer in self.customer_names:
            if not customer in self.active_customers:
                print customer
                self.crypto_keys.print_orphans(customer)
                self.print_orphan_bucket(customer)
                self.print_orphan_vpcs(customer)
                self.policies.print_orphans(customer)
                print ""

    @staticmethod
    def make_tags(taglist):
        result = dict()
        for d in taglist:
            result[d["Key"].lower()] = d["Value"]
        return result


def main():
    parser = ArgumentParser(description='Set EC2 instance tags based on the pattern of their names.')
    parser.add_argument("--region", default="us-east")
    # add region option

    args = parser.parse_args()
    region = args.region

    resources = Resources(region)
    resources.load()
    resources.print_orphans()
    return 0


if __name__ == '__main__':
    sys.exit(main())

