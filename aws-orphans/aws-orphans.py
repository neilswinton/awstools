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


class Policies(CustomerContainer):
    def __init__(self):
        CustomerContainer.__init__(self, False)

    def load(self):
        iam = boto3.client("iam")
        policies = iam.list_policies()
        for policy in policies["Policies"]:
            policy_list = self.customer_find_or_create(policy["PolicyName"])
            policy_list.append(policy)

    def print_orphans(self, customer):
        for policy in self[customer]:
            print "Orphan IAM Policy: %s" % customer


class Roles(CustomerContainer):
    def __init__(self):
        CustomerContainer.__init__(self, False)

    def load(self):
        iam = boto3.client("iam")
        roles = iam.list_roles()
        for role in roles["Roles"]:
            role_list = self.customer_find_or_create(role["RoleName"])
            role_list.append(role)

    def print_orphans(self, customer):
        for role in self[customer]:
            print "Orphan IAM Role: %s" % customer


class Resources:
    def __init__(self, region):
        self.region = region
        self.customer_to_vpc = dict()
        self.unowned_vpcs = []
        self.vpc_instance_count = dict()
        self.customer_keys = dict()
        self.customer_to_buckets = dict()
        self.active_customers = set()
        self.customer_names = []
        self.policies = Policies()
        self.roles = Roles()

    def load(self):
        self.roles.load()
        self.policies.load()
        self.load_s3_buckets()
        self.load_customer_keys()
        self.load_vpcs()

        customer_found = set()
        collections = [
            (self.customer_to_vpc, True),
            (self.customer_keys, False),
            (self.customer_to_buckets, False),
            (self.policies, self.policies.case_sensitive)]

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

    def load_customer_keys(self):
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
                        if not customer in self.customer_keys:
                            self.customer_keys[customer] = []
                        self.customer_keys[customer].append(key)

    def load_s3_buckets(self):
        customer_bucket_re = re.compile('^customer-(?P<customer>\w+)-[0-9a-f\-]+')
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

    def print_orphan_key(self, customer):
        customer = customer.lower()
        if customer in self.customer_keys:
            print "\tOrphan Crypto Key: %s" % customer
            for key in self.customer_keys[customer]:
                for (name, value) in key.iteritems():
                    print "\t\t%s: %s" % (name, value)

    def print_orphans(self):
        for customer in self.customer_names:
            if not customer in self.active_customers:
                print customer
                self.print_orphan_key(customer)
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

