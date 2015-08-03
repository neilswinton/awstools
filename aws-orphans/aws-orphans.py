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


class Options:
    def __init__(self):
        parser = ArgumentParser(description='Find orphaned resources and optionally clean them up')
        parser.add_argument("--region", default="us-east-1")
        parser.add_argument("--match", default=".*")
        parser.add_argument('--cleanup', dest='cleanup', action='store_true')
        parser.add_argument('--no-cleanup', dest='cleanup', action='store_false')
        parser.set_defaults(cleanup=False)
        args = parser.parse_args()

        self._region = args.region
        self._pattern = args.match
        self._cleanup = args.cleanup

    @property
    def region(self):
        return self._region

    @property
    def pattern(self):
        return self._pattern

    @property
    def cleanup(self):
        """

        :rtype : bool
        """
        return self._cleanup


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
        # noinspection PyUnusedLocal
        for resource in self[customer]:
            print message % customer

    def remove_customer(self, customer):
        pass

    def detach_customer(self, customer):
        pass


class NamedListBase(CustomerContainer):
    def __init__(self, lister):
        CustomerContainer.__init__(self, case_sensitive=False)
        self.lister = lister

    def load(self):
        for (customer, item) in self.lister():
            item_list = self.customer_find_or_create(customer)
            item_list.append(item)


class Policies(NamedListBase):
    def __init__(self):
        NamedListBase.__init__(self, self.get_policy_list)
        self.customer_name_re = re.compile('(?P<customer>\S+)-(s3accessor|provisioner)')
        self.iam_resource = boto3.resource("iam")

    def get_policy_list(self):
        iam_client = boto3.client("iam")
        policies = iam_client.list_policies()
        for policy in policies["Policies"]:
            policy_name = policy["PolicyName"]
            if policy_name.endswith("-s3accessor") or policy_name.endswith("-provisioner"):
                yield (self.policy_name_to_customer_name(policy_name), policy)

    def policy_name_to_customer_name(self, policy_name):
        match = self.customer_name_re.match(policy_name)
        return match.group("customer")

    def print_orphans(self, customer):
        for policy in self[customer]:
            print "\tOrphan IAM Policy: %s" % policy["PolicyName"]

    def remove_customer(self, customer):
        for policy_info in self[customer]:
            print "\tRemoving IAM Policy: %s" % policy_info["PolicyName"]
            policy = self.iam_resource.Policy(policy_info["Arn"])
            policy.delete()

    def detach_customer(self, customer):
        for policy_info in self[customer]:
            print "\tDetaching IAM Policy: %s" % policy_info["PolicyName"]
            policy = self.iam_resource.Policy(policy_info["Arn"])
            for role in policy.attached_roles.all():
                policy.detach_role(RoleName=role.name)


class Roles(NamedListBase):
    customer_name_re = re.compile('(?P<customer>\S+)-(s3accessor|provisioner)')

    def __init__(self):
        NamedListBase.__init__(self, self.get_role_list)
        self.iam_resource = boto3.resource("iam")

    def get_role_list(self):
        iam = boto3.client("iam")
        roles = iam.list_roles()
        for role in roles["Roles"]:
            role_name = role["RoleName"]
            if role_name.endswith("-s3accessor") or role_name.endswith("-provisioner"):
                yield (self.role_name_to_customer_name(role_name), role)

    def role_name_to_customer_name(self, role_name):
        match = self.customer_name_re.match(role_name)
        return match.group("customer")

    def print_orphans(self, customer):
        for policy in self[customer]:
            print "\tOrphan IAM Role: %s" % policy["RoleName"]

    def detach_customer(self, customer):
        for role_info in self[customer]:
            role = self.iam_resource.Role(role_info["RoleName"])
            for policy in role.attached_policies.all():
                role.detach_policy(PolicyArn=policy.arn)
            for profile in role.instance_profiles.all():
                profile.remove_role(RoleName=role.name)

    def remove_customer(self, customer):
        for role_info in self[customer]:
            print "\tRemoving IAM Role: %s" % role_info["RoleName"]
            role = self.iam_resource.Role(role_info["RoleName"])
            role.delete()


class CryptoKeys(CustomerContainer):
    def __init__(self, region):
        CustomerContainer.__init__(self, case_sensitive=False)
        self.region = region
        self.kms = boto3.client('kms', region_name=region)

    def load(self):
        keys = self.kms.list_keys()

        for key in keys["Keys"]:
            arn = key['KeyArn']
            arnparts = arn.split(":")
            if arnparts[3].startswith(self.region):
                info = self.kms.describe_key(KeyId=arn)
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

    def remove_customer(self, customer):
        for key in self[customer]:
            print "\tDeleting Key %s: %s" % (key["KeyId"], key["KeyArn"])
            self.kms.update_key_description(KeyId=key["KeyId"], Description='{"v":1,"t":"cz-key","s":"free","c":""}')


class S3Buckets(NamedListBase):
    def __init__(self):
        NamedListBase.__init__(self, self.get_bucket_list)
        self.s3_resource = boto3.resource("s3")
        self.s3_client  = boto3.client("s3")
        self.customer_bucket_re = re.compile(
            '^customer-(?P<customer>\S+)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')

    def get_bucket_list(self):
        s3 = boto3.client("s3")
        bucketlisting = s3.list_buckets()
        buckets = bucketlisting["Buckets"]
        for bucket in buckets:
            bucketname = bucket["Name"]
            match = self.customer_bucket_re.match(bucketname)
            if match and match.group("customer"):
                yield (match.group("customer"), bucketname)

    def print_orphans(self, customer):
        for bucketname in self[customer]:
            print "\tOrphan S3 bucket: %s" % bucketname

    def remove_customer(self, customer):
        for bucketname in self[customer]:
            bucket = self.s3_resource.Bucket(bucketname)
            print "\tDeleting S3 bucket %s" % bucketname
            for s3_object in bucket.objects.all():
                print "\t\tDeleting S3 object %s" % s3_object.key
                s3_object.delete()
            self.s3_client.delete_bucket(Bucket=bucketname)


class InstanceProfiles(NamedListBase):
    def __init__(self):
        NamedListBase.__init__(self, self.get_instance_profiles)
        self.iam = boto3.client("iam")
        self.customer_name_re = re.compile('(?P<customer>\S+)-(s3accessor|provisioner)')

    def instance_profile_name_to_customer_name(self, role_name):
        match = self.customer_name_re.match(role_name)
        return match.group("customer")

    def get_instance_profiles(self):
        is_incomplete = True
        marker = None

        while is_incomplete:
            if marker:
                response = self.iam.list_instance_profiles(MaxItems=100, Marker=marker)
            else:
                response = self.iam.list_instance_profiles(MaxItems=100)
            is_incomplete = response["IsTruncated"]
            if is_incomplete:
                marker = response["Marker"]
            for item in response["InstanceProfiles"]:
                name = item["InstanceProfileName"]
                if name.endswith("-s3accessor") or name.endswith("-provisioner"):
                    yield (self.instance_profile_name_to_customer_name(name), name)

    def print_orphans(self, customer):
        for item in self[customer]:
            print "\tOrphan Instance Profile %s" % item

    def remove_customer(self, customer):
        for instance_profile_name in self[customer]:
            print "\tDeleting instance profile: %s" % instance_profile_name
            self.iam.delete_instance_profile(InstanceProfileName=instance_profile_name)


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
        # noinspection PyUnresolvedReferences
        ec2 = boto3.session.Session(region_name=self.region).client("ec2")
        vpcs = ec2.describe_vpcs()
        vpcs = vpcs["Vpcs"]
        for vpc in filter(self.is_pattern_match, vpcs):
            active = False
            # noinspection PyTypeChecker
            vpcid = vpc["VpcId"]
            self.vpc_instance_count[vpcid] = 0
            instances = ec2.describe_instances(
                Filters=[{'Name': 'vpc-id', 'Values': [vpcid]}])
            reservations = instances["Reservations"]
            for reservation in reservations:
                # noinspection PyUnusedLocal
                for instance in reservation["Instances"]:
                    active = True
                    self.vpc_instance_count[vpcid] += 1
            # noinspection PyTypeChecker
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
        if "Tags" in vpc:
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
        if len(self.unowned_vpcs) > 0:
            print "Unowned VPCs:"
            for vpc in self.unowned_vpcs:
                print "\tUnowned VPC %s" % vpc["VpcId"]
                tags = Resources.make_tags(vpc["Tags"])
                for (key, value) in tags.iteritems():
                    print "\t\t%s: %s" % (key, value)

    def remove_customer(self, customer):
        for vpc in self[customer]:
            pass

            #


class Resources:
    def __init__(self, options):
        self.options = options
        self.customer_names = []
        self.vpcs = Vpcs(self.options.region, self.options.pattern)
        self.resources = [self.vpcs, InstanceProfiles(), S3Buckets(), CryptoKeys(self.options.region), Roles(),
                          Policies()]

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
        pattern_re = re.compile(self.options.pattern)
        for customer in filter(pattern_re.match, self.customer_names):
            if not customer in self.vpcs.get_active_customers():
                print customer
                for resource in self.resources:
                    resource.print_orphans(customer)
                print ""

    def print_unowned(self):
        self.vpcs.print_unowned()
        print ""

    def remove_orphans(self):
        pattern_re = re.compile(self.options.pattern)
        for customer in filter(pattern_re.match, self.customer_names):
            if not customer in self.vpcs.get_active_customers():
                print customer
                for resource in self.resources:
                    resource.detach_customer(customer)
                for resource in self.resources:
                    resource.remove_customer(customer)
                print ""

    @staticmethod
    def make_tags(taglist):
        result = dict()
        for d in taglist:
            result[d["Key"].lower()] = d["Value"]
        return result


def main():
    options = Options()
    resources = Resources(options)
    resources.load()
    resources.print_unowned()
    resources.print_orphans()
    if options.cleanup:
        resources.remove_orphans()
    return 0


if __name__ == '__main__':
    sys.exit(main())

