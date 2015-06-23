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

import boto.ec2
import boto.vpc
import boto.s3
import boto3
import json
import re



# noinspection PyUnusedLocal

def retag_instance(instance, tags):
    for (key, value) in tags.iteritems():
        tag_matched = None

        for tag in instance.tags:
            if key.lower() == tag.lower():
                tag_matched = tag
                key = tag
                break

        value_matched = tag_matched and value.lower() == instance.tags[tag_matched].lower()

        if tag_matched and not value_matched:
            # noinspection PyUnboundLocalVariable
            instance.remove_tag(tag)

        if not value_matched:
            instance.add_tag(key, value)
            print "%-8s => %-6s : %s" % (key, value, instance.tags["Name"])


def main():
    parser = ArgumentParser(description='Set EC2 instance tags based on the pattern of their names.')
    # add region option

    args = parser.parse_args()

    ec2 = boto.ec2.connect_to_region('us-east-1')
    VPC = boto.vpc.connect_to_region('us-east-1')
    S3 = boto.s3.connect_to_region('us-east-1')
    KMS = boto3.client('kms')
    vpcs = VPC.get_all_vpcs()

    customer_bucket_re = re.compile('^customer-(?P<customer>\w+)-[0-9a-f\-]+')
    customer_buckets = dict()
    buckets = S3.get_all_buckets()
    for bucket in buckets:
        match = customer_bucket_re.match(bucket.name)
        if match and match.group('customer'):
            customer_buckets[match.group('customer')] = bucket.name

    customer_keys = dict()
    keys = KMS.list_keys()
    keys = keys.values()

    for key in keys[0]:
        arn=key['KeyArn']
        info = KMS.describe_key(KeyId=arn)
        key_metadata = info['KeyMetadata']
        try:
            description=json.loads(key_metadata['Description'])
            value=":".join([x for x in description.values() if type(x) in [str, unicode]])
            customer = description['c']
            if customer and description['s'] == 'used':
                customer_keys[customer]=key
        except:
            value=key_metadata['Description']
        print key_metadata['KeyId'], value


    for vpc in vpcs:
        # print vpc.id
        reservations = ec2.get_all_instances(filters={"vpc_id": vpc.id})
        instances = [i for r in reservations for i in r.instances]
        if not instances:
            print "%s orphaned VPC" % (vpc.id)
            if 'Customer' in vpc.tags:
                customer = vpc.tags['Customer']
                if vpc.tags['Customer'] in customer_keys:
                    key = customer_keys[vpc.tags['Customer']]
                    print "\tKeyId: %s" % (key['KeyId'])
                if vpc.tags['Customer'] in customer_buckets:
                    print "\tS3 Bucket: %s" % (customer_buckets[customer])

            for (key, value) in vpc.tags.iteritems():
                print "\t%s: %s" % (key, value)

    return 0


if __name__ == '__main__':
    sys.exit(main())

