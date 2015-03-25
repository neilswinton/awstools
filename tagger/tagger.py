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

from boto.ec2 import connect_to_region

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
    parser.add_argument('patterns', metavar='pattern', type=str, nargs='+',
                        help='Regex to match on the instance name.')
    parser.add_argument('--owner',
                        help='Owner tag to set on matching instances')
    parser.add_argument('--persist', action="store_true", dest="persist",
                        help="Set Persist Tag to true on matching instances")
    parser.add_argument('--no-persist', action="store_false", dest="persist",
                        help="Set Persist tag to false on matching instances")

    args = parser.parse_args()
    if not "persist" in args:
        persist = True
    else:
        persist = args.persist

    tags = dict(persist=str(persist))
    if args.owner:
        tags["Owner"] = args.owner

    conn = connect_to_region('us-east-1')
    for pattern in args.patterns:

        reservations = conn.get_all_instances(filters={"tag:Name": pattern})
        instances = [i for r in reservations for i in r.instances]
        for instance in instances:
            retag_instance(instance, tags)
    return 0


if __name__ == '__main__':
    sys.exit(main())

