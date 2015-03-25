#!/usr/bin/env python
# coding: utf-8

#
# Copyright © 2015  Cazena, Inc
# All Rights Reserved
# 
# author: neil@cazena.com
# maintainer: neil@cazena.com
# 

"""
    package.module
    ~~~~~~~~~~~~~

    A description which can be long and explain the complete
    functionality of this module even with indented code examples.
    Class/Function however should not be documented here.

    :copyright: year by my name, see AUTHORS for more details
    :license: license_name, see LICENSE for more details
"""

import sys

from boto.ec2 import connect_to_region


# noinspection PyUnusedLocal
def main(args):
    print("{0: <32} : {1: >8}GB".format("Neil", 8))

    gb = 0
    totals = dict()
    totals['Unowned'] = 0
    conn = connect_to_region('us-east-1')
    all_volumes = conn.get_all_volumes()
    for v in all_volumes:
        instance = None
        if v.attach_data and v.attach_data.instance_id:
            reservations = conn.get_all_instances(instance_ids=[v.attach_data.instance_id])
            instance = reservations[0].instances[0]
        if instance:
            print v, v.size, "Instance: ", instance, instance.state, instance.launch_time
            owned = False
            for key, value in instance.tags.iteritems():
                key = key.lower()
                owned = owned or key == 'owner'
                if key == "owner" or key == "name":
                    print "\t%s:%s" % (key, str(value))
                    total_key = "{0:s}:{1:s}".format(key, value)
                    if not total_key in totals:
                        totals[total_key] = 0
                    totals[total_key] += v.size
            if not owned:
                totals['Unowned'] += v.size

        else:
            print v, "Instance: None", v.size
            totals['Unowned'] += v.size
        gb += v.size
    print "Total EBS Usage: %d" % gb

    for key, value in sorted(totals.items(), key=lambda s: s[0].lower()):
        print("{0: <32} : {1: >8}GB".format(key, value))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

