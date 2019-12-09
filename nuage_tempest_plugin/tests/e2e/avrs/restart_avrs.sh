#!/bin/bash

SOURCE_PATH=/home/stack/stackrc

source $SOURCE_PATH

# TODO(VRS-31019)
# we have to also restart the ovs, cause restarting avrs disables the proxy arp
for i in `openstack server list | grep -v 'controller' | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`; do

    ssh heat-admin@$i "sudo systemctl restart avrs; sleep 30; sudo systemctl restart openvswitch"

done
