# Copyright 2017 Nokia
# All Rights Reserved.
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from netaddr import IPNetwork

from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_lib.tests.nuage_test import NuageAdminNetworkTest


class SubnetsTest(NuageAdminNetworkTest):

    @decorators.attr(type='smoke')
    def test_create_2nd_v4_subnet_in_network(self):
        network = self.create_network()
        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(
                exceptions.BadRequest,
                "A network with multiple ipv4 subnets is not "
                "allowed when neutron-dhcp-agent is enabled",
                self.create_subnet,
                network, cidr=IPNetwork("20.0.0.0/24"),
                mask_bits=28)
        else:
            subnet2 = self.create_subnet(network, cidr=IPNetwork(
                "20.0.0.0/24"), mask_bits=28)
            self.assertIsNotNone(subnet2, "Unable to create second subnet")
