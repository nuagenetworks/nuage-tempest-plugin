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

from nuage_tempest_plugin.lib.test.nuage_test import NuageAdminNetworksTest
from nuage_tempest_plugin.lib.topology import Topology

LOG = Topology.get_logger(__name__)


class SubnetsTest(NuageAdminNetworksTest):

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

    def test_router_attached_subnet_update_clear_gateway_negative(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router()
        interface = self.routers_client.add_router_interface(
            router['id'], subnet_id=subnet['id'])
        self.assertIn('subnet_id', interface.keys())
        self.assertIn('port_id', interface.keys())
        # Verify router id is equal to device id in port details
        show_port_body = self.ports_client.show_port(
            interface['port_id'])
        self.assertEqual(show_port_body['port']['device_id'],
                         router['id'])
        msg = "Subnet attached to a router interface must have a gateway IP"
        kwargs = {'gateway_ip': None}
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.subnets_client.update_subnet,
                               subnet['id'],
                               **kwargs)

    # @decorators.attr(type='smoke')
    def test_subnet_delete_in_network_with_nuage_dhcp_ports(self):
        network = self.create_network()
        subnet1 = self.create_subnet(network)
        subnet2 = self.create_subnet(network)

        filters = {
            'device_owner': 'network:dhcp:nuage',
            'network_id': network['id']
        }
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']

        # check dhcp port number
        self.assertEqual(2, len(dhcp_ports))

        self.subnets_client.delete_subnet(subnet1['id'])
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']

        # check one dhcp port is deleted
        self.assertEqual(1, len(dhcp_ports))
        self.assertEqual(dhcp_ports[0]['fixed_ips'][0]['subnet_id'],
                         subnet2['id'])

    # @decorators.attr(type='smoke')
    def test_subnet_update_dhcp_disabled_in_network_with_nuage_dhcp_ports(
            self):
        network = self.create_network()
        subnet1 = self.create_subnet(network)
        subnet2 = self.create_subnet(network)

        filters = {
            'device_owner': 'network:dhcp:nuage',
            'network_id': network['id']
        }
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']

        # check dhcp port number
        self.assertEqual(2, len(dhcp_ports))

        kwargs = {'enable_dhcp': False}
        self.subnets_client.update_subnet(subnet1['id'], **kwargs)
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']

        # check dhcp port is deleted
        self.assertEqual(1, len(dhcp_ports))
        self.assertEqual(dhcp_ports[0]['fixed_ips'][0]['subnet_id'],
                         subnet2['id'])
