# Copyright 2012 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

import netaddr

from tempest.api.network import test_networks as tempest_test_networks
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()


class NuageNetworksIpV6Test(tempest_test_networks.NetworksIpV6Test):

    @classmethod
    def delete_router_interface(cls, router_id, subnet_id):
        cls.routers_client.remove_router_interface(
            router_id, subnet_id=subnet_id)

    @decorators.attr(type='smoke')
    def test_create_delete_subnet_with_dhcp_enabled(self):
        self._create_verify_delete_subnet()

    @decorators.attr(type='smoke')
    def test_create_delete_subnet_all_attributes(self):
        self._create_verify_delete_subnet(
            **self.subnet_dict(['gateway', 'host_routes', 'dns_nameservers']))


class NuageNetworksIpV6TestAttrs(tempest_test_networks.NetworksIpV6TestAttrs):

    @classmethod
    def create_port(cls, network, **kwargs):
        if CONF.network.port_vnic_type and 'binding:vnic_type' not in kwargs:
            kwargs['binding:vnic_type'] = CONF.network.port_vnic_type
        if CONF.network.port_profile and 'binding:profile' not in kwargs:
            kwargs['binding:profile'] = CONF.network.port_profile
        return super(
            NuageNetworksIpV6TestAttrs, cls).create_port(network,
                                                         **kwargs)

    def test_create_delete_subnet_with_v6_attributes_stateful(self):
        self.assertRaisesRegex(
            lib_exc.BadRequest,
            "Invalid input for operation: ipv6_ra_mode or ipv6_address_mode "
            "cannot be set when enable_dhcp is set to False",
            self._create_verify_delete_subnet,
            enable_dhcp=False,
            gateway=self._subnet_data[self._ip_version]['gateway'],
            ipv6_ra_mode='dhcpv6-stateful',
            ipv6_address_mode='dhcpv6-stateful')

    def test_create_delete_subnet_with_v6_attributes_slaac(self):
        self.assertRaisesRegex(
            lib_exc.BadRequest,
            "Attribute ipv6_ra_mode must be 'dhcpv6-stateful' or not set.",
            self._create_verify_delete_subnet,
            ipv6_ra_mode='slaac',
            ipv6_address_mode='slaac')

    def test_create_delete_subnet_with_v6_attributes_stateless(self):
        self.assertRaisesRegex(
            lib_exc.BadRequest,
            "Attribute ipv6_ra_mode must be 'dhcpv6-stateful' or not set.",
            self._create_verify_delete_subnet,
            ipv6_ra_mode='dhcpv6-stateless',
            ipv6_address_mode='dhcpv6-stateless')

    def _test_delete_subnet_with_ports(self, mode):
        """Create subnet and delete it with existing ports"""
        slaac_network = self.create_network()
        subnet_slaac = self.create_subnet(slaac_network,
                                          **{'ipv6_ra_mode': mode,
                                             'ipv6_address_mode': mode})
        port = self.create_port(slaac_network)
        self.assertIsNotNone(port['fixed_ips'][0]['ip_address'])
        self.subnets_client.delete_subnet(subnet_slaac['id'])
        subnets = self.subnets_client.list_subnets()
        subnet_ids = [subnet['id'] for subnet in subnets['subnets']]
        self.assertNotIn(subnet_slaac['id'], subnet_ids,
                         "Subnet wasn't deleted")
        self.assertRaisesRegex(
            lib_exc.Conflict,
            "There are one or more ports still in use on the network",
            self.networks_client.delete_network,
            slaac_network['id'])

    def test_create_delete_slaac_subnet_with_ports(self):
        """Test deleting subnet with SLAAC ports

        Create subnet with SLAAC, create ports in network
        and then you shall be able to delete subnet without port
        deletion. But you still can not delete the network.
        """
        self.assertRaisesRegex(
            lib_exc.BadRequest,
            "Attribute ipv6_ra_mode must be 'dhcpv6-stateful' or not set.",
            self._test_delete_subnet_with_ports,
            "slaac")

    def test_create_delete_stateless_subnet_with_ports(self):
        """Test deleting subnet with DHCPv6 stateless ports

        Create subnet with DHCPv6 stateless, create ports in network
        and then you shall be able to delete subnet without port
        deletion. But you still can not delete the network.
        """
        self.assertRaisesRegex(
            lib_exc.BadRequest,
            "Attribute ipv6_ra_mode must be 'dhcpv6-stateful' or not set.",
            self._test_delete_subnet_with_ports,
            "dhcpv6-stateless")


class NuageBulkNetworkOpsIpV6Test(
        tempest_test_networks.BulkNetworkOpsIpV6Test):

    @decorators.attr(type='smoke')
    def test_bulk_create_delete_subnet(self):
        networks = [self.create_network(), self.create_network()]
        # Creates 2 subnets in one request
        cidr = netaddr.IPNetwork(CONF.network.project_network_v6_cidr)
        mask_bits = CONF.network.project_network_v6_mask_bits

        cidrs = [subnet_cidr for subnet_cidr in cidr.subnet(mask_bits)]

        names = [data_utils.rand_name('subnet-') for i in range(len(networks))]
        subnets_list = []
        for i in range(len(names)):
            p1 = {
                'network_id': networks[i]['id'],
                'cidr': str(cidrs[i]),
                'name': names[i],
                'ip_version': self._ip_version,
                'enable_dhcp': False
            }
            subnets_list.append(p1)
        del subnets_list[1]['name']
        body = self.subnets_client.create_bulk_subnets(subnets=subnets_list)
        created_subnets = body['subnets']
        self.addCleanup(self._delete_subnets, created_subnets)
        # Asserting that the subnets are found in the list after creation
        body = self.subnets_client.list_subnets()
        subnets_list = [subnet['id'] for subnet in body['subnets']]
        for n in created_subnets:
            self.assertIsNotNone(n['id'])
            self.assertIn(n['id'], subnets_list)
