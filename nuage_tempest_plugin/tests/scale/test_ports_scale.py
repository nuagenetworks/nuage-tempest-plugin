# Copyright 2019 NOKIA - All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
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

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

CONF = Topology.get_conf()

SPOOFING_ENABLED = n_constants.ENABLED
SPOOFING_DISABLED = (n_constants.INHERITED if Topology.is_v5
                     else n_constants.DISABLED)


class PortsScaleTest(NuageBaseTest):

    @classmethod
    def setup_clients(cls):
        super(PortsScaleTest, cls).setup_clients()
        cls.nuage_client = NuageRestClient()
        # Increase api read timeout because router interface attach can
        # take a long time if there are many ports with aaps
        cls.manager.routers_client = cls.manager.network.RoutersClient(
            http_timeout=100)

    def test_nuage_port_allow_address_pair_scale(self):
        network = self.create_network()
        cidr = IPNetwork("10.0.0.0/16")
        subnet = self.create_subnet(network, cidr=cidr,
                                    mask_bits=cidr.prefixlen)
        num_ports_aap = 100
        addrpair_port = self.create_port(network, device_owner='nuage:vip')
        allowed_address_pairs = [
            {'ip_address': addrpair_port['fixed_ips'][0]['ip_address'],
             'mac_address': addrpair_port['mac_address']}]
        portids_to_aap = {}
        for i in range(num_ports_aap):
            port = self.create_port(
                network,
                allowed_address_pairs=allowed_address_pairs)
            portids_to_aap[port['id']] = allowed_address_pairs
        router = self.create_router()
        self.create_router_interface(router['id'], subnet['id'])

        l3domain_ext_id = self.nuage_client.get_vsd_external_id(router['id'])
        nuage_domain = self.nuage_client.get_resource(
            n_constants.DOMAIN,
            filters='externalID',
            filter_values=l3domain_ext_id)
        nuage_subnet = self.nuage_client.get_domain_subnet(
            n_constants.DOMAIN, nuage_domain[0]['ID'], by_subnet=subnet)
        for port_id in portids_to_aap:
            port_ext_id = self.nuage_client.get_vsd_external_id(port_id)
            nuage_vport = self.nuage_client.get_vport(
                n_constants.SUBNETWORK,
                nuage_subnet[0]['ID'],
                filters='externalID',
                filter_values=port_ext_id)
            self.assertEqual(SPOOFING_DISABLED,
                             nuage_vport[0]['addressSpoofing'])
            nuage_vip = self.nuage_client.get_virtual_ip(
                n_constants.VPORT,
                nuage_vport[0]['ID'],
                filters='virtualIP',
                filter_values=str(portids_to_aap[port_id][0]['ip_address']))
            self.assertEqual(portids_to_aap[port_id][0]['mac_address'],
                             nuage_vip[0]['MAC'])
            self.assertEqual(nuage_vip[0]['externalID'],
                             self.nuage_client.get_vsd_external_id(port_id))
