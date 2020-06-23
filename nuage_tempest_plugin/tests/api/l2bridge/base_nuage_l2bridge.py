# Copyright 2018 NOKIA
# All Rights Reserved.
#
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

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON
from tempest import config

CONF = config.CONF


class BaseNuageL2Bridge(NuageBaseTest):

    _ip_version = 4
    _cidr = IPNetwork('10.10.1.0/24')
    _mask_bits = 24
    _dual_cidr = IPNetwork('cafe:babe::/64')
    _dual_mask_bits = 64
    _dual_ip_version = 6
    _host_routes = [{'destination': '10.20.0.0/32',
                     'nexthop': '10.10.1.10'}]
    _dns_nameservers = ['7.8.8.8', '7.8.4.4']
    _segmentation_id_1 = 200
    _segmentation_id_2 = 201

    @classmethod
    def setup_clients(cls):
        super(BaseNuageL2Bridge, cls).setup_clients()
        cls.NuageNetworksClient = NuageNetworkClientJSON(
            cls.os_admin.auth_provider,
            **cls.os_admin.default_params)
        cls.NuageNetworksClientNonAdmin = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)

    def create_l2bridge(self, name, physnets, is_admin=True, cleanup=True):
        if is_admin:
            body = self.NuageNetworksClient.create_nuage_l2bridge(
                name, physnets=physnets)
        else:
            body = self.NuageNetworksClientNonAdmin.create_nuage_l2bridge(
                name, physnets=physnets)
        bridge = body['nuage_l2bridge']
        if cleanup:
            self.addCleanup(self.delete_l2bridge, bridge['id'])
        return bridge

    def get_l2bridge(self, l2bridge_id):
        body = self.NuageNetworksClient.get_nuage_l2bridge(l2bridge_id)
        return body['nuage_l2bridge']

    def update_l2bridge(self, l2bridge_id, name=None, physnets=None,
                        is_admin=True):
        body = None
        if is_admin:
            if name and physnets:
                body = self.NuageNetworksClient.update_nuage_l2bridge(
                    l2bridge_id,
                    name=name, physnets=physnets)
            elif name:
                body = self.NuageNetworksClient.update_nuage_l2bridge(
                    l2bridge_id,
                    name=name)
            elif physnets:
                body = self.NuageNetworksClient.update_nuage_l2bridge(
                    l2bridge_id,
                    physnets=physnets)
        else:
            if name and physnets:
                body = self.NuageNetworksClientNonAdmin.update_nuage_l2bridge(
                    l2bridge_id,
                    name=name, physnets=physnets)
            elif name and not physnets:
                body = self.NuageNetworksClientNonAdmin.update_nuage_l2bridge(
                    l2bridge_id,
                    name=name)
            elif physnets and not name:
                body = self.NuageNetworksClientNonAdmin.update_nuage_l2bridge(
                    l2bridge_id,
                    physnets=physnets)
        self.assertIsNotNone(body['nuage_l2bridge'])
        return body['nuage_l2bridge']

    def delete_l2bridge(self, l2bridge_id):
        self.NuageNetworksClient.delete_nuage_l2bridge(l2bridge_id)

    def validate_bridge_config(self, bridge, name, phys_nets):
        self.assertEqual(name, bridge['name'])
        self.assertEqual(len(phys_nets), len(bridge['physnets']))
        for phys_net in phys_nets:
            found_matching_phys_net = False
            for bridge_physnet in bridge['physnets']:
                if phys_net['physnet_name'] == bridge_physnet['physnet']:
                    self.assertEqual(phys_net['segmentation_id'],
                                     bridge_physnet['segmentation_id'])
                    self.assertEqual(phys_net['segmentation_type'],
                                     bridge_physnet['segmentation_type'])
                    found_matching_phys_net = True
                    break
            self.assertEqual(True, found_matching_phys_net)

    def validate_l2domain_on_vsd(self, l2domain, ip_type, bridge=None,
                                 subnet=None):
        dhcp_options = self.vsd.get_l2domain_dhcp_options(l2domain)
        if subnet:
            if Topology.is_v5:
                self.assertEqual(subnet['id'], l2domain.name)
            else:
                self.assertEqual(subnet['network_id'] + '_' + subnet['id'],
                                 l2domain.name)
            self.assertEqual(subnet['name'], l2domain.description)
            for dhcp_option in dhcp_options:
                self.assertEqual(self.ext_id(subnet['id']),
                                 dhcp_option.external_id)
        else:
            self.assertEqual(bridge['id'], l2domain.name)
            self.assertEqual(bridge['name'], l2domain.description)
            for dhcp_option in dhcp_options:
                self.assertEqual(self.ext_id(bridge['id']),
                                 dhcp_option.external_id)
        self.assertEqual(l2domain.ip_type, ip_type)

    @staticmethod
    def ext_id(ext_id):
        return ext_id + '@' + CONF.nuage.nuage_cms_id

    def l2domain_ext_id(self, subnet):
        return (self.ext_id(subnet['id']) if Topology.is_v5
                else self.ext_id(subnet['network_id']))
