# Copyright 2020 NOKIA
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

from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.mixins import net_topology as topology_mixin
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_client import NuageRestClient


CONF = Topology.get_conf()


class NuageHybridMplsSriov(NuageBaseTest,
                           topology_mixin.NetTopologyMixin):

    @classmethod
    def skip_checks(cls):
        super(NuageHybridMplsSriov, cls).skip_checks()
        if not CONF.nuage_sut.nuage_hybrid_mpls_enabled:
            raise cls.skipException('nuage_hybrid_mpls type driver '
                                    'not enabled in tempest.conf')

        if CONF.network.port_vnic_type not in ['direct', 'macvtap']:
            msg = ("Test requires nuage_test_sriov mech driver "
                   "and port_vnic_type=='direct'")
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(NuageHybridMplsSriov, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(NuageHybridMplsSriov, cls).resource_setup()
        cls.vsg_gateway = cls.nuage_client.create_gateway(
            data_utils.rand_name(name='vsg'),
            data_utils.rand_name(name='sys_id'), 'VSG')[0]
        cls.unmanaged_gateway = cls.nuage_client.create_gateway(
            data_utils.rand_name(name='umg'),
            data_utils.rand_name(name='sys_id'), 'UNMANAGED_GATEWAY')[0]

    @classmethod
    def resource_cleanup(cls):
        super(NuageHybridMplsSriov, cls).resource_cleanup()
        cls.nuage_client.delete_gateway(cls.vsg_gateway['ID'])
        cls.nuage_client.delete_gateway(cls.unmanaged_gateway['ID'])

    def test_nuage_hybrid_mpls_sriov_with_unmanaged_gateway(self):
        segments = [{"provider:network_type": "vlan",
                     "provider:segmentation_id": 210,
                     "provider:physical_network": "physnet1"},
                    {"provider:network_type": "nuage_hybrid_mpls"}]
        kwargs = {'segments': segments}
        network = self.create_network(manager=self.admin_manager, **kwargs)

        subnet_v4 = self.create_subnet(network,
                                       ip_version=4,
                                       manager=self.admin_manager)
        self.assertIsNotNone(subnet_v4)

        umg_port_name = data_utils.rand_name(name='uwmg-port1')
        umg_port1 = self.nuage_client.create_gateway_port(
            umg_port_name, umg_port_name, 'ACCESS',
            self.unmanaged_gateway['ID'],
            extra_params={'VLANRange': '0-4095'})[0]

        mapping1 = {'switch_id': self.unmanaged_gateway['systemID'],
                    'port_id': umg_port1['physicalName'],
                    'host_id': 'host-hierarchical',
                    'pci_slot': '0000:03:10.16'}

        with self.switchport_mapping(do_delete=False, **mapping1) \
                as switch_map1:
            self.addCleanup(self.switchport_mapping_client_admin.
                            delete_switchport_mapping, switch_map1['id'])

            kwargs = {
                'binding:vnic_type': 'direct',
                'binding:host_id': 'host-hierarchical',
                'binding:profile': {
                    'pci_slot': '0000:03:10.16',
                    'physical_network': 'physnet1',
                    'pci_vendor_info': '8086:10ed'
                }
            }

            self.create_port(network, self.admin_manager, **kwargs)

            l2domain = self.vsd.get_l2domain(by_network_id=network["id"],
                                             cidr=subnet_v4["cidr"])
            self.assertIsNotNone(self.vsd.get_vport(l2domain=l2domain,
                                                    by_port_id=network['id']))

    def test_nuage_hybrid_mpls_sriov_with_managed_gateway_neg(self):
        segments = [{"provider:network_type": "vlan",
                     "provider:segmentation_id": 210,
                     "provider:physical_network": "physnet1"},
                    {"provider:network_type": "nuage_hybrid_mpls"}]
        kwargs = {'segments': segments}
        network = self.create_network(manager=self.admin_manager, **kwargs)

        subnet_v4 = self.create_subnet(network,
                                       ip_version=4,
                                       manager=self.admin_manager)
        self.assertIsNotNone(subnet_v4)

        vsg_port_name = data_utils.rand_name(name='vsg-port1')
        vsg_port1 = self.nuage_client.create_gateway_port(
            vsg_port_name, vsg_port_name, 'ACCESS', self.vsg_gateway['ID'],
            extra_params={'VLANRange': '0-4095'})[0]

        mapping1 = {'switch_id': self.vsg_gateway['systemID'],
                    'port_id': vsg_port1['physicalName'],
                    'host_id': 'host-hierarchical',
                    'pci_slot': '0000:03:10.15'}

        with self.switchport_mapping(do_delete=False, **mapping1) as \
                switch_map1:
            self.addCleanup(self.switchport_mapping_client_admin.
                            delete_switchport_mapping, switch_map1['id'])

            kwargs = {
                'binding:vnic_type': 'direct',
                'binding:host_id': 'host-hierarchical',
                'binding:profile': {
                    'pci_slot': '0000:03:10.15',
                    'physical_network': 'physnet1',
                    'pci_vendor_info': '8086:10ed'
                }
            }

            port = self.create_port(network, self.admin_manager,
                                    False, **kwargs)

            self.assertEqual('binding_failed', port['binding:vif_type'])

            self.delete_port(port, self.admin_manager)

            l2domain = self.vsd.get_l2domain(by_network_id=network["id"],
                                             cidr=subnet_v4["cidr"])
            self.assertIsNone(self.vsd.get_vport(l2domain=l2domain,
                                                 by_port_id=network['id']))
