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

from netaddr import IPNetwork

from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.mixins import net_topology as topology_mixin
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

CONF = Topology.get_conf()


class NuageHybridMplsSriovTest(NuageBaseTest,
                               topology_mixin.NetTopologyMixin):

    @classmethod
    def skip_checks(cls):
        super(NuageHybridMplsSriovTest, cls).skip_checks()
        if Topology.before_nuage('20.5'):
            raise cls.skipException('nuage_hybrid_mpls is supported from '
                                    '20.5 onwards only')
        if not CONF.nuage_sut.nuage_hybrid_mpls_enabled:
            raise cls.skipException('nuage_hybrid_mpls type driver '
                                    'not enabled in tempest.conf')

        if CONF.network.port_vnic_type not in ['direct', 'macvtap']:
            msg = ("Test requires nuage_test_sriov mech driver "
                   "and port_vnic_type=='direct'")
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(NuageHybridMplsSriovTest, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(NuageHybridMplsSriovTest, cls).resource_setup()
        cls.vsg_gateway = cls.nuage_client.create_gateway(
            data_utils.rand_name(name='vsg'),
            data_utils.rand_name(name='sys_id'), 'VSG')[0]
        cls.unmanaged_gateway = cls.nuage_client.create_gateway(
            data_utils.rand_name(name='umg'),
            data_utils.rand_name(name='sys_id'), 'UNMANAGED_GATEWAY')[0]

    @classmethod
    def resource_cleanup(cls):
        super(NuageHybridMplsSriovTest, cls).resource_cleanup()
        cls.nuage_client.delete_gateway(cls.vsg_gateway['ID'])
        cls.nuage_client.delete_gateway(cls.unmanaged_gateway['ID'])

    def _create_os_topology(self, gateway, network_type):

        segments = [{"provider:network_type": "vlan",
                     "provider:segmentation_id": 210,
                     "provider:physical_network": "physnet1"},
                    {"provider:network_type": network_type}]
        kwargs = {'segments': segments}
        network = self.create_network(manager=self.admin_manager, **kwargs)

        subnet = self.create_subnet(network,
                                    ip_version=4,
                                    manager=self.admin_manager)
        self.assertIsNotNone(subnet)

        port_name = data_utils.rand_name(name='gw-port')
        gw_port = self.nuage_client.create_gateway_port(
            port_name, port_name, 'ACCESS',
            gateway['ID'],
            extra_params={'VLANRange': '0-4095'})[0]

        return network, subnet, gw_port

    def _create_vsd_mgd_os_topology(self):

        topology = {}

        l3template = self.vsd_create_l3domain_template()
        l3domain = self.vsd_create_l3domain(template_id=l3template.id)
        zone = self.vsd_create_zone(domain=l3domain)

        # MPLS
        kwargs = {'l2_encap_type': 'MPLS'}
        l3subnet_mpls = self.create_vsd_subnet(
            zone=zone, cidr4=IPNetwork('1.0.0.0/24'),
            gateway4='1.0.0.1', **kwargs)
        topology['l3subnet_mpls'] = l3subnet_mpls

        # VXLAN
        l3subnet_vxlan = self.create_vsd_subnet(zone=zone,
                                                cidr4=IPNetwork('2.0.0.0/24'),
                                                gateway4='2.0.0.1')
        topology['l3subnet_vxlan'] = l3subnet_vxlan

        # MPLS
        segments = [{"provider:network_type": "vlan",
                     "provider:segmentation_id": 210,
                     "provider:physical_network": "physnet1"},
                    {"provider:network_type": "nuage_hybrid_mpls"}]
        kwargs = {'segments': segments}
        network_mpls = self.create_network(manager=self.admin_manager,
                                           **kwargs)
        subnet_mpls = self.create_l3_vsd_managed_subnet(
            network_mpls, l3subnet_mpls, manager=self.admin_manager)
        topology['network_mpls'] = network_mpls
        topology['subnet_mpls'] = subnet_mpls

        # VXLAN
        segments = [{"provider:network_type": "vlan",
                     "provider:segmentation_id": 211,
                     "provider:physical_network": "physnet1"},
                    {"provider:network_type": "vxlan"}]
        kwargs = {'segments': segments}
        network_vxlan = self.create_network(manager=self.admin_manager,
                                            **kwargs)
        subnet_vxlan = self.create_l3_vsd_managed_subnet(
            network_vxlan, l3subnet_vxlan, manager=self.admin_manager)
        topology['network_vxlan'] = network_vxlan
        topology['subnet_vxlan'] = subnet_vxlan

        vsg_port_name = data_utils.rand_name(name='vsg-port')
        vsg_port = self.nuage_client.create_gateway_port(
            vsg_port_name, vsg_port_name, 'ACCESS',
            self.vsg_gateway['ID'],
            extra_params={'VLANRange': '0-4095'})[0]
        topology['vsg_port'] = vsg_port

        um_port_name = data_utils.rand_name(name='um-port')
        um_port = self.nuage_client.create_gateway_port(
            um_port_name, um_port_name, 'ACCESS',
            self.unmanaged_gateway['ID'],
            extra_params={'VLANRange': '0-4095'})[0]
        topology['um_port'] = um_port

        return topology

    def _validate_port_binding(self, network, subnet, should_succeed,
                               l3subnet=None, **kwargs):
        # When port binding is successful, a bridge port is created and
        # the vif_type is set to 'hw_veb'. When it fails, the value of
        # vif_type is binding_failed and no bridge port is created

        if should_succeed:
            vif_type = 'hw_veb'
            assert_vport = self.assertIsNotNone
        else:
            vif_type = 'binding_failed'
            assert_vport = self.assertIsNone

        port = self.create_port(network, self.admin_manager,
                                cleanup=True, **kwargs)
        self.assertEqual(vif_type, port['binding:vif_type'])
        if not l3subnet:
            l2domain = self.vsd.get_l2domain(by_subnet=subnet)
            assert_vport(self.vsd.get_vport(l2domain=l2domain,
                                            by_port_id=network['id']))
        else:
            assert_vport(self.vsd.get_vport(subnet=l3subnet,
                                            by_port_id=network['id']))

        self.delete_port(port, self.admin_manager)

    def test_os_nuage_hybrid_mpls_sriov_with_unmanaged_gateway(self):

        network, subnet, gw_port = self._create_os_topology(
            self.unmanaged_gateway, network_type='nuage_hybrid_mpls')

        mapping = {'switch_id': self.unmanaged_gateway['systemID'],
                   'port_id': gw_port['physicalName'],
                   'host_id': 'host-hierarchical',
                   'pci_slot': '0000:03:10.15'}

        with self.switchport_mapping(do_delete=False, **mapping) \
                as switch_map:
            self.addCleanup(self.switchport_mapping_client_admin.
                            delete_switchport_mapping, switch_map['id'])

            kwargs = {
                'binding:vnic_type': 'direct',
                'binding:host_id': 'host-hierarchical',
                'binding:profile': {
                    'pci_slot': '0000:03:10.15',
                    'physical_network': 'physnet1',
                    'pci_vendor_info': '8086:10ed'
                }
            }

            self._validate_port_binding(network, subnet,
                                        should_succeed=True, **kwargs)

    def test_os_nuage_hybrid_mpls_sriov_with_managed_gateway_neg(self):

        network, subnet, gw_port = self._create_os_topology(
            self.vsg_gateway, network_type='nuage_hybrid_mpls')

        mapping = {'switch_id': self.vsg_gateway['systemID'],
                   'port_id': gw_port['physicalName'],
                   'host_id': 'host-hierarchical',
                   'pci_slot': '0000:03:10.16'}

        with self.switchport_mapping(do_delete=False, **mapping) as \
                switch_map:
            self.addCleanup(self.switchport_mapping_client_admin.
                            delete_switchport_mapping, switch_map['id'])

            kwargs = {
                'binding:vnic_type': 'direct',
                'binding:host_id': 'host-hierarchical',
                'binding:profile': {
                    'pci_slot': '0000:03:10.16',
                    'physical_network': 'physnet1',
                    'pci_vendor_info': '8086:10ed'
                }
            }

            self._validate_port_binding(network, subnet,
                                        should_succeed=False, **kwargs)

    def test_os_vxlan_sriov_with_unmanaged_gateway_neg(self):
        network, subnet, gw_port = self._create_os_topology(
            self.unmanaged_gateway, network_type='vxlan')

        mapping = {'switch_id': self.unmanaged_gateway['systemID'],
                   'port_id': gw_port['physicalName'],
                   'host_id': 'host-hierarchical',
                   'pci_slot': '0000:03:10.17'}

        with self.switchport_mapping(do_delete=False, **mapping) \
                as switch_map:
            self.addCleanup(self.switchport_mapping_client_admin.
                            delete_switchport_mapping, switch_map['id'])

            kwargs = {
                'binding:vnic_type': 'direct',
                'binding:host_id': 'host-hierarchical',
                'binding:profile': {
                    'pci_slot': '0000:03:10.17',
                    'physical_network': 'physnet1',
                    'pci_vendor_info': '8086:10ed'
                }
            }

            self._validate_port_binding(network, subnet,
                                        should_succeed=False, **kwargs)

    def test_vsd_nuage_hybrid_mpls_scenario(self):
        # This test covers the topology that will be used in real
        # implementations. There will be one l3 domain with both
        # vxlan and mpls subnets. Negative cases are also included.

        topology = self._create_vsd_mgd_os_topology()

        # VXLAN - Bridge port creation
        mapping = {'switch_id': self.vsg_gateway['systemID'],
                   'port_id': topology['vsg_port']['physicalName'],
                   'host_id': 'host-hierarchical',
                   'pci_slot': '0000:03:10.18'}

        with self.switchport_mapping(do_delete=False, **mapping) \
                as switch_map:
            self.addCleanup(self.switchport_mapping_client_admin.
                            delete_switchport_mapping, switch_map['id'])

            kwargs = {
                'binding:vnic_type': 'direct',
                'binding:host_id': 'host-hierarchical',
                'binding:profile': {
                    'pci_slot': '0000:03:10.18',
                    'physical_network': 'physnet1',
                    'pci_vendor_info': '8086:10ed'
                }
            }

            self._validate_port_binding(topology['network_mpls'],
                                        topology['subnet_mpls'],
                                        should_succeed=False,
                                        l3subnet=topology['l3subnet_mpls'],
                                        **kwargs)
            self._validate_port_binding(topology['network_vxlan'],
                                        topology['subnet_vxlan'],
                                        should_succeed=True,
                                        l3subnet=topology['l3subnet_vxlan'],
                                        **kwargs)

        # MPLS - Bridge port creation
        mapping = {'switch_id': self.unmanaged_gateway['systemID'],
                   'port_id': topology['um_port']['physicalName'],
                   'host_id': 'host-hierarchical',
                   'pci_slot': '0000:03:10.19'}

        with self.switchport_mapping(do_delete=False, **mapping) \
                as switch_map:
            self.addCleanup(self.switchport_mapping_client_admin.
                            delete_switchport_mapping, switch_map['id'])

            kwargs = {
                'binding:vnic_type': 'direct',
                'binding:host_id': 'host-hierarchical',
                'binding:profile': {
                    'pci_slot': '0000:03:10.19',
                    'physical_network': 'physnet1',
                    'pci_vendor_info': '8086:10ed'
                }
            }

            self._validate_port_binding(topology['network_vxlan'],
                                        topology['subnet_vxlan'],
                                        should_succeed=False,
                                        l3subnet=topology['l3subnet_vxlan'],
                                        **kwargs)
            self._validate_port_binding(topology['network_mpls'],
                                        topology['subnet_mpls'],
                                        should_succeed=True,
                                        l3subnet=topology['l3subnet_mpls'],
                                        **kwargs)
