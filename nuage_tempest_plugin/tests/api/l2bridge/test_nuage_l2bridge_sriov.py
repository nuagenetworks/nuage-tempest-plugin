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

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.mixins import net_topology as topology_mixin
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.tests.api.l2bridge.base_nuage_l2bridge \
    import BaseNuageL2Bridge
from nuage_tempest_plugin.tests.api.vsd_managed \
    import base_vsd_managed_networks as base_vsd_managed

CONF = Topology.get_conf()


class TestNuageL2BridgeSRIOV(BaseNuageL2Bridge,
                             base_vsd_managed.BaseVSDManagedNetwork,
                             topology_mixin.NetTopologyMixin
                             ):
    personality = 'VSG'

    # This class assumes that the following resources are available:
    # physnet1,100,vlan
    # physnet2,100,vlan
    # physnet2,101,vlan
    @classmethod
    def setUpClass(cls):
        super(TestNuageL2BridgeSRIOV, cls).setUpClass()
        cls.expected_vport_type = constants.VPORT_TYPE_BRIDGE
        cls.expected_vlan = 123

    @classmethod
    def skip_checks(cls):
        super(TestNuageL2BridgeSRIOV, cls).skip_checks()
        if CONF.network.port_vnic_type not in ['direct', 'macvtap']:
            msg = ("Test requires nuage_test_sriov mech driver "
                   "and port_vnic_type=='direct'")
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TestNuageL2BridgeSRIOV, cls).resource_setup()
        # Only gateway here, to support parallel testing each tests makes its
        # own gateway port so no VLAN overlap should occur.
        cls.gateway = cls.nuage_client.create_gateway(
            data_utils.rand_name(name='vsg'),
            data_utils.rand_name(name='sys_id'), cls.personality)[0]

    @classmethod
    def resource_cleanup(cls):
        super(TestNuageL2BridgeSRIOV, cls).resource_cleanup()
        cls.nuage_client.delete_gateway(cls.gateway['ID'])

        for vsd_l2domain in cls.vsd_l2domains:
            cls.nuage_client.delete_l2domain(vsd_l2domain['ID'])

        for vsd_l2dom_template in cls.vsd_l2dom_templates:
            cls.nuage_client.delete_l2domaintemplate(
                vsd_l2dom_template['ID'])

    def _validate_bridge_config(self, bridge, name, phys_nets):
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

    def _validate_l2domain_on_vsd(self, bridge, expected_ext_id, l2domain):
        self.assertEqual(expected_ext_id, l2domain.external_id)
        self.assertEqual(bridge['id'], l2domain.name)
        self.assertEqual(bridge['name'], l2domain.description)
        dhcp_options = self.vsd.get_l2domain_dhcp_options(l2domain)
        for dhcp_option in dhcp_options:
            self.assertEqual(expected_ext_id, dhcp_option.external_id)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_add_segments_to_bridge_with_subnet_with_vm(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'}]
        name = data_utils.rand_name('test-l2bridge-dualipv4')
        bridge = self.create_l2bridge(name, physnets)
        bridge = self.get_l2bridge(bridge['id'])
        self._validate_bridge_config(bridge, name, physnets)

        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }

        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        if self.is_dhcp_agent_present():
            msg = ("Bad request: A network cannot be attached to an l2bridge"
                   " when neutron-dhcp-agent is enabled'")
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1, subnet_name=name + '-subnet-1',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            gw_port_name = data_utils.rand_name(name='gw-port1')
            gw_port1 = self.nuage_client.create_gateway_port(
                gw_port_name, gw_port_name, 'ACCESS', self.gateway['ID'],
                extra_params={'VLANRange': '0-4095'})[0]
            gw_port_name = data_utils.rand_name(name='gw-port2')
            gw_port2 = self.nuage_client.create_gateway_port(
                gw_port_name, gw_port_name, 'ACCESS', self.gateway['ID'],
                extra_params={'VLANRange': '0-4095'})[0]

            s1 = self.create_subnet(n1, subnet_name=name + '-subnet-1',
                                    client=self.admin_manager,
                                    cidr=IPNetwork('10.10.1.0/24'),
                                    mask_bits=24)

            bridge = self.get_l2bridge(bridge['id'])
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)
            self.assertEqual(s1['nuage_l2bridge'], bridge['id'])

            mapping1 = {'switch_id': self.gateway['systemID'],
                        'port_id': gw_port1['physicalName'],
                        'host_id': 'host-hierarchical',
                        'pci_slot': '0000:18:06.6'}
            mapping2 = {'switch_id': self.gateway['systemID'],
                        'port_id': gw_port2['physicalName'],
                        'host_id': 'host-hierarchical',
                        'pci_slot': '0000:18:06.7'}
            with self.switchport_mapping(do_delete=False, **mapping1) as map1,\
                    self.switchport_mapping(do_delete=False, **mapping2) \
                    as map2:

                self.addCleanup(
                    self.switchport_mapping_client_admin.
                    delete_switchport_mapping,
                    map1['id'])
                self.addCleanup(
                    self.switchport_mapping_client_admin.
                    delete_switchport_mapping,
                    map2['id'])

                kwargs = {
                    'fixed_ips': [{
                        'ip_address': '10.10.1.10',
                        'subnet_id': s1['id']}],
                    'binding:vnic_type': 'direct',
                    'binding:host_id': 'host-hierarchical',
                    'binding:profile': {
                        "pci_slot": "0000:18:06.6",
                        "physical_network": "physnet1",
                        "pci_vendor_info": "8086:10ed"
                    }
                }

                self.create_port(n1, self.admin_manager,
                                 **kwargs)

                vport_1 = self.vsd.get_vport(l2domain=l2domain,
                                             by_port_id=s1['network_id'])
                self.assertIsNotNone(vport_1,
                                     "Vport not created for port in network 1")

                physnets = [{
                    'physnet_name': 'physnet1',
                    'segmentation_id': 100,
                    'segmentation_type': 'vlan'
                }, {
                    'physnet_name': 'physnet2',
                    'segmentation_id': 100,
                    'segmentation_type': 'vlan'
                }]

                # Extend the bridge physnets

                self.update_l2bridge(bridge['id'], physnets=physnets)
                bridge = self.get_l2bridge(bridge['id'])
                self._validate_bridge_config(bridge, name, physnets)

                kwargs = {
                    'segments': [
                        {
                            'provider:network_type': 'vlan',
                            'provider:segmentation_id': 100,
                            'provider:physical_network': 'physnet2'},
                        {
                            'provider:network_type': 'vxlan'
                        }
                    ]
                }

                n2 = self.create_network(network_name=name + '-2',
                                         client=self.admin_manager,
                                         **kwargs)

                s2 = self.create_subnet(n2, subnet_name=name + '-subnet-2',
                                        client=self.admin_manager,
                                        cidr=IPNetwork('10.10.1.0/24'),
                                        mask_bits=24)

                bridge = self.get_l2bridge(bridge['id'])
                self.assertEqual(s2['nuage_l2bridge'], bridge['id'])
                l2domain = self.vsd.get_l2domain(
                    vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
                expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
                self._validate_l2domain_on_vsd(bridge, expected_ext_id,
                                               l2domain)

                kwargs = {
                    'fixed_ips': [{
                        'ip_address': '10.10.1.11',
                        'subnet_id': s2['id']
                    }],
                    'binding:vnic_type': 'direct',
                    'binding:host_id': 'host-hierarchical',
                    'binding:profile': {
                        "pci_slot": "0000:18:06.7",
                        "physical_network": "physnet2",
                        "pci_vendor_info": "8086:10ed"
                    }
                }
                self.create_port(n2, self.admin_manager,
                                 **kwargs)

                vport_2 = self.vsd.get_vport(l2domain=l2domain,
                                             by_port_id=s2['network_id'])
                self.assertIsNotNone(vport_2,
                                     "Vport not created for port in network 2")
                policygroups = vport_2.policy_groups.get()
                self.assertEqual(1, len(policygroups),
                                 "Port should be part of exactly 1 "
                                 "policygroup.")
                ingress = vport_2.ingress_acl_entry_templates.get(
                    filter=self.vsd.get_external_id_filter(bridge['id'])
                )
                egress = vport_2.egress_acl_entry_templates.get(
                    filter=self.vsd.get_external_id_filter(bridge['id'])
                )
                self.assertEqual(2, len(ingress),
                                 "Port should use exactly 2 "
                                 "ingress acl template entries.")
                self.assertEqual(2, len(egress),
                                 "Port should use exactly 2 "
                                 "egress acl template entries.")
