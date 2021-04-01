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

from tempest.common import utils
from tempest.lib import decorators

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class TestNuageHWVTEP(NuageBaseTest):

    physnet = 'physnet1'

    @classmethod
    def skip_checks(cls):
        super(NuageBaseTest, cls).skip_checks()
        if utils.is_extension_enabled('nuage-router', 'network'):
            msg = ('Extension nuage_router is enabled, '
                   'not running HW_VTEP tests.')
            raise cls.skipException(msg)

    def _test_hw_vtep(self, is_vsd_managed=False, is_ipv4=True,
                      is_ipv6=False, is_flat=False):
        (ipv4_subnet, ipv6_subnet,
         network, vsd_resource, vsd_domain) = self._create_network_subnets(
            is_ipv4, is_ipv6, is_vsd_managed, is_flat)
        if not is_vsd_managed:
            if is_ipv4:
                vsd_resource = self.vsd.get_l2domain(by_subnet=ipv4_subnet)
            else:
                vsd_resource = self.vsd.get_l2domain(by_subnet=ipv6_subnet)

        # resources under test
        self.create_port(network)

        # Bridge not expected at this moment, as port is not bound
        vports = vsd_resource.vports.get()
        self.assertEmpty(vports, 'vports found without bound port')

        # Create VM
        vm = self.create_tenant_server(networks=[network],
                                       prepare_for_connectivity=False)

        bp_vlan = 0 if is_flat else network['provider:segmentation_id']
        self._verify_switchport_bindings(expected_number_bindings=1)
        self._verify_bridge_port(vsd_resource,
                                 expected_bp_vlan=bp_vlan)

        # Create second VM, no change expected
        vm2 = self.create_tenant_server(networks=[network],
                                        prepare_for_connectivity=False)

        self._verify_switchport_bindings(expected_number_bindings=2)
        self._verify_bridge_port(vsd_resource,
                                 expected_bp_vlan=bp_vlan)

        self.cleanup_server(vm.id)

        self._verify_switchport_bindings(expected_number_bindings=1)
        self._verify_bridge_port(vsd_resource,
                                 expected_bp_vlan=bp_vlan)

        self.cleanup_server(vm2.id)

        vports = vsd_resource.vports.get()
        self.assertEmpty(vports, 'vports found without bound port')

    def _create_network_subnets(self, is_ipv4, is_ipv6, is_vsd_managed,
                                is_flat):
        # Use fake network to get tenant_id of current user
        network = self.create_network()
        project_id = network['project_id']
        if is_flat:
            kwargs = {'provider:network_type': 'flat',
                      'provider:physical_network': self.physnet}
        else:
            kwargs = {'provider:network_type': 'vlan',
                      'provider:physical_network': self.physnet}
        network = self.create_network(manager=self.admin_manager,
                                      project_id=project_id, **kwargs)
        network = self.get_network(network['id'], manager=self.admin_manager)
        ipv4_subnet = ipv6_subnet = vsd_resource = vsd_domain = None
        if is_vsd_managed:
            # create vsd managed resources
            if is_ipv4 and not is_ipv6:
                vsd_l2domain_template = self.vsd_create_l2domain_template(
                    ip_type="IPV4",
                    cidr4=self.cidr4,
                    dhcp_managed=True,
                    enable_dhcpv4=False)
            elif is_ipv6 and not is_ipv4:
                vsd_l2domain_template = self.vsd_create_l2domain_template(
                    dhcp_managed=True,
                    ip_type="IPV6",
                    cidr6=self.cidr6)
            else:
                vsd_l2domain_template = self.vsd_create_l2domain_template(
                    ip_type="DUALSTACK",
                    dhcp_managed=True,
                    cidr4=self.cidr4,
                    cidr6=self.cidr6,
                    enable_dhcpv4=False)
            vsd_resource = vsd_domain = self.vsd_create_l2domain(
                template=vsd_l2domain_template)
            if is_ipv4:
                ipv4_subnet = self.create_subnet(
                    network,
                    gateway=None,
                    cidr=self.cidr4,
                    mask_bits=self.mask_bits4_unsliced,
                    nuagenet=vsd_resource.id,
                    net_partition=self.net_partition,
                    enable_dhcp=False)
            if is_ipv6:
                ipv6_subnet = self.create_subnet(
                    network,
                    ip_version=6,
                    gateway=vsd_l2domain_template.ipv6_gateway,
                    cidr=IPNetwork(vsd_l2domain_template.ipv6_address),
                    mask_bits=IPNetwork(
                        vsd_l2domain_template.ipv6_address).prefixlen,
                    enable_dhcp=False,
                    nuagenet=vsd_resource.id,
                    net_partition=self.net_partition)
        else:
            # os managed is always l2
            if is_ipv4:
                ipv4_subnet = self.create_subnet(network, enable_dhcp=False)
            if is_ipv6:
                ipv6_subnet = self.create_subnet(network, ip_version=6,
                                                 enable_dhcp=False)
        return ipv4_subnet, ipv6_subnet, network, vsd_resource, vsd_domain

    def _verify_bridge_port(self, vsd_resource, expected_bp_vlan):
        vports = vsd_resource.vports.get()
        self.assertEqual(1, len(vports), 'Exactly one vport expected')
        vport = vports[0]
        self.assertEqual('BRIDGE', vport.type)
        self.assertEqual(vport.vlan, expected_bp_vlan)
        interfaces = vport.bridge_interfaces.get()
        self.assertEqual(1, len(interfaces))
        policy_groups = vport.policy_groups.get()
        self.assertEmpty(policy_groups)

    def _verify_switchport_bindings(self, expected_number_bindings):
        # TODO(Marcelo): Get bindings which corresponds only to this test
        # Skipping because other simultaneous tests might create
        # bindings which could make below check fail
        # self.assertEqual(expected_number_bindings,
        #                  len(self.plugin_network_client_admin.
        #                      list_switchport_bindings(
        #                          bridge='br-ex')['switchport_bindings']))
        pass

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_os_managed_ipv4_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=False, is_ipv4=True, is_ipv6=False)

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_os_managed_ipv6_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=False, is_ipv4=False, is_ipv6=True)

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_os_managed_dualstack_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=False, is_ipv4=True, is_ipv6=True)

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_vsd_managed_ipv4_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=True, is_ipv4=True, is_ipv6=False)

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_vsd_managed_ipv6_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=True, is_ipv4=False, is_ipv6=True)

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_vsd_managed_dualstack_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=True, is_ipv4=True, is_ipv6=False)

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_os_managed_flat_ipv4_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=False, is_ipv4=True, is_ipv6=False,
                           is_flat=True)

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_os_managed_flat_ipv6_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=False, is_ipv4=False, is_ipv6=True,
                           is_flat=True)

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_os_managed_flat_dualstack_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=False, is_ipv4=True, is_ipv6=True,
                           is_flat=True)

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_vsd_managed_flat_ipv4_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=True, is_ipv4=True, is_ipv6=False,
                           is_flat=True)

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_vsd_managed_flat_ipv6_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=True, is_ipv4=False, is_ipv6=True,
                           is_flat=True)

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_vsd_managed_flat_dualstack_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=True, is_ipv4=True, is_ipv6=False,
                           is_flat=True)

    @decorators.attr(type='smoke')
    def test_trunk_subport_lifecycle(self):
        self.client = self.plugin_network_client_admin

        kwargs = {'provider:network_type': 'flat',
                  'provider:physical_network': self.physnet}
        self.network = self.create_network(manager=self.admin_manager,
                                           **kwargs)
        subnet = self.create_subnet(self.network,
                                    enable_dhcp=False,
                                    manager=self.admin_manager)

        # Trunk1
        port1 = self.create_port(self.network, manager=self.admin_manager)
        trunk1_id = self.create_trunk(port1, client=self.client)['id']

        # Attach server to trunk1
        self.create_tenant_server(
            manager=self.admin_manager,
            ports=[port1],
            prepare_for_connectivity=False)

        self.wait_for_trunk_status(trunk1_id, 'ACTIVE', client=self.client)

        self._verify_switchport_bindings(expected_number_bindings=1)

        bp_vlan = 0
        vsd_resource = self.vsd.get_l2domain(by_subnet=subnet)
        self._verify_bridge_port(vsd_resource,
                                 expected_bp_vlan=bp_vlan)

        num_subports = 4
        segment_ids = range(3, 3 + num_subports)
        kwargs = {'provider:network_type': 'vlan',
                  'provider:physical_network': self.physnet}
        tagged_networks = [self.create_network(manager=self.admin_manager,
                                               **kwargs)
                           for _ in segment_ids]
        tagged_subnets = [self.create_subnet(network, enable_dhcp=False,
                                             manager=self.admin_manager)
                          for network in tagged_networks]
        tagged_ports = [self.create_port(network, manager=self.admin_manager)
                        for network in tagged_networks]
        subports = [{'port_id': tagged_ports[i]['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': segment_id}
                    for i, segment_id in enumerate(segment_ids)]

        # add all subports to trunk1
        self.add_trunk_subports(subports, trunk1_id, client=self.client)
        self.wait_for_trunk_status(trunk1_id, 'ACTIVE', client=self.client)
        for port in tagged_ports:
            self.wait_for_port_status(port['id'], 'ACTIVE',
                                      manager=self.admin_manager)

        for network, subnet in zip(tagged_networks, tagged_subnets):
            bp_vlans = network['provider:segmentation_id']
            vsd_resource = self.vsd.get_l2domain(by_subnet=subnet)
            self._verify_bridge_port(vsd_resource,
                                     expected_bp_vlan=bp_vlans)

        # One parent port and 4 subports
        self._verify_switchport_bindings(expected_number_bindings=5)

        # Force ERROR trunk status
        kwargs = {'provider:network_type': 'flat',
                  'provider:physical_network': 'physnet5'}
        network = self.create_network(manager=self.admin_manager,
                                      **kwargs)
        self.create_subnet(network, enable_dhcp=False,
                           manager=self.admin_manager)
        deg_port = self.create_port(network, manager=self.admin_manager)
        deg_subport = [{
            'port_id': deg_port['id'],
            'segmentation_type': 'vlan',
            'segmentation_id': 2000}]

        self.add_trunk_subports(deg_subport, trunk1_id, client=self.client)
        self.wait_for_port_status(deg_port['id'], 'DOWN',
                                  manager=self.admin_manager)
        self.wait_for_trunk_status(trunk1_id, 'ERROR', client=self.client)

        self.client.remove_subports(trunk1_id, deg_subport)
        self.wait_for_trunk_status(trunk1_id, 'ACTIVE', client=self.client)

        # move subports over to other trunk
        self.client.remove_subports(trunk1_id, subports)
        for port in tagged_ports:
            self.wait_for_port_status(port['id'], 'DOWN',
                                      manager=self.admin_manager)

        # Trunk2
        port2 = self.create_port(self.network, manager=self.admin_manager)
        trunk2_id = self.create_trunk(port2, subports,
                                      client=self.client)['id']
        # Attach server to trunk2
        self.create_tenant_server(
            manager=self.admin_manager,
            ports=[port2],
            prepare_for_connectivity=False)

        for trunk_id in (trunk1_id, trunk2_id):
            self.wait_for_trunk_status(trunk_id, 'ACTIVE', client=self.client)
        for port in tagged_ports:
            self.wait_for_port_status(port['id'], 'ACTIVE',
                                      manager=self.admin_manager)
        # One more because of server attached to trunk1
        self._verify_switchport_bindings(expected_number_bindings=6)


class TestNuageHWVTEPActiveActive(TestNuageHWVTEP):

    physnet = 'physnet2'

    def _verify_bridge_port(self, vsd_resource,
                            expected_bp_vlan):
        """_verify_bridge_port

        Physnet2 is attached to br-active
        br-active is connected to two GW configured as LAG with a RG.
        """

        vports = vsd_resource.vports.get()
        self.assertEqual(1, len(vports), 'Exactly one vport expected')
        vport = vports[0]
        self.assertEqual('BRIDGE', vport.type)
        self.assertEqual(vport.vlan, expected_bp_vlan)
        self.assertEqual('REDUNDANT_GW_GRP', vport.associated_gateway_type)
        interfaces = vport.bridge_interfaces.get()
        self.assertEqual(1, len(interfaces))
        policy_groups = vport.policy_groups.get()
        self.assertEmpty(policy_groups)

    def _verify_switchport_bindings(self, expected_number_bindings):
        self.assertEqual(expected_number_bindings,
                         len(self.plugin_network_client_admin.
                             list_switchport_bindings(
                                 bridge='br-active')['switchport_bindings']))


class TestNuageHWVTEPActiveStandby(TestNuageHWVTEP):

    physnet = 'physnet3'

    def _verify_bridge_port(self, vsd_resource,
                            expected_bp_vlan):
        """_verify_bridge_port

        Physnet3 is attached to br-standby
        br-standby is connected to two GW, not configured as LAG.
        """

        vports = vsd_resource.vports.get()
        self.assertEqual(2, len(vports), 'Exactly two vports expected')
        for vport in vports:
            self.assertEqual('BRIDGE', vport.type)
            self.assertEqual(vport.vlan, expected_bp_vlan)
            interfaces = vport.bridge_interfaces.get()
            self.assertEqual(1, len(interfaces))
            policy_groups = vport.policy_groups.get()
            self.assertEmpty(policy_groups)

    def _verify_switchport_bindings(self, expected_number_bindings):
        self.assertEqual(expected_number_bindings * 2,
                         len(self.plugin_network_client_admin.
                             list_switchport_bindings(
                                 bridge='br-standby')['switchport_bindings']))


class TestNuageHWVTEPSrl(TestNuageHWVTEP):

    physnet = 'physnet4'

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_os_managed_ipv4_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=False, is_ipv4=True, is_ipv6=False)
