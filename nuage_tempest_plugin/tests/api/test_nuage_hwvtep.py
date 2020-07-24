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
from tempest.common import waiters
from tempest.lib import decorators

from nuage_tempest_plugin.lib.mixins import net_topology as topology_mixin
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants


CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class TestNuageHWVTEP(NuageBaseTest, topology_mixin.NetTopologyMixin):

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
                vsd_resource = vsd_domain = self.vsd.get_l2domain(
                    by_subnet=ipv4_subnet)
            else:
                vsd_resource = vsd_domain = self.vsd.get_l2domain(
                    by_subnet=ipv6_subnet)

        # resources under test
        self.create_port(network)

        # Bridge not expected at this moment, as port is not bound
        vports = vsd_resource.vports.get()
        self.assertEmpty(vports, 'vports found without bound port')

        # Create VM
        vm = self.create_tenant_server(networks=[network],
                                       prepare_for_connectivity=False)
        if is_vsd_managed:
            pg = self._get_pg_allow_all(vsd_domain,
                                        should_have_pg=False)
            pg_id = None
        else:
            pg = self._get_pg_allow_all(vsd_domain)
            pg_id = pg.id
            self._verify_pg_allow_all(pg)

        self._verify_bridge_port(network, vsd_resource, is_flat,
                                 expected_pg_id=pg_id,
                                 expected_number_bindings=1)

        # Create second VM, no change expected
        vm2 = self.create_tenant_server(networks=[network],
                                        prepare_for_connectivity=False)

        self._verify_bridge_port(network, vsd_resource, is_flat,
                                 expected_pg_id=pg_id,
                                 expected_number_bindings=2)

        self.manager.servers_client.delete_server(vm.id)
        waiters.wait_for_server_termination(
            self.manager.servers_client, vm.id)

        self._verify_bridge_port(network, vsd_resource, is_flat,
                                 expected_pg_id=pg_id,
                                 expected_number_bindings=1)

        self.manager.servers_client.delete_server(vm2.id)
        waiters.wait_for_server_termination(
            self.manager.servers_client, vm2.id)

        vports = vsd_resource.vports.get()
        self.assertEmpty(vports, 'vports found without bound port')

    def _create_network_subnets(self, is_ipv4, is_ipv6, is_vsd_managed,
                                is_flat):
        # Use fake network to get tenant_id of current user
        network = self._create_network()
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

    def _get_pg_allow_all(self, parent_resource, should_have_pg=True):
        pgs = parent_resource.policy_groups.get(
            filter=self.vsd.get_external_id_filter('hw:PG_ALLOW_ALL'))
        if should_have_pg:
            self.assertEqual(1, len(pgs), 'Exactly 1 PG_ALLOW_ALL_HW expected')
            return pgs[0]
        else:
            self.assertEmpty(pgs)
            return None

    def _verify_pg_allow_all(self, policy_group):
        # Verify PG
        self.assertEqual(policy_group.type, 'HARDWARE')
        self.assertEqual(policy_group.name,
                         constants.NUAGE_PLCY_GRP_ALLOW_ALL_HW)
        self.assertEqual(policy_group.description,
                         constants.NUAGE_PLCY_GRP_ALLOW_ALL_HW)

        # Verify associated ACL
        in_rule = self.vsd.get_ingress_acl_entry(
            vspk_filter='locationID == "{}"'.format(policy_group.id))
        eg_rule = self.vsd.get_egress_acl_entry(
            vspk_filter='locationID == "{}"'.format(policy_group.id))

        self.assertIsNotNone(in_rule, "in_rule must not be None")
        self.assertEqual(in_rule.network_type, 'ANY')
        self.assertEqual(in_rule.location_type, 'POLICYGROUP')

        self.assertIsNotNone(eg_rule, "eg_rule must not be None")
        self.assertEqual(eg_rule.network_type, 'ANY')
        self.assertEqual(eg_rule.location_type, 'POLICYGROUP')

    def _verify_bridge_port(self, network, vsd_resource, is_flat,
                            expected_pg_id, expected_number_bindings):
        vports = vsd_resource.vports.get()
        self.assertEqual(1, len(vports), 'Exactly one vport expected')
        # TODO(Marcelo): Get bindings which corresponds only to this test
        # Skipping because other simultaneous tests might create
        # bindings which could make below check fail
        # self.assertEqual(expected_number_bindings,
        #                  len(self.switchport_binding_client_admin.
        #                      list_switchport_bindings(bridge='br-ex')))
        vport = vports[0]
        self.assertEqual('BRIDGE', vport.type)
        if is_flat:
            vlan = 0
        else:
            vlan = network['provider:segmentation_id']
        self.assertEqual(vlan, vport.vlan)
        interfaces = vport.bridge_interfaces.get()
        self.assertEqual(1, len(interfaces))
        policy_groups = vport.policy_groups.get()
        if expected_pg_id:
            self.assertEqual(1, len(policy_groups))
            self.assertEqual(expected_pg_id, policy_groups[0].id)
        else:
            self.assertEmpty(policy_groups)

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


class TestNuageHWVTEPActiveActive(TestNuageHWVTEP):

    physnet = 'physnet2'

    def _verify_bridge_port(self, network, vsd_resource, is_flat,
                            expected_pg_id, expected_number_bindings):
        """_verify_bridge_port

        Physnet2 is attached to br-active
        br-active is connected to two GW configured as LAG with a RG.
        """
        vports = vsd_resource.vports.get()
        self.assertEqual(1, len(vports), 'Exactly one vport expected')
        self.assertEqual(expected_number_bindings,
                         len(self.switchport_binding_client_admin.
                             list_switchport_bindings(bridge='br-active')))
        vport = vports[0]
        self.assertEqual('BRIDGE', vport.type)
        if is_flat:
            vlan = 0
        else:
            vlan = network['provider:segmentation_id']
        self.assertEqual(vlan, vport.vlan)
        self.assertEqual('REDUNDANT_GW_GRP', vport.associated_gateway_type)
        interfaces = vport.bridge_interfaces.get()
        self.assertEqual(1, len(interfaces))
        policy_groups = vport.policy_groups.get()
        if expected_pg_id:
            self.assertEqual(1, len(policy_groups))
            self.assertEqual(expected_pg_id, policy_groups[0].id)
        else:
            self.assertEmpty(policy_groups)


class TestNuageHWVTEPActiveStandby(TestNuageHWVTEP):

    physnet = 'physnet3'

    def _verify_bridge_port(self, network, vsd_resource, is_flat,
                            expected_pg_id, expected_number_bindings):
        """_verify_bridge_port

        Physnet3 is attached to br-standby
        br-standby is connected to two GW, not configured as LAG.
        """
        vports = vsd_resource.vports.get()
        self.assertEqual(2, len(vports), 'Exactly two vports expected')
        self.assertEqual(expected_number_bindings * 2,
                         len(self.switchport_binding_client_admin.
                             list_switchport_bindings(bridge='br-standby')))
        for vport in vports:
            self.assertEqual('BRIDGE', vport.type)
            if is_flat:
                vlan = 0
            else:
                vlan = network['provider:segmentation_id']
            self.assertEqual(vlan, vport.vlan)
            interfaces = vport.bridge_interfaces.get()
            self.assertEqual(1, len(interfaces))
            policy_groups = vport.policy_groups.get()
            if expected_pg_id:
                self.assertEqual(1, len(policy_groups))
                self.assertEqual(expected_pg_id, policy_groups[0].id)
            else:
                self.assertEmpty(policy_groups)
