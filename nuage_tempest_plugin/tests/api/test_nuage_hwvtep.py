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

from netaddr import IPAddress
from netaddr import IPNetwork

from tempest.common import utils
from tempest.common import waiters
from tempest.lib import decorators

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class TestNuageHWVTEP(NuageBaseTest):

    @classmethod
    def skip_checks(cls):
        super(NuageBaseTest, cls).skip_checks()
        if utils.is_extension_enabled('nuage-router', 'network'):
            msg = ('Extension nuage_router is enabled, '
                   'not running HW_VTEP tests.')
            raise cls.skipException(msg)

    def _test_hw_vtep(self, is_l3=False, is_vsd_managed=False, is_ipv4=True,
                      is_ipv6=False, is_flat=False):
        (ipv4_subnet, ipv6_subnet,
         network, vsd_resource) = self._create_network_subnets(
            is_ipv4, is_ipv6, is_l3, is_vsd_managed, is_flat)
        if not is_vsd_managed:
            if is_ipv4:
                vsd_resource = self.vsd.get_l2domain(
                    by_network_id=network['id'],
                    cidr=ipv4_subnet['cidr'],
                    ip_type=4)
            else:
                vsd_resource = self.vsd.get_l2domain(
                    by_network_id=network['id'],
                    cidr=ipv6_subnet['cidr'],
                    ip_type=6)

        # resources under test
        self.create_port(network)

        # Bridge not expected at this moment, as port is not bound
        vports = vsd_resource.vports.get()
        self.assertEmpty(vports, 'vports found without bound port')

        # Create VM
        vm = self.create_tenant_server(networks=[network],
                                       prepare_for_connectivity=False)
        # Get BRIDGE vport
        self._verify_bridge_port(network, vsd_resource, is_flat)
        # Get Bridge interface
        vm2 = self.create_tenant_server(networks=[network],
                                        prepare_for_connectivity=False)

        self._verify_bridge_port(network, vsd_resource, is_flat)

        self.manager.servers_client.delete_server(vm.id)
        waiters.wait_for_server_termination(
            self.manager.servers_client, vm.id)

        self._verify_bridge_port(network, vsd_resource, is_flat)

        self.manager.servers_client.delete_server(vm2.id)
        waiters.wait_for_server_termination(
            self.manager.servers_client, vm2.id)

        vports = vsd_resource.vports.get()
        self.assertEmpty(vports, 'vports found without bound port')

    def _create_network_subnets(self, is_ipv4, is_ipv6, is_l3, is_vsd_managed,
                                is_flat):
        # Use fake network to get tenant_id of current user
        network = self._create_network()
        project_id = network['project_id']
        if is_flat:
            kwargs = {'provider:network_type': 'flat',
                      'provider:physical_network': 'physnet1'}
        else:
            kwargs = {}
        network = self.create_network(manager=self.admin_manager,
                                      project_id=project_id, **kwargs)
        network = self.get_network(network['id'], manager=self.admin_manager)
        ipv4_subnet = ipv6_subnet = vsd_resource = None
        if is_vsd_managed:
            # create vsd managed resources
            if is_l3:
                vsd_l3domain_template = self.vsd_create_l3domain_template()
                vsd_l3domain = self.vsd_create_l3domain(
                    template_id=vsd_l3domain_template.id)

                vsd_zone = self.vsd_create_zone(domain=vsd_l3domain)
                subnet_cidr = IPNetwork('10.10.100.0/24')
                subnet_gateway = str(IPAddress(subnet_cidr) + 1)
                subnet_ipv6_cidr = IPNetwork("2001:5f74:c4a5:b82e::/64")
                subnet_ipv6_gateway = str(IPAddress(subnet_ipv6_cidr) + 1)

                if is_ipv4 and not is_ipv6:
                    vsd_resource = self.create_vsd_subnet(
                        zone=vsd_zone,
                        cidr4=subnet_cidr,
                        gateway4=subnet_gateway,
                        ip_type="IPV4")
                elif is_ipv6 and not is_ipv4:
                    vsd_resource = self.create_vsd_subnet(
                        zone=vsd_zone,
                        ip_type="IPV6",
                        cidr6=subnet_ipv6_cidr,
                        gateway6=subnet_ipv6_gateway,
                        enable_dhcpv6=True)
                else:
                    vsd_resource = self.create_vsd_subnet(
                        zone=vsd_zone,
                        ip_type="DUALSTACK",
                        cidr4=subnet_cidr,
                        gateway4=subnet_gateway,
                        cidr6=subnet_ipv6_cidr,
                        gateway6=subnet_ipv6_gateway,
                        enable_dhcpv6=True)

                if is_ipv4:
                    ipv4_subnet = self.create_l3_vsd_managed_subnet(
                        network, vsd_resource, ip_version=4)
                if is_ipv6:
                    ipv6_subnet = self.create_l3_vsd_managed_subnet(
                        network, vsd_resource, ip_version=6)
            else:
                if is_ipv4 and not is_ipv6:
                    vsd_l2domain_template = self.vsd_create_l2domain_template(
                        ip_type="IPV4",
                        cidr4=self.cidr4,
                        dhcp_managed=True)
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
                        cidr6=self.cidr6)
                vsd_resource = self.vsd_create_l2domain(
                    template=vsd_l2domain_template)
                if is_ipv4:
                    ipv4_subnet = self.create_subnet(
                        network,
                        gateway=None,
                        cidr=self.cidr4,
                        mask_bits=self.mask_bits4_unsliced,
                        nuagenet=vsd_resource.id,
                        net_partition=self.net_partition)
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
                ipv4_subnet = self.create_subnet(network)
            if is_ipv6:
                ipv6_subnet = self.create_subnet(network, ip_version=6)
        return ipv4_subnet, ipv6_subnet, network, vsd_resource

    def _verify_bridge_port(self, network, vsd_resource, is_flat):
        vports = vsd_resource.vports.get()
        self.assertEqual(1, len(vports), 'Exactly one vport expected')
        vport = vports[0]
        self.assertEqual('BRIDGE', vport.type)
        if not is_flat:
            vlan = network['provider:segmentation_id']
        else:
            vlan = 0
        self.assertEqual(vlan, vport.vlan)
        interfaces = vport.bridge_interfaces.get()
        self.assertEqual(1, len(interfaces))

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
    def test_nuage_hwvtep_vsd_managed_l3_ipv4_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=True, is_ipv4=True, is_ipv6=False,
                           is_l3=True)

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_vsd_managed_l3_ipv6_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=True, is_ipv4=False, is_ipv6=True,
                           is_l3=True)

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_vsd_managed_l3_dualstack_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=True, is_ipv4=True, is_ipv6=True,
                           is_l3=True)

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
    def test_nuage_hwvtep_vsd_managed_flat_l3_ipv4_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=True, is_ipv4=True, is_ipv6=False,
                           is_l3=True, is_flat=True)

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_vsd_managed_flat_l3_ipv6_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=True, is_ipv4=False, is_ipv6=True,
                           is_l3=True, is_flat=True)

    @decorators.attr(type='smoke')
    def test_nuage_hwvtep_vsd_managed_flat_l3_dualstack_with_vm(self):
        self._test_hw_vtep(is_vsd_managed=True, is_ipv4=True, is_ipv6=True,
                           is_l3=True, is_flat=True)
