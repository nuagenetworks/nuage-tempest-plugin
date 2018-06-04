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

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.tests.api.vsd_managed \
    import base_vsd_managed_networks

CONF = Topology.get_conf()

OS_FULL_CIDR24_RANGE = 254  # .256 -1 (.0) -1 (.255)

VSD_L2_SHARED_MGD_OPT3_CIDR = IPNetwork('21.21.21.0/24')
VSD_L2_SHARED_MGD_OPT3_GW = '21.21.21.1'
VSD_L2_SHARED_MGD_OPT3 = '21.21.21.121'
VSD_L3_SHARED_MGD_OPT3_CIDR = IPNetwork('31.31.31.0/24')
VSD_L3_SHARED_MGD_OPT3_GW = '31.31.31.1'
VSD_L3_SHARED_MGD_OPT3 = '31.31.31.131'
#
VALID_CIDR = IPNetwork('3.22.111.0/24')
VALID_CIDR_GW = '3.22.111.1'
#
EXPECT_DHCP_ENABLE_TRUE = "enable_dhcp in subnet must be True"
EXPECT_DHCP_ENABLE_FALSE = "enable_dhcp in subnet must be False"
EXPECT_GATEWAY_IP_MISMATCH = "Bad subnet request: " \
                             "Provided gateway-ip does not match " \
                             "VSD configuration"
EXPECT_CIDR_IN_RANGE = "Bad request: cidr in subnet must be"
EXPECT_GATEWAY_IN_CIDR = "Bad request: Gateway IP outside of the subnet CIDR"


class BaseVSDPublicResources(base_vsd_managed_networks.BaseVSDManagedNetwork):

    def setUp(self):
        super(BaseVSDPublicResources, self).setUp()
        # Setup image and flavor the test instance
        # Support both configured and injected values
        if not hasattr(self, 'image_ref'):
            self.image_ref = CONF.compute.image_ref
        if not hasattr(self, 'flavor_ref'):
            self.flavor_ref = CONF.compute.flavor_ref

    @classmethod
    def resource_setup(cls):
        super(BaseVSDPublicResources, cls).resource_setup()
        cls.vsd_l2_unmgd_template = \
            cls.create_vsd_dhcpunmanaged_l2dom_template()
        cls.vsd_l3_dom_template = cls.create_vsd_l3dom_template()
        cls.vsd_l3_subnet_unmgd_l3_shared_mgd_opt3 = ''
        cls.vsd_l3_subnet_unmgd_l3_shared_mgd = ''
        cls.vsd_l2_shared_unmanaged = \
            cls.create_vsd_shared_l2domain_unmanaged()
        cls.vsd_l2_shared_managed = cls.create_vsd_shared_l2domain_managed()
        cls.vsd_l2_shared_managed_opt3 = ''
        cls.vsd_l3_shared_mgd = ''
        cls.vsd_l3_shared_mgd_opt3 = ''
        cls.current_l2_dhcp_option_3 = ''
        cls.current_l3_dhcp_option_3 = ''

    @classmethod
    def resource_cleanup(cls):
        super(BaseVSDPublicResources, cls).resource_cleanup()

    def _given_vsdl2sharedunmgd_lnkd_to_vsdl2domunmgd(self):
        if not self.vsd_l2_shared_unmanaged:
            self.vsd_l2_shared_unmanaged = \
                self.create_vsd_shared_l2domain_unmanaged()
        vsd_l2_dom_unmgd_l2_shared_unmgd = \
            self.create_vsd_l2domain(tid=self.vsd_l2_unmgd_template[0]['ID'])
        self.link_l2domain_to_shared_domain(
            vsd_l2_dom_unmgd_l2_shared_unmgd[0]['ID'],
            self.vsd_l2_shared_unmanaged[0]['ID'])
        # update our copy
        vsd_l2_dom_unmgd_l2_shared_unmgd[0][
            'associatedSharedNetworkResourceID'] = \
            self.vsd_l2_shared_unmanaged[0]['ID']
        return vsd_l2_dom_unmgd_l2_shared_unmgd

    def _given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd(self):
        if not self.vsd_l2_shared_managed:
            self.vsd_l2_shared_managed = \
                self.create_vsd_shared_l2domain_managed()
        vsd_l2_dom_unmgd_l2_shared_mgd = \
            self.create_vsd_l2domain(tid=self.vsd_l2_unmgd_template[0]['ID'])
        # uplink them
        self.link_l2domain_to_shared_domain(
            vsd_l2_dom_unmgd_l2_shared_mgd[0]['ID'],
            self.vsd_l2_shared_managed[0]['ID'])
        # update our copy
        vsd_l2_dom_unmgd_l2_shared_mgd[0][
            'associatedSharedNetworkResourceID'] = \
            self.vsd_l2_shared_managed[0]['ID']
        return vsd_l2_dom_unmgd_l2_shared_mgd

    def _given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(self, dhcp_option_3):
        if not self.vsd_l2_shared_managed_opt3:
            kwargs = {
                'cidr': VSD_L2_SHARED_MGD_OPT3_CIDR,
                'gateway': VSD_L2_SHARED_MGD_OPT3_GW
            }
            self.vsd_l2_shared_managed_opt3 = \
                self.create_vsd_shared_l2domain_managed(**kwargs)
            self.nuage_vsd_client.create_dhcpoption_on_shared(
                self.vsd_l2_shared_managed_opt3[0]['ID'], 3, [dhcp_option_3])
            self.current_l2_dhcp_option_3 = dhcp_option_3
        elif dhcp_option_3 != self.current_l2_dhcp_option_3:
            # we want tot est with another dhcp+option_3 value, set it
            self.nuage_vsd_client.create_dhcpoption_on_shared(
                self.vsd_l2_shared_managed_opt3[0]['ID'], 3, [dhcp_option_3])
            self.current_l2_dhcp_option_3 = dhcp_option_3
        vsd_l2_dom_unmgd_l2_shared_mgd_opt3 = \
            self.create_vsd_l2domain(tid=self.vsd_l2_unmgd_template[0]['ID'])
        self.link_l2domain_to_shared_domain(
            vsd_l2_dom_unmgd_l2_shared_mgd_opt3[0]['ID'],
            self.vsd_l2_shared_managed_opt3[0]['ID'])
        # update our copy
        vsd_l2_dom_unmgd_l2_shared_mgd_opt3[0][
            'associatedSharedNetworkResourceID'] = \
            self.vsd_l2_shared_managed_opt3[0]['ID']
        return vsd_l2_dom_unmgd_l2_shared_mgd_opt3

    def _given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd(self):
        if not self.vsd_l3_shared_mgd:
            self.vsd_l3_shared_mgd = self.create_vsd_shared_l3domain_managed()
        vsd_l3_domain = self.create_vsd_l3domain(
            tid=self.vsd_l3_dom_template[0]['ID'])
        # create a public zone in this domain
        extra_params = {'publicZone': True}
        public_zone = self.create_vsd_zone(name='l3-public-zone',
                                           domain_id=vsd_l3_domain[0]['ID'],
                                           extra_params=extra_params)
        # Add an unmanaged subnet to it
        kwargs = {
            'extra_params': {'associatedSharedNetworkResourceID':
                             self.vsd_l3_shared_mgd[0]['ID']}
        }
        vsd_l3_subnet_publiczone_unmgd_l3_shared_mngd = \
            self.create_vsd_l3domain_unmanaged_subnet(
                zone_id=public_zone[0]['ID'], **kwargs)
        return vsd_l3_subnet_publiczone_unmgd_l3_shared_mngd

    def _given_vsdl3sharedmgdopt3_linked_to_vsdl3subnetunmgd(self,
                                                             dhcp_option_3):
        if not self.vsd_l3_shared_mgd_opt3:
            kwargs = {
                'cidr': VSD_L3_SHARED_MGD_OPT3_CIDR,
                'gateway': VSD_L3_SHARED_MGD_OPT3_GW
            }
            self.vsd_l3_shared_mgd_opt3 = \
                self.create_vsd_shared_l3domain_managed(**kwargs)
            self.nuage_vsd_client.create_dhcpoption_on_shared(
                self.vsd_l3_shared_mgd_opt3[0]['ID'], 3, [dhcp_option_3])
            self.current_l3_dhcp_option_3 = dhcp_option_3
        elif dhcp_option_3 != self.current_l3_dhcp_option_3:
            # we want to test with another dhcp_option_3 value: set it
            self.nuage_vsd_client.create_dhcpoption_on_shared(
                self.vsd_l3_shared_mgd_opt3[0]['ID'], 3, [dhcp_option_3])
            self.current_l3_dhcp_option_3 = dhcp_option_3
        vsd_l3_domain = self.create_vsd_l3domain(
            tid=self.vsd_l3_dom_template[0]['ID'])
        # create a public zone in this domain
        extra_params = {'publicZone': True}
        public_zone = self.create_vsd_zone(name='l3-public-zone',
                                           domain_id=vsd_l3_domain[0]['ID'],
                                           extra_params=extra_params)
        # Add an unmanaged subnet to it
        extra_params = {'associatedSharedNetworkResourceID':
                        self.vsd_l3_shared_mgd_opt3[0]['ID']}
        vsd_l3_subnet_publiczone_unmgd_l3_shared_mngd_opt3 = \
            self.create_vsd_l3domain_unmanaged_subnet(
                zone_id=public_zone[0]['ID'],
                name=data_utils.rand_name('vsd-l3-domain-subnet-unmgd'),
                extra_params=extra_params)
        return vsd_l3_subnet_publiczone_unmgd_l3_shared_mngd_opt3

    def _given_vsdl3sharedmgdopt3_0000_linked_to_vsdl3subnetunmgd(self):
        if not self.vsd_l3_shared_mgd_opt3:
            kwargs = {
                'cidr': VSD_L3_SHARED_MGD_OPT3_CIDR,
                'gateway': VSD_L3_SHARED_MGD_OPT3_GW
            }
            self.vsd_l3_shared_mgd_opt3 = \
                self.create_vsd_shared_l3domain_managed(**kwargs)
            self.nuage_vsd_client.create_dhcpoption_on_shared(
                self.vsd_l3_shared_mgd_opt3[0]['ID'], 3, ['0.0.0.0'])
        vsd_l3_domain = self.create_vsd_l3domain(
            tid=self.vsd_l3_dom_template[0]['ID'])
        # create a public zone in this domain
        extra_params = {'publicZone': True}
        public_zone = self.create_vsd_zone(name='l3-public-zone',
                                           domain_id=vsd_l3_domain[0]['ID'],
                                           extra_params=extra_params)
        # Add an unmanaged subnet to it
        extra_params = {'associatedSharedNetworkResourceID':
                        self.vsd_l3_shared_mgd_opt3[0]['ID']}
        self.create_vsd_shared_l3domain_managed()
        vsd_l3_subnet_publiczone_unmgd_l3_shared_mngd_opt3 = \
            self.create_vsd_l3domain_unmanaged_subnet(
                zone_id=public_zone[0]['ID'],
                name=data_utils.rand_name('vsd-l3-domain-subnet-unmgd'),
                extra_params=extra_params)
        return vsd_l3_subnet_publiczone_unmgd_l3_shared_mngd_opt3

    @classmethod
    def _check_neutron_network_dhcp_nuage_port(cls, network_id):
        # Check whether there is a port with device_owner = network:dhcp:nuage
        # in the given network
        port_list = cls.admin_ports_client.list_ports()
        port_found = False
        for port in port_list['ports']:
            if port['network_id'] == network_id:
                if port['device_owner'] == "network:dhcp:nuage":
                    port_found = True
                    break
        return port_found

    @classmethod
    def _get_external_port_id_from_vm(cls, vm_id):
        # Return external id of the (first) neutron port to which this
        # VM belongs
        ext_id = 0
        port_list = cls.admin_ports_client.list_ports()
        port_found = False
        the_port = []
        for port in port_list['ports']:
            if port['device_id'] == vm_id:
                the_port = port
                port_found = True
                break
        if not port_found:
            raise exceptions.NotFound("ERROR: this VM (%s) has no "
                                      "port".format(str(vm_id)))
        else:
            ext_id = cls.nuage_vsd_client.get_vsd_external_id(the_port['id'])
        return ext_id

    def _get_l2dom_vm_interface_ip_address(self, vm, vsd_domain_id):
        # returns first VM-interfce IP address of the given 'vm' in the
        # VSD domain with id = vsd_domain_id
        ext_id = self._get_external_port_id_from_vm(vm['id'])
        vm_interface = self.nuage_vsd_client.get_vm_iface(
            constants.L2_DOMAIN,
            vsd_domain_id,
            filters='externalID', filter_value=ext_id)
        return vm_interface[0]['IPAddress']

    def _get_l3_subnet_vm_interface_ip_address(self, vm, vsd_subnet_id):
        # returns first VM-interface IP address of the given 'vm' in the
        # VSD domain with id = vsd_domain_id
        ext_id = self._get_external_port_id_from_vm(vm['id'])
        vm_interface = self.nuage_vsd_client.get_vm_iface(
            constants.SUBNETWORK,
            vsd_subnet_id,
            filters='externalID', filter_value=ext_id)
        return vm_interface[0]['IPAddress']

    def _create_shared_network(self, name=None, shared=False):
        if name is None:
            name = data_utils.rand_name('ext-network')
        if shared:
            name = data_utils.rand_name('SHARED-network')
            post_body = {'name': name, 'shared': True}
            body = self.admin_networks_client.create_network(**post_body)
            self.addCleanup(self.admin_networks_client.delete_network,
                            body['network']['id'])
        else:
            post_body = {'name': name}
            body = self.networks_client.create_network(**post_body)
            self.addCleanup(self.networks_client.delete_network,
                            body['network']['id'])
        network = body['network']
        return network

    def _check_cidr_range(self, expected_cidr_range, subnet, user_passed_gw,
                          scenario=None):
        gateway_ip = subnet['gateway_ip']
        if scenario:
            scenario += " The subnet gateway ip is %s." % gateway_ip
        total_range = 0
        for pool in subnet['allocation_pools']:
            if scenario:
                scenario += " It has an allocation pool %s." % str(pool)
            # add range of this pool, + 1 to include the last one as well
            total_range += IPNetwork(pool['end']).last - \
                IPNetwork(pool['start']).first + 1
            if gateway_ip:
                if gateway_ip in pool:
                    break

        if gateway_ip is not None or user_passed_gw is not None:
            expected_cidr_range -= 1
        self.assertEqual(expected_cidr_range, total_range,
                         'Failure scenario: %s' % scenario if scenario else '')

    def _create_vsd_mgd_subnet(self, vsd_entity, os_shared_network,
                               enable_dhcp, gateway_ip, cidr, must_fail=False):
        network = self._create_shared_network(shared=os_shared_network)
        kwargs = {
            'network': network,
            'enable_dhcp': enable_dhcp,
            'cidr': cidr,
            'mask_bits': cidr.prefixlen,
            'net_partition': Topology.def_netpartition,
            'nuagenet': vsd_entity[0]['ID']
        }
        if gateway_ip is not '':
            kwargs['gateway'] = gateway_ip

        if os_shared_network:
            kwargs['client'] = self.os_admin

        if must_fail:
            if Topology.before_openstack('Newton'):
                failure_type = exceptions.ServerFault
            else:
                failure_type = exceptions.BadRequest

            self.assertRaises(
                failure_type,
                self.create_subnet,
                **kwargs)
        else:
            return network, self.create_subnet(**kwargs)

    def _check_vsd_l2_shared_l2_unmgd(self, vsd_l2dom_unmgd, os_shared_network,
                                      enable_dhcp, gateway_ip, cidr,
                                      **kwargs_expect):
        scenario = "Create OS-shared VSD-mgd network, bound to l2-unmanaged " \
                   "domain; OS dhcp is %s, CIDR is %s, gateway is %s." % \
                   (enable_dhcp, cidr, gateway_ip)
        network, subnet = self._create_vsd_mgd_subnet(
            vsd_l2dom_unmgd, os_shared_network, enable_dhcp, gateway_ip, cidr)

        # Then I expect a neutron port equal to
        # 'neutron_network_dhcp_nuage_port'
        network_dhcp_port_present = \
            self._check_neutron_network_dhcp_nuage_port(network['id'])

        if "expect_network_dhcp_nuage_port" in kwargs_expect:
            self.assertEqual(network_dhcp_port_present,
                             kwargs_expect['expect_network_dhcp_nuage_port'],
                             message="Mismatch for network:dhcp:nuage port, "
                                     "expect %s " % kwargs_expect[
                                 'expect_network_dhcp_nuage_port'])

        if "expected_gateway_ip" in kwargs_expect:
            # And gateway_ip equals to expected_gateway_ip
            self.assertEqual(str(subnet['gateway_ip']),
                             str(kwargs_expect['expected_gateway_ip']),
                             message="subnet gateway (%s) != expected value "
                                     "%s".format(str(subnet['gateway_ip']),
                                                 kwargs_expect[
                                                     'expected_gateway_ip']))

        # And an OS allocation pool covering the full CIDR range except the
        # gateway_ip if any
        self._check_cidr_range(OS_FULL_CIDR24_RANGE, subnet, gateway_ip,
                               scenario)

        # When I spin a VM
        vm = self._create_server(name=data_utils.rand_name('vm-l2um-l2shum'),
                                 network=network)
        # Then the IP address is in the CIDR range
        vm_ip_addr = vm['addresses'][network['name']][0]['addr']
        self.assertEqual(IPAddress(vm_ip_addr) in cidr, True,
                         message="IP address is not in CIDR ranage")
        # And the VM-interface-IP-address in the VSD-L2-domain equals the
        # OS VM-IP-address
        vm_interface_ip_address = self._get_l2dom_vm_interface_ip_address(
            vm, vsd_l2dom_unmgd[0]['ID'])

        if "expect_vm_ip_addresses_equal" in kwargs_expect:
            if kwargs_expect['expect_vm_ip_addresses_equal'] is '':
                self.assertIsNone(vm_interface_ip_address)
            else:
                self.assertEqual(str(vm_interface_ip_address), str(vm_ip_addr),
                                 message="VM-interface-IP-address different ()"
                                         " from OS VM Ip address ()!")

    def _check_vsd_l3_shared_l2_unmgd(self, vsd_l3_dom_subnet,
                                      os_shared_network, enable_dhcp,
                                      gateway_ip, cidr,
                                      **kwargs_expect):
        scenario = "Create OS-shared VSD-mgd network, bound to VSD l3subnet;" \
                   " OS dhcp is %s, CIDR is %s, gateway is %s." % \
                   (enable_dhcp, cidr, gateway_ip)
        network, subnet = self._create_vsd_mgd_subnet(
            vsd_l3_dom_subnet,
            os_shared_network, enable_dhcp, gateway_ip, cidr)

        # Then I expect a neutron port equal to
        # 'neutron_network_dhcp_nuage_port'
        network_dhcp_port_present = \
            self._check_neutron_network_dhcp_nuage_port(network['id'])

        if "expect_network_dhcp_nuage_port" in kwargs_expect:
            self.assertEqual(network_dhcp_port_present,
                             kwargs_expect['expect_network_dhcp_nuage_port'],
                             message="Mismatch for network:dhcp:nuage port, "
                                     "expect %s " %
                                     kwargs_expect[
                                         'expect_network_dhcp_nuage_port'])

        # And gateway_ip equals to expected_gateway_ip
        if "expected_gateway_ip" in kwargs_expect:
            # And gateway_ip equals to expected_gateway_ip
            self.assertEqual(str(subnet['gateway_ip']),
                             str(kwargs_expect['expected_gateway_ip']),
                             message="subnet gateway (%s) != expected value "
                                     "%s".format(str(subnet['gateway_ip']),
                                                 kwargs_expect[
                                                     'expected_gateway_ip']))

        # And an OS allocation pool covering the full CIDR range except the
        # gateway_ip if any
        self._check_cidr_range(OS_FULL_CIDR24_RANGE, subnet, gateway_ip,
                               scenario)

        # When I spin a VM
        vm = self._create_server(name=data_utils.rand_name('vm-l2um-l2shum'),
                                 network=network)
        # Then the IP address is in the CIDR range
        vm_ip_addr = vm['addresses'][network['name']][0]['addr']
        self.assertEqual(IPAddress(vm_ip_addr) in cidr, True,
                         message="IP address is not in CIDR ranage")
        # And the VM-interface-IP-address in the VSD-L2-domain equals the
        # OS VM-IP-address
        vm_interface_ip_address = self._get_l3_subnet_vm_interface_ip_address(
            vm, vsd_l3_dom_subnet[0]['ID'])

        if "expect_vm_ip_addresses_equal" in kwargs_expect:
            if kwargs_expect['expect_vm_ip_addresses_equal'] is '':
                self.assertIsNone(vm_interface_ip_address)
            else:
                self.assertEqual(str(vm_interface_ip_address), str(vm_ip_addr),
                                 message="VM-interface-IP-address different ()"
                                         " from OS VM Ip address ()!")

    def _create_security_group_for_nuage(self,
                                         security_group_rules_client=None,
                                         tenant_id=None,
                                         namestart='secgroup-smoke',
                                         security_groups_client=None):
        if security_group_rules_client is None:
            security_group_rules_client = self.security_group_rules_client
        if security_groups_client is None:
            security_groups_client = self.security_groups_client
        if tenant_id is None:
            tenant_id = security_groups_client.tenant_id
        secgroup = self._create_empty_security_group(
            namestart=namestart, client=security_groups_client,
            tenant_id=tenant_id)

        # Add rules to the security group
        rules = self._create_loginable_secgroup_rule_for_nuage(
            security_group_rules_client=security_group_rules_client,
            secgroup=secgroup,
            security_groups_client=security_groups_client)
        for rule in rules:
            self.assertEqual(tenant_id, rule['tenant_id'])
            self.assertEqual(secgroup['id'], rule['security_group_id'])
        return secgroup

    def _create_server(self, name, network):
        vm = self.create_tenant_server(tenant_networks=[network], name=name)
        return vm.get_server_details()
