# Copyright 2017 - Nokia
# All Rights Reserved.

from six import iteritems

from netaddr import IPAddress
from netaddr import IPNetwork

from tempest.lib import decorators
from tempest.lib import exceptions as tempest_exceptions

import testtools
from testtools.matchers import ContainsDict
from testtools.matchers import Equals

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as nuage_constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.tests.api.external_id.external_id \
    import ExternalId

MSG_IP_ADDRESS_INVALID_OR_RESERVED = ('IP Address %s is not valid '
                                      'or cannot be in reserved address space')

MSG_INVALID_INPUT_FOR_FIXED_IPS = ("Invalid input for fixed_ips. "
                                   "Reason: '%s' is not a valid IP address.")
MSG_INVALID_IP_ADDRESS_FOR_SUBNET = ('IP address %s is not a valid IP for '
                                     'the specified subnet.')

MSG_GATEWAY_NOT_IN_SUBNET_CIDR = 'Gateway IP outside of the subnet CIDR'
MSG_GATEWAY_NOT_VALID_ON_SUBNET = 'Gateway is not valid on subnet'
MSG_GATEWAY_INVALID_IP_ADDRESS = ("Invalid input for gateway_ip. "
                                  "Reason: '%s' is not a valid IP address.")

MSG_BASE = ('Bad request: ' if Topology.is_v5
            else 'Bad request: Error in REST call to VSD: ')
MSG_INVALID_IPV6_NETMASK = (
    MSG_BASE + 'Invalid IPv6 netmask. Netmask can only be between a '
               'minimum 64 and maximum {} length.'.format(
                   128 if Topology.is_v5 else 64))

MSG_RESERVED_IPV6_ADDRESS = (
    MSG_BASE + 'IP Address %s is not valid or cannot be in reserved '
               'address space.')

MSG_INVALID_GATEWAY_FOR_IP_TYPE = ("Invalid input for operation: gateway_ip "
                                   "'%s' does not match the ip_version '6'")


def _is_v4_ip(ip):
    return IPAddress(ip['ip_address']).version == 4


def _is_v6_ip(ip):
    return IPAddress(ip['ip_address']).version == 6


class OsManagedDualStackL2SubnetsTest(NuageBaseTest,
                                      nuage_test.NuageAdminNetworksTest):
    credentials = ['primary', 'admin']

    # TODO(waelj) port to VSD helper
    @classmethod
    def setup_clients(cls):
        super(OsManagedDualStackL2SubnetsTest, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    def _verify_ipv6_subnet_with_vsd_l2_domain(self, subnet, by_subnet):
        """_verify_ipv6_subnet_with_vsd_l2_domain

        Verifies the VSD l2 domain defined by 'by_subnet' with the openstack
        subnet 'subnet'.

        @param by_subnet: the subnet via which the l2 domain will be retrieved
        @param subnet: the subnet to compare the L2 domain with
        """
        vsd_l2_domain = self.vsd.get_l2domain(by_subnet=by_subnet)
        self.assertIsNotNone(vsd_l2_domain)
        self.assertIsNone(subnet['ipv6_ra_mode'])
        self.assertIsNone(subnet['ipv6_address_mode'])
        if Topology.has_single_stack_v6_support():
            self.assertEqual('DUALSTACK', vsd_l2_domain.ip_type)
            self.assertEqual(subnet['cidr'], vsd_l2_domain.ipv6_address)
            self.assertEqual(subnet['enable_dhcp'],
                             vsd_l2_domain.enable_dhcpv6)
        else:
            if subnet['enable_dhcp'] or by_subnet['enable_dhcp']:
                self.assertEqual('DUALSTACK', vsd_l2_domain.ip_type)
                self.assertEqual(subnet['cidr'], vsd_l2_domain.ipv6_address)
            else:
                self.assertIsNone(vsd_l2_domain.ip_type)
                self.assertIsNone(vsd_l2_domain.ipv6_address)

        if subnet['enable_dhcp']:
            filters = {
                'device_owner': 'network:dhcp:nuage',
                'network_id': subnet['network_id']
            }
            dhcp_ports = self.ports_client.list_ports(**filters)['ports']
            self.assertEqual(1, len(dhcp_ports))
            for fixed_ip in dhcp_ports[0]['fixed_ips']:
                if fixed_ip['subnet_id'] == subnet['id']:
                    self.assertEqual(fixed_ip['ip_address'],
                                     vsd_l2_domain.ipv6_gateway)
        elif Topology.is_v5:
            self.assertEqual(subnet['enable_dhcp'] or by_subnet['enable_dhcp'],
                             vsd_l2_domain.dhcp_managed)
        else:
            self.assertTrue(vsd_l2_domain.dhcp_managed)
            self.assertIsNone(vsd_l2_domain.ipv6_gateway)

        self.assertFalse(subnet['vsd_managed'])

        # TODO(waelj) VSD-20971 / VSD-21874
        # self.assertFalse(vsd_l2_domain.dualStackDynamicIPAllocation,
        #                  "VSD should not allocated IPv6 address")

    # TODO(waelj) port to VSD helper
    def _verify_vport_in_l2_domain(self, port, vsd_l2domain, **kwargs):
        nuage_vports = self.nuage_client.get_vport(
            nuage_constants.L2_DOMAIN,
            vsd_l2domain.id,
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(
            len(nuage_vports), 1,
            "Must find one VPort matching port: %s" % port['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport,
                        ContainsDict({'name': Equals(port['id'])}))

        # verify all other kwargs as attributes (key,value) pairs
        for key, value in iteritems(kwargs):
            if isinstance(value, dict):
                # compare dict
                raise NotImplementedError
            if isinstance(value, list):
                # self.assertThat(port, ContainsDict({key: Equals(value)}))
                self.assertItemsEqual(port[key], value)
            else:
                self.assertThat(port, ContainsDict({key: Equals(value)}))

    def _verify_port(self, port, subnet4=None, subnet6=None, **kwargs):
        has_ipv4_ip = False
        has_ipv6_ip = False

        for fixed_ip in port['fixed_ips']:
            ip_address = fixed_ip['ip_address']
            if subnet4 is not None and fixed_ip['subnet_id'] == subnet4['id']:
                self.verify_ip_in_allocation_pools(ip_address,
                                                   subnet4['allocation_pools'])
                has_ipv4_ip = True

            if subnet6 is not None and fixed_ip['subnet_id'] == subnet6['id']:
                self.verify_ip_in_allocation_pools(ip_address,
                                                   subnet6['allocation_pools'])
                has_ipv6_ip = True

        if subnet4:
            self.assertTrue(
                has_ipv4_ip,
                "Must have an IPv4 ip in subnet: %s" % subnet4['id'])

        if subnet6:
            self.assertTrue(
                has_ipv6_ip,
                "Must have an IPv6 ip in subnet: %s" % subnet6['id'])

        self.assertIsNotNone(port['mac_address'])

        # verify all other kwargs as attributes (key,value) pairs
        for key, value in iteritems(kwargs):
            if isinstance(value, dict):
                # compare dict
                raise NotImplementedError
            if isinstance(value, list):
                self.assertItemsEqual(port[key], value)
            else:
                self.assertThat(port, ContainsDict({key: Equals(value)}))

    ###########################################################################
    # Typical
    ###########################################################################
    @decorators.attr(type='smoke')
    def test_os_managed_dual_stack_subnet(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # Then a VSD L2 domain is created with type IPv4
        vsd_l2_domain = self.vsd.get_l2domain(
            by_subnet=ipv4_subnet)
        self.assertIsNotNone(vsd_l2_domain)
        self.assertEqual("IPV4", vsd_l2_domain.ip_type)

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        # Then the VSD L2 domain is changed to IPtype DualStack
        self._verify_ipv6_subnet_with_vsd_l2_domain(
            ipv6_subnet, ipv4_subnet)
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=None),
        self._verify_vport_in_l2_domain(port, vsd_l2_domain)

    @decorators.attr(type='smoke')
    def test_os_managed_dual_stack_subnet_with_dhcp_managed_ipv6(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # And I add an IPv6 subnet with DHCP, it should be OK
        ipv6_subnet = self.create_subnet(network, ip_version=6,
                                         enable_dhcp=True)
        self._verify_ipv6_subnet_with_vsd_l2_domain(
            ipv6_subnet, ipv4_subnet)

    @testtools.skipUnless(Topology.has_dhcp_v6_support(),
                          'No dhcp v6 supported')
    @decorators.attr(type='smoke')
    def test_os_managed_dual_stack_subnet_with_dns_server(self):
        # Provision OpenStack network
        network = self.create_network()
        kwargs = {6: {'dns_nameservers': ['2001:4860:4860::8844',
                                          '2001:4860:4860::8888']},
                  4: {'dns_nameservers': ['8.8.4.4', '8.8.8.8']}}

        ipv4_subnet = self.create_subnet(network, **kwargs[4])
        ipv6_subnet = self.create_subnet(network, ip_version=6,
                                         enable_dhcp=True, **kwargs[6])
        vsd_l2_domain = self.vsd.get_l2domain(by_subnet=ipv4_subnet)

        nuage_dhcpv4opt = self.nuage_client.get_dhcpoption(
            nuage_constants.L2_DOMAIN, vsd_l2_domain.id,
            ipv4_subnet['ip_version'])
        self._check_dhcp_option(nuage_dhcpv4opt, ipv4_subnet)

        nuage_dhcpv6opt = self.nuage_client.get_dhcpoption(
            nuage_constants.L2_DOMAIN, vsd_l2_domain.id,
            ipv6_subnet['ip_version'])
        self._check_dhcp_option(nuage_dhcpv6opt, ipv6_subnet)

    def _check_dhcp_option(self, nuage_dhcpopt, subnet, l2=True):
        opt_index = 0
        if subnet['ip_version'] == 4 and subnet.get('gateway_ip', None) and l2:
            self.assertGreater(len(nuage_dhcpopt), opt_index)
            self.assertEqual(self.ip_to_hex(
                subnet['gateway_ip']), nuage_dhcpopt[opt_index]['value'])
            self.assertEqual(nuage_dhcpopt[opt_index]['type'], "03")
            self.assertEqual(nuage_dhcpopt[opt_index]['externalID'],
                             self.nuage_client.get_vsd_external_id(
                                 subnet.get('id')))
            opt_index += 1

        if subnet.get('dns_nameservers'):
            self.assertGreater(len(nuage_dhcpopt), opt_index)
            self.assertEqual(nuage_dhcpopt[opt_index]['type'],
                             "06" if subnet['ip_version'] == 4 else "17")
            dns1 = self.ip_to_hex(subnet['dns_nameservers'][0])
            dns2 = self.ip_to_hex(subnet['dns_nameservers'][1])
            ip_length = 8 if subnet['ip_version'] == 4 else 32
            dhcp_dns = ([nuage_dhcpopt[opt_index]['value'][0:ip_length],
                         nuage_dhcpopt[opt_index]['value'][ip_length:]])
            self.assertIn(dns1, dhcp_dns)
            self.assertIn(dns2, dhcp_dns)

    ###########################################################################
    # Special cases
    ###########################################################################
    @testtools.skipIf(Topology.is_v5,
                      'IPv6 CIDRs are fully restricted by default from 6.0 '
                      'onwards only, i.e. when expert mode is left disabled')
    def test_os_managed_subnet_with_invalid_ipv6_prefixlen_neg(self):
        # Provision OpenStack network
        network = self.create_network()
        for ipv6_cidr in ['cafe:babe::/63', 'cafe:babe::/65']:
            ipv6_gateway = 'cafe:babe::1'
            self.assertRaisesRegex(
                tempest_exceptions.BadRequest,
                MSG_INVALID_IPV6_NETMASK,
                self.create_subnet,
                network,
                ip_version=6,
                cidr=IPNetwork(ipv6_cidr),
                mask_bits=IPNetwork(ipv6_cidr).prefixlen,
                gateway=ipv6_gateway)

    @testtools.skipUnless(Topology.has_single_stack_v6_support(),
                          'No single-stack v6 supported')
    @decorators.attr(type='smoke')
    def test_os_managed_dhcp_subnet_ipv6_first(self):
        self._test_os_managed_subnet_ipv6_first(enable_dhcp=True)

    @testtools.skipUnless(Topology.has_single_stack_v6_support(),
                          'No single-stack v6 supported')
    @decorators.attr(type='smoke')
    def test_os_managed_no_dhcp_subnet_ipv6_first(self):
        self._test_os_managed_subnet_ipv6_first(enable_dhcp=False)

    def _test_os_managed_subnet_ipv6_first(self, enable_dhcp=None):
        # Provision OpenStack network
        network = self.create_network()

        # Create an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=enable_dhcp, cleanup=False)

        # Verify L2Dom
        vsd_l2_domain = self.vsd.get_l2domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(ipv6_subnet['network_id']).at_cms_id()))
        self.assertIsNotNone(vsd_l2_domain)
        filters = {
            'device_owner': 'network:dhcp:nuage',
            'network_id': network['id']
        }
        self.assertEqual(vsd_l2_domain.ip_type, 'IPV6')
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        if Topology.has_dhcp_v6_support():
            self.assertEqual(enable_dhcp,
                             vsd_l2_domain.enable_dhcpv6)
        if enable_dhcp:
            self.assertEqual(1, len(dhcp_ports))
            self.assertEqual(dhcp_ports[0]['fixed_ips'][0]['subnet_id'],
                             ipv6_subnet['id'])
        else:
            self.assertEqual(0, len(dhcp_ports))

        # Verify port/Vport
        portv6 = self.create_port(network, cleanup=False)
        self._verify_port(portv6, subnet6=ipv6_subnet)
        self._verify_vport_in_l2_domain(portv6, vsd_l2_domain)

        # Create an IPv4 subnet in the same network
        ipv4_subnet = self.create_subnet(network, enable_dhcp=enable_dhcp)

        # Verify the L2Dom is Dualstack now
        vsd_l2_domain = self.vsd.get_l2domain(by_subnet=ipv6_subnet)
        self.assertIsNotNone(vsd_l2_domain)
        self.assertEqual(vsd_l2_domain.ip_type, 'DUALSTACK')
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        if enable_dhcp:
            self.assertTrue(vsd_l2_domain.enable_dhcpv4)
            self.assertEqual(1, len(dhcp_ports))
            self.assertEqual(dhcp_ports[0]['fixed_ips'][0]['subnet_id'],
                             ipv4_subnet['id'])
            self.assertEqual(dhcp_ports[0]['fixed_ips'][1]['subnet_id'],
                             ipv6_subnet['id'])
        else:
            self.assertFalse(vsd_l2_domain.enable_dhcpv4)
            self.assertEqual(0, len(dhcp_ports))

        # Delete Subnet/Port
        self.delete_port(portv6)
        self.delete_subnet(ipv6_subnet)
        vsd_l2_domain = self.vsd.get_l2domain(by_subnet=ipv4_subnet)

        # Verify the L2Dom
        self.assertIsNotNone(vsd_l2_domain)
        self.assertEqual(vsd_l2_domain.ip_type, 'IPV4')
        self.assertFalse(vsd_l2_domain.enable_dhcpv6)
        if enable_dhcp:
            self.assertEqual(1, len(dhcp_ports))
            self.assertEqual(dhcp_ports[0]['fixed_ips'][0]['subnet_id'],
                             ipv4_subnet['id'])
        else:
            self.assertEqual(0, len(dhcp_ports))

    @decorators.attr(type='smoke')
    def test_os_managed_dhcp_subnet_ipv4_first(self):
        self._test_os_managed_subnet_ipv4_first(enable_dhcp=True)

    @decorators.attr(type='smoke')
    def test_os_managed_no_dhcp_subnet_ipv4_first(self):
        self._test_os_managed_subnet_ipv4_first(enable_dhcp=False)

    def _test_os_managed_subnet_ipv4_first(self, enable_dhcp=None):
        # Provision OpenStack network
        network = self.create_network()

        # Create an IPv4 subnet
        ipv4_subnet = self.create_subnet(
            network, ip_version=4, enable_dhcp=enable_dhcp, cleanup=False)

        # Verify L2Dom
        vsd_l2_domain = self.vsd.get_l2domain(by_subnet=ipv4_subnet)
        self.assertIsNotNone(vsd_l2_domain)
        if enable_dhcp:
            self.assertEqual(vsd_l2_domain.ip_type, 'IPV4')

        # Verify port/Vport
        portv4 = self.create_port(network, cleanup=False)
        self._verify_port(portv4, subnet4=ipv4_subnet)
        self._verify_vport_in_l2_domain(portv4, vsd_l2_domain)

        # Create an IPv6 subnet in the same network
        ipv6_subnet = self.create_subnet(network, enable_dhcp=enable_dhcp,
                                         ip_version=6)

        # Verify the L2Dom is Dualstack now
        vsd_l2_domain = self.vsd.get_l2domain(by_subnet=ipv4_subnet)
        self.assertIsNotNone(vsd_l2_domain)
        if enable_dhcp:
            self.assertEqual(vsd_l2_domain.ip_type, 'DUALSTACK')

        # Delete v4 Subnet/Port
        self.delete_port(portv4)
        self.delete_subnet(ipv4_subnet)
        vsd_l2_domain = self.vsd.get_l2domain(by_subnet=ipv6_subnet)

        # Verify the L2Dom
        if Topology.has_single_stack_v6_support():
            self.assertIsNotNone(vsd_l2_domain)
            if enable_dhcp:
                self.assertEqual(vsd_l2_domain.ip_type, 'IPV6')
        else:
            self.assertIsNone(vsd_l2_domain)

    @decorators.attr(type='smoke')
    # OPENSTACK-1926
    def test_os_managed_dual_stack_subnet_ipv4_create_delete_create(self):
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network, cleanup=False)
        self.assertIsNotNone(ipv4_subnet)
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=None)
        self.assertIsNotNone(ipv6_subnet)
        self.check_dhcp_port(network['id'], [4, 6])

        # delete IPv4 subnet
        self.manager.subnets_client.delete_subnet(ipv4_subnet['id'])
        self.check_dhcp_port(network['id'], [6])

        # create again
        self.create_subnet(network)

    @decorators.attr(type='smoke')
    # OPENSTACK-1926
    def test_os_managed_dual_stack_subnet_ipv6_create_delete_create(self):
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=None,
            cleanup=False)
        self.assertIsNotNone(ipv6_subnet)
        self.check_dhcp_port(network['id'], [4, 6])

        # delete
        self.manager.subnets_client.delete_subnet(ipv6_subnet['id'])
        self.check_dhcp_port(network['id'], [4])

        # create again
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=None)
        self.assertIsNotNone(ipv6_subnet)

    @decorators.attr(type='smoke')
    def test_os_managed_dual_stack_subnet_with_ipv4_only_ports(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)

        # And I create a port in the network
        self.create_port(network)

        # TODO(waelj) Then the port has only an IPv4 address

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        # TODO(waelj) Then the port has both an IPv4 and IPv6 address

        # And I create a port in the network
        self.create_port(network)

        # TODO(waelj) Then the port has both an IPv4 and IPv6 address

        # Then the VSD L2 domain is changed to IPtype DualStack
        self._verify_ipv6_subnet_with_vsd_l2_domain(
            ipv6_subnet, ipv4_subnet)

    @decorators.attr(type='smoke')
    def test_os_managed_dual_stack_subnet_no_gateway(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # Then a VSD L2 domain is created with type IPv4
        vsd_l2_domain = self.vsd.get_l2domain(
            by_subnet=ipv4_subnet)
        self.assertIsNotNone(vsd_l2_domain)
        self.assertEqual("IPV4", vsd_l2_domain.ip_type)

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=None,
            enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        # Then the VSD L2 domain is changed to IPtype DualStack
        self._verify_ipv6_subnet_with_vsd_l2_domain(
            ipv6_subnet, ipv4_subnet)

        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=None),
        self._verify_vport_in_l2_domain(port, vsd_l2_domain)

    @decorators.attr(type='smoke')
    def test_os_managed_dual_stack_subnet_unmanaged(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network,
                                         enable_dhcp=False)
        self.assertIsNotNone(ipv4_subnet)

        # Then a VSD L2 domain is created with type IPv4
        vsd_l2_domain = self.vsd.get_l2domain(by_subnet=ipv4_subnet)
        self.assertIsNotNone(vsd_l2_domain)
        if Topology.is_v5:
            self.assertIsNone(vsd_l2_domain.ip_type)
        else:
            self.assertEqual(vsd_l2_domain.ip_type, 'IPV4')

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        # Then the VSD L2 domain is changed to IPtype DualStack
        self._verify_ipv6_subnet_with_vsd_l2_domain(
            ipv6_subnet, ipv4_subnet)

        port = self.create_port(network)
        self.assertIsNotNone(port)

    @decorators.attr(type='smoke')
    def test_no_vsd_auto_assignment_for_ipv6_addresses(self):
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # Then a VSD L2 domain is created with type IPv4
        vsd_l2_domain = self.nuage_client.get_l2domain(
            by_subnet=ipv4_subnet)[0]
        self.assertIsNotNone(vsd_l2_domain)
        self.assertFalse(vsd_l2_domain['dynamicIpv6Address' if Topology.is_v5
                         else 'dualStackDynamicIPAllocation'],
                         'VSD should not allocated IPv6 address')

        # When I add an IPv6 subnet
        ipv6_cidr = IPNetwork('cafe:babe::/64')
        ipv6_subnet = self.create_subnet(
            network,
            cidr=ipv6_cidr,
            mask_bits=ipv6_cidr.prefixlen,
            gateway=IPAddress(ipv6_cidr.first + 1),
            ip_version=6, allocation_pools=[
                {
                    'start': IPAddress('cafe:babe::a:0:0:0'),
                    'end': IPAddress('cafe:babe::a:ffff:ffff:ffff')
                }
            ])
        self.assertIsNotNone(ipv6_subnet)

        vsd_l2_domain = self.nuage_client.get_l2domain(
            by_subnet=ipv4_subnet)[0]
        self.assertIsNotNone(vsd_l2_domain)
        self.assertFalse(vsd_l2_domain['dynamicIpv6Address' if Topology.is_v5
                         else 'dualStackDynamicIPAllocation'],
                         'VSD should not allocated IPv6 address')

        # When I create a port outside the pool, it should succeed
        ip_out_of_ipv6_allocation_pool = IPAddress('cafe:babe::b:0:0:0')
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id']},
                                   {'subnet_id': ipv6_subnet['id'],
                                    'ip_address':
                                    ip_out_of_ipv6_allocation_pool}]}
        port = self.create_port(
            network, **port_args)
        self.assertIsNotNone(port)

    ########################################
    # IPv6 address formats
    ########################################
    def test_create_subnet_with_special_address_formats(self):
        # noinspection PyPep8
        valid_ipv6 = [
            ("2001:5f74:c4a5:b82e::/64",
             "2001:5f74:c4a5:b82e:0000:0000:0000:0001"),
            # valid address range, gateway full addressing - at first address
            ("2001:5f74:c4a5:b82e::/64",
             "2001:5f74:c4a5:b82e::1"),
            # valid address range, gateway zero's compressed addressing
            # - at first address
            ("2001:5f74:c4a5:b82e::/64",
             "2001:5f74:c4a5:b82e:0:000::1"),
            # valid address range, gateway partly compressed addressing
            # - at first address
            ("2001:5f74:c4a5:b82e::/64",
             "2001:5f74:c4a5:b82e:ffff:ffff:ffff:ffff"),
            # valid address, gateway at last address
            ("2001:5f74:c4a5:b82e::/64",
             "2001:5f74:c4a5:b82e:f483:3427:ab3e:bc21"),
            # valid address, gateway at random address
            ("2001:5F74:c4A5:B82e::/64",
             "2001:5f74:c4a5:b82e:f483:3427:aB3E:bC21"),
            # valid address, gateway at random address - mixed case
            ("2001:5f74:c4a5:b82e::/64",
             "2001:5f74:c4a5:b82e:f4:00::f"),
            # valid address, gateway at random address - compressed
            ("3ffe:0b00:0000:0001:5f74:0001:c4a5:b82e/64",
             "3ffe:0b00:0000:0001:5f74:0001:c4a5:ffff"),
            # prefix not matching bit mask
        ]
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        for ipv6_cidr, ipv6_gateway in valid_ipv6:
            # When I add an IPv6 subnet
            ipv6_subnet = self.create_subnet(
                network,
                ip_version=6,
                cidr=IPNetwork(ipv6_cidr),
                mask_bits=IPNetwork(ipv6_cidr).prefixlen,
                gateway=ipv6_gateway,
                enable_dhcp=False,
                cleanup=False)
            self.assertIsNotNone(ipv6_subnet)

            # Then the VSD L2 domain is changed to IPtype DualStack
            self._verify_ipv6_subnet_with_vsd_l2_domain(
                ipv6_subnet, by_subnet=ipv4_subnet)

            # And I create a port in the network
            port = self.create_port(network, cleanup=False)
            self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet),

            self.manager.ports_client.delete_port(port['id'])
            self.subnets_client.delete_subnet(ipv6_subnet['id'])

    ###########################################################################
    # Update IPv6 subnet attributes
    ###########################################################################
    @decorators.attr(type='smoke')
    def test_os_managed_dual_stack_subnet_update_no_vsd(self):
        # Update of openstack subnet attributes which are by design not
        # replicated to VSD
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network,
                                         enable_dhcp=False)
        self.assertIsNotNone(ipv4_subnet)

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        # Then the VSD L2 domain is changed to IPtype DualStack
        self._verify_ipv6_subnet_with_vsd_l2_domain(
            ipv6_subnet, ipv4_subnet)

        # Update attributes
        subnet_attributes = {'name': "updated name",
                             'description': "My subnet description"}

        ipv6_subnet_updated = self.update_subnet(
            ipv6_subnet,
            enable_dhcp=False,
            **subnet_attributes)

        self.assertThat("updated name", Equals(ipv6_subnet_updated['name']))
        self.assertThat("My subnet description",
                        Equals(ipv6_subnet_updated['description']))

        vsd_l2_domain = self.vsd.get_l2domain(
            by_subnet=ipv4_subnet)
        self.assertIsNotNone(vsd_l2_domain)

        # L2 domain description should match with network name
        # if it is dualstack
        self.assertThat(vsd_l2_domain.description, Equals(
            ipv4_subnet['name'] if Topology.is_v5 else network['name']))

    @decorators.attr(type='smoke')
    # OPENSTACK-1943
    def test_os_managed_dual_stack_subnet_update_gw_no_gw(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        # Then the VSD L2 domain is changed to DualStack
        self._verify_ipv6_subnet_with_vsd_l2_domain(
            ipv6_subnet, ipv4_subnet)

        # Update attributes
        subnet_attributes = {'gateway_ip': None}

        ipv6_subnet_updated = self.update_subnet(
            ipv6_subnet,
            enable_dhcp=False,
            **subnet_attributes)

        self._verify_ipv6_subnet_with_vsd_l2_domain(
            ipv6_subnet_updated, ipv4_subnet)
        self.assertIsNone(ipv6_subnet_updated['gateway_ip'])

    ###########################################################################
    # Negative cases
    ###########################################################################
    @decorators.attr(type='negative')
    @decorators.attr(type='smoke')
    def test_os_managed_dual_stack_create_ipv6_only_port_neg(self):
        network = self.create_network()
        ipv6_subnet = self.create_subnet(network, ip_version=6,
                                         enable_dhcp=False)

        if Topology.has_single_stack_v6_support():
            port1 = self.create_port(network)
            self._verify_port(port1, subnet4=None, subnet6=ipv6_subnet)

            port_ip = IPAddress(port1['fixed_ips'][0]['ip_address'])
            port_args = {
                'fixed_ips': [{'ip_address': port_ip + 10},
                              {'ip_address': port_ip + 11}]}

            port2 = self.create_port(network, **port_args)
            self._verify_port(port2, subnet4=None, subnet6=ipv6_subnet)
        else:
            self.assertRaisesRegex(
                tempest_exceptions.BadRequest,
                "Port can't be a pure ipv6 port. Need ipv4 fixed ip.",
                self.create_port,
                network)

    @testtools.skipIf(not Topology.has_single_stack_v6_support(),
                      'No singe-stack v6 supported')
    @decorators.attr(type='smoke')
    def test_os_managed_dual_stack_update_port_to_ipv6_only(self):
        network = self.create_network()

        self.create_subnet(network)
        self.create_subnet(network, ip_version=6, enable_dhcp=False)

        port = self.create_port(network)

        # 1. remove the v4 ip from the port
        v4_ip = next((ip for ip in port['fixed_ips'] if _is_v4_ip(ip)), None)
        v4_ip_a = IPAddress(v4_ip['ip_address'])
        v6_ip = next((ip for ip in port['fixed_ips'] if _is_v6_ip(ip)), None)
        v6_ip_a = IPAddress(v6_ip['ip_address'])

        f_ips = {'fixed_ips': [{'ip_address': v6_ip_a}]}

        self.update_port(port, **f_ips)

        # 2. add 2nd v6 ip (must succeed)
        f_ips = {'fixed_ips': [{'ip_address': v4_ip_a},
                               {'ip_address': v6_ip_a},
                               {'ip_address': v6_ip_a + 1}]}
        self.update_port(port, **f_ips)

        # 3. now remove v4 again
        f_ips = {'fixed_ips': [{'ip_address': v6_ip_a},
                               {'ip_address': v6_ip_a + 1}]}

        self.update_port(port, **f_ips)

    ###########################################################################
    # Negative cases
    ###########################################################################
    @decorators.attr(type='negative')
    def test_subnet_with_dhcp_unmanaged_ipv6_attr_slaac_neg(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # When I add an IPv6 subnet with DHCP, it should fail with BadRequest
        self.assertRaisesRegex(
            tempest_exceptions.BadRequest,
            "Invalid input for operation: " +
            "ipv6_ra_mode or ipv6_address_mode cannot be set when "
            "enable_dhcp is set to False.",
            self.create_subnet,
            network,
            ip_version=6,
            enable_dhcp=False,
            ipv6_ra_mode='slaac',
            ipv6_address_mode='slaac')

    @decorators.attr(type='negative')
    def test_subnet_with_dhcp_managed_ipv6_only_attr_slaac_neg(self):
        # Provision OpenStack network
        network = self.create_network()

        self.assertRaisesRegex(
            tempest_exceptions.BadRequest,
            "Attribute ipv6_ra_mode must be 'dhcpv6-stateful' or not set.",
            self.create_subnet,
            network,
            mask_bits=64,
            ip_version=6,
            enable_dhcp=True,
            ipv6_ra_mode='slaac',
            ipv6_address_mode='slaac')

    @decorators.attr(type='negative')
    def test_subnet_with_dhcp_managed_ipv6_attr_slaac_neg(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # And I add an IPv6 subnet with slaac, it should fail with BadRequest
        self.assertRaisesRegex(
            tempest_exceptions.BadRequest,
            "Attribute ipv6_ra_mode must be 'dhcpv6-stateful' or not set.",
            self.create_subnet,
            network,
            mask_bits=64,
            ip_version=6,
            enable_dhcp=True,
            ipv6_ra_mode='slaac',
            ipv6_address_mode='slaac')

    @decorators.attr(type='negative')
    def test_multiple_ipv6_subnets_neg(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        if Topology.has_single_stack_v6_support():
            ipv6_subnet = self.create_subnet(
                network, cidr=IPNetwork("2fbe:4568:a:b::/64"), mask_bits=64,
                ip_version=6, enable_dhcp=False)
            self.assertIsNotNone(ipv6_subnet)
        else:
            # When I add an a second IPv6 subnet, it should fail
            self.assertRaisesRegex(
                tempest_exceptions.BadRequest,
                "A network with an ipv6 subnet may only have maximum "
                "1 ipv4 and 1 ipv6 subnet",
                self.create_subnet,
                network,
                cidr=IPNetwork("2fbe:4568:a:b::/64"),
                mask_bits=64,
                ip_version=6,
                enable_dhcp=False)

    @decorators.attr(type='negative')
    def test_dual_stack_subnet_multiple_ipv4_subnets_neg(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        if Topology.is_v5:
            msg = ('A network with an ipv6 subnet may only have maximum 1 ipv4'
                   ' and 1 ipv6 subnet')
        else:
            msg = ('A network can only have maximum 1 ipv4 and 1 ipv6 subnet'
                   ' existing together')
        self.assertRaisesRegex(
            tempest_exceptions.BadRequest,
            msg,
            self.create_subnet,
            network)

    @decorators.attr(type='negative')
    def test_multiple_ipv4_subnets_with_ipv6_subnet_neg(self):
        if self.is_dhcp_agent_present():
            raise self.skipException(
                'Cannot run this test case when DHCP agent is enabled')
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # When I add an IPv4 subnet
        ipv4_subnet2 = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet2)

        if Topology.is_v5:
            msg = ('A network with an ipv6 subnet may only have maximum 1 '
                   'ipv4 and 1 ipv6 subnet')
        else:
            msg = ('A network can only have maximum 1 ipv4 and 1 ipv6 subnet '
                   'existing together')

        # When I add an IPv6 subnet, it should fail
        self.assertRaisesRegex(
            tempest_exceptions.BadRequest,
            msg,
            self.create_subnet,
            network,
            cidr=IPNetwork("2fbe:4568:a:b::/64"),
            mask_bits=64,
            ip_version=6,
            enable_dhcp=False)

    @decorators.attr(type='negative')
    def test_delete_ipv4_subnet_with_port_from_dual_stack_subnets_neg(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # And I create a port in the network
        port1 = self.create_port(network)
        self.assertIsNotNone(port1)

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        self.assertRaisesRegex(
            tempest_exceptions.Conflict,
            "One or more ports have an IP allocation from this subnet",
            self.subnets_client.delete_subnet,
            ipv4_subnet['id'])

    @decorators.attr(type='negative')
    def test_delete_ipv4_subnet_with_dualstack_port_neg(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # And I create a port in the network
        port1 = self.create_port(network)
        self.assertIsNotNone(port1)

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=False, cleanup=False)
        self.assertIsNotNone(ipv6_subnet)

        # Then I can delete the IPv6 subnet
        self.subnets_client.delete_subnet(ipv6_subnet['id'])

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        # And I create a port in the network
        port2 = self.create_port(network)
        self.assertIsNotNone(port2)

        # Then I can't clean the subnet anymore
        self.assertRaisesRegex(
            tempest_exceptions.Conflict,
            "One or more ports have an IP allocation from this subnet",
            self.subnets_client.delete_subnet,
            ipv6_subnet['id'])

    ########################################
    # IPv6 address formats
    ########################################

    def test_create_subnet_invalid_ipv6_gateway_neg(
            self):
        invalid_ipv6 = [
            (   # Reserved addresses
                # See https://www.iana.org/assignments/
                # iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
                "fe80:5f74:c4a5:b82e::/120",
                "fe80:5f74:c4a5:b82e::1",
                MSG_RESERVED_IPV6_ADDRESS % "fe80:5f74:c4a5:b82e::/120"),
            (   # Reserved addresses: 6to4
                "2002:5f74:c4a5:b82e::/120",
                "2002:5f74:c4a5:b82e::1",
                (MSG_RESERVED_IPV6_ADDRESS % '2002:5f74:c4a5:b82e::/120')
                if Topology.is_v5 else MSG_INVALID_IPV6_NETMASK),
            (
                "2001:5f74:c4a5:b82e::/63",
                "2001:5f74:c4a5:b82e::1",
                MSG_INVALID_IPV6_NETMASK),
            (
                "::/0",
                "::1",
                "Invalid input for operation: 0 is not allowed as CIDR prefix "
                "length."),
            (
                "2001:5f74:c4a5:b82e::/64",
                "2001:5f74:c4a5:b82b:ffff:ffff:ffff:ffff",
                MSG_GATEWAY_NOT_IN_SUBNET_CIDR),
            # Gateway not valid on CIDR
            (
                "2001:5f74:c4a5:b82e::/64",
                "2001:5f74:c4a5:b82e::/128",
                MSG_GATEWAY_INVALID_IP_ADDRESS % "2001:5f74:c4a5:b82e::/128"),
            # Gateway should be single address
            (
                "2001:5f74:c4a5:b82e::/64",
                "2001:5f74:c4a5:b82e::ZZZZ",
                MSG_GATEWAY_INVALID_IP_ADDRESS % "2001:5f74:c4a5:b82e::ZZZZ"),
            # Gateway should be valid address
            (
                "2001:5f74:c4a5:b82e::/64",
                "169.172.0.0",
                MSG_INVALID_GATEWAY_FOR_IP_TYPE % "169.172.0.0"),
            # Gateway is an IPv4 address
        ]

        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        for ipv6_cidr, ipv6_gateway, msg in invalid_ipv6:
            self.assertRaisesRegex(
                tempest_exceptions.BadRequest,
                msg,
                self.create_subnet,
                network,
                ip_version=6,
                cidr=IPNetwork(ipv6_cidr),
                mask_bits=IPNetwork(ipv6_cidr).prefixlen,
                gateway=ipv6_gateway,
                enable_dhcp=False)

    def test_create_port_with_invalid_address_formats_neg(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network,
            cidr=IPNetwork("2001:5f74:c4a5:b82e::/64"),
            mask_bits=64,
            ip_version=6,
            enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        # noinspection PyPep8
        invalid_ipv6 = [
            ('::1', MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            # Loopback
            ('FE80::1', MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            # Link local address
            ("FF00:5f74:c4a5:b82e:ffff:ffff:ffff:ffff",
             MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            # multicast
            ('FF00::1', MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            # multicast address
            ('::1', MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            # not specified address
            ('::', MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            # empty address
            ("2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
             MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            # valid address, not in subnet
            ('', MSG_INVALID_INPUT_FOR_FIXED_IPS),
            # empty string
            ("2001:5f74:c4a5:b82e:ffff:ffff:ffff:ffff:ffff",
             MSG_INVALID_INPUT_FOR_FIXED_IPS),
            # invalid address, too much segments
            ("2001:5f74:c4a5:b82e:ffff:ffff:ffff",
             MSG_INVALID_INPUT_FOR_FIXED_IPS),
            # invalid address, seven segments
            ("2001;5f74.c4a5.b82e:ffff:ffff:ffff",
             MSG_INVALID_INPUT_FOR_FIXED_IPS),
            # invalid address, wrong characters
            ("2001:5f74:c4a5:b82e:100.12.13.1",
             MSG_INVALID_INPUT_FOR_FIXED_IPS),
            # invalid fornmat: must have :: between hex and decimal part.
        ]

        for ipv6, msg in invalid_ipv6:
            port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                        'ip_address':
                                        IPNetwork(ipv4_subnet['cidr'])[+10]},
                                       {'subnet_id': ipv6_subnet['id'],
                                        'ip_address': ipv6}]}
            self.assertRaisesRegex(tempest_exceptions.BadRequest,
                                   msg % ipv6,
                                   self.create_port, network, **port_args)

    ###########################################################################
    # Update IPv6 subnet attributes - negative
    ###########################################################################
    def test_os_managed_dual_stack_subnet_update_neg(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network,
                                         enable_dhcp=False)
        self.assertIsNotNone(ipv4_subnet)

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        self.assertRaisesRegex(tempest_exceptions.BadRequest,
                               "Cannot update read-only attribute ip_version",
                               self.update_subnet,
                               ipv6_subnet,
                               ip_version=4)

        # # Update attributes
        # subnet_attributes =  {'name': "updated name",
        #                       'description': "My subnet description" }
        # self.assertRaisesRegex(tempest_exceptions.BadRequest,
        #                        "Cannot update read-only " \
        #                        "attribute ip_version',
        # self.update_subnet,
        # ipv6_subnet,
        # ip_version=6,
        # **subnet_attributes)
