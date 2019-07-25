# Copyright 2017 - Nokia
# All Rights Reserved.

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.utils import constants as nuage_constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

from tempest.lib import decorators


class OsManagedDualStackL3SubnetsTest(NuageBaseTest):
    _vsd_ipv4_address = 'address'
    _vsd_ipv6_address = 'IPv6Address'

    @classmethod
    def skip_checks(cls):
        super(OsManagedDualStackL3SubnetsTest, cls).skip_checks()
        if not NUAGE_FEATURES.os_managed_dualstack_subnets:
            raise cls.skipException(
                'OS Managed Dual Stack is not supported in this release')

    @classmethod
    def setup_clients(cls):
        super(OsManagedDualStackL3SubnetsTest, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    def create_v6_subnet(self, network, cleanup=True, enable_dhcp=False):
        return self.create_subnet(network, ip_version=6,
                                  enable_dhcp=enable_dhcp,
                                  cleanup=cleanup)

    def _verify_ipv6_subnet_with_vsd_l2_domain(self, subnet, external_id,
                                               cidr):
        vsd_l2_domain = self.vsd.get_l2domain(
            by_network_id=external_id, cidr=cidr)
        self.assertIsNotNone(vsd_l2_domain)
        self.assertEqual('DUALSTACK', vsd_l2_domain.ip_type)
        self.assertIsNone(subnet['ipv6_ra_mode'])
        self.assertIsNone(subnet['ipv6_address_mode'])
        self.assertEqual(subnet['cidr'], vsd_l2_domain.ipv6_address)
        if subnet.get('enable_dhcp'):
            self.assertTrue(vsd_l2_domain.enable_dhcpv6)
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
        else:
            self.assertFalse(vsd_l2_domain.enable_dhcpv6)
            self.assertIsNone(vsd_l2_domain.ipv6_gateway)
        self.assertFalse(subnet['vsd_managed'])
        self.assertEqual(subnet['enable_dhcp'],
                         False, "IPv6 subnet MUST have enable_dhcp=FALSE")

    ###########################################################################
    # Typical
    ###########################################################################
    @decorators.attr(type='smoke')
    def test_os_managed_dual_stack_l3_subnet(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # Then a VSD L2 domain is created with type IPv4
        vsd_l2_domain = self.vsd.get_l2domain(
            by_network_id=ipv4_subnet['network_id'],
            cidr=ipv4_subnet['cidr'])
        self.assertIsNotNone(vsd_l2_domain)
        self.assertEqual("IPV4", vsd_l2_domain.ip_type)

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        # Then the VSD L2 domain is changed to IP type DualStack
        self._verify_ipv6_subnet_with_vsd_l2_domain(
            ipv6_subnet, ipv4_subnet['network_id'], ipv4_subnet['cidr'])

        router = self.create_router()
        self.assertIsNotNone(router)

        vsd_l3_domain = self.vsd.get_l3domain(by_router_id=router['id'])
        self.assertIsNotNone(vsd_l3_domain)

        self.router_attach(router, ipv4_subnet)

        vsd_l3_domain.fetch()
        vsd_l3_subnet = self.vsd.get_subnet_from_domain(
            domain=vsd_l3_domain, by_network_id=ipv4_subnet['network_id'],
            cidr=ipv4_subnet['cidr'])
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=None),
        self._verify_vport_in_l3_subnet(port, vsd_l3_subnet)

        server1 = self.create_tenant_server(
            ports=[port])
        self.assertIsNotNone(server1)

    @decorators.attr(type='smoke')
    def test_os_managed_dual_stack_l3_subnet_with_dns_server(self):
        # Provision OpenStack network
        network = self.create_network()
        kwargs = {6: {'dns_nameservers': ['2001:4860:4860::8844',
                                          '2001:4860:4860::8888']},
                  4: {'dns_nameservers': ['8.8.4.4', '8.8.8.8']}}

        ipv4_subnet = self.create_subnet(network, **kwargs[4])
        router = self.create_router()
        self.router_attach(router, ipv4_subnet)

        ipv6_subnet = self.create_subnet(network, ip_version=6,
                                         enable_dhcp=True, **kwargs[6])

        nuage_subnet = self.nuage_client.get_domain_subnet(
            parent=None, parent_id=None,
            filters=['externalID', self._vsd_ipv4_address,
                     self._vsd_ipv6_address],
            filter_value=[ipv4_subnet['network_id'], ipv4_subnet['cidr'],
                          ipv6_subnet['cidr']])
        nuage_dhcpv4opt = self.nuage_client.get_dhcpoption(
            nuage_constants.SUBNETWORK, nuage_subnet[0]['ID'],
            ipv4_subnet['ip_version'])
        self._check_dhcp_option(nuage_dhcpv4opt, ipv4_subnet, l2=False)

        nuage_dhcpv6opt = self.nuage_client.get_dhcpoption(
            nuage_constants.SUBNETWORK, nuage_subnet[0]['ID'],
            ipv6_subnet['ip_version'])
        self._check_dhcp_option(nuage_dhcpv6opt, ipv6_subnet, l2=False)

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
    # A few smoky scenario's with subnet attach
    ###########################################################################

    # -------------------------------------------------------------------------
    # Section A: attach the ipv4 subnet and check proceeding of a few scenarios
    # -------------------------------------------------------------------------

    # eventually delete this - this is obviously elsewhere tested
    @decorators.attr(type='smoke')
    def test_dualstack_attach_ipv4_and_cleanup(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)
        self.create_v6_subnet(network)

        self.router_attach(router, ipv4_subnet)

    @decorators.attr(type='smoke')
    def test_dualstack_attach_ipv4_delete_ipv6_and_cleanup(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)
        ipv6_subnet = self.create_v6_subnet(network, cleanup=False,
                                            enable_dhcp=True)

        self.router_attach(router, ipv4_subnet)
        self.check_dhcp_port(network['id'], [4, 6])

        self.delete_subnet(ipv6_subnet)
        self.check_dhcp_port(network['id'], [4])

    @decorators.attr(type='smoke')
    def test_dualstack_attach_ipv4_delete_ipv6_and_recreate(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)
        ipv6_subnet = self.create_v6_subnet(network, cleanup=False)

        self.router_attach(router, ipv4_subnet)

        # delete the ipv6 subnet
        self.delete_subnet(ipv6_subnet)

        # recreate an ipv6 subnet
        self.create_v6_subnet(network)

    # -------------------------------------------------------------------------
    # Section B: attach the ipv6 subnet and check proceeding of a few scenarios
    # -------------------------------------------------------------------------

    @decorators.attr(type='smoke')
    def test_pure_ipv6_attach_and_cleanup(self):
        network = self.create_network()
        router = self.create_router()

        ipv6_subnet = self.create_v6_subnet(network)

        self.router_attach(router, ipv6_subnet)

    @decorators.attr(type='smoke')
    def test_dualstack_attach_ipv6_and_cleanup(self):
        network = self.create_network()
        router = self.create_router()

        self.create_subnet(network)
        ipv6_subnet = self.create_v6_subnet(network)

        self.router_attach(router, ipv6_subnet)

    @decorators.attr(type='smoke')
    def test_dualstack_attach_ipv6_delete_ipv4_and_cleanup(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network, cleanup=False)
        ipv6_subnet = self.create_v6_subnet(network, enable_dhcp=True)

        self.router_attach(router, ipv6_subnet)
        self.check_dhcp_port(network['id'], [4, 6])

        self.delete_subnet(ipv4_subnet)
        self.check_dhcp_port(network['id'], [6])

    @decorators.attr(type='smoke')
    # This is the scenario described in OPENSTACK-1990
    def test_dualstack_attach_ipv6_delete_ipv4_and_recreate(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network, cleanup=False)
        ipv6_subnet = self.create_v6_subnet(network)

        self.router_attach(router, ipv6_subnet)

        # delete the ipv4 subnet
        self.delete_subnet(ipv4_subnet)

        # recreate an ipv4 subnet
        self.create_subnet(network)

    # -------------------------------------------------------------------------
    # Section C: Double attachment
    # -------------------------------------------------------------------------

    @decorators.attr(type='smoke')
    def test_dualstack_attach_in_v4_then_v6_order_and_cleanup(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)
        ipv6_subnet = self.create_v6_subnet(network)

        self.router_attach(router, ipv4_subnet)
        self.router_attach(router, ipv6_subnet)

    @decorators.attr(type='smoke')
    def test_dualstack_attach_in_v4_then_v6_order_and_cleanup_reversely(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)
        ipv6_subnet = self.create_v6_subnet(network)
        filters = {
            'device_owner': 'network:dhcp:nuage',
            'network_id': ipv4_subnet['network_id']
        }
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(1, len(dhcp_ports))
        self.assertEqual(dhcp_ports[0]['fixed_ips'][0]['subnet_id'],
                         ipv4_subnet['id'])

        self.router_attach(router, ipv4_subnet, cleanup=False)
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(0, len(dhcp_ports))
        self.router_attach(router, ipv6_subnet)

        self.router_detach(router, ipv4_subnet)
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(0, len(dhcp_ports))

    @decorators.attr(type='smoke')
    def test_dualstack_attach_in_v6_then_v4_order_and_cleanup(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)
        ipv6_subnet = self.create_v6_subnet(network)

        self.router_attach(router, ipv6_subnet)
        self.router_attach(router, ipv4_subnet)

    @decorators.attr(type='smoke')
    def test_dualstack_attach_in_v6_then_v4_order_and_cleanup_reversely(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)
        ipv6_subnet = self.create_v6_subnet(network)
        filters = {
            'device_owner': 'network:dhcp:nuage',
            'network_id': ipv4_subnet['network_id']
        }
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(1, len(dhcp_ports))
        self.assertEqual(dhcp_ports[0]['fixed_ips'][0]['subnet_id'],
                         ipv4_subnet['id'])

        self.router_attach(router, ipv6_subnet, cleanup=False)
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(0, len(dhcp_ports))
        self.router_attach(router, ipv4_subnet)

        self.router_detach(router, ipv6_subnet)
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(0, len(dhcp_ports))

    @decorators.attr(type='smoke')
    def test_dualstack_attach_detach_check_nuage_dhcp_port(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)
        ipv6_subnet = self.create_v6_subnet(network)
        filters = {
            'device_owner': 'network:dhcp:nuage',
            'network_id': ipv4_subnet['network_id']
        }
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(1, len(dhcp_ports))
        self.assertEqual(dhcp_ports[0]['fixed_ips'][0]['subnet_id'],
                         ipv4_subnet['id'])

        self.router_attach(router, ipv6_subnet, cleanup=False)
        self.router_attach(router, ipv4_subnet, cleanup=False)
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(0, len(dhcp_ports))

        self.router_detach(router, ipv6_subnet)
        self.router_detach(router, ipv4_subnet)
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(1, len(dhcp_ports))
        self.assertEqual(dhcp_ports[0]['fixed_ips'][0]['subnet_id'],
                         ipv4_subnet['id'])

    # -------------------------------------------------------------------------
    # Section D: Special cases
    # -------------------------------------------------------------------------

    @decorators.attr(type='smoke')
    def test_router_attach_ipv4_and_add_ipv6(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)

        self.router_attach(router, ipv4_subnet, cleanup=False)

        # now add ipv6 subnet
        self.create_v6_subnet(network)

        # and detach ipv4
        self.router_detach(router, ipv4_subnet)

    @decorators.attr(type='smoke')
    # This is the scenario described in OPENSTACK-2004
    def test_router_attach_ipv6_and_add_ipv4(self):
        network = self.create_network()
        router = self.create_router()

        ipv6_subnet = self.create_v6_subnet(network)

        self.router_attach(router, ipv6_subnet, cleanup=False)

        # now add ipv4 subnet
        self.create_subnet(network)

        # and detach ipv6
        self.router_detach(router, ipv6_subnet)
