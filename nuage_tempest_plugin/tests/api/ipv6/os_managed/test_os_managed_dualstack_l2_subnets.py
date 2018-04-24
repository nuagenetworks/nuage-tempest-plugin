# Copyright 2017 - Nokia
# All Rights Reserved.

from six import iteritems

from netaddr import IPAddress
from netaddr import IPNetwork
from netaddr import IPRange

from tempest.lib import decorators
from tempest.lib import exceptions as tempest_exceptions

from testtools.matchers import ContainsDict
from testtools.matchers import Equals

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES
from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.test import tags
from nuage_tempest_plugin.lib.utils import constants as nuage_constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.tests.api.upgrade.external_id.external_id \
    import ExternalId

MSG_IP_ADDRESS_INVALID_OR_RESERVED = "IP Address %s is not valid " \
                                     "or cannot be in reserved address space"

MSG_INVALID_INPUT_FOR_FIXED_IPS = "Invalid input for fixed_ips. " \
                                  "Reason: '%s' is not a valid IP address."
MSG_INVALID_IP_ADDRESS_FOR_SUBNET = "IP address %s is not a valid IP for " \
                                    "the specified subnet."

MSG_GATEWAY_NOT_IN_SUBNET_CIDR = "Gateway IP outside of the subnet CIDR"
MSG_GATEWAY_NOT_VALID_ON_SUBNET = "Gateway is not valid on subnet"
MSG_GATEWAY_INVALID_IP_ADDRESS = "Invalid input for gateway_ip. " \
                                 "Reason: '%s' is not a valid IP address."

MSG_INVALID_IPV6_NETMASK = "Invalid IPv6 netmask. Netmask can only be " \
                           "between a minimum 64 and maximum 128 length."

MSG_INVALID_GATEWAY_FOR_IP_TYPE = "Invalid input for operation: gateway_ip " \
                                  "'%s' does not match the ip_version '6'"


def _is_v4_ip(ip):
    return (IPAddress(ip['ip_address']).version == 4)


def _is_v6_ip(ip):
    return (IPAddress(ip['ip_address']).version == 6)


@nuage_test.class_header(tags=[tags.ML2])
class OsManagedDualStackL2SubnetsTest(NuageBaseTest,
                                      nuage_test.NuageAdminNetworksTest):
    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        super(OsManagedDualStackL2SubnetsTest, cls).skip_checks()
        if not NUAGE_FEATURES.os_managed_dualstack_subnets:
            raise cls.skipException(
                'OS Managed Dual Stack is not supported in this release')

    # TODO(waelj) port to VSD helper
    @classmethod
    def setup_clients(cls):
        super(OsManagedDualStackL2SubnetsTest, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    def _verify_ipv6_subnet_with_vsd_l2_domain(self, subnet, external_id):
        vsd_l2_domain = self.vsd.get_l2domain(
            vspk_filter='externalID == "{}"'.format(external_id))
        self.assertIsNotNone(vsd_l2_domain)
        self.assertEqual('DUALSTACK', vsd_l2_domain.ip_type)
        self.assertIsNone(subnet['ipv6_ra_mode'])
        self.assertIsNone(subnet['ipv6_address_mode'])
        self.assertEqual(subnet['cidr'], vsd_l2_domain.ipv6_address)
        self.assertEqual(subnet['gateway_ip'], vsd_l2_domain.ipv6_gateway)
        self.assertFalse(subnet['vsd_managed'])
        self.assertEqual(subnet['enable_dhcp'],
                         False, "IPv6 subnet MUST have enable_dhcp=FALSE")
        # TODO(waelj) VSD-20971 / VSD-21874
        # self.assertFalse(vsd_l2_domain.dynamicIpv6Address,
        #                  "VSD should not allocated IPv6 address")

    def _verify_ipv6_subnet_with_vsd_l2_domain_unmanaged(self, subnet,
                                                         external_id):
        vsd_l2_domain = self.vsd.get_l2domain(
            vspk_filter='externalID == "{}"'.format(external_id))
        self.assertIsNotNone(vsd_l2_domain)
        self.assertIsNone(vsd_l2_domain.ip_type)
        self.assertIsNone(subnet['ipv6_ra_mode'])
        self.assertIsNone(subnet['ipv6_address_mode'])
        self.assertIsNone(vsd_l2_domain.ipv6_address)
        self.assertIsNone(vsd_l2_domain.ipv6_gateway)
        self.assertFalse(subnet['vsd_managed'])
        self.assertEqual(subnet['enable_dhcp'],
                         False, "IPv6 subnet MUST have enable_dhcp=FALSE")
        # TODO(waelj) VSD-20971 / VSD-21874
        # self.assertFalse(vsd_l2_domain.dynamicIpv6Address,
        #                  "VSD should not allocated IPv6 address")

    # TODO(waelj) port to VSD helper
    def _verify_vport_in_l2_domain(self, port, vsd_l2domain, **kwargs):
        nuage_vports = self.nuage_client.get_vport(
            nuage_constants.L2_DOMAIN,
            vsd_l2domain.id,
            filters='externalID',
            filter_value=port['id'])
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
            if subnet4 and fixed_ip['subnet_id'] == subnet4['id']:
                self.verify_ip_in_allocation_pools(ip_address,
                                                   subnet4['allocation_pools'])
                has_ipv4_ip = True

            if subnet6 and fixed_ip['subnet_id'] == subnet6['id']:
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
    @nuage_test.header()
    def test_os_managed_dual_stack_subnet(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # Then a VSD L2 domain is created with type IPv4
        vsd_l2_domain = self.vsd.get_l2domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(ipv4_subnet['id']).at_cms_id()))
        self.assertIsNotNone(vsd_l2_domain)
        self.assertEqual("IPV4", vsd_l2_domain.ip_type)

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        # Then the VSD L2 domain is changed to IPtype DualStack
        self._verify_ipv6_subnet_with_vsd_l2_domain(
            ipv6_subnet, ExternalId(ipv4_subnet['id']).at_cms_id())

        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=None),
        self._verify_vport_in_l2_domain(port, vsd_l2_domain)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_os_managed_dual_stack_subnet_with_dhcp_managed_ipv6(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # And I add an IPv6 subnet with DHCP, it should be OK
        ipv6_subnet = self.create_subnet(network, ip_version=6,
                                         enable_dhcp=True)
        self.assertIsNotNone(ipv6_subnet)

    ###########################################################################
    # Special cases
    ###########################################################################
    @decorators.attr(type='smoke')
    @nuage_test.header()
    # OPENSTACK-1947
    def test_os_managed_dual_stack_subnet_with_invalid_ipv6_prefixlen(self):
        # Provision OpenStack network
        network = self.create_network()
        ipv6_cidr, ipv6_gateway = "2001:5f74:c4a5:b82e::/63", \
                                  "2001:5f74:c4a5:b82e:0000:0000:0000:0001"
        self.assertRaisesRegex(
            tempest_exceptions.BadRequest,
            MSG_INVALID_IPV6_NETMASK,
            self.create_subnet,
            network,
            ip_version=6,
            cidr=IPNetwork(ipv6_cidr),
            mask_bits=IPNetwork(ipv6_cidr).prefixlen,
            gateway=ipv6_gateway,
            enable_dhcp=False)

        # corner case which tests we are able to create
        # subnet with prefixlen 128 only when No Gateway is provided.
        ipv6_cidr, ipv6_gateway = "2001:5f74:c4a5:b82e::/128", None
        ipv6_subnet = self.create_subnet(
            network, ip_version=6, cidr=IPNetwork(ipv6_cidr),
            mask_bits=IPNetwork(ipv6_cidr).prefixlen,
            gateway=None,
            enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_os_managed_dual_stack_subnet_ipv6_first(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        # Then no L2 domain is created
        vsd_l2_domain = self.vsd.get_l2domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(ipv6_subnet['id']).at_cms_id()))
        self.assertIsNone(vsd_l2_domain)

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # Then the VSD L2 domain is changed to IPtype DualStack
        self._verify_ipv6_subnet_with_vsd_l2_domain(
            ipv6_subnet, ExternalId(ipv4_subnet['id']).at_cms_id())

    @decorators.attr(type='smoke')
    @nuage_test.header()
    # OPENSTACK-1926
    def test_os_managed_dual_stack_subnet_ipv4_create_delete_create(self):
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network, cleanup=False)
        self.assertIsNotNone(ipv4_subnet)
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=None,
            enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        # delete IPv4 subnet
        self.manager.subnets_client.delete_subnet(ipv4_subnet['id'])

        # create again
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    # OPENSTACK-1926
    def test_os_managed_dual_stack_subnet_ipv6_create_delete_create(self):
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=None,
            enable_dhcp=False,
            cleanup=False)
        self.assertIsNotNone(ipv6_subnet)

        # delete
        self.manager.subnets_client.delete_subnet(ipv6_subnet['id'])

        # create again
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=None,
            enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

    @decorators.attr(type='smoke')
    @nuage_test.header()
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
            ipv6_subnet, ExternalId(ipv4_subnet['id']).at_cms_id())

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_os_managed_dual_stack_subnet_no_gateway(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # Then a VSD L2 domain is created with type IPv4
        vsd_l2_domain = self.vsd.get_l2domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(ipv4_subnet['id']).at_cms_id()))
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
            ipv6_subnet, ExternalId(ipv4_subnet['id']).at_cms_id())

        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=None),
        self._verify_vport_in_l2_domain(port, vsd_l2_domain)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_os_managed_dual_stack_subnet_unmanaged(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network,
                                         enable_dhcp=False)
        self.assertIsNotNone(ipv4_subnet)

        # Then a VSD L2 domain is created with type IPv4
        vsd_l2_domain = self.vsd.get_l2domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(ipv4_subnet['id']).at_cms_id()))
        self.assertIsNotNone(vsd_l2_domain)
        self.assertIsNone(vsd_l2_domain.ip_type)

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        # Then the VSD L2 domain is changed to IPtype DualStack
        self._verify_ipv6_subnet_with_vsd_l2_domain_unmanaged(
            ipv6_subnet, ExternalId(ipv4_subnet['id']).at_cms_id())

        port = self.create_port(network)
        self.assertIsNotNone(port)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_no_vsd_auto_assignment_for_ipv6_addresses(self):
        """See VSD-21971"""
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # Then a VSD L2 domain is created with type IPv4
        vsd_l2_domain = self.nuage_client.get_l2domain(
            filters='externalID',
            filter_value=ExternalId(ipv4_subnet['id']).at_cms_id())

        self.assertIsNotNone(vsd_l2_domain)
        self.assertIsNotNone(vsd_l2_domain[0])
        self.assertFalse(vsd_l2_domain[0]['dynamicIpv6Address'],
                         "VSD should not allocated IPv6 address")

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=None,
            mask_bits=126,
            enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        vsd_l2_domain = self.nuage_client.get_l2domain(
            filters='externalID',
            filter_value=ExternalId(ipv4_subnet['id']).at_cms_id())

        self.assertIsNotNone(vsd_l2_domain)
        self.assertIsNotNone(vsd_l2_domain[0])
        self.assertFalse(vsd_l2_domain[0]['dynamicIpv6Address'],
                         "VSD should not allocated IPv6 address")

        # Allocated port for each address in the allocation pools
        ipv6_range = IPRange(ipv6_subnet['allocation_pools'][0]['start'],
                             ipv6_subnet['allocation_pools'][0]['end'])
        for ipv6 in ipv6_range:
            port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id']},
                                       {'subnet_id': ipv6_subnet['id'],
                                        'ip_address': ipv6}]}
            port = self.create_port(network, **port_args)
            self.assertIsNotNone(port)

        # When I create a port outside the pool, it should fail with BadRequest
        ip_out_of_ipv6_allocation_pool = IPAddress(ipv6_range.last + 1)
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id']},
                                   {'subnet_id': ipv6_subnet['id'],
                                    'ip_address':
                                    ip_out_of_ipv6_allocation_pool}]}
        self.assertRaisesRegex(
            tempest_exceptions.BadRequest,
            "IP address {} is not a valid IP for the specified subnet."
            .format(ip_out_of_ipv6_allocation_pool),
            self.create_port,
            network,
            **port_args)

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
            # valid address, gateway at last addres
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
                ipv6_subnet, ExternalId(ipv4_subnet['id']).at_cms_id())

            # And I create a port in the network
            port = self.create_port(network, cleanup=False)
            self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet),

            self.manager.ports_client.delete_port(port['id'])
            self.subnets_client.delete_subnet(ipv6_subnet['id'])

    ###########################################################################
    # Update IPv6 subnet attributes
    ###########################################################################
    @decorators.attr(type='smoke')
    @nuage_test.header()
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
        self._verify_ipv6_subnet_with_vsd_l2_domain_unmanaged(
            ipv6_subnet, ExternalId(ipv4_subnet['id']).at_cms_id())

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
            vspk_filter='externalID == "{}"'
            .format(ExternalId(ipv4_subnet['id']).at_cms_id()))
        self.assertIsNotNone(vsd_l2_domain)

        # L2 domain description should match with IPv4 subnet name
        # TODO(waelj) OPENSTACK-1945
        self.assertThat(vsd_l2_domain.description, Equals(ipv4_subnet['name']))
        pass

    @decorators.attr(type='smoke')
    @nuage_test.header()
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
            ipv6_subnet, ExternalId(ipv4_subnet['id']).at_cms_id())

        # Update attributes
        subnet_attributes = {'gateway_ip': None}

        ipv6_subnet_updated = self.update_subnet(
            ipv6_subnet,
            enable_dhcp=False,
            **subnet_attributes)

        self._verify_ipv6_subnet_with_vsd_l2_domain(
            ipv6_subnet_updated, ExternalId(ipv4_subnet['id']).at_cms_id())
        self.assertIsNone(ipv6_subnet_updated['gateway_ip'])

    ###########################################################################
    # Negative cases
    ###########################################################################
    @decorators.attr(type='negative')
    @nuage_test.header()
    def test_os_managed_dual_stack_create_ipv6_only_port_neg(self):
        network = self.create_network()

        self.create_subnet(network, ip_version=6, enable_dhcp=False)

        self.assertRaisesRegex(
            tempest_exceptions.BadRequest,
            "Port can't be a pure ipv6 port. Need ipv4 fixed ip.",
            self.create_port,
            network)

        port_args = {
            'fixed_ips': [{'ip_address': IPAddress(self.cidr6.first + 10)},
                          {'ip_address': IPAddress(self.cidr6.first + 11)}]}

        self.assertRaisesRegex(
            tempest_exceptions.BadRequest,
            "Port can't be a pure ipv6 port. Need ipv4 fixed ip.",
            self.create_port,
            network,
            **port_args)

    @decorators.attr(type='negative')
    @nuage_test.header()
    def test_os_managed_dual_stack_update_port_to_ipv6_only_neg(self):
        network = self.create_network()

        self.create_subnet(network)
        self.create_subnet(network, ip_version=6, enable_dhcp=False)

        port = self.create_port(network)

        # 1. remove the v4 ip from the port (must fail)
        v4_ip = next((ip for ip in port['fixed_ips'] if _is_v4_ip(ip)), None)
        v4_ip_a = IPAddress(v4_ip['ip_address'])
        v6_ip = next((ip for ip in port['fixed_ips'] if _is_v6_ip(ip)), None)
        v6_ip_a = IPAddress(v6_ip['ip_address'])

        f_ips = {'fixed_ips': [{'ip_address': v6_ip_a}]}

        self.assertRaisesRegex(
            tempest_exceptions.BadRequest,
            "Port can't be a pure ipv6 port. Need ipv4 fixed ip.",
            self.update_port,
            port,
            **f_ips)

        # 2. add 2nd v6 ip (must succeed)
        f_ips = {'fixed_ips': [{'ip_address': v4_ip_a},
                               {'ip_address': v6_ip_a},
                               {'ip_address': v6_ip_a + 1}]}
        self.update_port(port, **f_ips)

        # 3. now remove v4 again (must fail)
        f_ips = {'fixed_ips': [{'ip_address': v6_ip_a},
                               {'ip_address': v6_ip_a + 1}]}

        self.assertRaisesRegex(
            tempest_exceptions.BadRequest,
            "Port can't be a pure ipv6 port. Need ipv4 fixed ip.",
            self.update_port,
            port,
            **f_ips)

    @decorators.attr(type='negative')
    @nuage_test.header()
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
    @nuage_test.header()
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
    @nuage_test.header()
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
    @nuage_test.header()
    def test_multiple_ipv6_subnets_neg(self):
        # Provision OpenStack network
        network = self.create_network()

        # # When I create an IPv4 subnet
        # ipv4_subnet = self.create_subnet(network)
        # self.assertIsNotNone(ipv4_subnet)

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

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
    @nuage_test.header()
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

        # When I add a second IPv4 subnet, it should fail
        self.assertRaisesRegex(
            tempest_exceptions.BadRequest,
            "A network with an ipv6 subnet may only have maximum "
            "1 ipv4 and 1 ipv6 subnet",
            self.create_subnet,
            network)

    @decorators.attr(type='negative')
    @nuage_test.header()
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

        # When I add an IPv6 subnet, it should fail
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
    @nuage_test.header()
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
    @nuage_test.header()
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
                MSG_IP_ADDRESS_INVALID_OR_RESERVED
                % "fe80:5f74:c4a5:b82e::/120"),
            (   # Reserved addresses: 6to4
                "2002:5f74:c4a5:b82e::/120",
                "2002:5f74:c4a5:b82e::1",
                MSG_IP_ADDRESS_INVALID_OR_RESERVED
                % "2002:5f74:c4a5:b82e::/120"),
            (
                "2001:5f74:c4a5:b82e::/63",
                "2001:5f74:c4a5:b82e::1",
                MSG_INVALID_IPV6_NETMASK),
            (
                "::/0",
                "::1",
                "Invalid input for operation: 0 is not allowed as CIDR prefix "
                "length."),
            # invalid CIDR prefix 0
            (
                "2001:5f74:c4a5:b82e::/64",
                "2001:5f74:c4a5:b82b:ffff:ffff:ffff:ffff",
                MSG_GATEWAY_NOT_IN_SUBNET_CIDR),
            # Gateway not in CIDR
            (
                "2001:5f74:c4a5:b82e::/64",
                "2001:5f74:c4a5:b82e::",
                MSG_GATEWAY_NOT_VALID_ON_SUBNET),
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
    @nuage_test.header()
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
