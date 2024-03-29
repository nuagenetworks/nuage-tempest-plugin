# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPAddress
from netaddr import IPNetwork

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.tests.api.ipv6.vsd_managed.base_nuage_networks \
    import BaseVSDManagedNetworksIPv6Test

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as tempest_exceptions

MSG_INVALID_GATEWAY = "Invalid IPv6 network gateway"
MSG_INVALID_IPV6_ADDRESS = "Invalid network IPv6 address"
MSG_IP_ADDRESS_INVALID_OR_RESERVED = "IP Address is not valid or " \
                                     "cannot be in reserved address space"

MSG_INVALID_INPUT_FOR_FIXED_IPS = "Invalid input for fixed_ips. " \
                                  "Reason: '%s' is not a valid IP address."
MSG_INVALID_IP_ADDRESS_FOR_SUBNET = "IP address %s is not a valid IP " \
                                    "for the specified subnet."

CONF = Topology.get_conf()


class VSDManagedDualStackCommonBase(BaseVSDManagedNetworksIPv6Test):

    os_dhcp_managed = None
    vsd_dhcp_managed = None

    ###########################################################################
    #
    #  The author of this test clearly did not know that gateway in VSD
    #  does not refer to gateway in case of L2.
    #  For ipv6 moreover, as VSP doesn't support dhcpv6, the whole intent
    #  of this test is missed.  So read it with that in mind please .....
    #  We use it for other purpose though.
    #
    ###########################################################################

    def _create_vsd_l2domain_template_dualstack_valid(self):

        # noinspection PyPep8
        valid_ipv6 = [
            ("2001:5f74:c4a5:b82e::/64",
             "2001:5f74:c4a5:b82e:0000:0000:0000:0001"),
            # valid address range, gateway full addressing
            # - at first address
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
             "3ffe:0b00:0000:0001:5f74:0001:c4a5:ffff")
            # prefix not matching bit mask
        ]

        for cidr6, gateway6 in valid_ipv6:

            def do_test(ipv6_cidr, dhcp6_server_ip, use_allocation_pool=False):

                ipv6_cidr = IPNetwork(ipv6_cidr)

                testcase = "TC-({},{},{})".format(
                    str(ipv6_cidr), str(dhcp6_server_ip), use_allocation_pool)

                if self.os_dhcp_managed:
                    # OS DHCP managed, VSD DHCP managed
                    vsd_l2domain_template = self.vsd_create_l2domain_template(
                        dhcp_managed=True, ip_type="DUALSTACK",
                        cidr4=self.cidr4, enable_dhcpv4=True,
                        cidr6=ipv6_cidr, ipv6_gateway=dhcp6_server_ip,
                        enable_dhcpv6=True)

                    self._verify_vsd_l2domain_template(
                        vsd_l2domain_template,
                        ip_type="DUALSTACK", dhcp_managed=True,
                        cidr4=self.cidr4, enable_dhcpv4=True,
                        cidr6=ipv6_cidr, ipv6_gateway=dhcp6_server_ip,
                        enable_dhcpv6=True)

                elif self.vsd_dhcp_managed:
                    # OS DHCP unmanaged, VSD DHCP managed (new 6.x style)
                    vsd_l2domain_template = self.vsd_create_l2domain_template(
                        dhcp_managed=True, ip_type="DUALSTACK",
                        cidr4=self.cidr4, enable_dhcpv4=False,
                        cidr6=IPNetwork(ipv6_cidr), enable_dhcpv6=False)

                    self._verify_vsd_l2domain_template(
                        vsd_l2domain_template,
                        dhcp_managed=True, ip_type="DUALSTACK",
                        cidr4=self.cidr4, gateway=None, enable_dhcpv4=False,
                        cidr6=ipv6_cidr, ipv6_gateway=None,
                        enable_dhcpv6=False)
                else:
                    # OS DHCP unmanaged, VSD DHCP unmanaged (legacy 5.x style)
                    vsd_l2domain_template = self.vsd_create_l2domain_template(
                        dhcp_managed=False)

                    self._verify_vsd_l2domain_template(
                        vsd_l2domain_template, dhcp_managed=False,
                        ip_type=None, netmask=None, address=None, gateway=None,
                        ipv6_address=None, ipv6_gateway=None)

                vsd_l2domain = self.vsd_create_l2domain(
                    template=vsd_l2domain_template)
                self._verify_vsd_l2domain_with_template(
                    vsd_l2domain, vsd_l2domain_template)

                # create OpenStack IPv6 subnet based on VSD l2dom subnet
                net_name = data_utils.rand_name('network-')
                network = self.create_network(network_name=net_name)

                mask_bits = ipv6_cidr.prefixlen
                kwargs = {
                    'ip_version': 6,
                    'cidr': ipv6_cidr,
                    'mask_bits': mask_bits,
                    # gateway is not set (VSD in any case doesn't mind ...)
                    'enable_dhcp': (vsd_l2domain_template.enable_dhcpv6
                                    if self.vsd_dhcp_managed and
                                    Topology.has_dhcp_v6_support()
                                    else False),
                    'nuagenet': vsd_l2domain.id,
                    'net_partition': self.net_partition
                }

                if use_allocation_pool:
                    start6 = ipv6_cidr[10]
                    end6 = ipv6_cidr[20]
                    pool = {'start': start6, 'end': end6}
                    kwargs['allocation_pools'] = [pool]
                else:
                    start6 = ipv6_cidr[2]  # gateway ip is cleared but
                    # as it originally was set, allocation pool is not adjusted
                    end6 = ipv6_cidr[-1]  # :ff:ff

                ipv6_subnet = self.create_subnet(network, **kwargs)
                self.assertEqual(ipv6_cidr, IPNetwork(ipv6_subnet['cidr']))
                if self.os_dhcp_managed:
                    self.assertEqual(
                        IPNetwork(ipv6_subnet['cidr']),
                        IPNetwork(vsd_l2domain_template.ipv6_address))
                self.assertEqual(
                    start6,
                    IPAddress(ipv6_subnet['allocation_pools'][0]['start']),
                    message='testcase: ' + testcase)
                self.assertEqual(
                    end6,
                    IPAddress(ipv6_subnet['allocation_pools'][0]['end']),
                    message='testcase: ' + testcase)

                kwargs = {
                    'cidr': self.cidr4,
                    'mask_bits': self.mask_bits4_unsliced,
                    # in case we run 5.x, this is always True when VSD is
                    # dhcp managed
                    'enable_dhcp': (self.os_dhcp_managed or
                                    Topology.is_v5 and
                                    self.vsd_dhcp_managed),
                    'gateway': None,
                    # gateway is not set (which ~ to option 3 not set)
                    'nuagenet': vsd_l2domain.id,
                    'net_partition': self.net_partition
                }
                if use_allocation_pool:
                    start4 = self.cidr4[10]
                    end4 = self.cidr4[20]
                    pool = {'start': start4, 'end': end4}
                    kwargs['allocation_pools'] = [pool]
                else:
                    start4 = self.cidr4[1]  # .1 as of gateway not set.
                    end4 = self.cidr4[-2]  # .254

                # create OpenStack IPv4 subnet based on VSD l2domain
                ipv4_subnet = self.create_subnet(network, **kwargs)
                self.assertEqual(str(self.cidr4), ipv4_subnet['cidr'])
                self.assertEqual(
                    start4,
                    IPAddress(ipv4_subnet['allocation_pools'][0]['start']),
                    message='testcase: ' + testcase)
                self.assertEqual(
                    end4,
                    IPAddress(ipv4_subnet['allocation_pools'][0]['end']),
                    message='testcase: ' + testcase)

                # create a port in the network - IPAM by OS
                port = self.create_port(network)
                self._verify_port(port, subnet4=None, subnet6=ipv6_subnet,
                                  status='DOWN',
                                  nuage_policy_groups=None,
                                  nuage_redirect_targets=[],
                                  nuage_floatingip=None,
                                  testcase=testcase)
                self._verify_vport_in_l2_domain(port, vsd_l2domain)

            # first normal case
            do_test(cidr6, gateway6)

            # now make it more interesting with allocation pools
            do_test(cidr6, gateway6, True)


class VSDManagedL2DualStackDhcpDisabledTest(VSDManagedDualStackCommonBase):

    os_dhcp_managed = False
    vsd_dhcp_managed = True   # new 6.x style, DHCP managed
    #                                          with DHCP flags cleared

    def _given_vsd_l2_dhcp_disabled_domain(self, gateway=None,
                                           IPv6Gateway=None):
        if self.vsd_dhcp_managed:
            if not Topology.has_full_dhcp_control_in_vsd():
                self.skipTest(
                    'DHCP cannot be disabled on mgd l2 domain in this release')
            return self._given_vsd_l2domain(
                dhcp_managed=True,
                cidr4=self.cidr4, enable_dhcpv4=False,
                cidr6=self.cidr6, enable_dhcpv6=False,
                return_template=True, gateway=gateway, IPv6Gateway=IPv6Gateway)
        else:
            return self._given_vsd_l2domain(
                dhcp_managed=False,
                cidr4=self.cidr4, cidr6=self.cidr6,
                return_template=True)

    def _check_interface_ip(self, server, ipv4_ip, ipv6_ip):
        vm_details = self.nuage_client.get_resource(
            'vms',
            filters='externalID',
            filter_values=self.nuage_client.get_vsd_external_id(server.id),
            flat_rest_path=True)[0]
        if self.vsd_dhcp_managed:
            self.assertEqual(vm_details.get('interfaces')[0]['IPAddress'],
                             ipv4_ip)
            self.assertEqual(vm_details.get('interfaces')[0]['IPv6Address'],
                             ipv6_ip)
        else:
            self.assertIsNone(vm_details.get('interfaces')[0]['IPAddress'])
            self.assertIsNone(vm_details.get('interfaces')[0]['IPv6Address'])

    #################################################################
    # TODO(Kris) This test is duplicate with what is in base class? #
    #################################################################

    def test_create_ipv6_subnet_in_vsd_managed_l2domain_dhcp_unmanaged(self):
        """test_create_ipv6_subnet_in_vsd_managed_l2domain_dhcp_unmanaged

        OpenStack IPv4 and IPv6 subnets linked to VSD l2 dualstack l2domain
        - create VSD l2 domain template dualstack
        - create VSD l2 domain
        - create OS network
        - create OS subnets
        - create OS port
        """

        # Given I have a VSD-managed-L2-dhcp-disabled subnet
        _, vsd_l2_domain = self._given_vsd_l2_dhcp_disabled_domain()

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            cidr=self.cidr4, mask_bits=self.mask_bits4_unsliced,
            gateway=None, enable_dhcp=False,
            nuagenet=vsd_l2_domain.id, net_partition=Topology.def_netpartition)
        self.assertEqual(
            str(next(IPNetwork(self.cidr4).subnet(self.mask_bits4_unsliced))),
            ipv4_subnet['cidr'])
        filters = {
            'device_owner': 'network:dhcp:nuage',
            'network_id': network['id']
        }
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(0, len(dhcp_ports))

        # create a port in the network
        port_ipv4_only = self.create_port(network)
        self._verify_port(port_ipv4_only,
                          subnet4=ipv4_subnet, subnet6=None,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port_ipv4_only, vsd_l2_domain)

        # create Openstack IPv6 subnet on Openstack based on VSD l3dom subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            cidr=self.cidr6, gateway=self.gateway6,
            mask_bits=self.mask_bits6, enable_dhcp=False,
            nuagenet=vsd_l2_domain.id, net_partition=Topology.def_netpartition)
        filters = {
            'device_owner': 'network:dhcp:nuage',
            'network_id': network['id']
        }
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(0, len(dhcp_ports))

        # create a port in the network
        port = self.create_port(network)
        self._verify_port(port,
                          subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port, vsd_l2_domain)

    ###########################################################################
    # From base class
    ###########################################################################
    def test_create_vsd_l2domain_template_dualstack_valid(self):
        self._create_vsd_l2domain_template_dualstack_valid()

    ###########################################################################
    # Special cases
    ###########################################################################

    ###########################################################################
    # backwards compatibility
    # - TODO(Kris) bw compatible with what ? This test is duplicate with above?
    ###########################################################################

    def test_ipv4_subnet_linked_to_ipv4_vsd_l2domain_managed_no_dhcp(self):
        # Given I have a VSD-L2-Unmanaged subnet
        _, vsd_l2_domain = self._given_vsd_l2_dhcp_disabled_domain()

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            cidr=self.cidr4, gateway=None,
            mask_bits=self.mask_bits4_unsliced, enable_dhcp=False,
            nuagenet=vsd_l2_domain.id, net_partition=Topology.def_netpartition)
        self.assertEqual(
            str(next(IPNetwork(self.cidr4).subnet(self.mask_bits4_unsliced))),
            ipv4_subnet['cidr'])
        filters = {
            'device_owner': 'network:dhcp:nuage',
            'network_id': network['id']
        }
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(0, len(dhcp_ports))

        # create a port in the network
        port_ipv4_only = self.create_port(network)
        self._verify_port(port_ipv4_only,
                          subnet4=ipv4_subnet, subnet6=None,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port_ipv4_only, vsd_l2_domain)

    @decorators.attr(type='smoke')
    def test_update_port_dhcp_disable_subnet_linked_to_vsd_l2domain_with_vm(
            self):
        _, vsd_l2_domain = self._given_vsd_l2_dhcp_disabled_domain()
        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            cidr=self.cidr4, gateway=None,
            mask_bits=self.mask_bits4_unsliced, enable_dhcp=False,
            nuagenet=vsd_l2_domain.id, net_partition=Topology.def_netpartition)
        ipv6_subnet = self.create_subnet(
            network,
            cidr=self.cidr6, gateway=None, enable_dhcp=False, ip_version=6,
            nuagenet=vsd_l2_domain.id, net_partition=Topology.def_netpartition)
        fixed_ips = [
            {
                "ip_address": str(self.cidr4.ip + 3),
                "subnet_id": ipv4_subnet["id"]
            },
            {
                "ip_address": str(self.cidr4.ip + 4),
                "subnet_id": ipv4_subnet["id"]
            },
            {
                "ip_address": str(self.cidr6.ip + 3),
                "subnet_id": ipv6_subnet["id"]
            },
            {
                "ip_address": str(self.cidr6.ip + 4),
                "subnet_id": ipv6_subnet["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        server = self.create_tenant_server(ports=[port])
        self._check_interface_ip(server, str(self.cidr4.ip + 4),
                                 str(self.cidr6.ip + 4) + '/64')
        fixed_ips = [
            {
                "ip_address": str(self.cidr4.ip + 5),
                "subnet_id": ipv4_subnet["id"]
            },
            {
                "ip_address": str(self.cidr4.ip + 6),
                "subnet_id": ipv4_subnet["id"]
            },
            {
                "ip_address": str(self.cidr6.ip + 5),
                "subnet_id": ipv6_subnet["id"]
            },
            {
                "ip_address": str(self.cidr6.ip + 6),
                "subnet_id": ipv6_subnet["id"]
            }
        ]
        port = self.update_port(port=port, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to update port")
        self.assertEqual(port["fixed_ips"], fixed_ips,
                         message="The port did not update properly.")
        self._check_interface_ip(server, str(self.cidr4.ip + 6),
                                 str(self.cidr6.ip + 6) + '/64')

    ###########################################################################
    # Negative cases
    ###########################################################################

    def test_create_ports_in_vsd_managed_l2domain_dhcp_unmanaged_neg(self):
        """test_create_ports_in_vsd_managed_l2domain_dhcp_unmanaged_neg

        OpenStack IPv4 and IPv6 subnets linked to VSD l2 dualstack l2domain
        - create VSD l2 domain template dualstack
        - create VSD l2 domain
        - create OS network
        - create OS subnets
        - create OS port
        """
        # Given I have a VSD-L2-Unmanaged subnet
        vsd_l2_domain_template, vsd_l2_domain = \
            self._given_vsd_l2_dhcp_disabled_domain()

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            cidr=self.cidr4, mask_bits=self.mask_bits4_unsliced,
            gateway=None, enable_dhcp=False,
            nuagenet=vsd_l2_domain.id, net_partition=Topology.def_netpartition)
        self.assertEqual(
            str(next(IPNetwork(self.cidr4).subnet(self.mask_bits4_unsliced))),
            ipv4_subnet['cidr'])

        # shall not create a port with fixed-ip IPv6 in ipv4 subnet
        port_args = {'fixed_ips':
                     [{'subnet_id': ipv4_subnet['id'],
                       'ip_address': IPAddress(self.cidr6.first + 21)}]}
        self.assertRaisesRegex(
            tempest_exceptions.BadRequest,
            "IP address %s is not a valid IP for the specified subnet" %
            (IPAddress(self.cidr6.first + 21)),
            self.create_port,
            network,
            **port_args)

        # create Openstack IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            cidr=self.cidr6, mask_bits=self.cidr6.prefixlen,
            gateway=vsd_l2_domain_template.ipv6_gateway, enable_dhcp=False,
            nuagenet=vsd_l2_domain.id, net_partition=Topology.def_netpartition)

        # shall not create port with IP already in use
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                    'ip_address':
                                        IPAddress(self.cidr4.first + 10)},
                                   {'subnet_id': ipv6_subnet['id'],
                                    'ip_address':
                                        IPAddress(self.cidr6.first + 10)}]}

        valid_port = self.create_port(network, **port_args)
        self.assertIsNotNone(valid_port)

        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr4.first + 11)},
                                   {'subnet_id': ipv6_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr6.first + 10)}]}

        self.assertRaisesRegex(
            tempest_exceptions.Conflict,
            'IP address {} already allocated in '
            'subnet {}'.format(IPAddress(self.cidr6.first + 10),
                               ipv6_subnet['id']),
            self.create_port,
            network,
            **port_args)

        # shall not create port with fixed ip in outside cidr
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr4.first + 12)},
                                   {'subnet_id': ipv6_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr6.first - 20)}]}
        self.assertRaisesRegex(
            tempest_exceptions.BadRequest,
            "IP address %s is not a valid IP for the specified subnet" %
            (IPAddress(self.cidr6.first - 20)),
            self.create_port,
            network,
            **port_args)

    def test_create_port_in_vsd_managed_l2domain_dhcp_unmanaged_neg(self):
        """test_create_port_in_vsd_managed_l2domain_dhcp_unmanaged_neg

        OpenStack IPv4 and IPv6 subnets linked to VSD l2 dualstack l2domain
        - create VSD l2 domain template dualstack
        - create VSD l2 domain
        - create OS network
        - create OS subnets
        - create OS port
        """
        # Given I have a VSD-L2-Unmanaged subnet
        _, vsd_l2_domain = self._given_vsd_l2_dhcp_disabled_domain()

        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            cidr=self.cidr4, mask_bits=self.mask_bits4_unsliced,
            gateway=None, enable_dhcp=False,
            nuagenet=vsd_l2_domain.id, net_partition=Topology.def_netpartition)

        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6, cidr=self.cidr6, mask_bits=self.mask_bits6,
            gateway=self.gateway6, enable_dhcp=False,
            nuagenet=vsd_l2_domain.id, net_partition=Topology.def_netpartition)

        # noinspection PyPep8
        invalid_ipv6 = [
            ('::1', MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            # Loopback
            ('FE80::1', MSG_INVALID_IP_ADDRESS_FOR_SUBNET),
            #  Link local address
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
            # invalid address, too many segments
            ("2001:5f74:c4a5:b82e:ffff:ffff:ffff",
             MSG_INVALID_INPUT_FOR_FIXED_IPS),
            # invalid address, seven segments
            ("2001;5f74.c4a5.b82e:ffff:ffff:ffff",
             MSG_INVALID_INPUT_FOR_FIXED_IPS),
            # invalid address, wrong characters
            ("2001:5f74:c4a5:b82e:100.12.13.1",
             MSG_INVALID_INPUT_FOR_FIXED_IPS),
            # invalid format: must have :: between hex and decimal part.
        ]

        for ipv6, msg in invalid_ipv6:
            port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                        'ip_address':
                                            IPAddress(self.cidr4.first + 1)},
                                       {'subnet_id': ipv6_subnet['id'],
                                        'ip_address': ipv6}]}
            self.assertRaisesRegex(
                tempest_exceptions.BadRequest,
                msg % ipv6, self.create_port, network, **port_args)


class LegacyVSDManagedL2DualStackDhcpDisabledTest(
        VSDManagedL2DualStackDhcpDisabledTest):

    vsd_dhcp_managed = False  # legacy 5.x style, DHCP unmanaged

    @classmethod
    def skip_checks(cls):
        super(LegacyVSDManagedL2DualStackDhcpDisabledTest, cls).skip_checks()
        if CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed':
            raise cls.skipException("VSD managed ipam is not compatible with "
                                    "VSD unmanaged l2domains.")
