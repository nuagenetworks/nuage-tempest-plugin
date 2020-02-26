# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPAddress
from netaddr import IPNetwork
from testtools.matchers import ContainsDict
from testtools.matchers import Equals

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as nuage_constants
from nuage_tempest_plugin.tests.api.ipv6.vsd_managed. \
    test_dualstack_subnet_l2_dhcp_unmanaged \
    import VSDManagedDualStackCommonBase

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

MSG_INVALID_GATEWAY = "Invalid network gateway"
MSG_INVALID_ADDRESS = "Invalid network address"

MSG_INVALID_IPV6_ADDRESS = "Invalid network IPv6 address"
MSG_INVALID_IPV6_NETMASK = "Invalid IPv6 netmask"
MSG_INVALID_IPV6_GATEWAY = "Invalid IPv6 network gateway"

MSG_IP_ADDRESS_INVALID_OR_RESERVED = "IP Address is not valid or cannot be " \
                                     "in reserved address space"

MSG_INVALID_INPUT_FOR_FIXED_IPS = "Invalid input for fixed_ips. " \
                                  "Reason: '%s' is not a valid IP address."
MSG_INVALID_IP_ADDRESS_FOR_SUBNET = "IP address %s is not a valid IP for " \
                                    "the specified subnet."


class VSDManagedDualStackL2DHCPManagedTest(VSDManagedDualStackCommonBase):

    os_dhcp_managed = True
    vsd_dhcp_managed = True

    def link_dualstack_net_l2(
            self,
            cidr4=None, mask_bits4=None, dhcp4_port=None, gateway4=None,
            cidr6=None, mask_bits6=None, dhcp6_port=None, gateway6=None,
            pool4=None, pool6=None,
            vsd_l2dom=None, should_pass4=True, should_pass6=True):

        cidr4 = cidr4 or IPNetwork('10.10.100.0/24')
        mask_bits4 = mask_bits4 or cidr4.prefixlen
        dhcp4_port = dhcp4_port or str(cidr4[1])

        cidr6 = cidr6 or IPNetwork('cafe:babe::/64')
        mask_bits6 = mask_bits6 or cidr6.prefixlen

        if vsd_l2dom is None:
            vsd_l2domain_template = self.vsd_create_l2domain_template(
                ip_type="DUALSTACK",
                dhcp_managed=True,
                cidr4=cidr4,
                cidr6=cidr6,
                gateway=dhcp4_port)

            vsd_l2dom = self.vsd_create_l2domain(
                template=vsd_l2domain_template)

        # create OpenStack network
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        # create OpenStack IPv4 subnet on OpenStack based on VSD l2domain
        kwargs4 = {
            'gateway': gateway4,
            'cidr': cidr4,
            'mask_bits': mask_bits4,
            'nuagenet': vsd_l2dom.id,
            'net_partition': self.net_partition
        }
        if pool4:
            kwargs4['allocation_pools'] = [pool4]

        if should_pass4:
            ipv4_subnet = self.create_subnet(network, **kwargs4)
            self.assertEqual(ipv4_subnet['cidr'], str(cidr4))
            if pool4:
                subnet_pool4 = ipv4_subnet['allocation_pools']
                self.assertEqual(1, len(subnet_pool4))
                self.assertEqual(pool4, subnet_pool4[0])
        else:
            self.assertRaises(exceptions.BadRequest,
                              self.create_subnet, network, **kwargs4)

        # create OpenStack IPv6 subnet on OpenStack based on VSD l2dom subnet
        kwargs6 = {
            'gateway': gateway6,
            'cidr': cidr6,
            'mask_bits': mask_bits6,
            'ip_version': 6,
            'enable_dhcp': False,
            'nuagenet': vsd_l2dom.id,
            'net_partition': self.net_partition
        }
        if pool6:
            kwargs6['allocation_pools'] = [pool6]

        if should_pass6:
            ipv6_subnet = self.create_subnet(network, **kwargs6)
            self.assertEqual(str(cidr6), ipv6_subnet['cidr'])
            if pool6:
                subnet_pool6 = ipv6_subnet['allocation_pools']
                self.assertEqual(1, len(subnet_pool6))
                self.assertEqual(pool6, subnet_pool6[0])
        else:
            self.assertRaises(exceptions.BadRequest,
                              self.create_subnet, network, **kwargs6)

        return vsd_l2dom

    @decorators.attr(type='smoke')
    def test_dualstack_vsd_mgd_l2dom_dhcp_mgd(self):
        self.link_dualstack_net_l2()

    @decorators.attr(type='smoke')
    def test_dualstack_vsd_mgd_l2dom_dhcp_mgd_allocation_pools(self):
        pool4 = {'start': '10.10.100.100', 'end': '10.10.100.109'}
        pool6 = {'start': 'cafe:babe::100', 'end': 'cafe:babe::109'}

        self.link_dualstack_net_l2(pool4=pool4, pool6=pool6)

    @decorators.attr(type='smoke')
    def test_dual_ds_vsd_mgd_l2dom_dhcp_mgd_disjunct_allocation_pools(self):
        pool4 = {'start': '10.10.100.100', 'end': '10.10.100.109'}
        pool6 = {'start': 'cafe:babe::100', 'end': 'cafe:babe::109'}

        vsd_l2dom = self.link_dualstack_net_l2(pool4=pool4, pool6=pool6)

        pool4 = {'start': '10.10.100.110', 'end': '10.10.100.119'}
        pool6 = {'start': 'cafe:babe::110', 'end': 'cafe:babe::119'}

        self.link_dualstack_net_l2(pool4=pool4, pool6=pool6,
                                   vsd_l2dom=vsd_l2dom)

    @decorators.attr(type='smoke')
    def test_dual_ds_vsd_mgd_l2dom_dhcp_mgd_non_disj_v4_alloc_pools_neg(self):
        pool4 = {'start': '10.10.100.100', 'end': '10.10.100.110'}
        pool6 = {'start': 'cafe:babe::100', 'end': 'cafe:babe::109'}

        vsd_l2dom = self.link_dualstack_net_l2(pool4=pool4, pool6=pool6)

        pool4 = {'start': '10.10.100.110', 'end': '10.10.100.119'}
        pool6 = {'start': 'cafe:babe::110', 'end': 'cafe:babe::119'}

        self.link_dualstack_net_l2(pool4=pool4, pool6=pool6,
                                   vsd_l2dom=vsd_l2dom, should_pass4=False)

    @decorators.attr(type='smoke')
    def test_dual_ds_vsd_mgd_l2dom_dhcp_mgd_non_disj_v6_alloc_pools_neg(self):
        pool4 = {'start': '10.10.100.100', 'end': '10.10.100.109'}
        pool6 = {'start': 'cafe:babe::100', 'end': 'cafe:babe::110'}

        vsd_l2dom = self.link_dualstack_net_l2(pool4=pool4, pool6=pool6)

        pool4 = {'start': '10.10.100.110', 'end': '10.10.100.119'}
        pool6 = {'start': 'cafe:babe::110', 'end': 'cafe:babe::119'}

        self.link_dualstack_net_l2(pool4=pool4, pool6=pool6,
                                   vsd_l2dom=vsd_l2dom, should_pass6=False)

    @decorators.attr(type='smoke')
    def test_create_ipv6_subnet_in_vsd_mgd_l2dom_dhcp_mgd_with_ports(self):
        """test_create_ipv6_subnet_in_vsd_managed_l2domain_dhcp_managed

        OpenStack IPv4 and IPv6 subnets linked to VSD l2 dualstack l2domain
        - create VSD l2 domain template dualstack
        - create VSD l2 domain
        - create OS network
        - create OS subnets
        - create OS port
        """
        # create l2domain on VSD
        vsd_l2domain_template = self.vsd_create_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=self.cidr4,
            cidr6=self.cidr6,
            gateway=self.gateway4)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=self.cidr4,
                                           cidr6=self.cidr6,
                                           gateway=self.gateway4)

        vsd_l2domain = self.vsd_create_l2domain(template=vsd_l2domain_template)
        self._verify_vsd_l2domain_with_template(
            vsd_l2domain, vsd_l2domain_template)

        # create OpenStack IPv4 subnet on OpenStack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=None,
            cidr=self.cidr4,
            mask_bits=self.mask_bits4_unsliced,
            nuagenet=vsd_l2domain.id,
            net_partition=self.net_partition)
        self.assertEqual(ipv4_subnet['cidr'], str(self.cidr4))

        # create a port in the network
        port_ipv4_only = self.create_port(network, cleanup=False)
        self._verify_port(port_ipv4_only, subnet4=ipv4_subnet, subnet6=None,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port_ipv4_only, vsd_l2domain)

        # create OpenStack IPv6 subnet on OpenStack based on VSD l2dom subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=vsd_l2domain_template.ipv6_gateway,
            cidr=self.cidr6,
            mask_bits=self.mask_bits6,
            enable_dhcp=False,
            nuagenet=vsd_l2domain.id,
            net_partition=self.net_partition)

        self.assertEqual(
            ipv6_subnet['cidr'], vsd_l2domain_template.ipv6_address)

        # Mind ... VSD will have allocated an IP to the prev created port now
        # We need to sure we don't create port now which collides with that
        # Therefore clean up this port first now
        self.ports_client.delete_port(port_ipv4_only['id'])

        # create a port with fixed-ip in the IPv4 subnet, and no IP in IPv6
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr4.first + 7)}]}
        port = self.create_port(network, **port_args)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=None),
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

        # create a port with fixed-ip in the IPv4 subnet and in IPv6
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr4.first + 11)},
                                   {'subnet_id': ipv6_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr6.first + 11)}]}
        port = self.create_port(network, **port_args)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet),
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

        # can have multiple fixed ip's in same subnet
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr4.first + 33)},
                                   {'subnet_id': ipv6_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr6.first + 33)},
                                   {'subnet_id': ipv6_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr6.first + 34)}]}
        port = self.create_port(network, **port_args)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN')
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

        # create a port in the network
        # OpenStack now chooses a random IP address.
        # To avoid conflict with the above fixed IP's, do this case last
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

    @decorators.attr(type='smoke')
    def test_create_ipv6_subnet_in_vsd_mgd_l2domain_with_ipv6_network_first(
            self):
        """test_create_ipv6_subnet_in_vsd_mgd_l2domain_with_ipv6_network_first

        OpenStack IPv4 and IPv6 subnets linked to
        VSD l2 dualstack l2 domain
        - create VSD l2 domain template dualstack
        - create VSD l2 domain
        - create OS network
        - create OS subnets
        -- first the ipv6 network
        -- than the ipv4 network
        - create OS port
        """
        # create l2domain on VSD
        vsd_l2domain_template = self.vsd_create_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=self.cidr4,
            cidr6=self.cidr6,
            gateway=self.gateway4)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=self.cidr4,
                                           cidr6=self.cidr6,
                                           gateway=self.gateway4)

        vsd_l2domain = self.vsd_create_l2domain(template=vsd_l2domain_template)
        self._verify_vsd_l2domain_with_template(
            vsd_l2domain, vsd_l2domain_template)

        # create OpenStack IPv6 subnet on OpenStack based on VSD l2dom subnet
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=vsd_l2domain_template.ipv6_gateway,
            cidr=IPNetwork(vsd_l2domain_template.ipv6_address),
            mask_bits=IPNetwork(
                vsd_l2domain_template.ipv6_address).prefixlen,
            enable_dhcp=False,
            nuagenet=vsd_l2domain.id,
            net_partition=self.net_partition)

        self.assertEqual(ipv6_subnet['cidr'],
                         vsd_l2domain_template.ipv6_address)
        filters = {
            'device_owner': 'network:dhcp:nuage',
            'network_id': network['id']
        }
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(0, len(dhcp_ports))

        port = self.create_port(network)
        self._verify_port(port, subnet4=None, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

        # create OpenStack IPv4 subnet on OpenStack based on VSD l2domain
        ipv4_subnet = self.create_subnet(
            network,
            gateway=None,
            cidr=self.cidr4,
            mask_bits=self.mask_bits4_unsliced,
            nuagenet=vsd_l2domain.id,
            net_partition=self.net_partition)
        self.assertEqual(ipv4_subnet['cidr'], str(self.cidr4))
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(1, len(dhcp_ports))
        self.assertEqual(dhcp_ports[0]['fixed_ips'][0]['subnet_id'],
                         ipv4_subnet['id'])
        self.assertEqual(dhcp_ports[0]['fixed_ips'][0]['ip_address'],
                         vsd_l2domain.gateway)

        # create a port in the network - IPAM by OS
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

        # create a port in the network - IPAM by OS
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

    ###########################################################################
    # From base class
    ###########################################################################
    def test_create_vsd_l2domain_template_dualstack_valid(self):
        self._create_vsd_l2domain_template_dualstack_valid()

    ###########################################################################
    # Special cases
    ###########################################################################

    ########################################
    # backwards compatibility
    ########################################
    @decorators.attr(type='smoke')
    def test_ipv4_subnet_linked_to_ipv4_vsd_l2domain(self):
        vsd_l2domain_template = self.vsd_create_l2domain_template(
            ip_type="IPV4",
            cidr4=self.cidr4,
            dhcp_managed=True)

        self._verify_vsd_l2domain_template(
            vsd_l2domain_template,
            ip_type="IPV4",
            dhcp_managed=True,
            cidr4=self.cidr4,
            gateway=self.gateway4,
            netmask=str(self.cidr4.netmask))

        vsd_l2domain = self.vsd_create_l2domain(template=vsd_l2domain_template)
        self._verify_vsd_l2domain_with_template(
            vsd_l2domain, vsd_l2domain_template)

        # create OpenStack IPv4 subnet on OpenStack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=None,
            cidr=self.cidr4,
            mask_bits=self.mask_bits4_unsliced,
            nuagenet=vsd_l2domain.id,
            net_partition=self.net_partition)
        self.assertEqual(ipv4_subnet['cidr'], str(self.cidr4))

        # create a port in the network
        port_ipv4_only = self.create_port(network)
        self._verify_port(port_ipv4_only, subnet4=ipv4_subnet, subnet6=None,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port_ipv4_only, vsd_l2domain)

    ########################################
    # minimal attributes - default values
    ########################################

    @nuage_test.skip_because(bug='VSD-18509')
    @decorators.attr(type='smoke')
    def test_create_vsd_l2domain_template_dualstack_valid_failing_at_vsd(self):
        valid_ipv6 = [
            ("0:0:0:ffff::/64", "::ffff:100.12.13.1"),
            # ("2001:5f74:c4a5:b82e::/64", "2001:5f74:c4a5:b82e::100.12.13.1"),
            # valid address, gateway at mixed ipv4 and ipv6 format
            # (digit-dot notation)
        ]

        for ipv6_cidr, ipv6_gateway in valid_ipv6:
            vsd_l2domain_template = self.vsd_create_l2domain_template(
                ip_type="DUALSTACK",
                cidr4=self.cidr4,
                dhcp_managed=True,
                ipv6_address=ipv6_cidr,
                ipv6_gateway=ipv6_gateway
            )

            self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                               ip_type="DUALSTACK",
                                               dhcp_managed=True,
                                               cidr4=self.cidr4,
                                               ipv6_address=ipv6_cidr,
                                               ipv6_gateway=ipv6_gateway)

    @decorators.attr(type='smoke')
    def test_create_fixed_ipv6_ports_in_vsd_managed_l2domain(self):
        """test_create_fixed_ipv6_ports_in_vsd_managed_l2domain

        OpenStack IPv4 and IPv6 subnets linked to VSD l2 dualstack l2domain
        - create VSD l2 domain template dualstack
        - create VSD l2 domain
        - create OS network
        - create OS subnets
        - create OS port
        """

        # create l2domain on VSD
        vsd_l2domain_template = self.vsd_create_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=self.cidr4,
            cidr6=self.cidr6,
            gateway=self.gateway4,
            gateway6=self.gateway6,
            enable_dhcpv4=True,
            enable_dhcpv6=True)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=self.cidr4,
                                           cidr6=self.cidr6,
                                           ipv6_gateway=self.gateway6,
                                           gateway=self.gateway4)

        vsd_l2domain = self.vsd_create_l2domain(template=vsd_l2domain_template)
        self._verify_vsd_l2domain_with_template(
            vsd_l2domain, vsd_l2domain_template)

        # create OpenStack IPv4 subnet on OpenStack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=None,
            cidr=self.cidr4,
            mask_bits=self.mask_bits4_unsliced,
            nuagenet=vsd_l2domain.id,
            net_partition=self.net_partition)
        self.assertEqual(ipv4_subnet['cidr'], str(self.cidr4))

        # create a port in the network
        port_ipv4_only = self.create_port(network)
        self._verify_port(port_ipv4_only, subnet4=ipv4_subnet, subnet6=None,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)

        nuage_vports = self.nuage_client.get_vport(
            nuage_constants.L2_DOMAIN,
            vsd_l2domain.id,
            filters='externalID',
            filter_value=port_ipv4_only['id'])
        self.assertEqual(
            len(nuage_vports), 1,
            "Must find one VPort matching port: %s" % port_ipv4_only['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport,
                        ContainsDict({'name': Equals(port_ipv4_only['id'])}))

        # create OpenStack IPv6 subnet on OpenStack based on VSD l2dom subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=self.gateway6,
            cidr=self.cidr6,
            mask_bits=self.mask_bits6,
            enable_dhcp=True,
            nuagenet=vsd_l2domain.id,
            net_partition=self.net_partition)

        self.assertEqual(
            ipv6_subnet['cidr'], vsd_l2domain_template.ipv6_address)

        # create a port in the network
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)

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

    ###########################################################################
    # Negative cases
    ###########################################################################
    @decorators.attr(type='smoke')
    def test_ipv6_subnet_linked_to_ipv4_vsd_l2domain_neg(self):
        vsd_l2domain_template = self.vsd_create_l2domain_template(
            ip_type="IPV4",
            cidr4=self.cidr4,
            dhcp_managed=True)

        self._verify_vsd_l2domain_template(
            vsd_l2domain_template,
            ip_type="IPV4",
            dhcp_managed=True,
            cidr4=self.cidr4,
            gateway=self.gateway4,
            netmask=str(self.cidr4.netmask))

        vsd_l2domain = self.vsd_create_l2domain(
            template=vsd_l2domain_template)
        self._verify_vsd_l2domain_with_template(
            vsd_l2domain, vsd_l2domain_template)

        # create OpenStack IPv6 subnet on linked to VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        if Topology.from_openstack('Newton'):
            expected_exception = exceptions.BadRequest
            expected_message = "Subnet with ip_version 6 can't be linked " \
                               "to vsd subnet with IPType IPV4"
        else:
            expected_exception = exceptions.ServerFault
            expected_message = "create_subnet_postcommit failed."

        self.assertRaisesRegex(
            expected_exception,
            expected_message,
            self.create_subnet,
            network,
            ip_version=6,
            enable_dhcp=False,
            nuagenet=vsd_l2domain.id,
            net_partition=self.net_partition)

    @decorators.attr(type='smoke')
    def test_create_port_in_vsd_managed_l2domain_dhcp_managed_neg(self):
        """test_create_port_in_vsd_managed_l2domain_dhcp_managed_neg

        OpenStack IPv4 and IPv6 subnets linked to VSD l2 dualstack l2domain
        - create VSD l2 domain template dualstack
        - create VSD l2 domain
        - create OS network
        - create OS subnets
        - create OS port
        """
        # create l2domain on VSD
        vsd_l2domain_template = self.vsd_create_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=self.cidr4,
            cidr6=self.cidr6,
            gateway=self.gateway4)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=self.cidr4,
                                           cidr6=self.cidr6,
                                           gateway=self.gateway4)

        vsd_l2domain = self.vsd_create_l2domain(template=vsd_l2domain_template)
        self._verify_vsd_l2domain_with_template(
            vsd_l2domain, vsd_l2domain_template)

        # create OpenStack IPv4 subnet on OpenStack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=None,
            cidr=self.cidr4,
            mask_bits=self.mask_bits4_unsliced,
            nuagenet=vsd_l2domain.id,
            net_partition=self.net_partition)
        self.assertEqual(ipv4_subnet['cidr'], str(self.cidr4))

        # shall not create a port with fixed-ip IPv6 in ipv4 subnet
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr6.first + 21)}]}
        self.assertRaisesRegex(
            exceptions.BadRequest,
            "IP address %s is not a valid IP for the specified subnet" %
            (IPAddress(self.cidr6.first + 21)),
            self.create_port,
            network,
            **port_args)

        # create OpenStack IPv6 subnet on OpenStack based on VSD l2dom subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=self.gateway6,
            cidr=self.cidr6,
            mask_bits=self.mask_bits6,
            enable_dhcp=False,
            nuagenet=vsd_l2domain.id,
            net_partition=self.net_partition)

        # shall not create port with IP already in use
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr4.first + 10)},
                                   {'subnet_id': ipv6_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr6.first + 10)}]}

        valid_port = self.create_port(network, **port_args)
        self.assertIsNotNone(valid_port)

        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr4.first + 11)},
                                   {'subnet_id': ipv6_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr6.first + 10)}]}

        if Topology.from_openstack('Newton'):
            expected_exception = exceptions.Conflict,
            expected_message = "IP address %s already allocated in subnet %s" \
                % (IPAddress(self.cidr6.first + 10), ipv6_subnet['id'])
        else:
            expected_exception = exceptions.Conflict,
            expected_message = "Unable to complete operation for network %s." \
                               " The IP address %s is in use." \
                % (network['id'], IPAddress(self.cidr6.first + 10)),

        self.assertRaisesRegex(
            expected_exception,
            expected_message,
            self.create_port,
            network,
            **port_args)

        # shall not create port with fixed ip in outside cidr
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr4.first + 201)},
                                   {'subnet_id': ipv6_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr6.first - 20)}]}
        self.assertRaisesRegex(
            exceptions.BadRequest,
            "IP address %s is not a valid IP for the specified subnet" %
            (IPAddress(self.cidr6.first - 20)),
            self.create_port,
            network,
            **port_args)

        # shall not a port with no ip in the IPv4 subnet but only fixed-ip IPv6
        port_args = {'fixed_ips': [{'subnet_id': ipv6_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr6.first + 21)}]}

        port = self.create_port(network, **port_args)
        self._verify_port(port, subnet4=None, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

        port_args = {'fixed_ips': [{'subnet_id': ipv6_subnet['id'],
                                    'ip_address': IPAddress(
                                        self.cidr6.first + 22)}]}

        port = self.create_port(network, **port_args)
        self._verify_port(port, subnet4=None, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l2_domain(port, vsd_l2domain)

        # TODO(KRIS) Try to make sense of this
        #
        # # OpenStack-17001 - VSD accepts os port creation in L2 dualstack
        # # network with fixed-ip = IPv6Gateway IP
        # # shall not create port with fixed ip on the IPv6 gateway address
        # port_args = dict(fixed_ips=[{'subnet_id': ipv4_subnet['id']},
        #                             {'subnet_id': ipv6_subnet['id'],
        #                              'ip_address':
        #                                  vsd_l2domain_template.ipv6_gateway}
        #                             ])
        # if Release(CONF.nuage_sut.openstack_version) >= Release('Newton'):
        #     expected_exception = exceptions.Conflict,
        #     expected_message = "IP address %s already allocated in "
        #                        "subnet %s" \
        #                        % (vsd_l2domain_template.ipv6_gateway,
        #                           ipv6_subnet['id'])
        # else:
        #     expected_exception = exceptions.ServerFault
        #     expected_message = "The IP address %s is in use." %\
        #                        vsd_l2domain_template.ipv6_gateway,
        #
        # self.assertRaisesRegex(
        #     expected_exception,
        #     expected_message,
        #     self.create_port,
        #     network,
        #     **port_args)

    @decorators.attr(type='smoke')
    def test_create_port_neg(self):
        """test_create_port_neg

        OpenStack IPv4 and IPv6 subnets linked to VSD l2 dualstack l2domain
        - create VSD l2 domain template dualstack
        - create VSD l2 domain
        - create OS network
        - create OS subnets
        - create OS port
        """
        # create l2domain on VSD
        vsd_l2domain_template = self.vsd_create_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=self.cidr4,
            cidr6=self.cidr6)
        vsd_l2domain = self.vsd_create_l2domain(template=vsd_l2domain_template)

        # create OpenStack IPv4 subnet on OpenStack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=None,
            cidr=self.cidr4,
            enable_dhcp=True,
            mask_bits=self.mask_bits4_unsliced,
            nuagenet=vsd_l2domain.id,
            net_partition=self.net_partition)

        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=self.gateway6,
            cidr=self.cidr6,
            mask_bits=self.mask_bits6,
            enable_dhcp=False,
            nuagenet=vsd_l2domain.id,
            net_partition=self.net_partition)

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
            # invalid format: must have :: between hex and decimal part.
        ]

        for ipv6, msg in invalid_ipv6:
            port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                        'ip_address': IPAddress(
                                            self.cidr4.first + 40)},
                                       {'subnet_id': ipv6_subnet['id'],
                                        'ip_address': ipv6}]}
            self.assertRaisesRegex(exceptions.BadRequest, msg % ipv6,
                                   self.create_port, network, **port_args)

    # Telenor scenario with multiple vsd managed subnets in a network
    @decorators.attr(type='smoke')
    def test_link_multi_l2domain_to_network_dualstack(self):
        net_name = data_utils.rand_name('multi-vsd-mgd-dualstack')
        network = self.create_network(network_name=net_name)

        vsd_l2domain_template1 = self.vsd_create_l2domain_template(
            ip_type="DUALSTACK",
            cidr4=IPNetwork('10.0.0.0/24'),
            cidr6=IPNetwork('cafe:babe::/64'),
            dhcp_managed=True,
            enable_dhcpv6=True
        )
        vsd_l2domain1 = self.vsd_create_l2domain(
            template=vsd_l2domain_template1)
        vsd_l2domain_template2 = self.vsd_create_l2domain_template(
            ip_type="DUALSTACK",
            cidr4=IPNetwork('10.1.0.0/24'),
            cidr6=IPNetwork('cbfe:babe::/64'),
            dhcp_managed=True,
            enable_dhcpv6=True
        )
        vsd_l2domain2 = self.vsd_create_l2domain(
            template=vsd_l2domain_template2)

        v4_1 = self.create_subnet(
            network,
            cidr=IPNetwork('10.0.0.0/24'),
            mask_bits=24,
            gateway=None,
            nuagenet=vsd_l2domain1.id,
            net_partition=Topology.def_netpartition)
        filters = {
            'device_owner': 'network:dhcp:nuage',
            'network_id': network['id']
        }
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(1, len(dhcp_ports))
        self.assertEqual(dhcp_ports[0]['fixed_ips'][0]['subnet_id'],
                         v4_1['id'])
        self.assertEqual(dhcp_ports[0]['fixed_ips'][0]['ip_address'],
                         vsd_l2domain1.gateway)
        v6_1 = self.create_subnet(
            network,
            ip_version=6,
            cidr=IPNetwork('cafe:babe::/64'),
            mask_bits=self.mask_bits6,
            nuagenet=vsd_l2domain1.id,
            net_partition=Topology.def_netpartition)
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(1, len(dhcp_ports))
        self.assertEqual(dhcp_ports[0]['fixed_ips'][1]['subnet_id'],
                         v6_1['id'])
        self.assertEqual(dhcp_ports[0]['fixed_ips'][1]['ip_address'],
                         vsd_l2domain1.ipv6_gateway)
        if self.is_dhcp_agent_present():
            self.assertRaises(
                exceptions.BadRequest,
                self.create_subnet,
                network,
                cidr=IPNetwork('10.1.0.0/24'),
                mask_bits=24,
                gateway=None,
                nuagenet=vsd_l2domain2.id,
                net_partition=Topology.def_netpartition)
            self.assertRaises(
                exceptions.BadRequest,
                self.create_subnet,
                network,
                ip_version=6,
                cidr=IPNetwork('cbfe:babe::/64'),
                mask_bits=64,
                nuagenet=vsd_l2domain2.id,
                net_partition=Topology.def_netpartition)
        else:
            v4_2 = self.create_subnet(
                network,
                cidr=IPNetwork('10.1.0.0/24'),
                mask_bits=24,
                gateway=None,
                nuagenet=vsd_l2domain2.id,
                net_partition=Topology.def_netpartition)
            dhcp_ports = self.ports_client.list_ports(**filters)['ports']
            self.assertEqual(2, len(dhcp_ports))
            for dhcp_port in dhcp_ports:
                if dhcp_port['fixed_ips'][0]['subnet_id'] == v4_2['id']:
                    self.assertEqual(dhcp_port['fixed_ips'][0]['ip_address'],
                                     vsd_l2domain2.gateway)
            v6_2 = self.create_subnet(
                network,
                ip_version=6,
                cidr=IPNetwork('cbfe:babe::/64'),
                mask_bits=self.mask_bits6,
                nuagenet=vsd_l2domain2.id,
                net_partition=Topology.def_netpartition)
            dhcp_ports = self.ports_client.list_ports(**filters)['ports']
            self.assertEqual(2, len(dhcp_ports))
            for dhcp_port in dhcp_ports:
                if dhcp_port['fixed_ips'][1]['subnet_id'] == v6_2['id']:
                    self.assertEqual(dhcp_port['fixed_ips'][1]['ip_address'],
                                     vsd_l2domain2.ipv6_gateway)

            # check ports
            # dualstack port of same l2domain
            kwargs = {
                'fixed_ips': [{'subnet_id': v4_1['id']},
                              {'subnet_id': v6_1['id']}]
            }
            self.create_port(network, **kwargs)
            kwargs = {
                'fixed_ips': [{'subnet_id': v4_2['id']},
                              {'subnet_id': v6_2['id']}]
            }
            self.create_port(network, **kwargs)
            kwargs = {
                'fixed_ips': [{'subnet_id': v4_1['id']},
                              {'subnet_id': v6_2['id']}]
            }
            self.assertRaises(
                exceptions.BadRequest,
                self.create_port,
                network,
                **kwargs
            )
            kwargs = {
                'fixed_ips': [{'subnet_id': v6_1['id']},
                              {'subnet_id': v4_2['id']}]
            }
            self.assertRaises(
                exceptions.BadRequest,
                self.create_port,
                network,
                **kwargs
            )

    # Telenor scenario with multiple vsd managed subnets in a network
    @decorators.attr(type='smoke')
    def test_link_multi_l2domain_to_network_mix_dualstack(self):
        if self.is_dhcp_agent_present():
            raise self.skipException(
                'Multiple VSD managed subnets linked to different l2domains '
                'in a network not supported when DHCP agent is enabled.')
        net_name = data_utils.rand_name('multi-vsd-mgd-dualstack')
        network = self.create_network(network_name=net_name)

        vsd_l2domain_template1 = self.vsd_create_l2domain_template(
            ip_type="DUALSTACK",
            cidr4=IPNetwork('10.0.0.0/24'),
            cidr6=IPNetwork('cafe:babe::/64'),
            dhcp_managed=True,
            enable_dhcpv6=True
        )
        vsd_l2domain1 = self.vsd_create_l2domain(
            template=vsd_l2domain_template1)
        vsd_l2domain_template2 = self.vsd_create_l2domain_template(
            ip_type="DUALSTACK",
            cidr4=IPNetwork('10.1.0.0/24'),
            cidr6=IPNetwork('cbfe:babe::/64'),
            dhcp_managed=True,
            enable_dhcpv6=True
        )
        vsd_l2domain2 = self.vsd_create_l2domain(
            template=vsd_l2domain_template2)

        v4_subnet = self.create_subnet(
            network,
            cidr=IPNetwork('10.0.0.0/24'),
            mask_bits=24,
            gateway=None,
            nuagenet=vsd_l2domain1.id,
            net_partition=Topology.def_netpartition)
        filters = {
            'device_owner': 'network:dhcp:nuage',
            'network_id': network['id']
        }
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(1, len(dhcp_ports))
        self.assertEqual(dhcp_ports[0]['fixed_ips'][0]['subnet_id'],
                         v4_subnet['id'])
        self.assertEqual(dhcp_ports[0]['fixed_ips'][0]['ip_address'],
                         vsd_l2domain1.gateway)
        v6_subnet = self.create_subnet(
            network,
            ip_version=6,
            cidr=IPNetwork('cbfe:babe::/64'),
            mask_bits=64,
            nuagenet=vsd_l2domain2.id,
            net_partition=Topology.def_netpartition)
        dhcp_ports = self.ports_client.list_ports(**filters)['ports']
        self.assertEqual(2, len(dhcp_ports))
        for dhcp_port in dhcp_ports:
            if dhcp_port['fixed_ips'][0]['subnet_id'] == v6_subnet['id']:
                self.assertEqual(
                    dhcp_port['fixed_ips'][0]['ip_address'],
                    vsd_l2domain2.ipv6_gateway)
