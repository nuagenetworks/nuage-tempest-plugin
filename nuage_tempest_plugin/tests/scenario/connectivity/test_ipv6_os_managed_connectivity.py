# Copyright 2017 - Nokia
# All Rights Reserved.

from oslo_log import log as logging
import testtools

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology

from tempest.lib import decorators


class Ipv6ConnectivityTest(NuageBaseTest):

    LOG = logging.getLogger(__name__)

    @classmethod
    def skip_checks(cls):
        super(Ipv6ConnectivityTest, cls).skip_checks()
        if not NUAGE_FEATURES.os_managed_dualstack_subnets:
            raise cls.skipException(
                'OS Managed Dual Stack is not supported in this release')

    ###########################################################################
    # Typical cases - DualStack
    ###########################################################################
    @testtools.skipIf(not Topology.access_to_l2_supported(),
                      'Access to vm\'s in l2 networks is unsupported.')
    def test_icmp_connectivity_os_managed_dualstack_l2_domain(self):
        # Provision OpenStack network
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        # create open-ssh sg (allow icmp and ssh from anywhere)
        ssh_security_group = self._create_security_group(
            namestart='tempest-open-ssh')

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])
        server2 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network, should_pass=True)

        # Define IPv6 interface in the guest VMs
        # as VSP does not support DHCPv6 for IPv6 addresses
        server1_ipv6 = server1.get_server_ip_in_network(
            network['name'], ip_type=6)
        server2_ipv6 = server2.get_server_ip_in_network(
            network['name'], ip_type=6)

        server1.configure_dualstack_interface(
            server1_ipv6, subnet=ipv6_subnet, device='eth0')
        server2.configure_dualstack_interface(
            server2_ipv6, subnet=ipv6_subnet, device='eth0')

        # Test IPv6 connectivity between peer servers
        self.assert_ping6(server1, server2, network)

    @decorators.attr(type='smoke')
    @testtools.skipIf(not Topology.run_connectivity_tests(),
                      'Connectivity tests are disabled.')
    def test_icmp_connectivity_os_managed_dualstack_l3_domain(self):
        # Provision OpenStack network
        network = self.create_network()

        ipv4_subnet = self.create_subnet(network)
        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)

        router = self.create_test_router()
        self.router_attach(router, ipv4_subnet)

        # create open-ssh sg (allow icmp and ssh from anywhere)
        ssh_security_group = self._create_security_group(
            namestart='tempest-open-ssh')

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])
        server2 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])

        self.prepare_for_ping_test(server1)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

        # Define IPv6 interface in the guest VMs
        # as VSP does not support DHCPv6 for IPv6 addresses
        server1_ipv6 = server1.get_server_ip_in_network(
            network['name'], ip_type=6)
        server2_ipv6 = server2.get_server_ip_in_network(
            network['name'], ip_type=6)

        self.prepare_for_nic_provisioning(server1)
        self.prepare_for_nic_provisioning(server2)

        server1.configure_dualstack_interface(
            server1_ipv6, subnet=ipv6_subnet, device='eth0')
        server2.configure_dualstack_interface(
            server2_ipv6, subnet=ipv6_subnet, device='eth0')

        # Test IPv6 connectivity between peer servers
        self.assert_ping6(server1, server2, network)
