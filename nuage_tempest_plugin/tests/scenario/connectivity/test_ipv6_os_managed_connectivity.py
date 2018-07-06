# Copyright 2017 - Nokia
# All Rights Reserved.

import testtools

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology

from tempest.test import decorators


class Ipv6OsManagedConnectivityTest(NuageBaseTest):

    @decorators.attr(type='smoke')
    @testtools.skipIf(not Topology.run_connectivity_tests(),
                      'Connectivity tests are disabled.')
    def test_icmp_connectivity_os_managed_dualstack_l2_domain(self):
        # Provision OpenStack network
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network, gateway=None)
        self.assertIsNotNone(ipv4_subnet)

        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=False, gateway=None)
        self.assertIsNotNone(ipv6_subnet)

        # create open-ssh sg (allow icmp and ssh from anywhere)
        ssh_security_group = self._create_security_group(
            namestart='tempest-open-ssh')

        # Launch tenant servers in OpenStack network
        server2 = self.create_reachable_tenant_server_in_l2_network(
            network, ssh_security_group)
        server1 = self.create_reachable_tenant_server_in_l2_network(
            network, ssh_security_group)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network, should_pass=True)

        # Define IPv6 interface in the guest VMs
        # as VSP does not support DHCPv6 for IPv6 addresses
        server1_ipv6 = server1.get_server_ip_in_network(
            network['name'], ip_type=6)
        server2_ipv6 = server2.get_server_ip_in_network(
            network['name'], ip_type=6)

        server1.configure_dualstack_interface(
            server1_ipv6, subnet=ipv6_subnet, device='eth1')
        server2.configure_dualstack_interface(
            server2_ipv6, subnet=ipv6_subnet, device='eth1')

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
        server2 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])
        server1 = self.create_tenant_server(
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
