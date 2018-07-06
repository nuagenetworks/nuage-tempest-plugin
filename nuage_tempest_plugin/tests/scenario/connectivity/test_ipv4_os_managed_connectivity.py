# Copyright 2017 - Nokia
# All Rights Reserved.

import testtools

from netaddr import IPNetwork

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology

from tempest.lib import decorators

LOG = Topology.get_logger(__name__)


class Ipv4OsManagedConnectivityTest(NuageBaseTest):

    @decorators.attr(type='smoke')
    @testtools.skipIf(not Topology.run_connectivity_tests(),
                      'Connectivity tests are disabled.')
    def test_icmp_connectivity_os_managed_l2_domain(self):
        # Provision OpenStack network resources
        network = self.create_network()
        subnet = self.create_subnet(network, gateway=None)
        self.assertIsNotNone(subnet)

        # Create open-ssh sg (allow icmp and ssh from anywhere)
        ssh_security_group = self._create_security_group(
            namestart='tempest-open-ssh')

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])

        server3 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])

        server4 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])

        server1 = self.create_reachable_tenant_server_in_l2_network(
            network, ssh_security_group)

        # Test IPv4 connectivity between peer servers
        success_rate = int(self.assert_ping(
            server1, server2, network,
            return_boolean_to_indicate_success=True))
        success_rate += int(self.assert_ping(
            server1, server3, network,
            return_boolean_to_indicate_success=True))
        success_rate += int(self.assert_ping(
            server1, server4, network,
            return_boolean_to_indicate_success=True))

        self.assertEqual(3, success_rate, 'Success rate not met!')

    @decorators.attr(type='smoke')
    @testtools.skipIf(not Topology.run_connectivity_tests(),
                      'Connectivity tests are disabled.')
    def test_icmp_connectivity_os_managed_l3_domain(self):
        # Provision OpenStack network resources
        router = self.create_test_router()
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.router_attach(router, subnet)

        # Create open-ssh sg (allow icmp and ssh from anywhere)
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

    @testtools.skipIf(not Topology.run_connectivity_tests(),
                      'Connectivity tests are disabled.')
    def test_icmp_connectivity_os_managed_l3_domain_neg(self):
        # Provision OpenStack network resources
        router = self.create_test_router()
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.router_attach(router, subnet)

        # create open-ssh sg (allow icmp and ssh from anywhere)
        ssh_security_group = self._create_security_group(
            namestart='tempest-open-ssh')

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])
        server2 = self.create_tenant_server(
            tenant_networks=[network])  # in default sg - so not accessible!

        self.prepare_for_ping_test(server1)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network, should_pass=False)

    @decorators.attr(type='smoke')
    @testtools.skipIf(not Topology.run_connectivity_tests(),
                      'Connectivity tests are disabled.')
    def test_icmp_connectivity_os_managed_l3_domain_dual_nic(self):
        # Provision OpenStack network resources
        router = self.create_test_router()
        network1 = self.create_network()
        subnet1 = self.create_subnet(network1,
                                     gateway='10.10.1.1',
                                     cidr=IPNetwork('10.10.1.0/24'),
                                     mask_bits=24)
        self.router_attach(router, subnet1)

        network2 = self.create_network()
        self.create_subnet(network2,
                           gateway='10.10.2.1',
                           cidr=IPNetwork('10.10.2.0/24'),
                           mask_bits=24)

        # Create open-ssh sg (allow icmp and ssh from anywhere)
        ssh_security_group = self._create_security_group(
            namestart='tempest-open-ssh')

        # Launch tenant servers in OpenStack network
        server12 = self.create_tenant_server(
            tenant_networks=[network1, network2],
            security_groups=[{'name': ssh_security_group['name']}])

        server12_p1 = self.osc_get_server_port_in_network(server12, network1)

        server1 = self.create_tenant_server(
            tenant_networks=[network1],
            security_groups=[{'name': ssh_security_group['name']}])
        server2 = self.create_tenant_server(
            tenant_networks=[network2],
            security_groups=[{'name': ssh_security_group['name']}])

        self.prepare_for_ping_test(server12, server12_p1)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server12, server1, network1)
        self.assert_ping(server12, server2, network2)
