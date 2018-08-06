# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPNetwork

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology

from tempest.lib import decorators

LOG = Topology.get_logger(__name__)


class Ipv4OsManagedConnectivityTest(NuageBaseTest):

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l2_os_managed(self):
        # Provision OpenStack network resources
        network = self.create_network()
        self.create_subnet(network, gateway=None)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group])

        server3 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group])

        server4 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group])

        server1 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True)

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
    def test_icmp_connectivity_l3_os_managed(self):
        # Provision OpenStack network resources
        router = self.create_test_router()
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.router_attach(router, subnet)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True)

        server2 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group])

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

    def test_icmp_connectivity_l3_os_managed_neg(self):
        # Provision OpenStack network resources
        router = self.create_test_router()
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.router_attach(router, subnet)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True)

        server2 = self.create_tenant_server(
            networks=[network])  # in default sg - so not accessible!

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network, should_pass=False)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_os_managed_dual_nic(self):
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

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # create server12 port
        p1 = self.create_port(
            network=network1,
            security_groups=[ssh_security_group['id']])
        p2 = self.create_port(
            network=network2,
            security_groups=[ssh_security_group['id']],
            extra_dhcp_opts=[{'opt_name': 'router', 'opt_value': '0'}])

        # Launch tenant servers in OpenStack network
        server12 = self.create_tenant_server(
            ports=[p1, p2],
            make_reachable=True)

        server1 = self.create_tenant_server(
            networks=[network1],
            security_groups=[ssh_security_group])

        server2 = self.create_tenant_server(
            networks=[network2],
            security_groups=[ssh_security_group])

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server12, server1, network1)
        self.assert_ping(server12, server2, network2)
