# Copyright 2017 - Nokia
# All Rights Reserved.

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest

from tempest.test import decorators


class Ipv6OsManagedConnectivityTest(NuageBaseTest):

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l2_os_managed_dualstack(self):
        # Provision OpenStack network
        network = self.create_network()
        self.create_subnet(network, gateway=None)
        self.create_subnet(
            network, ip_version=6, enable_dhcp=False, gateway=None)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True,
            configure_dualstack_itf=True)

        server3 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True,
            configure_dualstack_itf=True)

        server4 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True,
            configure_dualstack_itf=True)

        server1 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True,
            configure_dualstack_itf=True)

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

        # Test IPv6 connectivity between peer servers
        success_rate = int(self.assert_ping6(
            server1, server2, network,
            return_boolean_to_indicate_success=True))
        success_rate += int(self.assert_ping6(
            server1, server3, network,
            return_boolean_to_indicate_success=True))
        success_rate += int(self.assert_ping6(
            server1, server4, network,
            return_boolean_to_indicate_success=True))

        self.assertEqual(3, success_rate, 'Success rate not met!')

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_os_managed_dualstack(self):
        # Provision OpenStack network
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network)
        self.create_subnet(network, ip_version=6, enable_dhcp=False)

        router = self.create_test_router()
        self.router_attach(router, ipv4_subnet)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True,
            configure_dualstack_itf=True)

        server1 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True,
            configure_dualstack_itf=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

        # Test IPv6 connectivity between peer servers
        self.assert_ping6(server1, server2, network)
