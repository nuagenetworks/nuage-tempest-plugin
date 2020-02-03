# Copyright 2017 - Nokia
# All Rights Reserved.

from tempest.test import decorators

import nuage_tempest_plugin.lib.test.nuage_test as nuage_test
from nuage_tempest_plugin.lib.topology import Topology

LOG = nuage_test.Topology.get_logger(__name__)
CONF = Topology.get_conf()


class DualstackOsManagedConnectivityTest(nuage_test.NuageBaseTest):

    default_prepare_for_connectivity = True

    def _test_icmp_connectivity_os_managed_dualstack(self, is_l3=False):
        # Provision OpenStack network
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network)
        self.create_subnet(network, ip_version=6)

        if is_l3:
            router = self.create_public_router()
            self.router_attach(router, ipv4_subnet)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network, ip_version=6)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_os_managed_dualstack(self):
        self._test_icmp_connectivity_os_managed_dualstack(is_l3=True)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l2_os_managed_dualstack(self):
        self._test_icmp_connectivity_os_managed_dualstack(is_l3=False)

    def test_icmp_connectivity_os_managed_dualstack_128_sg_prefix(self):
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network)
        self.create_subnet(network, ip_version=6)

        router = self.create_public_router()
        self.router_attach(router, ipv4_subnet)

        sg1 = self.create_security_group()
        sg_id = sg1['id']
        for sg_rule in sg1['security_group_rules']:
            self.security_group_rules_client.delete_security_group_rule(
                sg_rule['id'])

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server3_port = self.create_port(
            network,
            security_groups=[ssh_security_group['id']])

        server3 = self.create_tenant_server(
            ports=[server3_port],
            prepare_for_connectivity=True,
            start_web_server=True)

        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        self.update_port(server3_port, security_groups=[sg_id])

        # validate if the tcp connection is not yet active.
        for from_server in (server1, server2):
            self.assert_tcp_connectivity(
                from_server=from_server, to_server=server3, ip_version=6,
                network_name=network['name'], is_connectivity_expected=False)

        # Add a rule to allow IPv6 traffic from server 1
        ipv6_ip_prefix = server1.get_server_ip_in_network(
            network['name'], ip_version=6) + '/128'
        self.security_group_rules_client.create_security_group_rule(
            security_group_id=sg_id, direction='ingress',
            ethertype="IPv6", protocol='tcp',
            remote_ip_prefix=ipv6_ip_prefix)

        # now validate that TCP will work from server1 with ingress
        # itself although there is no egress rule.
        self.assert_tcp_connectivity(
            from_server=server1, to_server=server3, ip_version=6,
            network_name=network['name'], is_connectivity_expected=True)
        self.assert_tcp_connectivity(
            from_server=server2, to_server=server3, ip_version=6,
            network_name=network['name'], is_connectivity_expected=False)
