# Copyright 2017 - Nokia
# All Rights Reserved.

import testscenarios

from tempest.test import decorators

import nuage_tempest_plugin.lib.test.nuage_test as nuage_test
from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()

load_tests = testscenarios.load_tests_apply_scenarios


class DualstackOsMgdConnectivityTestBase(nuage_test.NuageBaseTest):

    default_prepare_for_connectivity = True
    nuage_aggregate_flows = 'off'

    def _test_icmp_connectivity_os_managed_dualstack(self, is_l3=False):
        # Provision OpenStack network
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network)
        self.create_subnet(network, ip_version=6)

        if is_l3:
            kwargs = {'external_network_id': self.ext_net_id}
            if self.nuage_aggregate_flows != 'off':
                kwargs['nuage_aggregate_flows'] = self.nuage_aggregate_flows
            router = self.create_router(**kwargs)
            self.router_attach(router, ipv4_subnet)

        # create open-ssh security group
        stateful = self.nuage_aggregate_flows == 'off'
        ssh_security_group = self.create_open_ssh_security_group(
            stateful=stateful)

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group])

        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network, ip_version=6)


class DualstackOsMgdConnectivityTest(DualstackOsMgdConnectivityTestBase):

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l2_os_managed_dualstack(self):
        self._test_icmp_connectivity_os_managed_dualstack(is_l3=False)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_os_managed_dualstack(self):
        self._test_icmp_connectivity_os_managed_dualstack(is_l3=True)

    def test_icmp_connectivity_os_managed_dualstack_v6_128_sg_prefix(self):
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network)
        self.create_subnet(network, ip_version=6)

        router = self.create_public_router()
        self.router_attach(router, ipv4_subnet)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # create a new open-ssh security group
        dedicated_ssh_sg = self.create_open_ssh_security_group()

        # delete all v6 rules from the SG prior to creating server 3 with it
        sg = self.get_security_group(dedicated_ssh_sg['id'])
        for sg_rule in sg['security_group_rules']:
            if sg_rule['ethertype'] == 'IPv6':
                self.delete_security_group_rule(sg_rule['id'])

        # and re-add v6 ICMP rules, such that DAD can happen
        for direction in ('ingress', 'egress'):
            self.create_security_group_rule_with_manager(
                dedicated_ssh_sg,
                direction=direction, ethertype='IPv6', protocol='icmp')

        server3 = self.create_tenant_server(
            [network],
            security_groups=[dedicated_ssh_sg],
            start_web_server=True)

        # validate there is no v6 TCP connectivity to server 3
        for server in (server1, server2):
            self.assert_tcp_connectivity(
                from_server=server, to_server=server3, ip_version=6,
                network_name=network['name'],
                is_connectivity_expected=False)

        # now add a rule to allow v6 TCP traffic from server 1
        ipv6_ip_prefix = server1.get_server_ip_in_network(
            network['name'], ip_version=6) + '/128'
        self.create_security_group_rule_with_manager(
            dedicated_ssh_sg,
            direction='ingress', ethertype='IPv6', protocol='tcp',
            remote_ip_prefix=ipv6_ip_prefix)

        # now validate that v6 TCP from server 1 happens, with ingress allowed
        # on server 3 and no egress rule defined
        self.assert_tcp_connectivity(
            from_server=server1, to_server=server3, ip_version=6,
            network_name=network['name'], is_connectivity_expected=True)

        # but still not from server 2
        self.assert_tcp_connectivity(
            from_server=server2, to_server=server3, ip_version=6,
            network_name=network['name'], is_connectivity_expected=False)


class DualstackOsMgdConnectivityWithAggrFlowsTest(
        DualstackOsMgdConnectivityTestBase):

    scenarios = testscenarios.scenarios.multiply_scenarios([
        # Current PBR based aggregate flows feature blocks non-PBR
        # traffic in the domain. Temporary no connectivity tests for PBR mode.
        # ('Aggregate flow pbr', {'nuage_aggregate_flows': 'pbr'}),
        ('Aggregate flow route', {'nuage_aggregate_flows': 'route'})
    ])

    @classmethod
    def skip_checks(cls):
        super(DualstackOsMgdConnectivityWithAggrFlowsTest, cls).skip_checks()
        if Topology.before_nuage('20.5'):
            raise cls.skipException('OS managed aggregate flows are '
                                    'unavailable before 20.5')

    def test_icmp_connectivity_l3_os_managed_dualstack(self):
        self._test_icmp_connectivity_os_managed_dualstack(is_l3=True)
