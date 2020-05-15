# Copyright 2015 Midokura SARL, 2019 NOKIA
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
from netaddr import IPAddress
from netaddr import IPNetwork
import testtools

from tempest import test

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.tests.api.test_fwaas import fwaas_mixins


CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class TestFWaaS(fwaas_mixins.FWaaSClientMixin, NuageBaseTest):

    default_prepare_for_connectivity = True

    def setUp(self):
        super(TestFWaaS, self).setUp()
        required_exts = ['fwaas', 'security-group', 'router']
        for ext in required_exts:
            if not test.is_extension_enabled(ext, 'network'):
                msg = "%s Extension not enabled." % ext
                raise self.skipException(msg)

    def assert_no_icmp_connectivity(self, **kwargs):
        self.assert_icmp_connectivity(is_connectivity_expected=False,
                                      **kwargs)

    def assert_no_tcp_connectivity(self, **kwargs):
        self.assert_tcp_connectivity(is_connectivity_expected=False,
                                     **kwargs)

    def assert_connectivity(self, **kwargs):
        self.assert_icmp_connectivity(**kwargs)
        self.assert_tcp_connectivity(**kwargs)

    def assert_no_connectivity(self, **kwargs):
        self.assert_no_icmp_connectivity(**kwargs)
        self.assert_no_tcp_connectivity(**kwargs)

    def _empty_policy(self, router_id=None, **_kwargs):
        # NOTE(yamamoto): an empty policy would deny all
        # We allow ipv4 traffic here
        fw_rule_ipv4 = self.create_firewall_rule(action='allow', ip_version=4)
        fw_policy = self.create_firewall_policy(
            firewall_rules=[fw_rule_ipv4['id']])
        fw = self.create_firewall(firewall_policy_id=fw_policy['id'],
                                  router_ids=[router_id])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
        }

    def _all_disabled_rules(self, **_kwargs):
        # NOTE(yamamoto): a policy whose rules are all disabled would deny all
        fw_rule = self.create_firewall_rule(action="allow", enabled=False,
                                            ip_version=6)
        fw_rule_ipv4 = self.create_firewall_rule(action='allow', ip_version=4)
        fw_policy = self.create_firewall_policy(
            firewall_rules=[fw_rule['id'], fw_rule_ipv4['id']])
        fw = self.create_firewall(firewall_policy_id=fw_policy['id'])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'fw_rule': fw_rule,
        }

    def _block_destination_ip(self, server1_fixed_ip, server2_fixed_ip,
                              router_id, **_kwargs):
        rules = [
            # NOTE(yamamoto): The filtering is taken place after
            # destination ip is rewritten to fixed-ip.
            self.create_firewall_rule(destination_ip_address=server2_fixed_ip,
                                      action="deny", ip_version=6),
            self.create_firewall_rule(action='allow', ip_version=6),
            self.create_firewall_rule(action="allow", ip_version=4)
        ]
        rule_ids = [r['id'] for r in rules]
        fw_policy = self.create_firewall_policy(firewall_rules=rule_ids)
        fw = self.create_firewall(firewall_policy_id=fw_policy['id'],
                                  router_ids=[router_id])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'server1_fixed_ip': server1_fixed_ip,
            'server2_fixed_ip': server2_fixed_ip,
        }

    def _block_source_ip(self, server1_fixed_ip, server2_fixed_ip, router_id,
                         **_kwargs):
        rules = [
            # NOTE(yamamoto): The filtering is taken place after
            # destination ip is rewritten to fixed-ip.
            self.create_firewall_rule(source_ip_address=server1_fixed_ip,
                                      action="deny", ip_version=6),
            self.create_firewall_rule(action='allow', ip_version=6),
            self.create_firewall_rule(action="allow", ip_version=4)
        ]
        fw_policy = self.create_firewall_policy(
            firewall_rules=[r['id'] for r in rules])
        fw = self.create_firewall(firewall_policy_id=fw_policy['id'],
                                  router_ids=[router_id])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'server1_fixed_ip': server1_fixed_ip,
            'server2_fixed_ip': server2_fixed_ip,
        }

    def _block_icmp(self, router_id=None, **_kwargs):
        deny_icmp = self.create_firewall_rule(
            protocol="ipv6-icmp",
            action="deny",
            ip_version=6
        )
        allow_ipv6 = self.create_firewall_rule(
            action="allow", ip_version=6)
        allow_ipv4 = self.create_firewall_rule(action='allow', ip_version=4)
        fw_policy = self.create_firewall_policy(
            firewall_rules=[deny_icmp['id'], allow_ipv6['id'],
                            allow_ipv4['id']])

        fw = self.create_firewall(firewall_policy_id=fw_policy['id'],
                                  router_ids=[router_id])
        self._wait_firewall_ready(fw['id'])

        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'fw_rule': deny_icmp,
            'router_id': router_id
        }

    def _block_all_with_default_allow(self, router_id, **_kwargs):
        fw_rule = self.create_firewall_rule(
            action="deny", ip_version=6)
        fw_rule_allow = self.create_firewall_rule(
            action="allow", ip_version=6)
        fw_rule_ipv4 = self.create_firewall_rule(action='allow', ip_version=4)
        fw_policy = self.create_firewall_policy(
            firewall_rules=[fw_rule['id'], fw_rule_allow['id'],
                            fw_rule_ipv4['id']])
        fw = self.create_firewall(firewall_policy_id=fw_policy['id'],
                                  router_ids=[router_id])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'fw_rules': [fw_rule],
        }

    def _block_certain_ports(self, router_id, **_kwargs):
        deny_source_9090 = self.create_firewall_rule(
            action="deny", ip_version=6, source_port=9090, protocol='tcp')
        deny_destination_80 = self.create_firewall_rule(
            action="deny", ip_version=6, destination_port=80, protocol='tcp')
        allow_v6 = self.create_firewall_rule(
            action="allow", ip_version=6)
        allow_v4 = self.create_firewall_rule(
            action='allow', ip_version=4)

        fw_policy = self.create_firewall_policy(
            firewall_rules=[deny_source_9090['id'],
                            deny_destination_80['id'],
                            allow_v6['id'],
                            allow_v4['id']]
        )
        fw = self.create_firewall(firewall_policy_id=fw_policy['id'],
                                  router_ids=[router_id])
        self._wait_firewall_ready(fw['id'])
        return {
            'fw': fw,
            'fw_policy': fw_policy,
            'fw_rules': (deny_source_9090, deny_destination_80),
        }

    def _confirm_certain_ports_blocked(self, from_server, to_server):

        servers = {'from_server': from_server, 'to_server': to_server}

        # icmp not blocked
        self.assert_icmp_connectivity(**servers)

        # ports that are not blocked
        self.assert_tcp_connectivity(destination_port=81,
                                     source_port=9091,
                                     **servers)
        # blocked destination port
        self.assert_no_tcp_connectivity(destination_port=80,
                                        source_port=9092,
                                        **servers)
        # blocked source port
        self.assert_no_tcp_connectivity(destination_port=81,
                                        source_port=9090,
                                        **servers)

    def _confirm_certain_ports_allowed(self, from_server, to_server):

        servers = {'from_server': from_server, 'to_server': to_server}

        # icmp not blocked
        self.assert_icmp_connectivity(**servers)

        # ports that are not blocked
        self.assert_tcp_connectivity(
            destination_port=81, source_port=9091, **servers)

        # blocked destination port
        self.assert_tcp_connectivity(
            destination_port=80, source_port=9092, **servers)

        # blocked source port
        self.assert_tcp_connectivity(
            destination_port=81, source_port=9090, **servers)

    def _remove_rule_and_wait(self, firewall_id, firewall_policy_id,
                              firewall_rule_id):
        self.firewall_policies_client.remove_firewall_rule_from_policy(
            firewall_policy_id=firewall_policy_id,
            firewall_rule_id=firewall_rule_id)
        self._wait_firewall_ready(firewall_id)

    def _delete_firewall(self, ctx):
        self.delete_firewall_and_wait(ctx['fw']['id'])

    def _remove_rule(self, ctx):
        for rule in ctx['fw_rules']:
            self._remove_rule_and_wait(
                firewall_id=ctx['fw']['id'],
                firewall_policy_id=ctx['fw_policy']['id'],
                firewall_rule_id=rule['id'])

    def _disable_rules(self, ctx):
        for rule in ctx['fw_rules']:
            self.firewall_rules_client.update_firewall_rule(
                firewall_rule_id=rule['id'],
                enabled=False)
        self._wait_firewall_ready(ctx['fw']['id'])

    def _reverse_rules_order(self, ctx):
        self.firewall_policies_client.update_firewall_policy(
            ctx['fw_policy']['id'],
            firewall_rules=list(reversed(ctx['fw_policy']['firewall_rules'])))
        self._wait_firewall_ready(ctx['fw']['id'])

    def _confirm_blocked_one_way(self, from_server, to_server, **_kwargs):

        # one way
        self.assert_no_icmp_connectivity(from_server=from_server,
                                         to_server=to_server)
        self.assert_no_tcp_connectivity(from_server=from_server,
                                        to_server=to_server)

        # other way
        self.assert_icmp_connectivity(from_server=to_server,
                                      to_server=from_server)
        self.assert_tcp_connectivity(from_server=to_server,
                                     to_server=from_server)

    def _confirm_icmp_blocked_but_tcp_allowed(self, from_server, to_server):
        self.assert_no_icmp_connectivity(from_server=from_server,
                                         to_server=to_server)
        self.assert_tcp_connectivity(from_server=from_server,
                                     to_server=to_server)

    def _create_topology(self, router, cidrv4=None, cidrv6=None):
        """Create a topology for testing

        +--------+             +-----------+
        |"server"|             | "subnet"  |
        |   VM   +-------------+ "network" |
        +--------+             +----+------+
                                    |
                                    | router interface port
                               +----+-----+
                               | "router" |
                               +----+-----+
                                    | router gateway port
                                    |
                                    |
                               +----+------------------+
                               | existing network      |
                               | ("public_network_id") |
                               +-----------------------+
        """
        network = self.create_network()
        subnet = self.create_subnet(network, cidr=cidrv4)
        subnet6 = self.create_subnet(network, ip_version=6, cidr=cidrv6)
        self.router_attach(router, subnet)
        self.router_attach(router, subnet6)
        security_group = self._create_security_group()
        self.create_security_group_rule(security_group, direction='ingress',
                                        protocol='tcp', ethertype='IPv6',
                                        port_range_min=80, port_range_max=9999)
        server = self.create_tenant_server([network],
                                           security_groups=[security_group],
                                           prepare_for_connectivity=True)
        fixed_ip4 = IPAddress(
            server.get_server_ip_in_network(network['name'], 4))
        fixed_ip6 = IPAddress(
            server.get_server_ip_in_network(network['name'], 6))

        return server, fixed_ip4, fixed_ip6

    def _test_firewall_basic(self, block, allow=None,
                             confirm_allowed=None, confirm_blocked=None,
                             ports_for_webserver=(80,)):
        LOG.info('[{}] Begin _test_firewall_basic'.format(self.test_name))
        if allow is None:
            allow = self._delete_firewall
        if confirm_allowed is None:
            confirm_allowed = self.assert_connectivity
        if confirm_blocked is None:
            confirm_blocked = self.assert_no_connectivity

        LOG.info('[{}] 1. Creating topology'.format(self.test_name))
        router = self._get_router()

        (server2, server2_fixed_ip4,
         server2_fixed_ip6) = self._create_topology(
            router, cidrv4=IPNetwork('20.0.0.0/24'),
            cidrv6=IPNetwork('cafe:bace::/64'))
        (server1, server1_fixed_ip4,
         server1_fixed_ip6) = self._create_topology(
            router, cidrv4=IPNetwork('10.0.0.0/24'),
            cidrv6=IPNetwork('cafe:babe::/64'))
        for port in ports_for_webserver:
            self.start_web_server(server1, port=port)
            self.start_web_server(server2, port=port)

        self.sleep(10, 'Naively mitigating slow CI', tag=self.test_name)

        server1.echo_debug_info()
        server2.echo_debug_info()

        LOG.info('[{}] 2. Verify connectivity'.format(self.test_name))
        self.assert_connectivity(from_server=server1,
                                 to_server=server2)

        self.sleep(10, 'Naively mitigating slow CI')

        LOG.info('[{}] 3. Create firewall'.format(self.test_name))
        ctx = block(server1_fixed_ip=server1_fixed_ip6,
                    server2_fixed_ip=server2_fixed_ip6,
                    router_id=router['id'])

        self.sleep(10, 'Naively mitigating slow CI', tag=self.test_name)

        LOG.info('[{}] 4. Verify no connectivity'.format(self.test_name))
        confirm_blocked(from_server=server1, to_server=server2)

        LOG.info('[{}] 5. Allow traffic'.format(self.test_name))
        allow(ctx)

        self.sleep(10, 'Naively mitigating slow CI', tag=self.test_name)

        LOG.info('[{}] 6. Verify connectivity'.format(self.test_name))
        confirm_allowed(from_server=server1, to_server=server2)

    def test_block_port(self):
        self._test_firewall_basic(
            block=self._block_certain_ports,
            confirm_blocked=self._confirm_certain_ports_blocked,
            allow=self._disable_rules,
            confirm_allowed=self._confirm_certain_ports_allowed,
            ports_for_webserver=(80, 81))

    def test_firewall_block_source_ip(self):
        self._test_firewall_basic(
            block=self._block_source_ip,
            confirm_blocked=self._confirm_blocked_one_way)

    def test_firewall_destination_ip(self):
        self._test_firewall_basic(
            block=self._block_destination_ip,
            confirm_blocked=self._confirm_blocked_one_way)

    def test_firewall_block_icmp(self):
        self._test_firewall_basic(
            block=self._block_icmp,
            confirm_blocked=self._confirm_icmp_blocked_but_tcp_allowed)

    def test_firewall_remove_rule(self):
        self._test_firewall_basic(block=self._block_all_with_default_allow,
                                  allow=self._remove_rule)

    def test_firewall_disable_rule(self):
        self._test_firewall_basic(block=self._block_all_with_default_allow,
                                  allow=self._disable_rules)

    def test_firewall_empty_policy(self):
        self._test_firewall_basic(block=self._empty_policy)

    def test_firewall_all_disabled_rules(self):
        self._test_firewall_basic(block=self._all_disabled_rules)

    @testtools.skipIf(Topology.at_nuage('6.0') or Topology.at_nuage('5.4'),
                      reason='VSD-42518')
    def test_firewall_order_rules(self):
        self._test_firewall_basic(block=self._block_all_with_default_allow,
                                  allow=self._reverse_rules_order)
