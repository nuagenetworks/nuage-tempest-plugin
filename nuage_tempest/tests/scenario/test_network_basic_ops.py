# Copyright 2017 - Nokia
# All Rights Reserved.

import testtools

from tempest.lib import exceptions as lib_exc
from tempest.scenario import test_network_basic_ops
from tempest import test
from tempest.test import decorators


class TestNetworkBasicOps(test_network_basic_ops.TestNetworkBasicOps):

    def setUp(self):
        super(TestNetworkBasicOps, self).setUp()

    def _check_network_internal_connectivity(self, network,
                                             should_connect=True):
        """via ssh check VM internal connectivity:

        Upstream checks connectivity by pinging internal ports:
        - ping internal gateway and DHCP port, implying in-tenant connectivity
        pinging both, because L3 and DHCP agents might be on different nodes
        However this does not fly with nuage, restrictiong for now
        """
        floating_ip, server = self.floating_ip_tuple
        # TODO(gridinv): for now only vm ports, should be extended
        # to network:dhcp when external dhcp is landed
        internal_ips = (
            p['fixed_ips'][0]['ip_address'] for p in
            self.os_admin.ports_client.list_ports(
                tenant_id=server['tenant_id'],
                network_id=network['id'])['ports']
            if p['device_owner'].startswith('compute')
        )
        self._check_server_connectivity(floating_ip,
                                        internal_ips,
                                        should_connect)

    def _create_loginable_secgroup_rule(self, security_group_rules_client=None,
                                        secgroup=None,
                                        security_groups_client=None):
        """Create loginable security group rule

        These rules are intended to permit inbound ssh and icmp
        traffic from all sources, so no group_id is provided.
        Setting a group_id would only permit traffic from ports
        belonging to the same security group.
        """

        if security_group_rules_client is None:
            security_group_rules_client = self.security_group_rules_client
        if security_groups_client is None:
            security_groups_client = self.security_groups_client
        rules = []
        rulesets = [
            dict(
                # ssh
                protocol='tcp',
                port_range_min=22,
                port_range_max=22,
            ),
            dict(
                # ping
                protocol='icmp',
            )
        ]
        sec_group_rules_client = security_group_rules_client
        for ruleset in rulesets:
            for r_direction in ['ingress', 'egress']:
                ruleset['direction'] = r_direction
                try:
                    sg_rule = self._create_security_group_rule(
                        sec_group_rules_client=sec_group_rules_client,
                        secgroup=secgroup,
                        security_groups_client=security_groups_client,
                        **ruleset)
                except lib_exc.Conflict as ex:
                    # if rule already exist - skip rule and continue
                    msg = 'Security group rule already exists'
                    if msg not in ex._error_string:
                        raise ex
                else:
                    self.assertEqual(r_direction, sg_rule.get('direction'))
                    rules.append(sg_rule)

        return rules

    @decorators.idempotent_id('04b9fe4e-85e8-4aea-b937-ea93885ac59f')
    @testtools.skip("router admin state change does not impact traffic")
    @test.services('compute', 'network')
    def test_update_router_admin_state(self):
        pass

    @decorators.idempotent_id('f5dfcc22-45fd-409f-954c-5bd500d7890b')
    @testtools.skip("port admin state change does not impact traffic")
    @test.services('compute', 'network')
    def test_update_instance_port_admin_state(self):
        pass
