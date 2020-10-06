# Copyright 2020 - Nokia
# All Rights Reserved.

import json
import random
import testscenarios

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils.ovs import AvrsFlowQuery
from nuage_tempest_plugin.tests.e2e.e2e_base_test import E2eTestBase

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)

load_tests = testscenarios.load_tests_apply_scenarios


class AvrsOsManagedConnectivityTest(E2eTestBase):
    # Test scenarios, generate tests for product of these lists
    is_icmpv6_offload_supported = True
    if Topology.has_single_stack_v6_support():
        scenarios = testscenarios.scenarios.multiply_scenarios([
            ('L3', {'is_l3': True}),
            ('L2', {'is_l3': False})
        ], [
            ('IPv4', {'ip_versions': E2eTestBase.IP_VERSIONS_V4}),
            ('IPv6', {'ip_versions': E2eTestBase.IP_VERSIONS_V6}),
            ('Dualstack', {'ip_versions': E2eTestBase.IP_VERSIONS_DUALSTACK})
        ])
    else:
        scenarios = testscenarios.scenarios.multiply_scenarios([
            ('L3', {'is_l3': True}),
            ('L2', {'is_l3': False})
        ], [
            ('IPv4', {'ip_versions': E2eTestBase.IP_VERSIONS_V4}),
            ('Dualstack', {'ip_versions': E2eTestBase.IP_VERSIONS_DUALSTACK})
        ])

    @classmethod
    def setUpClass(cls):
        super(AvrsOsManagedConnectivityTest, cls).setUpClass()
        hypervisors = cls.get_hypervisors('avrs')
        cls.selected_hypervisors = random.sample(hypervisors,
                                                 min(2, len(hypervisors)))

    def dump_flows(self, hypervisor):
        """Dump flows on hypervisor"""
        flows = json.loads(self.execute_on_hypervisor(
            hypervisor, 'sudo fpcmd fp-vswitch-flows-json'))
        return AvrsFlowQuery(flows)

    def test_restart_avrs(self):
        if Topology.api_workers > 1:
            raise self.skipException('Skip OVS restart tests when multiple '
                                     'workers are present')

        # Provision OpenStack network resources.
        network = self.create_network()
        subnet = self.create_subnet(network)

        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.router_attach(router, subnet)

        # Create open-ssh security group.
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network.
        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test connectivity between peer servers.
        self.assert_ping(server1, server2, network)

        for hypervisor in self.selected_hypervisors:
            self.restart_avrs(hypervisor['host_ip'])

        # Test connectivity between peer servers again.
        self.assert_ping(server1, server2, network)

    def test_fast_path_same_hv_virtio_virtio(self):
        super(
            AvrsOsManagedConnectivityTest, self)._test_same_hv_virtio_virtio()

    def test_fast_path_diff_hv_virtio_virtio(self):
        super(
            AvrsOsManagedConnectivityTest, self)._test_diff_hv_virtio_virtio()
