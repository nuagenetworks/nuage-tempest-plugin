# Copyright 2019 - Nokia
# All Rights Reserved.

import os

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class BaseTestCase(object):
    """Wrapper around the base to avoid it being executed standalone"""

    class AvrsOsManagedConnectivityTest(nuage_test.NuageBaseTest):

        def _test_restart_avrs(self, is_l3=None):
            # Provision OpenStack network resources.
            network = self.create_network()
            subnet = self.create_subnet(network)

            if is_l3:
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

            script_path = os.path.dirname(os.path.abspath(__file__))
            self.execute_from_shell(
                '{}/restart_avrs.sh'.format(script_path),
                success_expected=False, pause=60
            )

            # Test connectivity between peer servers again.
            self.assert_ping(server1, server2, network)

        @nuage_test.skip_because(bug='OPENSTACK-2766')
        def test_restart_avrs_l2(self):
            self._test_restart_avrs(is_l3=False)

        @nuage_test.skip_because(bug='OPENSTACK-2766')
        def test_restart_avrs_l3(self):
            self._test_restart_avrs(is_l3=True)


class AvrsIpv4OsManagedConnectivityTest(
        BaseTestCase.AvrsOsManagedConnectivityTest):
    _ip_version = 4


class AvrsIpv6OsManagedConnectivityTest(
        BaseTestCase.AvrsOsManagedConnectivityTest):
    _ip_version = 6
