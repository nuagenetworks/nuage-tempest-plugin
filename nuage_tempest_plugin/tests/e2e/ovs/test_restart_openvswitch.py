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

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology

LOG = Topology.get_logger(__name__)
CONF = Topology.get_conf()


class RestartOpenvSwitchScenarioTest(nuage_test.NuageBaseTest):

    @classmethod
    def skip_checks(cls):
        super(RestartOpenvSwitchScenarioTest, cls).skip_checks()
        if Topology.tempest_concurrency > 1:
            raise cls.skipException('Skip OVS restart tests when multiple '
                                    'workers are present')

    def _test_restart_openvswitch(self, l3=None, ip_versions=None):
        # Verifying that connectivity and metadata-agent functionality
        # preserved after restarting OpenvSwitch.

        # Provision OpenStack network resources
        network = self.create_network()
        subnet = None
        for ip_version in ip_versions:
            subnet = self.create_subnet(
                network, ip_version=ip_version,
                mask_bits=24 if ip_version == 4 else 64,
                enable_dhcp=True)
        if l3:
            self.assertIsNotNone(subnet)
            router = self.create_router(
                external_network_id=CONF.network.public_network_id
            )
            self.router_attach(router, subnet)

        security_group = self.create_open_ssh_security_group()

        server1 = self.create_tenant_server(
            networks=[network],
            security_groups=[security_group],
            prepare_for_connectivity=True)

        server2 = self.create_tenant_server(
            networks=[network],
            security_groups=[security_group],
            prepare_for_connectivity=True)

        # check connectivity.
        self.assert_ping(server2, server1, network)

        # verify metadata
        server1.verify_metadata()
        server2.verify_metadata()

        # restart openvswitch service
        # limitation: would only work on a devstack!
        self.execute_from_shell('sudo systemctl restart openvswitch')
        self.sleep(60, msg='Waiting for OvS to be restarted!')

        # check connectivity again
        self.assert_ping(server2, server1, network)

        # verify metadata
        server1.verify_metadata()
        server2.verify_metadata()

    def test_restart_openvswitch_l3_v4(self):
        self._test_restart_openvswitch(l3=True, ip_versions=[4])

    def test_restart_openvswitch_l2_v4(self):
        self._test_restart_openvswitch(l3=False, ip_versions=[4])

    @nuage_test.skip_because(bug='OPENSTACK-2896')
    def test_restart_openvswitch_l3_v6(self):
        self._test_restart_openvswitch(l3=True, ip_versions=[6])

    @nuage_test.skip_because(bug='OPENSTACK-2896')
    def test_restart_openvswitch_l2_v6(self):
        self._test_restart_openvswitch(l3=False, ip_versions=[6])

    def test_restart_openvswitch_l3_dualstack(self):
        self._test_restart_openvswitch(l3=True, ip_versions=[6, 4])

    def test_restart_openvswitch_l2_dualstack(self):
        self._test_restart_openvswitch(l3=False, ip_versions=[6, 4])
