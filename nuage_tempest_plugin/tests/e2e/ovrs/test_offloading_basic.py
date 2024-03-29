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
import random
import testscenarios
import testtools

from tempest.common import waiters
from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils.ovs import OvrsFlowQuery
from nuage_tempest_plugin.tests.e2e.e2e_base_test import E2eTestBase

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)

load_tests = testscenarios.load_tests_apply_scenarios


class BasicOffloadingL3Test(E2eTestBase):
    """Basic offloading tests

    Check the following behavior:

    | Offloading | VIRTIO-VIRTIO | VIRTIO-SWITCHDEV | SWITCHDEV-SWITCHDEV |
    | :--------: | :-----------: | :--------------: | :-----------------: |
    |  Same HV   |      no       |       no!        |         yes         |
    |  Diff HV   |      no       | yes on switchdev |         yes         |

    Important note: ICMPv6 is NOT expected to offload due to limitations
    on ConnectX-5 EN NIC.

    """
    # Test scenarios, generate tests for product of these lists
    scenarios = testscenarios.scenarios.multiply_scenarios([
        ('IPv4', {'ip_versions': E2eTestBase.IP_VERSIONS_V4}),
        ('IPv6', {'ip_versions': E2eTestBase.IP_VERSIONS_V6}),
        ('Dualstack', {'ip_versions': E2eTestBase.IP_VERSIONS_DUALSTACK})
    ], [
        ('Same subnet', {'is_same_subnet': True}),
        ('Different subnet', {'is_same_subnet': False})
    ])

    # Variables for test generation
    is_l3 = True

    # list of tuples [(network, gateway_mac)], the first network will contain
    # the src port for traffic generation, the second one contains the
    # destination port. They can be the same, i.e. traffic within single subnet
    networks = []

    # limitations of OVRS
    is_fip_offload_supported = False
    is_icmpv6_offload_supported = False  # limitation of CX-5 at the moment

    @classmethod
    def setUpClass(cls):
        super(BasicOffloadingL3Test, cls).setUpClass()
        hypervisors = cls.get_hypervisors('ovrs')
        cls.selected_hypervisors = random.sample(hypervisors,
                                                 min(2, len(hypervisors)))

    @classmethod
    def skip_checks(cls):
        """Raise skip exception if needed"""
        super(BasicOffloadingL3Test, cls).skip_checks()
        if not Topology.has_default_switchdev_port_profile():
            raise cls.skipException('Test requires the created ports to be '
                                    'offload-capable by default')

    def dump_flows(self, hypervisor):
        """Dump flows on hypervisor"""
        flows = self.execute_on_hypervisor(
            hypervisor, 'sudo ovs-dpctl dump-flows -m').splitlines()
        return OvrsFlowQuery(flows)

    def _validate_interfaces(self, from_port, to_port):
        pass

    def test_same_hv_switchdev_switchdev(self):
        hv = self.selected_hypervisors[0]['hypervisor_hostname']

        from_port = self.create_port(**self.default_port_args[0])
        to_port = self.create_port(**self.default_port_args[1])

        self.assertTrue(self.is_offload_capable(from_port))
        self.assertTrue(self.is_offload_capable(to_port))

        to_server = self.create_tenant_server(
            ports=[to_port],
            availability_zone='nova:' + hv,
            prepare_for_connectivity=True,
            manager=self.admin_manager,
            start_web_server=True,
            name=data_utils.rand_name('test-server-offload'),
            **self._get_server_extra_args())

        from_server = self.create_tenant_server(
            ports=[from_port],
            availability_zone='nova:' + hv,
            prepare_for_connectivity=True,
            manager=self.admin_manager,
            name=data_utils.rand_name('test-server-offload-fip'),
            **self._get_server_extra_args())

        self._offload_test(
            from_server=from_server, from_port=from_port,
            to_server=to_server, to_port=to_port,
            destination_network=self.default_port_args[1]['network'])

    def test_diff_hv_switchdev_switchdev(self):
        if len(self.selected_hypervisors) < 2:
            raise self.skipException('at least 2 hypervisors required')

        hv0 = self.selected_hypervisors[0]['hypervisor_hostname']
        hv1 = self.selected_hypervisors[1]['hypervisor_hostname']

        from_port = self.create_port(**self.default_port_args[0])
        to_port = self.create_port(**self.default_port_args[1])

        self.assertTrue(self.is_offload_capable(from_port))
        self.assertTrue(self.is_offload_capable(to_port))

        to_server = self.create_tenant_server(
            ports=[to_port],
            availability_zone='nova:' + hv1,
            prepare_for_connectivity=True,
            manager=self.admin_manager,
            start_web_server=True,
            name=data_utils.rand_name('test-server-offload'),
            **self._get_server_extra_args())

        from_server = self.create_tenant_server(
            ports=[from_port],
            availability_zone='nova:' + hv0,
            prepare_for_connectivity=True,
            manager=self.admin_manager,
            name=data_utils.rand_name('test-server-offload-fip'),
            **self._get_server_extra_args())

        self._offload_test(
            from_server=from_server, from_port=from_port,
            to_server=to_server, to_port=to_port,
            destination_network=self.default_port_args[1]['network'])

    def test_same_hv_virtio_switchdev(self):
        hv = self.selected_hypervisors[0]['hypervisor_hostname']

        from_port = self.create_port(**self.virtio_port_args[0])
        to_port = self.create_port(**self.default_port_args[1])

        self.assertFalse(self.is_offload_capable(from_port))
        self.assertTrue(self.is_offload_capable(to_port))

        to_server = self.create_tenant_server(
            ports=[to_port],
            availability_zone='nova:' + hv,
            prepare_for_connectivity=True,
            manager=self.admin_manager,
            start_web_server=True,
            name=data_utils.rand_name('test-server-offload'),
            **self._get_server_extra_args())

        from_server = self.create_tenant_server(
            ports=[from_port],
            availability_zone='nova:' + hv,
            prepare_for_connectivity=True,
            manager=self.admin_manager,
            name=data_utils.rand_name('test-server-offload-fip'),
            **self._get_server_extra_args())

        self._offload_test(
            from_server=from_server, from_port=from_port,
            to_server=to_server, to_port=to_port,
            destination_network=self.default_port_args[1]['network'])

    def test_diff_hv_virtio_switchdev(self):

        if len(self.selected_hypervisors) < 2:
            raise self.skipException('at least 2 hypervisors required')

        hv0 = self.selected_hypervisors[0]['hypervisor_hostname']
        hv1 = self.selected_hypervisors[1]['hypervisor_hostname']

        from_port = self.create_port(**self.virtio_port_args[0])
        to_port = self.create_port(**self.default_port_args[1])

        self.assertFalse(self.is_offload_capable(from_port))
        self.assertTrue(self.is_offload_capable(to_port))

        to_server = self.create_tenant_server(
            ports=[to_port],
            availability_zone='nova:' + hv1,
            prepare_for_connectivity=True,
            manager=self.admin_manager,
            start_web_server=True,
            name=data_utils.rand_name('test-server-offload'),
            **self._get_server_extra_args())

        from_server = self.create_tenant_server(
            ports=[from_port],
            availability_zone='nova:' + hv0,
            prepare_for_connectivity=True,
            manager=self.admin_manager,
            name=data_utils.rand_name('test-server-offload-fip'),
            **self._get_server_extra_args())

        self._offload_test(
            from_server=from_server, from_port=from_port,
            to_server=to_server, to_port=to_port,
            destination_network=self.default_port_args[1]['network'])

    def test_diff_hv_switchdev_switchdev_no_port_security(self):
        if len(self.selected_hypervisors) < 2:
            raise self.skipException('at least 2 hypervisors required')

        hv0 = self.selected_hypervisors[0]['hypervisor_hostname']
        hv1 = self.selected_hypervisors[1]['hypervisor_hostname']

        from_port = self.create_port(**dict(self.default_port_args[0],
                                            port_security_enabled=False,
                                            security_groups=[]))
        to_port = self.create_port(**dict(self.default_port_args[1],
                                          port_security_enabled=False,
                                          security_groups=[]))

        self.assertTrue(self.is_offload_capable(from_port))
        self.assertTrue(self.is_offload_capable(to_port))

        to_server = self.create_tenant_server(
            ports=[to_port],
            availability_zone='nova:' + hv1,
            prepare_for_connectivity=True,
            manager=self.admin_manager,
            start_web_server=True,
            name=data_utils.rand_name('test-server-offload'),
            **self._get_server_extra_args())

        from_server = self.create_tenant_server(
            ports=[from_port],
            availability_zone='nova:' + hv0,
            prepare_for_connectivity=True,
            manager=self.admin_manager,
            name=data_utils.rand_name('test-server-offload-fip'),
            **self._get_server_extra_args())

        self._offload_test(
            from_server=from_server, from_port=from_port,
            to_server=to_server, to_port=to_port,
            destination_network=self.default_port_args[1]['network'])

    def test_same_hv_virtio_virtio(self):
        super(BasicOffloadingL3Test, self)._test_same_hv_virtio_virtio()

    @testtools.skipUnless(CONF.compute_feature_enabled.live_migration and
                          CONF.compute_feature_enabled.
                          block_migration_for_live_migration and
                          CONF.compute_feature_enabled.
                          live_migrate_back_and_forth,
                          'Block Live migration not available')
    def test_block_migration_back_and_forth(self):
        if len(self.selected_hypervisors) < 2:
            raise self.skipException('at least 2 hypervisors required')

        hv = self.selected_hypervisors[0]['hypervisor_hostname']

        from_port = self.create_port(**self.default_port_args[0])
        to_port = self.create_port(**self.default_port_args[1])

        self.assertTrue(self.is_offload_capable(from_port))
        self.assertTrue(self.is_offload_capable(to_port))

        to_server = self.create_tenant_server(
            ports=[to_port],
            availability_zone='nova:' + hv,
            prepare_for_connectivity=True,
            manager=self.admin_manager,
            start_web_server=True,
            name=data_utils.rand_name('test-server-offload'),
            **self._get_server_extra_args())

        from_server = self.create_tenant_server(
            ports=[from_port],
            availability_zone='nova:' + hv,
            prepare_for_connectivity=True,
            manager=self.admin_manager,
            name=data_utils.rand_name('test-server-offload-fip'),
            **self._get_server_extra_args())

        self._offload_test(
            from_server=from_server, from_port=from_port,
            to_server=to_server, to_port=to_port,
            destination_network=self.default_port_args[1]['network'])

        # Migrate vm
        target_hv = self.selected_hypervisors[1]['hypervisor_hostname']

        self.admin_manager.servers_client.live_migrate_server(
            to_server.id, host=target_hv, block_migration=True,
            disk_over_commit=False)

        waiters.wait_for_server_status(self.admin_manager.servers_client,
                                       to_server.id, 'ACTIVE')
        to_server.server_details = None
        new_hv = to_server.get_hypervisor_hostname()
        self.assertEqual(target_hv, new_hv, 'Server did not migrate')

        self._offload_test(
            from_server=from_server, from_port=from_port,
            to_server=to_server, to_port=to_port,
            destination_network=self.default_port_args[1]['network'])

        # Migrate vm back
        self.admin_manager.servers_client.live_migrate_server(
            to_server.id, host=hv, block_migration=True,
            disk_over_commit=False)

        waiters.wait_for_server_status(self.admin_manager.servers_client,
                                       to_server.id, 'ACTIVE')
        to_server.server_details = None
        new_hv = to_server.get_hypervisor_hostname()
        self.assertEqual(hv, new_hv, 'Server did not migrate')

        self._offload_test(
            from_server=from_server, from_port=from_port,
            to_server=to_server, to_port=to_port,
            destination_network=self.default_port_args[1]['network'])


class BasicOffloadingL2Test(BasicOffloadingL3Test):
    scenarios = testscenarios.scenarios.multiply_scenarios([
        ('IPv4', {'ip_versions': E2eTestBase.IP_VERSIONS_V4}),
        ('IPv6', {'ip_versions': E2eTestBase.IP_VERSIONS_V6}),
        ('Dualstack', {'ip_versions': E2eTestBase.IP_VERSIONS_DUALSTACK})
    ], [
        ('Same subnet', {'is_same_subnet': True})
    ])
    is_l3 = False
