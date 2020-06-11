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

from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils.ovs import OvrsFlowQuery
from nuage_tempest_plugin.tests.e2e.e2e_base_test import E2eTestBase

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)

load_tests = testscenarios.load_tests_apply_scenarios


class BasicOffloadingTest(E2eTestBase):
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
        ('L3', {'is_l3': True}),
        ('L2', {'is_l3': False})
    ], [
        ('IPv4', {'ip_versions': E2eTestBase.IP_VERSIONS_V4}),
        ('IPv6', {'ip_versions': E2eTestBase.IP_VERSIONS_V6}),
        ('Dualstack', {'ip_versions': E2eTestBase.IP_VERSIONS_DUALSTACK})
    ], [
        ('Same subnet', {'is_same_subnet': True}),
        ('Different subnet', {'is_same_subnet': False})
    ])

    # Variables for test generation

    # list of tuples [(network, gateway_mac)], the first network will contain
    # the src port for traffic generation, the second one contains the
    # destination port. They can be the same, i.e. traffic within single subnet
    networks = []

    # limitations of OVRS
    is_fip_offload_supported = False
    is_icmpv6_offload_supported = False  # limitation of CX-5 at the moment

    @classmethod
    def setUpClass(cls):
        super(BasicOffloadingTest, cls).setUpClass()
        hypervisors = cls.get_hypervisors('ovrs')
        cls.selected_hypervisors = random.sample(hypervisors,
                                                 min(2, len(hypervisors)))

    @classmethod
    def skip_checks(cls):
        """Raise skip exception if needed"""
        super(BasicOffloadingTest, cls).skip_checks()
        if not Topology.has_default_switchdev_port_profile():
            raise cls.skipException('Test requires the created ports to be '
                                    'offload-capable by default')

    def dump_flows(self, hypervisor):
        """Dump flows on hypervisor"""
        flows = self.execute_on_hypervisor(
            hypervisor, 'sudo ovs-dpctl dump-flows -m').splitlines()
        return OvrsFlowQuery(flows)

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

    @nuage_test.skip_because(bug='VRS-31204')
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

    @nuage_test.skip_because(bug='VRS-31204')
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

    @nuage_test.skip_because(bug='VRS-31204')
    def test_same_hv_virtio_virtio(self):
        super(BasicOffloadingTest, self)._test_same_hv_virtio_virtio()

    @nuage_test.skip_because(bug='VRS-31204')
    def test_diff_hv_virtio_virtio(self):
        super(BasicOffloadingTest, self)._test_diff_hv_virtio_virtio()
