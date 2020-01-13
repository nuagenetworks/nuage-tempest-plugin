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
from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils.ovs import FlowQuery
from nuage_tempest_plugin.tests.e2e.e2e_base_test import E2eTestBase


CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)

VIRTIO_ARGS = {'binding:vnic_type': 'normal', 'binding:profile': {}}


class BaseTestCase(object):
    """Wrapper around the base to avoid it being executed standalone"""

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
        ip_versions = ()
        is_l3 = False
        is_icmpv6_offload_supported = False  # limitation of CX-5 at the moment

        router = None
        network = None
        default_port_args = None
        virtio_port_args = None
        sg = None

        @classmethod
        def setup_clients(cls):
            super(E2eTestBase, cls).setup_clients()
            cls.hv_client = cls.admin_manager.hypervisor_client

        @classmethod
        def setUpClass(cls):
            super(BaseTestCase.BasicOffloadingTest, cls).setUpClass()

            hypervisors = cls.get_hypervisors()
            cls.selected_hypervisors = random.sample(hypervisors,
                                                     min(2, len(hypervisors)))
            if len(cls.selected_hypervisors) < 1:
                raise cls.skipException('at least 1 hypervisors required')

        def setUp(self):
            """Setup test topology"""
            super(BaseTestCase.BasicOffloadingTest, self).setUp()

            self.network = self.create_network()

            if self.is_l3:
                self.router = self.create_router(
                    external_network_id=CONF.network.public_network_id)

            for ip_version in self.ip_versions:
                subnet = self.create_subnet(self.network,
                                            ip_version=ip_version)
                if self.is_l3:
                    self.router_attach(self.router, subnet)

            self.sg = self.create_open_ssh_security_group(
                client=self.admin_manager)
            sgr_client = self.admin_manager.security_group_rules_client

            for ip_version in self.ip_versions:
                self.create_tcp_rule(self.sg, direction='ingress',
                                     ip_version=ip_version,
                                     sec_group_rules_client=sgr_client)
                self.create_tcp_rule(self.sg, direction='egress',
                                     ip_version=ip_version,
                                     sec_group_rules_client=sgr_client)

            self.default_port_args = dict(network=self.network,
                                          client=self.admin_manager,
                                          security_groups=[self.sg['id']])
            self.virtio_port_args = dict(VIRTIO_ARGS, **self.default_port_args)

        def assert_icmp_connectivity(self, *args, **kwargs):
            LOG.info('Verify ICMP traffic')

            self._assert_connectivity(
                super(E2eTestBase, self).assert_icmp_connectivity,
                self._validate_icmp_offloading, *args, **kwargs)

        def _validate_icmp_offloading(self, flows, from_port, is_cross_hv,
                                      to_port, ip_version):

            if ip_version == 6 and not self.is_icmpv6_offload_supported:
                LOG.info('skipping ICMPv6 offloading checks as they are not '
                         'supported by CX-5')
                return

            filtered_flows = FlowQuery(flows)
            filtered_flows.ip_version(ip_version)
            filtered_flows.icmp()

            self._validate_offloading(
                filtered_flows.result(), from_port, is_cross_hv, to_port)

        def _assert_connectivity(self, traffic_generator, flow_validator,
                                 *args, **kwargs):
            from_hv = self.get_hypervisor(kwargs.get('from_server'))
            to_hv = self.get_hypervisor(kwargs.get('to_server'))
            from_port = kwargs.pop('from_port')
            to_port = kwargs.pop('to_port')
            is_cross_hv = from_hv['id'] != to_hv['id']

            # generate traffic
            traffic_generator(*args, **kwargs)

            # verify offloading
            flows = self.dump_flows(from_hv)
            flow_validator(
                flows, from_port, is_cross_hv,
                to_port, kwargs.get('ip_version'))

            if is_cross_hv:
                flows = self.dump_flows(to_hv)
                flow_validator(
                    flows, to_port, is_cross_hv,
                    from_port, kwargs.get('ip_version'))

        def assert_tcp_connectivity(self, *args, **kwargs):
            LOG.info('Verify TCP traffic')

            self._assert_connectivity(
                super(E2eTestBase, self).assert_tcp_connectivity,
                self._validate_tcp_offloading, *args, **kwargs)

        def _validate_tcp_offloading(self, flows, from_port, is_cross_hv,
                                     to_port, ip_version):

            filtered_flows = FlowQuery(flows)
            filtered_flows.ip_version(ip_version)
            filtered_flows.tcp()

            self._validate_offloading(
                filtered_flows.result(), from_port, is_cross_hv, to_port)

        def _offload_test(self, from_server, from_port, to_server, to_port):
            """Send traffic between the servers and analyze ovs flows

            :param from_server: Server initiating traffic
            :param from_port: Port on that server used for initiating traffic
            :param to_server: Server responding to incoming traffic
            :param to_port: Port on that server used for the traffic
            """
            for ip_version in self.ip_versions:
                LOG.info('Verify IPv{} traffic'.format(ip_version))

                kwargs = dict(from_server=from_server, to_server=to_server,
                              network_name=self.network['name'],
                              ip_version=ip_version,
                              from_port=from_port, to_port=to_port)

                self.assert_tcp_connectivity(**kwargs)
                self.assert_icmp_connectivity(**kwargs)

        def _is_offloading_expected(self, from_port, to_port, is_different_hv):
            """Whether flow should be offloaded on first hypervisor

            | Offload | VIRTIO-VIRTIO | SWITCHDEV-VIRTIO | SWITCHDEV-SWITCHDEV|
            | :-----: | :-----------: | :--------------: | :-----------------:|
            | Same HV |      no       |       no!        |         yes        |
            | Diff HV |      no       | yes on switchdev |         yes        |
            """
            if is_different_hv:
                return self.is_offload_capable(from_port)
            else:
                return (self.is_offload_capable(from_port) and
                        self.is_offload_capable(to_port))

        def _validate_offloading(self, flows, from_port, is_different_hv,
                                 to_port):
            is_offloading_expected = self._is_offloading_expected(
                from_port, to_port, is_different_hv)

            LOG.info('Validate flow originating from hypervisor')
            self._validate_offloaded_flow(
                flows, is_different_hv, is_offloading_expected, to_port,
                is_originating_from_hv=True)

            LOG.info('Validate flow arriving at hypervisor')
            self._validate_offloaded_flow(
                flows, is_different_hv, is_offloading_expected, from_port,
                is_originating_from_hv=False)

        def _validate_offloaded_flow(self, flows, is_vxlan_tunneled,
                                     is_offloading_expected,
                                     to_port, is_originating_from_hv):
            expected_flows = FlowQuery(flows).dst_mac(to_port['mac_address'])

            if is_vxlan_tunneled:
                if is_originating_from_hv:
                    expected_flows.action_set_tunnel_vxlan()
                else:
                    expected_flows.vxlan()

            if is_offloading_expected:
                expected_flows.offload()
            else:
                expected_flows.no_offload()

            msg = ("No traffic found with offload={offload} "
                   "and vxlan={vxlan} and dst_mac={dst_mac}"
                   .format(offload='yes' if is_offloading_expected else 'no',
                           vxlan='yes' if is_vxlan_tunneled else 'no',
                           dst_mac=to_port['mac_address']))

            self.assertNotEmpty(expected_flows.result(), msg)

        def _get_server_extra_args(self):
            """Force config drive for L2 to work around metadata agent issue"""
            args = {}
            if not self.is_l3:
                args['config_drive'] = True
            return args

        def test_same_hv_switchdev_switchdev(self):
            hv = self.selected_hypervisors[0]['hypervisor_hostname']

            from_port = self.create_port(**self.default_port_args)
            to_port = self.create_port(**self.default_port_args)

            self.assertTrue(self.is_offload_capable(from_port))
            self.assertTrue(self.is_offload_capable(to_port))

            to_server = self.create_tenant_server(
                ports=[to_port],
                availability_zone='nova:' + hv,
                prepare_for_connectivity=True,
                client=self.admin_manager,
                start_web_server=True,
                name=data_utils.rand_name('test-server-offload'),
                **self._get_server_extra_args())

            from_server = self.create_tenant_server(
                ports=[from_port],
                availability_zone='nova:' + hv,
                prepare_for_connectivity=True,
                client=self.admin_manager,
                name=data_utils.rand_name('test-server-offload-fip'),
                **self._get_server_extra_args())

            self._offload_test(from_server=from_server, from_port=from_port,
                               to_server=to_server, to_port=to_port)

        def test_diff_hv_switchdev_switchdev(self):

            if len(self.selected_hypervisors) < 2:
                raise self.skipException('at least 2 hypervisors required')

            hv0 = self.selected_hypervisors[0]['hypervisor_hostname']
            hv1 = self.selected_hypervisors[1]['hypervisor_hostname']

            from_port = self.create_port(**self.default_port_args)
            to_port = self.create_port(**self.default_port_args)

            self.assertTrue(self.is_offload_capable(from_port))
            self.assertTrue(self.is_offload_capable(to_port))

            to_server = self.create_tenant_server(
                ports=[to_port],
                availability_zone='nova:' + hv1,
                prepare_for_connectivity=True,
                client=self.admin_manager,
                start_web_server=True,
                name=data_utils.rand_name('test-server-offload'),
                **self._get_server_extra_args())

            from_server = self.create_tenant_server(
                ports=[from_port],
                availability_zone='nova:' + hv0,
                prepare_for_connectivity=True,
                client=self.admin_manager,
                name=data_utils.rand_name('test-server-offload-fip'),
                **self._get_server_extra_args())

            self._offload_test(from_server=from_server, from_port=from_port,
                               to_server=to_server, to_port=to_port)

        @nuage_test.skip_because(bug='VRS-31204')
        def test_same_hv_virtio_switchdev(self):
            hv = self.selected_hypervisors[0]['hypervisor_hostname']

            from_port = self.create_port(**self.virtio_port_args)
            to_port = self.create_port(**self.default_port_args)

            self.assertFalse(self.is_offload_capable(from_port))
            self.assertTrue(self.is_offload_capable(to_port))

            to_server = self.create_tenant_server(
                ports=[to_port],
                availability_zone='nova:' + hv,
                prepare_for_connectivity=True,
                client=self.admin_manager,
                start_web_server=True,
                name=data_utils.rand_name('test-server-offload'),
                **self._get_server_extra_args())

            from_server = self.create_tenant_server(
                ports=[from_port],
                availability_zone='nova:' + hv,
                prepare_for_connectivity=True,
                client=self.admin_manager,
                name=data_utils.rand_name('test-server-offload-fip'),
                **self._get_server_extra_args())

            self._offload_test(from_server=from_server, from_port=from_port,
                               to_server=to_server, to_port=to_port)

        @nuage_test.skip_because(bug='VRS-31204')
        def test_diff_hv_virtio_switchdev(self):

            if len(self.selected_hypervisors) < 2:
                raise self.skipException('at least 2 hypervisors required')

            hv0 = self.selected_hypervisors[0]['hypervisor_hostname']
            hv1 = self.selected_hypervisors[1]['hypervisor_hostname']

            from_port = self.create_port(**self.virtio_port_args)
            to_port = self.create_port(**self.default_port_args)

            self.assertFalse(self.is_offload_capable(from_port))
            self.assertTrue(self.is_offload_capable(to_port))

            to_server = self.create_tenant_server(
                ports=[to_port],
                availability_zone='nova:' + hv1,
                prepare_for_connectivity=True,
                client=self.admin_manager,
                start_web_server=True,
                name=data_utils.rand_name('test-server-offload'),
                **self._get_server_extra_args())

            from_server = self.create_tenant_server(
                ports=[from_port],
                availability_zone='nova:' + hv0,
                prepare_for_connectivity=True,
                client=self.admin_manager,
                name=data_utils.rand_name('test-server-offload-fip'),
                **self._get_server_extra_args())

            self._offload_test(from_server=from_server, from_port=from_port,
                               to_server=to_server, to_port=to_port)

        @nuage_test.skip_because(bug='VRS-31204')
        def test_same_hv_virtio_virtio(self):
            hv = self.selected_hypervisors[0]['hypervisor_hostname']

            from_port = self.create_port(**self.virtio_port_args)
            to_port = self.create_port(**self.virtio_port_args)

            self.assertFalse(self.is_offload_capable(from_port))
            self.assertFalse(self.is_offload_capable(to_port))

            to_server = self.create_tenant_server(
                ports=[to_port],
                availability_zone='nova:' + hv,
                prepare_for_connectivity=True,
                client=self.admin_manager,
                start_web_server=True,
                name=data_utils.rand_name('test-server-offload'),
                **self._get_server_extra_args())

            from_server = self.create_tenant_server(
                ports=[from_port],
                availability_zone='nova:' + hv,
                prepare_for_connectivity=True,
                client=self.admin_manager,
                name=data_utils.rand_name('test-server-offload-fip'),
                **self._get_server_extra_args())

            self._offload_test(from_server=from_server, from_port=from_port,
                               to_server=to_server, to_port=to_port)

        @nuage_test.skip_because(bug='VRS-31204')
        def test_diff_hv_virtio_virtio(self):

            if len(self.selected_hypervisors) < 2:
                raise self.skipException('at least 2 hypervisors required')

            hv0 = self.selected_hypervisors[0]['hypervisor_hostname']
            hv1 = self.selected_hypervisors[1]['hypervisor_hostname']

            from_port = self.create_port(**self.virtio_port_args)
            to_port = self.create_port(**self.virtio_port_args)

            self.assertFalse(self.is_offload_capable(from_port))
            self.assertFalse(self.is_offload_capable(to_port))

            to_server = self.create_tenant_server(
                ports=[to_port],
                availability_zone='nova:' + hv1,
                prepare_for_connectivity=True,
                client=self.admin_manager,
                start_web_server=True,
                name=data_utils.rand_name('test-server-offload'),
                **self._get_server_extra_args())

            from_server = self.create_tenant_server(
                ports=[from_port],
                availability_zone='nova:' + hv0,
                prepare_for_connectivity=True,
                client=self.admin_manager,
                name=data_utils.rand_name('test-server-offload-fip'),
                **self._get_server_extra_args())

            self._offload_test(from_server=from_server, from_port=from_port,
                               to_server=to_server, to_port=to_port)

        def test_diff_hv_switchdev_switchdev_no_port_security(self):

            if len(self.selected_hypervisors) < 2:
                raise self.skipException('at least 2 hypervisors required')

            hv0 = self.selected_hypervisors[0]['hypervisor_hostname']
            hv1 = self.selected_hypervisors[1]['hypervisor_hostname']

            args = dict(self.default_port_args, port_security_enabled=False,
                        security_groups=[])
            from_port = self.create_port(**args)
            to_port = self.create_port(**args)

            self.assertTrue(self.is_offload_capable(from_port))
            self.assertTrue(self.is_offload_capable(to_port))

            to_server = self.create_tenant_server(
                ports=[to_port],
                availability_zone='nova:' + hv1,
                prepare_for_connectivity=True,
                client=self.admin_manager,
                start_web_server=True,
                name=data_utils.rand_name('test-server-offload'),
                **self._get_server_extra_args())

            from_server = self.create_tenant_server(
                ports=[from_port],
                availability_zone='nova:' + hv0,
                prepare_for_connectivity=True,
                client=self.admin_manager,
                name=data_utils.rand_name('test-server-offload-fip'),
                **self._get_server_extra_args())

            self._offload_test(from_server=from_server, from_port=from_port,
                               to_server=to_server, to_port=to_port)


class L3IPv4Connectivity(BaseTestCase.BasicOffloadingTest):
    ip_versions = (4,)
    is_l3 = True


class L3IPv6Connectivity(BaseTestCase.BasicOffloadingTest):
    ip_versions = (6,)
    is_l3 = True


class L2IPv4Connectivity(BaseTestCase.BasicOffloadingTest):
    ip_versions = (4,)
    is_l3 = False


class L2IPv6Connectivity(BaseTestCase.BasicOffloadingTest):
    ip_versions = (6,)
    is_l3 = False


class L3DualStackConnectivity(BaseTestCase.BasicOffloadingTest):
    ip_versions = (4, 6)
    is_l3 = True


class L2DualStackConnectivity(BaseTestCase.BasicOffloadingTest):
    ip_versions = (4, 6)
    is_l3 = False
