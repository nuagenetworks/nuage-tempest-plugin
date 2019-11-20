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

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils.ovs import FlowQuery
from nuage_tempest_plugin.tests.e2e.e2e_base_test import E2eTestBase


CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)

VIRTIO_ARGS = {'binding:vnic_type': 'normal', 'binding:profile': {}}


class BasicOffloadingL3Test(E2eTestBase):
    """Basic offloading tests

    Check the following behavior:

    | Offloading | VIRTIO-VIRTIO | VIRTIO-SWITCHDEV | SWITCHDEV-SWITCHDEV |
    | :--------: | :-----------: | :--------------: | :-----------------: |
    |  Same HV   |      no       |       no!        |         yes         |
    |  Diff HV   |      no       | yes on switchdev |         yes         |

    """
    router = None
    network = None
    default_port_args = None
    virtio_port_args = None

    @classmethod
    def setup_clients(cls):
        super(E2eTestBase, cls).setup_clients()
        cls.hv_client = cls.admin_manager.hypervisor_client

    @classmethod
    def setUpClass(cls):
        super(BasicOffloadingL3Test, cls).setUpClass()

        hypervisors = cls.hv_client.list_hypervisors(
            detail=True)['hypervisors']

        cls.selected_hypervisors = random.sample(hypervisors,
                                                 min(2, len(hypervisors)))
        if len(cls.selected_hypervisors) < 1:
            raise cls.skipException('at least 1 hypervisors required')

    def setUp(self):
        """Setup test topology"""
        super(BasicOffloadingL3Test, self).setUp()

        # TODO(glenn) remove restart openvswitch VRS-31204
        # for hv in self.selected_hypervisors:
        #     self.restart_openvswitch(hv)

        self.router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.network = self.create_network()
        self.router_attach(self.router, self.create_subnet(self.network))

        self.default_port_args = dict(network=self.network,
                                      client=self.admin_manager,
                                      port_security_enabled=False)
        self.virtio_port_args = dict(VIRTIO_ARGS, **self.default_port_args)

    def dump_flows(self, both_hypervisors):
        flows_hv_0 = (super(BasicOffloadingL3Test, self)
                      .dump_flows(self.selected_hypervisors[0]))
        LOG.debug("Flows hypervisor 0: {}".format(flows_hv_0))

        flows_hv_1 = (super(BasicOffloadingL3Test, self)
                      .dump_flows(self.selected_hypervisors[1])
                      if both_hypervisors else None)
        LOG.debug("Flows hypervisor 1: {}".format(flows_hv_1))

        return flows_hv_0, flows_hv_1

    def _offload_test(self, from_server, from_port, to_server, to_port):
        """Send traffic between the servers and analyze ovs flows

        :param from_server: Server initiating traffic
        :param from_port: Port on that server used for initiating traffic
        :param to_server: Server responding to incoming traffic
        :param to_port: Port on that server used for the traffic
        """

        server_0 = from_server.get_server_details()
        server_1 = to_server.get_server_details()
        is_different_hv = (server_0['OS-EXT-SRV-ATTR:hypervisor_hostname'] !=
                           server_1['OS-EXT-SRV-ATTR:hypervisor_hostname'])

        self.assert_icmp_connectivity(from_server=from_server,
                                      to_server=to_server,
                                      network_name=self.network['name'],
                                      ip_version=4)
        flows_after_icmp = self.dump_flows(is_different_hv)

        self.assert_tcp_connectivity(from_server=from_server,
                                     to_server=to_server,
                                     network_name=self.network['name'],
                                     ip_version=4)
        flows_after_tcp = self.dump_flows(is_different_hv)

        LOG.info('Validating flows on hypervisor 0')
        self._validate_hypervisor_flows(
            flows_after_icmp[0], flows_after_tcp[0],
            from_port, is_different_hv, to_port)

        if is_different_hv:
            LOG.info('Validating flows on hypervisor 1')

        # from_port and to_port are switched now since
        # naming is from the perspective of the VM initiating traffic
        index = 1 if is_different_hv else 0
        self._validate_hypervisor_flows(
            flows_after_icmp[index], flows_after_tcp[index], to_port,
            is_different_hv, from_port)

    def _validate_hypervisor_flows(self, flows_after_icmp, flows_after_tcp,
                                   from_port, is_different_hv, to_port):
        # No offloading for VIRTIO-SWITCHDEV traffic on same hypervisor
        is_offloading_possible = (is_different_hv or
                                  self.is_offload_capable(from_port) ==
                                  self.is_offload_capable(to_port))
        is_offloading_expected = (is_offloading_possible and
                                  self.is_offload_capable(from_port))

        LOG.debug("Validating ICMP flows")
        self._validate_flow_pair(FlowQuery(flows_after_icmp).icmp().result(),
                                 from_port, to_port,
                                 is_different_hv, is_offloading_expected)

        LOG.debug("Validating TCP flows")
        self._validate_flow_pair(FlowQuery(flows_after_tcp).tcp().result(),
                                 from_port, to_port,
                                 is_different_hv, is_offloading_expected)

    def _validate_flow_pair(self, flows, from_port, to_port,
                            is_vxlan_tunneled, is_offloading_expected):

        LOG.info('Validate flow originating from hypervisor')
        self._validate_flow(flows,
                            is_vxlan_tunneled,
                            is_offloading_expected,
                            to_port, is_originating_from_hv=True)

        LOG.info('Validate flow arriving at hypervisor')
        self._validate_flow(flows,
                            is_vxlan_tunneled,
                            is_offloading_expected,
                            from_port, is_originating_from_hv=False)

    def _validate_flow(self, flows, is_vxlan_tunneled,
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

    def test_same_hv_switchdev_switchdev(self):
        hv = self.selected_hypervisors[0]['hypervisor_hostname']

        from_port = self.create_port(**self.default_port_args)
        to_port = self.create_port(**self.default_port_args)

        self.assertTrue(self.is_offload_capable(from_port))
        self.assertTrue(self.is_offload_capable(to_port))

        to_server = self.create_tenant_server(
            ports=[to_port],
            availability_zone='nova:' + hv,
            client=self.admin_manager,
            start_web_server=True,
            name=data_utils.rand_name('test-server-offload'))

        from_server = self.create_tenant_server(
            ports=[from_port],
            availability_zone='nova:' + hv,
            prepare_for_connectivity=True,
            client=self.admin_manager,
            name=data_utils.rand_name('test-server-offload-fip'))

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
            client=self.admin_manager,
            start_web_server=True,
            name=data_utils.rand_name('test-server-offload'))

        from_server = self.create_tenant_server(
            ports=[from_port],
            availability_zone='nova:' + hv0,
            prepare_for_connectivity=True,
            client=self.admin_manager,
            name=data_utils.rand_name('test-server-offload-fip'))

        self._offload_test(from_server=from_server, from_port=from_port,
                           to_server=to_server, to_port=to_port)

    def test_same_hv_virtio_switchdev(self):
        hv = self.selected_hypervisors[0]['hypervisor_hostname']

        from_port = self.create_port(**self.virtio_port_args)
        to_port = self.create_port(**self.default_port_args)

        self.assertFalse(self.is_offload_capable(from_port))
        self.assertTrue(self.is_offload_capable(to_port))

        to_server = self.create_tenant_server(
            ports=[to_port],
            availability_zone='nova:' + hv,
            client=self.admin_manager,
            start_web_server=True,
            name=data_utils.rand_name('test-server-offload'))

        from_server = self.create_tenant_server(
            ports=[from_port],
            availability_zone='nova:' + hv,
            prepare_for_connectivity=True,
            client=self.admin_manager,
            name=data_utils.rand_name('test-server-offload-fip'))

        self._offload_test(from_server=from_server, from_port=from_port,
                           to_server=to_server, to_port=to_port)

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
            client=self.admin_manager,
            start_web_server=True,
            name=data_utils.rand_name('test-server-offload'))

        from_server = self.create_tenant_server(
            ports=[from_port],
            availability_zone='nova:' + hv0,
            prepare_for_connectivity=True,
            client=self.admin_manager,
            name=data_utils.rand_name('test-server-offload-fip'))

        self._offload_test(from_server=from_server, from_port=from_port,
                           to_server=to_server, to_port=to_port)

    def test_same_hv_virtio_virtio(self):
        hv = self.selected_hypervisors[0]['hypervisor_hostname']

        from_port = self.create_port(**self.virtio_port_args)
        to_port = self.create_port(**self.virtio_port_args)

        self.assertFalse(self.is_offload_capable(from_port))
        self.assertFalse(self.is_offload_capable(to_port))

        to_server = self.create_tenant_server(
            ports=[to_port],
            availability_zone='nova:' + hv,
            client=self.admin_manager,
            start_web_server=True,
            name=data_utils.rand_name('test-server-offload'))

        from_server = self.create_tenant_server(
            ports=[from_port],
            availability_zone='nova:' + hv,
            prepare_for_connectivity=True,
            client=self.admin_manager,
            name=data_utils.rand_name('test-server-offload-fip'))

        self._offload_test(from_server=from_server, from_port=from_port,
                           to_server=to_server, to_port=to_port)

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
            client=self.admin_manager,
            start_web_server=True,
            name=data_utils.rand_name('test-server-offload'))

        from_server = self.create_tenant_server(
            ports=[from_port],
            availability_zone='nova:' + hv0,
            prepare_for_connectivity=True,
            client=self.admin_manager,
            name=data_utils.rand_name('test-server-offload-fip'))

        self._offload_test(from_server=from_server, from_port=from_port,
                           to_server=to_server, to_port=to_port)

    def test_diff_hv_switchdev_switchdev_extra_servers(self):

        if len(self.selected_hypervisors) < 2:
            raise self.skipException('at least 2 hypervisors required')

        hv0 = self.selected_hypervisors[0]['hypervisor_hostname']
        hv1 = self.selected_hypervisors[1]['hypervisor_hostname']

        from_port = self.create_port(**self.default_port_args)
        to_port = self.create_port(**self.default_port_args)
        extra_port = self.create_port(**self.virtio_port_args)

        self.assertTrue(self.is_offload_capable(from_port))
        self.assertTrue(self.is_offload_capable(to_port))
        self.assertFalse(self.is_offload_capable(extra_port))

        self.create_tenant_server(
            ports=[extra_port],
            availability_zone='nova:' + hv0,
            client=self.admin_manager,
            name=data_utils.rand_name('test-server-virtio-extra'))

        to_server = self.create_tenant_server(
            ports=[to_port],
            availability_zone='nova:' + hv1,
            client=self.admin_manager,
            start_web_server=True,
            name=data_utils.rand_name('test-server-offload'))

        from_server = self.create_tenant_server(
            ports=[from_port],
            availability_zone='nova:' + hv0,
            prepare_for_connectivity=True,
            client=self.admin_manager,
            name=data_utils.rand_name('test-server-offload-fip'))

        self._offload_test(from_server=from_server, from_port=from_port,
                           to_server=to_server, to_port=to_port)
