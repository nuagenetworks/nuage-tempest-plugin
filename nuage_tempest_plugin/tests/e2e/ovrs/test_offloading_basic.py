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

    @pre OVRS hypervisors

    Check the following behavior:

    | Offloading | VIRTIO-VIRTIO | VIRTIO-SWITCHDEV | SWITCHDEV-SWITCHDEV |
    | :--------: | :-----------: | :--------------: | :-----------------: |
    |  Same HV   |      no       |       no!        |         yes         |
    |  Diff HV   |      no       | yes on switchdev |         yes         |

    Test topology:
      hypervisor 0: 2 virtio + 2 switchdev VMs, reachable with FIP
      hypervisor 1: 1 virtio + 1 switchev VM

    """
    # servers on hypervisor 0
    server_0_0 = None
    server_0_1 = None
    server_0_2 = None
    server_0_3 = None

    # ports for servers on hypervisor 0
    port_virtio_0_0 = None
    port_virtio_0_1 = None
    port_offload_0_0 = None
    port_offload_0_1 = None

    # servers on hypervisor 1
    server_1_0 = None
    server_1_1 = None

    # ports for servers on hypervisor 1
    port_virtio_1_0 = None
    port_offload_1_0 = None

    # all above ports are in a network / subnet attached to below router
    router = None
    network = None

    @classmethod
    def setup_clients(cls):
        super(E2eTestBase, cls).setup_clients()
        cls.hv_client = cls.admin_manager.hypervisor_client

    @classmethod
    def setUpClass(cls):
        super(BasicOffloadingL3Test, cls).setUpClass()

        hypervisors = cls.hv_client.list_hypervisors(
            detail=True)['hypervisors']

        if len(hypervisors) < 2:
            raise cls.skipException('at least 2 hypervisors required')

        cls.selected_hypervisors = random.sample(hypervisors, 2)

    def setUp(self):
        """Setup test topology"""
        super(BasicOffloadingL3Test, self).setUp()

        self.router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.network = self.create_network()
        self.router_attach(self.router, self.create_subnet(self.network))

        default_port_args = dict(network=self.network,
                                 client=self.admin_manager,
                                 port_security_enabled=False)
        virtio_port_args = dict(VIRTIO_ARGS, **default_port_args)

        # ports for servers on hypervisor 0
        self.port_virtio_0_0 = self.create_port(**virtio_port_args)
        self.assertFalse(self.is_offload_capable(self.port_virtio_0_0))

        self.port_virtio_0_1 = self.create_port(**virtio_port_args)
        self.assertFalse(self.is_offload_capable(self.port_virtio_0_1))

        self.port_offload_0_0 = self.create_port(**default_port_args)
        self.assertTrue(self.is_offload_capable(self.port_offload_0_0))

        self.port_offload_0_1 = self.create_port(**default_port_args)
        self.assertTrue(self.is_offload_capable(self.port_offload_0_1))

        # ports for servers on hypervisor 1
        self.port_virtio_1_0 = self.create_port(**virtio_port_args)
        self.assertFalse(self.is_offload_capable(self.port_virtio_1_0))

        self.port_offload_1_0 = self.create_port(**default_port_args)
        self.assertTrue(self.is_offload_capable(self.port_offload_1_0))

        # servers on hypervisor 0
        hv = self.selected_hypervisors[0]['hypervisor_hostname']
        self.server_0_0 = self.create_tenant_server(
            ports=[self.port_virtio_0_0],
            availability_zone='nova:' + hv,
            prepare_for_connectivity=True,
            client=self.admin_manager,
            name=data_utils.rand_name('test-server-virtio-fip'))
        self.server_0_1 = self.create_tenant_server(
            ports=[self.port_virtio_0_1],
            availability_zone='nova:' + hv,
            client=self.admin_manager,
            name=data_utils.rand_name('test-server-virtio'))
        self.server_0_2 = self.create_tenant_server(
            ports=[self.port_offload_0_0],
            availability_zone='nova:' + hv,
            prepare_for_connectivity=True,
            client=self.admin_manager,
            name=data_utils.rand_name('test-server-offload-fip'))
        self.server_0_3 = self.create_tenant_server(
            ports=[self.port_offload_0_1],
            availability_zone='nova:' + hv,
            client=self.admin_manager,
            name=data_utils.rand_name('test-server-offload'))

        # servers on hypervisor 1
        hv = self.selected_hypervisors[1]['hypervisor_hostname']
        self.server_1_0 = self.create_tenant_server(
            ports=[self.port_virtio_1_0],
            availability_zone='nova:' + hv,
            client=self.admin_manager,
            name=data_utils.rand_name('test-server-virtio'))
        self.server_1_1 = self.create_tenant_server(
            ports=[self.port_offload_1_0],
            availability_zone='nova:' + hv,
            client=self.admin_manager,
            name=data_utils.rand_name('test-server-offload'))

    def _offload_test(self, from_server, from_port, to_server, to_port):
        """Send traffic between the servers and analyze ovs flows

        Currently only ICMP traffic is supported

        :param from_server: Server initiating traffic
        :param from_port: Port on that server used for initiating traffic
        :param to_server: Server responding to incoming traffic
        :param to_port: Port on that server used for the traffic
        """

        # TODO(Kris) RHEL image uses cloudinit, no dhcp client will start
        from_server.dhcp_validated = True
        to_server.dhcp_validated = True

        self.assert_icmp_connectivity(from_server=from_server,
                                      to_server=to_server,
                                      network_name=self.network['name'],
                                      ip_version=4)

        flows_hv_0 = self.dump_flows(self.selected_hypervisors[0])
        flows_hv_1 = self.dump_flows(self.selected_hypervisors[1])

        LOG.debug("Flows hypervisor 0:" + flows_hv_0)
        LOG.debug("Flows hypervisor 1:" + flows_hv_1)

        server_0 = from_server.get_server_details()
        server_1 = to_server.get_server_details()
        is_different_hv = (server_0['OS-EXT-SRV-ATTR:hypervisor_hostname'] !=
                           server_1['OS-EXT-SRV-ATTR:hypervisor_hostname'])

        # No offloading for VIRTIO-SWITCHDEV traffic on same hypervisor
        is_offloading_possible = (False if not is_different_hv and
                                  self.is_offload_capable(from_port) !=
                                  self.is_offload_capable(to_port) else True)

        LOG.info('Validating flows on hypervisor 0')
        self._validate_icmp_flows(
            flows_hv_0, from_port, to_port, is_different_hv,
            is_offloading_expected=(self.is_offload_capable(from_port) and
                                    is_offloading_possible))

        if is_different_hv:
            LOG.info('Validating flows on hypervisor 1')
            self._validate_icmp_flows(
                flows_hv_1, to_port, from_port, is_different_hv,
                is_offloading_expected=(self.is_offload_capable(to_port) and
                                        is_offloading_possible))

        # TODO(glenn) send TCP traffic also

    def _validate_icmp_flows(self, flows, from_port, to_port,
                             is_vxlan_tunneled, is_offloading_expected):

        LOG.info('Validate ICMP flow originating from hypervisor')
        self._validate_icmp_flow(FlowQuery(flows).icmp(),
                                 is_vxlan_tunneled,
                                 is_offloading_expected,
                                 to_port, is_originating_from_hv=True)

        LOG.info('Validate ICMP flow arriving at hypervisor')
        self._validate_icmp_flow(FlowQuery(flows).icmp(),
                                 is_vxlan_tunneled,
                                 is_offloading_expected,
                                 from_port, is_originating_from_hv=False)

    def _validate_icmp_flow(self, flow_query, is_vxlan_tunneled,
                            is_offloading_expected,
                            to_port, is_originating_from_hv):
        expected_flows = flow_query.dst_mac(to_port['mac_address'])

        if is_vxlan_tunneled:
            if is_originating_from_hv:
                expected_flows.action_set_tunnel_vxlan()
            else:
                expected_flows.vxlan()

        if is_offloading_expected:
            expected_flows.offload()
        else:
            expected_flows.no_offload()

        msg = ("No icmp traffic found with offload={offload} "
               "and vxlan={vxlan} and dst_mac={dst_mac}"
               .format(offload='yes' if is_offloading_expected else 'no',
                       vxlan='yes' if is_vxlan_tunneled else 'no',
                       dst_mac=to_port['mac_address']))

        self.assertNotEmpty(expected_flows.result(), msg)

    def test_same_hv_switchdev_switchdev(self):
        from_server = self.server_0_2
        from_port = self.port_offload_0_0
        to_server = self.server_0_3
        to_port = self.port_offload_0_1
        self._offload_test(from_server=from_server, from_port=from_port,
                           to_server=to_server, to_port=to_port)

    def test_diff_hv_switchdev_switchdev(self):
        from_server = self.server_0_2
        from_port = self.port_offload_0_0
        to_server = self.server_1_1
        to_port = self.port_offload_1_0

        self._offload_test(from_server=from_server, from_port=from_port,
                           to_server=to_server, to_port=to_port)

    def test_same_hv_virtio_switchdev(self):
        from_server = self.server_0_0
        from_port = self.port_virtio_0_0
        to_server = self.server_0_2
        to_port = self.port_offload_0_0

        self._offload_test(from_server=from_server, from_port=from_port,
                           to_server=to_server, to_port=to_port)

    def test_diff_hv_virtio_switchdev(self):
        from_server = self.server_0_0
        from_port = self.port_virtio_0_0
        to_server = self.server_1_1
        to_port = self.port_offload_1_0

        self._offload_test(from_server=from_server, from_port=from_port,
                           to_server=to_server, to_port=to_port)

    def test_same_hv_virtio_virtio(self):
        from_server = self.server_0_0
        from_port = self.port_virtio_0_0
        to_server = self.server_0_1
        to_port = self.port_virtio_0_1

        self._offload_test(from_server=from_server, from_port=from_port,
                           to_server=to_server, to_port=to_port)

    def test_diff_hv_virtio_virtio(self):
        from_server = self.server_0_0
        from_port = self.port_virtio_0_0
        to_server = self.server_1_0
        to_port = self.port_virtio_1_0

        self._offload_test(from_server=from_server, from_port=from_port,
                           to_server=to_server, to_port=to_port)
