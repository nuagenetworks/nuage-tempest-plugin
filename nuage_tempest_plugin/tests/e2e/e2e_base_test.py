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
import abc

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils as utils
from tempest.lib.common.utils import data_utils

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)
VIRTIO_ARGS = {'binding:vnic_type': 'normal', 'binding:profile': {}}


class E2eTestBase(NuageBaseTest):
    # defaults
    IP_VERSIONS_V4 = (4,)
    IP_VERSIONS_V6 = (6,)
    IP_VERSIONS_DUALSTACK = (4, 6)
    hypervisors = None
    is_icmpv6_offload_supported = False  # limitation of CX-5 at the moment
    is_same_subnet = True  # Whether to do cross-subnet connectivity test
    is_l3 = True  # Whether to test L3- or L2 connectivity
    ip_versions = IP_VERSIONS_DUALSTACK  # Which IP versions to use for tests
    default_port_args = None  # Arguments for create_port (first VM, second VM)
    virtio_port_args = None  # Arguments for create_port VIRTIO (first, second)

    """Base test class for end-to-end tests"""

    @classmethod
    def setup_clients(cls):
        super(E2eTestBase, cls).setup_clients()
        cls.hv_client = cls.admin_manager.hypervisor_client

    @classmethod
    def setUpClass(cls):
        super(E2eTestBase, cls).setUpClass()

    def setUp(self):
        """Setup test topology"""
        super(E2eTestBase, self).setUp()

        self._skip_checks()

        # Router for L3 tests
        router = (self.create_router(
            external_network_id=self.ext_net_id, manager=self.admin_manager)
            if self.is_l3 else None)

        # For cross-subnet tests, each subnet resides in its own network
        self.networks = [self._build_net_topology(router)]
        self.networks.append(self.networks[0] if self.is_same_subnet
                             else self._build_net_topology(router))

        sg = self.create_open_ssh_security_group(
            manager=self.admin_manager)

        for ip_version in self.ip_versions:
            self.create_tcp_rule(sg, direction='ingress',
                                 ip_version=ip_version,
                                 manager=self.admin_manager)
            self.create_tcp_rule(sg, direction='egress',
                                 ip_version=ip_version,
                                 manager=self.admin_manager)

        self.default_port_args = [dict(network=network[0],
                                       manager=self.admin_manager,
                                       security_groups=[sg['id']])
                                  for network in self.networks]
        self.virtio_port_args = [dict(VIRTIO_ARGS, **args)
                                 for args in self.default_port_args]

    def _skip_checks(self):
        """Raise skip exception if needed"""
        if len(self.selected_hypervisors) < 1:
            raise self.skipException('At least 1 hypervisor required')

        if not self.is_l3 and not self.is_same_subnet:
            raise self.skipException('No connectivity in this case. '
                                     'A negative test could be added later.')

    def _build_net_topology(self, router=None):
        network = self.create_network(manager=self.admin_manager)
        gateway_mac_address = None
        # Creates either single stack IPv4 / IPv6 or dualstack networks
        for ip_version in self.ip_versions:
            subnet = self.create_subnet(
                network,
                cidr=utils.gimme_a_cidr(ip_version),
                ip_version=ip_version,
                manager=self.admin_manager)
            if router:
                self.router_attach(router, subnet, manager=self.admin_manager)
                vspk_subnet = self.vsd.get_subnet(
                    by_network_id=network['id'], cidr=subnet['cidr'])
                # gateway mac is the same for IPv4/6 in dualstack network
                gateway_mac_address = vspk_subnet.gateway_mac_address
        return network, gateway_mac_address

    @classmethod
    def get_hypervisors(cls):
        if not cls.hypervisors:
            cls.hypervisors = cls.hv_client.list_hypervisors(
                detail=True)['hypervisors']
        return cls.hypervisors

    @classmethod
    def get_hypervisor(cls, server):
        server = server.get_server_details()
        return next(
            hv for hv in cls.get_hypervisors()
            if (hv['hypervisor_hostname'] ==
                server['OS-EXT-SRV-ATTR:hypervisor_hostname']))

    @abc.abstractmethod
    def dump_flows(self, hypervisor):
        """Dump flows on hypervisor"""
        pass

    def restart_openvswitch(self, hypervisor):
        cmd = ('ssh heat-admin@{host_ip} "sudo service openvswitch restart"'
               .format(host_ip=hypervisor['host_ip']))
        return self.execute_from_shell(cmd)

    def restart_avrs(self, hypervisor):
        cmd = ('ssh heat-admin@{host_ip} "sudo service avrs restart"'
               .format(host_ip=hypervisor['host_ip']))
        return self.execute_from_shell(cmd)

    def _get_server_extra_args(self):
        """Force config drive for L2 to work around metadata agent issue"""
        args = {}
        if not self.is_l3:
            args['config_drive'] = True
        return args

    def _offload_test(self, from_server, from_port, to_server, to_port,
                      destination_network):
        """Send traffic between the servers and analyze ovs flows

        :param from_server: Server initiating traffic
        :param from_port: Port on that server used for initiating traffic
        :param to_server: Server responding to incoming traffic
        :param to_port: Port on that server used for the traffic
        """
        from_hv = self.get_hypervisor(from_server)
        to_hv = self.get_hypervisor(to_server)

        for ip_version in self.ip_versions:
            kwargs = dict(from_server=from_server, to_server=to_server,
                          network_name=destination_network['name'],
                          ip_version=ip_version)

            LOG.info('Verify TCP/IPv{} traffic'.format(ip_version))
            self.assert_tcp_connectivity(**kwargs)
            self.validate_flows(self._validate_tcp_offloading, from_hv, to_hv,
                                from_port, to_port, ip_version)

            LOG.info('Verify ICMP/IPv{} traffic'.format(ip_version))
            self.assert_icmp_connectivity(**kwargs)
            self.validate_flows(self._validate_icmp_offloading, from_hv, to_hv,
                                from_port, to_port, ip_version)

    def validate_flows(self, flow_validator, from_hv, to_hv, from_port,
                       to_port, ip_version):
        # Note that flows will expire after some time, don't add any
        # api calls other other time intensive operations here

        is_cross_hv = from_hv['id'] != to_hv['id']
        gateway_mac_src_subnet = self.networks[0][1]
        gateway_mac_dst_subnet = self.networks[1][1]

        flows = self.dump_flows(from_hv)
        flow_validator(
            flows, from_port, is_cross_hv, to_port, ip_version,
            gateway_mac_src_subnet)

        if is_cross_hv:
            flows = self.dump_flows(to_hv)
            flow_validator(
                flows, to_port, is_cross_hv, from_port,
                ip_version, gateway_mac_dst_subnet)

    def _validate_tcp_offloading(self, flows, from_port, is_cross_hv,
                                 to_port, ip_version, gateway_mac_src_subnet):

        filtered_flows = flows.ip_version(ip_version)

        if from_port['port_security_enabled']:
            filtered_flows.tcp()
        else:
            # VRS-33651: VRS is is wildly inconsistent
            if (self.is_l3 and self.ip_versions != self.IP_VERSIONS_V6 and
                    self.is_same_subnet):
                filtered_flows.wildcard_protocol()
            else:
                filtered_flows.tcp()

        self._validate_offloading(
            filtered_flows, from_port, is_cross_hv, to_port,
            gateway_mac_src_subnet)

    def _validate_offloading(self, flows, from_port, is_different_hv,
                             to_port, gateway_mac_src_subnet):
        is_offloading_expected = self._is_offloading_expected(
            from_port, to_port, is_different_hv)

        LOG.info('Validate flow originating from hypervisor')
        flows.reset()
        self._validate_offloaded_flow(
            flows, is_different_hv, is_offloading_expected,
            dst_mac=(to_port['mac_address'] if self.is_same_subnet
                     else gateway_mac_src_subnet),
            is_originating_from_hv=True)

        LOG.info('Validate flow arriving at hypervisor')
        flows.reset()
        self._validate_offloaded_flow(
            flows, is_different_hv, is_offloading_expected,
            dst_mac=from_port['mac_address'], is_originating_from_hv=False)

    def _validate_icmp_offloading(self, flows, from_port, is_cross_hv,
                                  to_port, ip_version, gateway_mac_src_subnet):

        if ip_version == 6 and not self.is_icmpv6_offload_supported:
            LOG.info('skipping ICMPv6 offloading checks as they are not '
                     'supported by CX-5')
            return

        filtered_flows = flows.ip_version(ip_version)

        if from_port['port_security_enabled']:
            filtered_flows.icmp()
        else:
            # VRS-33651: VRS is wildly inconsistent
            if (self.is_l3 and self.ip_versions != self.IP_VERSIONS_V6 and
                    self.is_same_subnet):
                filtered_flows.wildcard_protocol()
            else:
                filtered_flows.icmp()
        self._validate_offloading(
            filtered_flows, from_port, is_cross_hv, to_port,
            gateway_mac_src_subnet)

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

    def _validate_offloaded_flow(self, flows, is_vxlan_tunneled,
                                 is_offloading_expected,
                                 dst_mac, is_originating_from_hv):
        expected_flows = flows.dst_mac(dst_mac)

        if is_offloading_expected:
            expected_flows.offload()
        else:
            expected_flows.no_offload()

        msg = ("No traffic found with with offload={offload} and "
               "dst_mac={dst_mac}"
               .format(offload='yes' if is_offloading_expected else 'no',
                       dst_mac=dst_mac))
        self.assertNotEmpty(expected_flows.result(), msg)

        if is_vxlan_tunneled:
            if is_originating_from_hv:
                expected_flows.action_set_tunnel_vxlan()
            else:
                expected_flows.vxlan()

        msg = ("No traffic found with offload={offload} "
               "and vxlan={vxlan} and dst_mac={dst_mac}"
               .format(offload='yes' if is_offloading_expected else 'no',
                       vxlan='yes' if is_vxlan_tunneled else 'no',
                       dst_mac=dst_mac))

        self.assertNotEmpty(expected_flows.result(), msg)

    def _test_same_hv_virtio_virtio(self):
        hv = self.selected_hypervisors[0]['hypervisor_hostname']

        from_port = self.create_port(**self.virtio_port_args[0])
        to_port = self.create_port(**self.virtio_port_args[1])

        self.assertFalse(self.is_offload_capable(from_port))
        self.assertFalse(self.is_offload_capable(to_port))

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

    def _test_diff_hv_virtio_virtio(self):

        if len(self.selected_hypervisors) < 2:
            raise self.skipException('at least 2 hypervisors required')

        hv0 = self.selected_hypervisors[0]['hypervisor_hostname']
        hv1 = self.selected_hypervisors[1]['hypervisor_hostname']

        from_port = self.create_port(**self.virtio_port_args[0])
        to_port = self.create_port(**self.virtio_port_args[1])

        self.assertFalse(self.is_offload_capable(from_port))
        self.assertFalse(self.is_offload_capable(to_port))

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
