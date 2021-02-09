# Copyright 2016 Red Hat, Inc., 2020 NOKIA
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
import testtools
import time

from oslo_log import log
from tempest.common import utils
from tempest.common import waiters
from tempest.test import decorators

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.tests.scenario.qos import base_nuage_qos

CONF = Topology.get_conf()

LOG = log.getLogger(__name__)


class NuageFloatingIPProprietaryQosTest(base_nuage_qos.NuageQosTestmixin,
                                        nuage_test.NuageBaseTest):
    same_network = True

    @classmethod
    @utils.requires_ext(extension='router', service='network')
    def resource_setup(cls):
        super(NuageFloatingIPProprietaryQosTest, cls).resource_setup()

    @testtools.skipIf(
        not CONF.nuage_feature_enabled.proprietary_fip_rate_limiting,
        'Support for fip rate limiting required')
    @decorators.attr(type='smoke')
    def test_nuage_fip_rate_limit(self):
        """test_nuage_fip_rate_limit

           Test floating IP with ingress and egress bandwidth limiting enabled
           by sending a file from the instance to the test node.
           Then calculating the bandwidth every ~1 sec by the number of bits
           received / elapsed time.
        """

        network = self.create_network()
        subnet4 = self.create_subnet(network=network)
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.router_attach(router, subnet4)

        # Ensure TCP traffic is allowed
        security_group = self.create_open_ssh_security_group()
        self.create_traffic_sg_rule(security_group,
                                    direction='ingress',
                                    ip_version=4,
                                    dest_port=self.DEST_PORT)

        server = self.create_tenant_server(
            networks=[network], security_groups=[security_group],
            prepare_for_connectivity=True)
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        egress_kbps = 1500
        ingress_kbps = 2000
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=egress_kbps,
            nuage_ingress_fip_rate_kbps=ingress_kbps)

        self._test_bandwidth(server, egress_bw=egress_kbps,
                             ingress_bw=ingress_kbps,
                             test_msg='original Fip.')

        # Update floating ip QOS to new value
        egress_kbps = 1200
        ingress_kbps = 1400
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=egress_kbps,
            nuage_ingress_fip_rate_kbps=ingress_kbps)

        self._test_bandwidth(server, egress_bw=egress_kbps,
                             ingress_bw=ingress_kbps,
                             test_msg='updated Fip.')

    @testtools.skipIf(
        not CONF.nuage_feature_enabled.proprietary_fip_rate_limiting,
        'Support for fip rate limiting required')
    def test_nuage_fip_rate_limit_reboot(self):
        """test_nuage_fip_rate_limit_reboot

           Test floating IP with ingress and egress bandwidth limiting enabled
           by sending a file from the instance to the test node.
           Then calculating the bandwidth every ~1 sec by the number of bits
           received / elapsed time.
           Specifically testing that after reboot of VM QOS rate is maintained.
        """

        network = self.create_network()
        subnet4 = self.create_subnet(network=network)
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.router_attach(router, subnet4)

        # Ensure TCP traffic is allowed
        security_group = self.create_open_ssh_security_group()
        self.create_traffic_sg_rule(security_group,
                                    direction='ingress',
                                    ip_version=4,
                                    dest_port=self.DEST_PORT)

        server = self.create_tenant_server(
            networks=[network], security_groups=[security_group],
            prepare_for_connectivity=True)
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        egress_kbps = 1500
        ingress_kbps = 2000
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=egress_kbps,
            nuage_ingress_fip_rate_kbps=ingress_kbps)

        self._test_bandwidth(server, egress_bw=egress_kbps,
                             ingress_bw=ingress_kbps,
                             test_msg='original Fip.')

        # reboot server
        self.manager.servers_client.reboot_server(server.id, type='HARD')
        waiters.wait_for_server_status(self.manager.servers_client, server.id,
                                       'ACTIVE')
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        self._test_bandwidth(server, egress_bw=egress_kbps,
                             ingress_bw=ingress_kbps,
                             test_msg='original Fip after reboot.')

        # Update floating ip QOS to new value
        egress_kbps = 1200
        ingress_kbps = 1400
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=egress_kbps,
            nuage_ingress_fip_rate_kbps=ingress_kbps)

        self._test_bandwidth(server, egress_bw=egress_kbps,
                             ingress_bw=ingress_kbps,
                             test_msg='updated Fip.')

        # reboot server
        self.manager.servers_client.reboot_server(server.id, type='HARD')
        waiters.wait_for_server_status(self.manager.servers_client,
                                       server.id,
                                       'ACTIVE')
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        self._test_bandwidth(server, egress_bw=egress_kbps,
                             ingress_bw=ingress_kbps,
                             test_msg='updated Fip after reboot.')

    @testtools.skipIf(
        not CONF.nuage_feature_enabled.proprietary_fip_rate_limiting,
        'Support for fip rate limiting required')
    def test_nuage_fip_rate_limit_multivm(self):
        """test_nuage_fip_rate_limit_multivm

           Test floating IP with ingress and egress bandwidth limiting enabled
           by sending a file from the instance to the test node.
           Enable multiple VMs with a rate limit, to make sure subsequent VMs
           do not get stuck at one specific rate.
        """

        network = self.create_network()
        subnet4 = self.create_subnet(network=network)
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.router_attach(router, subnet4)

        # Ensure TCP traffic is allowed
        security_group = self.create_open_ssh_security_group()
        self.create_traffic_sg_rule(security_group,
                                    direction='ingress',
                                    ip_version=4,
                                    dest_port=self.DEST_PORT)
        server = self.create_tenant_server(
            networks=[network], security_groups=[security_group],
            prepare_for_connectivity=True)
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        egress_kbps = 1500
        ingress_kbps = 2000
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=egress_kbps,
            nuage_ingress_fip_rate_kbps=ingress_kbps)

        self._test_bandwidth(server, egress_bw=egress_kbps,
                             ingress_bw=ingress_kbps,
                             test_msg='original Fip.')

        self.delete_server(server.id)
        server2 = self.create_tenant_server(
            networks=[network], security_groups=[security_group],
            prepare_for_connectivity=True)
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server2.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        egress_kbps = 2000
        ingress_kbps = 2500
        self.update_floatingip(
            server2.associated_fip,
            nuage_egress_fip_rate_kbps=egress_kbps,
            nuage_ingress_fip_rate_kbps=ingress_kbps)

        self._test_bandwidth(server2, egress_bw=egress_kbps,
                             ingress_bw=ingress_kbps,
                             test_msg='Updated Fip.')


class RateLimitingNuageQosScenarioTest(base_nuage_qos.NuageQosTestmixin,
                                       nuage_test.NuageBaseTest):

    @classmethod
    @utils.requires_ext(extension='qos', service='network')
    def resource_setup(cls):
        super(RateLimitingNuageQosScenarioTest, cls).resource_setup()

    def test_qos_basic_and_update(self):
        """This test covers both:

            1) Basic QoS functionality
            This is a basic test that check that a QoS policy with
            a bandwidth limit rule is applied correctly by sending
            a file from the instance to the test node.
            Then calculating the bandwidth every ~1 sec by the number of bits
            received / elapsed time.

            2) Update QoS policy
            Administrator has the ability to update existing QoS policy,
            this test is planned to verify that:
            - actual BW is affected as expected after updating QoS policy.
            Test scenario:
            1) Associating QoS Policy with 'Original_bandwidth'
               to the test node
            2) BW validation - by downloading file on test node.
               ('Original_bandwidth' is expected)
            3) Updating existing QoS Policy to a new BW value
               'Updated_bandwidth'
            4) BW validation - by downloading file on test node.
               ('Updated_bandwidth' is expected)
            Note:
            There are two options to associate QoS policy to VM:
            'Neutron Port' or 'Network', in this test
            both options are covered.
        """
        if 'bandwidth_limit' not in self.list_qos_rule_types():
            self.skipTest('bandwidth_limit rule type is required.')
        BW_LIMIT_NETWORK = 2000
        BW_LIMIT_UPDATE_NETWORK = 3000
        BW_LIMIT_PORT = 2000
        BW_LIMIT_UPDATE_PORT = 4000

        network = self.create_network()
        subnet4 = self.create_subnet(network=network)
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.router_attach(router, subnet4)

        # Ensure TCP traffic is allowed
        security_group = self.create_open_ssh_security_group()
        self.create_traffic_sg_rule(security_group,
                                    direction='ingress',
                                    ip_version=4,
                                    dest_port=self.DEST_PORT)

        server = self.create_tenant_server(
            networks=[network], security_groups=[security_group],
            prepare_for_connectivity=True)
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        bw_limit_policy_id = self.create_qos_policy()['id']
        rule_id = self.create_qos_bandwidth_limit_rule(
            qos_policy_id=bw_limit_policy_id,
            max_kbps=BW_LIMIT_NETWORK,
            max_burst_kbps=BW_LIMIT_NETWORK)['id']

        # Assign QOS policy to network
        self.update_network(network['id'], qos_policy_id=bw_limit_policy_id,
                            manager=self.admin_manager)
        self.addCleanup(self.update_network, network['id'],
                        manager=self.admin_manager, qos_policy_id=None)

        self._test_bandwidth(server, egress_bw=BW_LIMIT_NETWORK,
                             test_msg='QOS policy assigned to network.')

        # update active QOS policy
        self.update_qos_bandwidth_limit_rule(
            bw_limit_policy_id, rule_id, max_kbps=BW_LIMIT_UPDATE_NETWORK,
            max_burst_kbps=BW_LIMIT_UPDATE_NETWORK)

        self._test_bandwidth(server, egress_bw=BW_LIMIT_UPDATE_NETWORK,
                             test_msg='updated QOS policy assigned '
                                      'to network.')

        # Set QOS policy on Port
        port = server.get_server_port_in_network(network)
        new_bw_limit_policy_id = self.create_qos_policy()['id']
        new_rule_id = self.create_qos_bandwidth_limit_rule(
            qos_policy_id=new_bw_limit_policy_id,
            max_kbps=BW_LIMIT_PORT,
            max_burst_kbps=BW_LIMIT_PORT)['id']
        self.update_port(port, qos_policy_id=new_bw_limit_policy_id,
                         manager=self.admin_manager)
        self.addCleanup(self.update_port, port,
                        manager=self.admin_manager,
                        qos_policy_id=None)

        self._test_bandwidth(server, egress_bw=BW_LIMIT_PORT,
                             test_msg='QOS policy assigned to port.')

        # update active QOS policy
        self.update_qos_bandwidth_limit_rule(
            new_bw_limit_policy_id, new_rule_id, max_kbps=BW_LIMIT_UPDATE_PORT,
            max_burst_kbps=BW_LIMIT_UPDATE_PORT)

        self._test_bandwidth(server, egress_bw=BW_LIMIT_UPDATE_PORT,
                             test_msg='Updaed QOS policy assigned to port.')

        # Delete QOS policy on port
        self.update_port(port, manager=self.admin_manager, qos_policy_id=None)

        self._test_bandwidth(server, egress_bw=BW_LIMIT_UPDATE_NETWORK,
                             test_msg='Network QOS policy after delete of '
                                      'policy on port.')

    @testtools.skipIf(
        not CONF.nuage_feature_enabled.proprietary_fip_rate_limiting,
        'Support for fip rate limiting required')
    def test_nuage_qos_fip_rate_limiting(self):
        """test_nuage_qos_fip_rate_limiting

        Test bandwidth when attaching both network/vport rate limiting and
        fip rate limiting to an instance.

        """
        if 'bandwidth_limit' not in self.list_qos_rule_types():
            self.skipTest('bandwidth_limit rule type is required.')

        BW_LIMIT_NETWORK = 2000
        BW_LIMIT_PORT = 1600
        BW_LIMIT_FIP = 1400
        BW_LIMIT_UPDATE_PORT = 1200

        network = self.create_network()
        subnet4 = self.create_subnet(network=network)
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.router_attach(router, subnet4)

        # Ensure TCP traffic is allowed
        security_group = self.create_open_ssh_security_group()
        self.create_traffic_sg_rule(security_group,
                                    direction='ingress',
                                    ip_version=4,
                                    dest_port=self.DEST_PORT)

        server = self.create_tenant_server(
            networks=[network], security_groups=[security_group],
            prepare_for_connectivity=True)
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        # Create QoS policy
        bw_limit_policy_id = self.create_qos_policy()['id']
        self.create_qos_bandwidth_limit_rule(
            qos_policy_id=bw_limit_policy_id,
            max_kbps=BW_LIMIT_NETWORK,
            max_burst_kbps=BW_LIMIT_NETWORK)

        # Assign QOS policy to network
        self.update_network(network['id'], qos_policy_id=bw_limit_policy_id,
                            manager=self.admin_manager)
        self.addCleanup(self.update_network, network['id'],
                        manager=self.admin_manager, qos_policy_id=None)

        # Check bw limited at network policy level
        self._test_bandwidth(server, egress_bw=BW_LIMIT_NETWORK,
                             test_msg='QOS policy assigned to network.')

        self.update_floatingip(server.associated_fip,
                               nuage_egress_fip_rate_kbps=BW_LIMIT_FIP)

        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP,
                             test_msg='Fip Rate limit active.')

        # Create a new QoS policy
        port = server.get_server_port_in_network(network)
        new_bw_limit_policy_id = self.create_qos_policy()['id']
        new_rule_id = self.create_qos_bandwidth_limit_rule(
            qos_policy_id=new_bw_limit_policy_id,
            max_kbps=BW_LIMIT_PORT,
            max_burst_kbps=BW_LIMIT_PORT)['id']
        self.update_port(port, qos_policy_id=new_bw_limit_policy_id,
                         manager=self.admin_manager)
        self.addCleanup(self.update_port, port,
                        manager=self.admin_manager,
                        qos_policy_id=None)

        # BW limit of the port is higher than that of the FIP
        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP,
                             test_msg='QOS policy assigned to port.')

        # Update QOS policy so BW of port < BW of FIP
        self.update_qos_bandwidth_limit_rule(
            new_bw_limit_policy_id, new_rule_id, max_kbps=BW_LIMIT_UPDATE_PORT,
            max_burst_kbps=BW_LIMIT_UPDATE_PORT)

        self._test_bandwidth(server, egress_bw=BW_LIMIT_UPDATE_PORT,
                             test_msg='updated QOS policy assigned to port.')

        # Delete network and port qos, expect fip QOS still active
        self.update_network(network['id'], manager=self.admin_manager,
                            qos_policy_id=None)
        self.update_port(port, manager=self.admin_manager,
                         qos_policy_id=None)

        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP,
                             test_msg='only FIP rate limiting active.')


class QoSDscpTest(nuage_test.NuageBaseTest, base_nuage_qos.NuageQosTestmixin):
    FILE_PATH = '/tmp/dscptest'
    DSCP_MARK = 10
    UPDATED_DSCP_MARK = 12

    @classmethod
    @utils.requires_ext(extension='qos', service='network')
    def resource_setup(cls):
        super(QoSDscpTest, cls).resource_setup()

    def tcpdump_run(self, server, protocol, ip_version, source_ip):
        """Create tcpdump listener for protocol traffic.

        Listener is created always on remote host.
        """
        tcpdump_cmd = 'src {} and '.format(source_ip)
        if protocol == 'icmp' and ip_version == 4:
            tcpdump_cmd += 'icmp[0]==8 '
        elif protocol == 'icmp' and ip_version == 6:
            tcpdump_cmd += 'icmp6 and ip6[40] == 128'
        else:
            tcpdump_cmd += protocol
        server.send(
            'sudo /usr/sbin/tcpdump -vvv {tcpdump_cmd} '
            '-c 1 &> {file} &'.format(
                tcpdump_cmd=tcpdump_cmd, file=self.FILE_PATH),
            one_off_attempt=True)

    def _check_dscp_marking(self, server_from, server_to,
                            expected_dscp_mark=DSCP_MARK):
        # Check DSCP marking for (icmp, tcp, udp) x (ipv4, ipv6)
        failures = []
        for protocol in ['icmp', 'tcp', 'udp']:
            for ip_version in [4, 6]:
                # Kill tcpdump process & delete result file
                self.kill_process(server_to, 'tcpdump')
                cmd = 'sudo rm {}'.format(self.FILE_PATH)
                server_to.send(cmd, one_off_attempt=True)
                # Run tcpdump process
                source = server_from.get_server_ips(
                    filter_by_ip_version=ip_version)[0][0]
                self.tcpdump_run(server_to, protocol, ip_version, source)

                # Run traffic
                destination = server_to.get_server_ips(
                    filter_by_ip_version=ip_version)[0][0]
                if protocol == 'icmp':
                    server_from.ping(destination=destination)
                else:
                    # Provision server
                    self.nc_run(server_to, self.DEST_PORT, 'ingress',
                                protocol=protocol)
                    udp = '-u' if protocol == 'udp' else ''
                    send_cmd = ("echo -n 'HELLO' | "
                                "nc -w 1 {udp} {dest} {port}").format(
                        udp=udp, dest=destination, port=self.DEST_PORT)
                    server_from.send(send_cmd, one_off_attempt=True)

                # Wait for tcpdump to flush to file.
                time.sleep(1)
                ts_header = hex(expected_dscp_mark << 2)
                # Validate remote file
                tcpdump_output = server_to.send(
                    'cat {}'.format(self.FILE_PATH), one_off_attempt=True)
                if ts_header not in tcpdump_output:
                    msg = (
                        'Failed to detect DSCP mark {} for '
                        'protocol {}, ip_version {}.'.format(
                            expected_dscp_mark, protocol, ip_version))
                    LOG.error(msg)
                    failures.append(msg)
                else:
                    LOG.debug(
                        'Succesfully detected DSCP mark {} for '
                        'protocol {}, ip_version {}.'.format(
                            expected_dscp_mark, protocol, ip_version))
        if failures:
            self.fail('\n'.join(failures))

    def test_dscp_marking_basic_and_update(self):
        """This test covers both:

            1) Basic QoS DSCP functionality
            This is a basic test that check that a QoS policy with
            a DSCP marking rule is applied correctly by sending traffic from
            one node to the other.
            Using tcpdump the DSCP mark is verified when packets arrive
            at the 'to' host from the host with the policy enabled.
            - icmp traffic
            - tcp traffic
            - udp traffic
            For ipv4 and ipv6

            2) Update QoS policy
            Administrator has the ability to update existing QoS policy,
            this test is planned to verify that:
            - actual DSCP mark is affected as expected
              after updating QoS policy.
            Test scenario:
            1) Associating QoS Policy with 'original DSCP mark'
               to the test node
            2) DSCP mark validation
            3) Updating existing QoS Policy to a new DSCP mark
            4) DSCP mark validation
            Note:
            There are two options to associate QoS policy to VM:
            'Neutron Port' or 'Network', in this test
            both options are covered.
        """

        # Setup resources
        network = self.create_network()
        subnet4 = self.create_subnet(network=network)
        subnet6 = self.create_subnet(network=network, ip_version=6)
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.router_attach(router, subnet4)
        self.router_attach(router, subnet6)

        # Ensure ICMP/SSH/UDP/TCP traffic is allowed
        security_group = self.create_open_ssh_security_group()
        for ip_version in [4, 6]:
            for protocol in ['udp', 'tcp']:
                self.create_traffic_sg_rule(security_group,
                                            direction='ingress',
                                            protocol=protocol,
                                            ip_version=ip_version,
                                            dest_port=self.DEST_PORT)

        server_from = self.create_tenant_server(
            networks=[network], security_groups=[security_group],
            prepare_for_connectivity=True)
        server_to = self.create_tenant_server(
            networks=[network], security_groups=[security_group],
            prepare_for_connectivity=True)

        # Create QoS policy
        dscp_marking_policy_id = self.create_qos_policy()['id']

        # As admin user create QoS rule
        rule_id = self.create_qos_dscp_marking_rule(
            qos_policy_id=dscp_marking_policy_id,
            dscp_mark=self.DSCP_MARK)['id']

        # Associate QoS to the network
        self.update_network(
            network['id'], manager=self.admin_manager,
            qos_policy_id=dscp_marking_policy_id)
        self.addCleanup(self.update_network, network['id'],
                        manager=self.admin_manager,
                        qos_policy_id=None)

        # Check DSCP mark (original)
        self._check_dscp_marking(server_from, server_to)

        # As admin user update QoS rule
        self.update_qos_dscp_marking_rule(
            qos_policy_id=dscp_marking_policy_id, dscp_marking_rule_id=rule_id,
            dscp_mark=self.UPDATED_DSCP_MARK)

        # Check that actual DSCP mark
        # is as expected (Update DSCP)
        self._check_dscp_marking(server_from, server_to,
                                 expected_dscp_mark=self.UPDATED_DSCP_MARK)

        # Create a new QoS policy
        dscp_marking_policy_id_new = self.create_qos_policy()['id']

        # As admin user create a new QoS rule
        port = server_from.get_server_port_in_network(network)
        rule_id_new = self.create_qos_dscp_marking_rule(
            qos_policy_id=dscp_marking_policy_id_new,
            dscp_mark=self.DSCP_MARK)['id']

        # Associate a new QoS policy to Neutron port
        self.update_port(port, manager=self.admin_manager,
                         qos_policy_id=dscp_marking_policy_id_new)
        self.addCleanup(self.update_port, port,
                        manager=self.admin_manager,
                        qos_policy_id=None)

        # Check that actual DSCP mark while pinging
        # is as expected (Original DSCP)
        self._check_dscp_marking(server_from, server_to)

        # As admin user update QoS rule
        self.update_qos_dscp_marking_rule(
            qos_policy_id=dscp_marking_policy_id_new,
            dscp_marking_rule_id=rule_id_new,
            dscp_mark=self.UPDATED_DSCP_MARK)

        # Check that actual DSCP mark while downloading file
        # is as expected (Update DSCP)
        self._check_dscp_marking(server_from, server_to,
                                 expected_dscp_mark=self.UPDATED_DSCP_MARK)
