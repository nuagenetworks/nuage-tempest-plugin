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

from neutron_tempest_plugin.common import utils as common_utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base as neutron_base
from neutron_tempest_plugin.scenario import constants
from neutron_tempest_plugin.scenario import test_floatingip
from neutron_tempest_plugin.scenario import test_qos
from oslo_log import log
from tempest.common import utils
from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.tests.scenario.qos import base_nuage_qos

CONF = config.CONF

LOG = log.getLogger(__name__)


class NuageFloatingIPProprietaryQosTest(
        test_floatingip.FloatingIpTestCasesMixin,
        base_nuage_qos.NuageQoSTestMixin,
        neutron_base.BaseTempestTestCase):

    same_network = True

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    def resource_setup(cls):
        super(NuageFloatingIPProprietaryQosTest, cls).resource_setup()

    def test_qos(self):
        """Test floating IP is binding to a QoS policy with

           ingress and egress bandwidth limit rules. And it applied correctly
           by sending a file from the instance to the test node.
           Then calculating the bandwidth every ~1 sec by the number of bits
           received / elapsed time.
        """

        self._test_basic_resources()
        ssh_client = self._create_ssh_client()

        fip = self.os_admin.network_client.get_floatingip(
            self.fip['id'])['floatingip']
        self.assertEqual(self.port['id'], fip['port_id'])

        if hasattr(self, 'FILE_SIZE'):
            # Queens & Rocky: create file
            self._create_file_for_bw_tests(ssh_client)

        self.os_admin.network_client.update_floatingip(
            self.fip['id'],
            nuage_egress_fip_rate_kbps=500,
            nuage_ingress_fip_rate_kbps=1000)
        expected_egress_bw = 500 * 1024 * self.TOLERANCE_FACTOR / 8.0
        # expected_ingress_bw = 1000 * 1024 * self.TOLERANCE_FACTOR / 8.0
        common_utils.wait_until_true(
            lambda: self._check_bw(
                ssh_client, self.fip['floating_ip_address'],
                port=self.NC_PORT, expected_bw=expected_egress_bw),
            timeout=120, sleep=1,
            exception=common_utils.WaitTimeout("Timed out waiting for traffic "
                                               "to be limited in egress "
                                               "direction"))
        # VRS-47436: No OS ingress RL, no VSD egress fip rate limiting
        # common_utils.wait_until_true(
        #     lambda: self._check_bw_ingress(
        #         ssh_client, self.fip['floating_ip_address'],
        #         port=self.NC_PORT + 1, expected_bw=expected_ingress_bw),
        #     timeout=120, sleep=1,
        #   exception=common_utils.WaitTimeout("Timed out waiting for traffic"
        #                                      "to be limited in ingress "
        #                                      "direction")))

        # Update floating ip QOS to new value
        self.os_admin.network_client.update_floatingip(
            self.fip['id'],
            nuage_egress_fip_rate_kbps=200,
            nuage_ingress_fip_rate_kbps=400)

        expected_egress_bw = 200 * 1024 * self.TOLERANCE_FACTOR / 8.0
        # expected_ingress_bw = 400 * 1024 * self.TOLERANCE_FACTOR / 8.0
        common_utils.wait_until_true(
            lambda: self._check_bw(
                ssh_client, self.fip['floating_ip_address'],
                port=self.NC_PORT, expected_bw=expected_egress_bw),
            timeout=120, sleep=1,
            exception=common_utils.WaitTimeout("Timed out waiting for traffic "
                                               "to be limited in egress "
                                               "direction after fip rate limit"
                                               " update"))
        # common_utils.wait_until_true(
        #     lambda: self._check_bw_ingress(
        #         ssh_client, self.fip['floating_ip_address'],
        #         port=self.NC_PORT + 1, expected_bw=expected_ingress_bw),
        #     timeout=120, sleep=1,
        #  exception=common_utils.WaitTimeout("Timed out waiting for traffic"
        #                                     "to be limited in ingress "
        #                                     "direction after fip rate
        #                                     "limit update"))


class RateLimitingNuageQosScenarioTest(test_qos.QoSTest,
                                       base_nuage_qos.NuageQoSTestMixin):

    DOWNLOAD_DURATION = 10
    CHECK_TIMEOUT = DOWNLOAD_DURATION * 10
    FILE_SIZE = 1024 * 1024 * 2
    COUNT = 4096

    @testtools.skip("Ingress QOS currently not supported")
    def test_qos_basic_and_update_ingress(self):

        # Setup resources
        self._test_basic_resources()
        ssh_client = self._create_ssh_client()

        # Create QoS policy
        bw_limit_policy_id = self._create_qos_policy()

        # As admin user create QoS rule
        rule_id = self.os_admin.network_client.create_bandwidth_limit_rule(
            policy_id=bw_limit_policy_id,
            max_kbps=constants.LIMIT_KILO_BITS_PER_SECOND,
            max_burst_kbps=constants.LIMIT_KILO_BITS_PER_SECOND,
            direction='ingress')[
                'bandwidth_limit_rule']['id']

        # Associate QoS to the network
        self.os_admin.network_client.update_network(
            self.network['id'], qos_policy_id=bw_limit_policy_id)

        if hasattr(self, '_create_file_for_bw_tests'):
            # Queens & Rocky: create file
            self._create_file_for_bw_tests(ssh_client)

        # Basic test, Check that actual BW while uploading file
        # is as expected (Original BW)
        common_utils.wait_until_true(lambda: self._check_bw_ingress(
            ssh_client,
            self.fip['floating_ip_address'],
            port=self.NC_PORT),
            timeout=self.CHECK_TIMEOUT,
            sleep=1)

        # As admin user update QoS rule
        self.os_admin.network_client.update_bandwidth_limit_rule(
            bw_limit_policy_id,
            rule_id,
            max_kbps=constants.LIMIT_KILO_BITS_PER_SECOND * 2,
            max_burst_kbps=constants.LIMIT_KILO_BITS_PER_SECOND * 2)

        # Check that actual BW while uploading file
        # is as expected (Update BW)
        common_utils.wait_until_true(lambda: self._check_bw_ingress(
            ssh_client,
            self.fip['floating_ip_address'],
            port=self.NC_PORT,
            expected_bw=test_qos.QoSTestMixin.LIMIT_BYTES_SEC * 2),
            timeout=self.CHECK_TIMEOUT,
            sleep=1)

        # Create a new QoS policy
        bw_limit_policy_id_new = self._create_qos_policy()

        # As admin user create a new QoS rule
        rule_id_new = self.os_admin.network_client.create_bandwidth_limit_rule(
            policy_id=bw_limit_policy_id_new,
            max_kbps=constants.LIMIT_KILO_BITS_PER_SECOND,
            max_burst_kbps=constants.LIMIT_KILO_BITS_PER_SECOND)[
                'bandwidth_limit_rule']['id']

        # Associate a new QoS policy to Neutron port
        self.os_admin.network_client.update_port(
            self.port['id'], qos_policy_id=bw_limit_policy_id_new)

        # Check that actual BW while uploading file
        # is as expected (Original BW)
        common_utils.wait_until_true(lambda: self._check_bw_ingress(
            ssh_client,
            self.fip['floating_ip_address'],
            port=self.NC_PORT),
            timeout=self.FILE_DOWNLOAD_TIMEOUT,
            sleep=1)

        # As admin user update QoS rule
        self.os_admin.network_client.update_bandwidth_limit_rule(
            bw_limit_policy_id_new,
            rule_id_new,
            max_kbps=constants.LIMIT_KILO_BITS_PER_SECOND * 3,
            max_burst_kbps=constants.LIMIT_KILO_BITS_PER_SECOND * 3)

        # Check that actual BW while uploading file
        # is as expected (Update BW)
        common_utils.wait_until_true(lambda: self._check_bw(
            ssh_client,
            self.fip['floating_ip_address'],
            port=self.NC_PORT,
            expected_bw=test_qos.QoSTestMixin.LIMIT_BYTES_SEC * 3),
            timeout=self.FILE_DOWNLOAD_TIMEOUT,
            sleep=1)


class QoSDscpTest(nuage_test.NuageBaseTest):

    FILE_PATH = '/tmp/dscptest'
    DSCP_MARK = 10
    UPDATED_DSCP_MARK = 12

    DEST_PORT = 1789

    @classmethod
    @utils.requires_ext(extension="qos", service="network")
    def resource_setup(cls):
        super(QoSDscpTest, cls).resource_setup()

    @staticmethod
    def kill_process(server, process):
        cmd = "sudo killall -q {process}".format(process=process)
        server.send(cmd, one_off_attempt=True)

    def create_qos_policy(self, name=None,
                          manager=None, cleanup=True):
        manager = manager or self.admin_manager
        name = name or data_utils.rand_name('test-policy')
        args = {'name': name,
                'description': 'test policy',
                'shared': False}
        qos_policy = manager.qos_client.create_qos_policy(
            **args)['policy']
        if cleanup:
            self.addCleanup(manager.qos_client.delete_qos_policy,
                            qos_policy['id'])
        return qos_policy

    def create_qos_dscp_marking_rule(self, qos_policy_id,
                                     manager=None,
                                     **kwargs):
        manager = manager or self.admin_manager
        uri = '/qos/policies/{}/dscp_marking_rules'.format(qos_policy_id)
        post_data = {'dscp_marking_rule': kwargs}
        return manager.qos_client.create_resource(uri, post_data)

    def update_qos_dscp_marking_rule(self, qos_policy_id, dscp_marking_rule_id,
                                     manager=None,
                                     **kwargs):
        manager = manager or self.admin_manager
        uri = '/qos/policies/{}/dscp_marking_rules/{}'.format(
            qos_policy_id, dscp_marking_rule_id)
        post_data = {'dscp_marking_rule': kwargs}
        return manager.qos_client.update_resource(uri, post_data)

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
            "sudo /usr/sbin/tcpdump -vvv {tcpdump_cmd} "
            "-c 1 &> {file} &".format(
                tcpdump_cmd=tcpdump_cmd, file=self.FILE_PATH),
            one_off_attempt=True)

    def nc_run(self, server, protocol, port):
        udp = ''
        if protocol.lower() == 'udp':
            udp = '-u'
        nc_cmd = ("screen -d -m sh -c '"
                  "while true; do nc {udp} -p {port} -l > /dev/null; "
                  "done;'".format(port=port, udp=udp))
        server.send(nc_cmd, one_off_attempt=True, as_sudo=True)
        server.send("sudo netstat -tln", one_off_attempt=True)

    def _check_dscp_marking(self, server_from, server_to,
                            expected_dscp_mark=DSCP_MARK):
        # Check DSCP marking for (icmp, tcp, udp) x (ipv4, ipv6)
        failures = []
        for protocol in ['icmp', 'tcp', 'udp']:
            for ip_version in [4, 6]:
                # Kill tcpdump process & delete result file
                self.kill_process(server_to, 'tcpdump')
                cmd = "sudo rm {}".format(self.FILE_PATH)
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
                    self.nc_run(server_to, protocol, self.DEST_PORT)
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
                        "Failed to detect DSCP mark {} for "
                        "protocol {}, ip_version {}.".format(
                            expected_dscp_mark, protocol, ip_version))
                    LOG.error(msg)
                    failures.append(msg)
                else:
                    LOG.debug(
                        "Succesfully detected DSCP mark {} for "
                        "protocol {}, ip_version {}.".format(
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
            1) Associating QoS Policy with "original DSCP mark"
               to the test node
            2) DSCP mark validation
            3) Updating existing QoS Policy to a new DSCP mark
            4) DSCP mark validation
            Note:
            There are two options to associate QoS policy to VM:
            "Neutron Port" or "Network", in this test
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
            dscp_mark=self.DSCP_MARK)[
                'dscp_marking_rule']['id']

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
            dscp_mark=self.DSCP_MARK)[
                'dscp_marking_rule']['id']

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
