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
import sys
import testtools
import time

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.common import utils as common_utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base as neutron_base
from neutron_tempest_plugin.scenario import constants
from neutron_tempest_plugin.scenario import test_floatingip
from neutron_tempest_plugin.scenario import test_qos
from oslo_log import log
from tempest.common import utils
from tempest.lib import decorators
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.topology import Topology
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

    @testtools.skipIf(Topology.before_nuage('20.10'),
                      'VRS-47436')
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
        # Check bw not limited
        unlimited_bw = sys.maxsize
        common_utils.wait_until_true(
            lambda: self._check_bw(ssh_client,
                                   self.fip['floating_ip_address'],
                                   port=self.NC_PORT,
                                   expected_bw=unlimited_bw),
            timeout=240)

        self.os_admin.network_client.update_floatingip(
            self.fip['id'],
            nuage_egress_fip_rate_kbps=500,
            nuage_ingress_fip_rate_kbps=1000)
        expected_egress_bw = 500 * 1024 * self.TOLERANCE_FACTOR / 8.0
        expected_ingress_bw = 1000 * 1024 * self.TOLERANCE_FACTOR / 8.0
        common_utils.wait_until_true(
            lambda: self._check_bw(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT,
                expected_bw=expected_egress_bw),
            timeout=120,
            sleep=1)
        common_utils.wait_until_true(
            lambda: self._check_bw_ingress(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT,
                expected_bw=expected_ingress_bw),
            timeout=120,
            sleep=1)

        # Update floating ip QOS to new value
        self.os_admin.network_client.update_floatingip(
            self.fip['id'],
            nuage_egress_fip_rate_kbps=200,
            nuage_ingress_fip_rate_kbps=400)

        expected_egress_bw = 200 * 1024 * self.TOLERANCE_FACTOR / 8.0
        expected_ingress_bw = 400 * 1024 * self.TOLERANCE_FACTOR / 8.0
        common_utils.wait_until_true(
            lambda: self._check_bw(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT,
                expected_bw=expected_egress_bw),
            timeout=120,
            sleep=1)
        common_utils.wait_until_true(
            lambda: self._check_bw_ingress(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT,
                expected_bw=expected_ingress_bw),
            timeout=120,
            sleep=1)


class RateLimitingNuageQosScenarioTest(test_qos.QoSTest,
                                       base_nuage_qos.NuageQoSTestMixin):

    DOWNLOAD_DURATION = 10
    CHECK_TIMEOUT = DOWNLOAD_DURATION * 10

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

        if hasattr(self, 'FILE_SIZE'):
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


class QoSDscpTest(test_qos.QoSTestMixin, neutron_base.BaseTempestTestCase):

    FILE_PATH = '/tmp/dscptest'
    DSCP_MARK = 10
    UPDATED_DSCP_MARK = 12

    @classmethod
    @utils.requires_ext(extension="qos", service="network")
    def resource_setup(cls):
        super(QoSDscpTest, cls).resource_setup()

    def kill_tcpdump_process(self, ssh_client):
        try:
            cmd = "sudo killall -q tcpdump"
            ssh_client.exec_command(cmd)
            cmd = "sudo rm {}".format(self.FILE_PATH)
            ssh_client.exec_command(cmd)
        except exceptions.SSHExecCommandFailed:
            pass

    def ensure_tcpdump_running(self, ssh_client, dscp_mark):
        """Ensure that tcpdump is running.

        Listener is created always on remote host.
        """

        def process_is_running(ssh_client, process_name):
            try:
                ssh_client.exec_command("pidof %s" % process_name)
                return True
            except exceptions.SSHExecCommandFailed:
                return False

        def spawn_and_check_process():
            self.tcpdump_run(ssh_client, dscp_mark)
            return process_is_running(ssh_client, "tcpdump")

        common_utils.wait_until_true(spawn_and_check_process, timeout=120)

    def tcpdump_run(self, ssh_client, dscp_mark):
        """Create tcpdump listener for dscp_mark icmp traffic.

        Listener is created always on remote host.
        """
        # convert dscp mark to TOS field dec value
        tos_value = dscp_mark << 2
        try:
            ssh_client.exec_command(
                "sudo /usr/sbin/tcpdump icmp[0]==8 and "
                "ip[1]=={tos_value} -c 1 &> {file} &".format(
                    tos_value=tos_value,
                    file=self.FILE_PATH))
        except exceptions.SSHTimeout as ssh_e:
            LOG.debug(ssh_e)
            raise

    def _check_dscp_marking(self, ssh_client_from, ssh_client_to, destination,
                            expected_dscp_mark=DSCP_MARK):
        self.kill_tcpdump_process(ssh_client_to)
        self.ensure_tcpdump_running(ssh_client_to, expected_dscp_mark)
        # ping to from from
        self.check_remote_connectivity(ssh_client_from, destination)
        # Wait for tcpdump to flush to file.
        time.sleep(1)
        # Validate remote file
        tcpdump_output = ssh_client_to.exec_command(
            'cat {}'.format(self.FILE_PATH))
        return '1 packet received by filter' in tcpdump_output

    @decorators.attr(type='smoke')
    def test_dscp_marking_basic_and_update(self):
        """This test covers both:

            1) Basic QoS DSCP functionality
            This is a basic test that check that a QoS policy with
            a DSCP marking rule is applied correctly by pinging from
            one node to the other.
            Using tcpdump the DSCP mark is verified when ping packets arrive
            at the pinged host from the host with the policy enabled.

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
        self.setup_network_and_server()
        # Setup a second server
        secgroup = self.security_groups[-1]
        rulesets = [{'protocol': 'icmp', 'direction': 'ingress'}]
        self.create_secgroup_rules(rulesets,
                                   self.security_groups[-1]['id'])
        server_kwargs = {
            'flavor_ref': CONF.compute.flavor_ref,
            'image_ref': CONF.compute.image_ref,
            'key_name': self.keypair['name'],
            'networks': [{'uuid': self.network['id']}],
            'security_groups': [{'name': secgroup['name']}],
        }
        self.server2 = self.create_server(**server_kwargs)
        self.wait_for_server_active(self.server2['server'])
        self.port2 = self.client.list_ports(network_id=self.network['id'],
                                            device_id=self.server2[
                                                'server']['id'])['ports'][0]
        self.fip2 = self.create_floatingip(port=self.port2)
        self.check_connectivity(self.fip2['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])

        ssh_client_from = self._create_ssh_client()
        ssh_client_to = ssh.Client(self.fip2['floating_ip_address'],
                                   CONF.validation.image_ssh_user,
                                   pkey=self.keypair['private_key'])

        # Create QoS policy
        dscp_marking_policy_id = self._create_qos_policy()

        # As admin user create QoS rule
        rule_id = self.os_admin.network_client.create_dscp_marking_rule(
            policy_id=dscp_marking_policy_id,
            dscp_mark=self.DSCP_MARK)[
                'dscp_marking_rule']['id']

        # Associate QoS to the network
        self.os_admin.network_client.update_network(
            self.network['id'], qos_policy_id=dscp_marking_policy_id)

        # Check DSCP mark (original)
        common_utils.wait_until_true(lambda: self._check_dscp_marking(
            ssh_client_from, ssh_client_to,
            self.fip2['floating_ip_address']),
            timeout=120,
            sleep=1)

        # As admin user update QoS rule
        self.os_admin.network_client.update_dscp_marking_rule(
            dscp_marking_policy_id,
            rule_id,
            dscp_mark=self.UPDATED_DSCP_MARK)

        # Check that actual DSCP mark while pinging
        # is as expected (Update DSCP)
        common_utils.wait_until_true(lambda: self._check_dscp_marking(
            ssh_client_from, ssh_client_to,
            self.fip2['floating_ip_address'],
            expected_dscp_mark=self.UPDATED_DSCP_MARK),
            timeout=120,
            sleep=1)

        # Create a new QoS policy
        dscp_marking_policy_id_new = self._create_qos_policy()

        # As admin user create a new QoS rule
        rule_id_new = self.os_admin.network_client.create_dscp_marking_rule(
            policy_id=dscp_marking_policy_id_new,
            dscp_mark=self.DSCP_MARK)[
                'dscp_marking_rule']['id']

        # Associate a new QoS policy to Neutron port
        self.os_admin.network_client.update_port(
            self.port['id'], qos_policy_id=dscp_marking_policy_id_new)

        # Check that actual DSCP mark while pinging
        # is as expected (Original DSCP)
        common_utils.wait_until_true(lambda: self._check_dscp_marking(
            ssh_client_from, ssh_client_to,
            self.fip2['floating_ip_address']),
            timeout=120,
            sleep=1)

        # As admin user update QoS rule
        self.os_admin.network_client.update_dscp_marking_rule(
            dscp_marking_policy_id_new,
            rule_id_new,
            dscp_mark=self.UPDATED_DSCP_MARK)

        # Check that actual BW while downloading file
        # is as expected (Update BW)
        common_utils.wait_until_true(lambda: self._check_dscp_marking(
            ssh_client_from, ssh_client_to,
            self.fip2['floating_ip_address'],
            expected_dscp_mark=self.UPDATED_DSCP_MARK),
            timeout=120,
            sleep=1)
