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

from oslo_log import log

from neutron_lib import constants as neutron_lib_constants
from tempest.common import utils
from tempest.lib import exceptions as tempest_exc

from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin.common import utils as common_utils
from neutron_tempest_plugin.scenario import base as neutron_base
from neutron_tempest_plugin.scenario import constants
from neutron_tempest_plugin.scenario import test_floatingip
from neutron_tempest_plugin.scenario import test_qos


LOG = log.getLogger(__name__)


class NuageFloatingIPProprietaryQosTest(
        test_floatingip.FloatingIpTestCasesMixin, test_qos.QoSTestMixin,
        neutron_base.BaseTempestTestCase):

    same_network = True

    @classmethod
    @utils.requires_ext(extension="router", service="network")
    def resource_setup(cls):
        super(NuageFloatingIPProprietaryQosTest, cls).resource_setup()

    @staticmethod
    def get_ncat_server_cmd(port, protocol):
        udp = ''
        if protocol.lower() == neutron_lib_constants.PROTO_NAME_UDP:
            udp = '-u'
        return ("screen -d -m sh -c '"
                "while true; do nc {udp} -p {port} -lk < /dev/zero; "
                "done;'".format(port=port, udp=udp))

    def ensure_nc_listen(self, ssh_client, port, protocol, echo_msg=None,
                         servers=None):
        """Ensure that nc server listening on the given TCP/UDP port is up.

        Listener is created always on remote host.
        """
        try:
            value = ssh_client.exec_command(
                self.get_ncat_server_cmd(port, protocol))
            LOG.debug(str(ssh_client.exec_command("sudo netstat -tln")))
            return value
        except tempest_exc.SSHTimeout as ssh_e:
            LOG.debug(ssh_e)
            self._log_console_output(servers)
            raise

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
            nuage_ingress_fip_rate_kbps=constants.LIMIT_KILO_BITS_PER_SECOND,
            nuage_egress_fip_rate_kbps=constants.LIMIT_KILO_BITS_PER_SECOND)

        common_utils.wait_until_true(
            lambda: self._check_bw(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT),
            timeout=120,
            sleep=1)


class RateLimitingNuageQosScenarioTest(test_qos.QoSTest):
    BUFFER_SIZE = 1024
    DOWNLOAD_DURATION = 10
    CHECK_TIMEOUT = DOWNLOAD_DURATION * 10

    @staticmethod
    def get_ncat_server_cmd(port, protocol):
        udp = ''
        if protocol.lower() == neutron_lib_constants.PROTO_NAME_UDP:
            udp = '-u'
        return ("screen -d -m sh -c '"
                "while true; do nc {udp} -p {port} -lk < /dev/zero; "
                "done;'".format(port=port, udp=udp))

    def ensure_nc_listen(self, ssh_client, port, protocol, echo_msg=None,
                         servers=None):
        """Ensure that nc server listening on the given TCP/UDP port is up.

        Listener is created always on remote host.
        """
        try:
            value = ssh_client.exec_command(
                self.get_ncat_server_cmd(port, protocol))
            LOG.debug(str(ssh_client.exec_command("sudo netstat -tln")))
            return value
        except tempest_exc.SSHTimeout as ssh_e:
            LOG.debug(ssh_e)
            self._log_console_output(servers)
            raise

    def check_connectivity(self, host, ssh_user, ssh_key,
                           servers=None, ssh_timeout=None):
        # Set MTU on cirros VM for QOS
        # VRS-35132
        ssh_client = ssh.Client(host, ssh_user,
                                pkey=ssh_key, timeout=ssh_timeout)
        try:
            ssh_client.test_connection_auth()
            ssh_client.exec_command("set -eu -o pipefail; PATH=$PATH:/sbin; "
                                    "sudo ip link set dev eth0 mtu 1450")
        except tempest_exc.SSHTimeout as ssh_e:
            LOG.debug(ssh_e)
            self._log_console_output(servers)
            self._log_local_network_status()
            raise
