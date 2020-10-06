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
import socket
import time

from neutron_lib import constants as neutron_lib_constants
from neutron_tempest_plugin.common import ssh
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import constants
from neutron_tempest_plugin.scenario import test_qos
from oslo_log import log
from tempest.lib import exceptions as tempest_exc

LOG = log.getLogger(__name__)

CONF = config.CONF


class NuageQoSTestMixin(test_qos.QoSTestMixin):

    WRITE_SIZE = 1024 * 1024

    def _test_basic_resources(self):
        self.setup_network_and_server()
        self.check_connectivity(self.fip['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])
        rulesets = [{'protocol': 'tcp',
                     'direction': 'ingress',
                     'port_range_min': self.NC_PORT,
                     'port_range_max': self.NC_PORT + 1,
                     'remote_ip_prefix': '0.0.0.0/0'}]
        self.create_secgroup_rules(rulesets,
                                   self.security_groups[-1]['id'])

    def check_connectivity(self, host, ssh_user, ssh_key,
                           servers=None, ssh_timeout=None):
        # Set MTU on cirros VM for QOS
        ssh_client = ssh.Client(host, ssh_user,
                                pkey=ssh_key, timeout=ssh_timeout)
        try:
            ssh_client.test_connection_auth()
            ssh_client.exec_command("set -eu -o pipefail; PATH=$PATH:/sbin; "
                                    "sudo ip link set dev eth0 mtu 1400")
        except tempest_exc.SSHTimeout as ssh_e:
            LOG.debug(ssh_e)
            self._log_console_output(servers)
            self._log_local_network_status()
            raise

    def _check_bw_ingress(self, ssh_client, host, port,
                          expected_bw=test_qos.QoSTestMixin.LIMIT_BYTES_SEC):
        self.ensure_nc_listen_ingress(ssh_client, port, "tcp")
        # Open TCP socket to remote VM and download big file
        start_time = time.time()
        try:
            client_socket = test_qos._connect_socket(
                host, port, constants.SOCKET_CONNECT_TIMEOUT)
        except (AttributeError, TypeError):
            client_socket = test_qos._connect_socket(
                host, port)

        total_bytes_written = 0
        write_data = ('x' * (self.BUFFER_SIZE - 1) + '\n').encode()
        try:
            while total_bytes_written < self.WRITE_SIZE:
                client_socket.send(write_data)
                total_bytes_written += len(write_data)

            # Calculate and return actual BW + logging result
            time_elapsed = time.time() - start_time
            bytes_per_second = total_bytes_written / time_elapsed
            print(bytes_per_second / 1000)
            LOG.debug("time_elapsed = %(time_elapsed).16f, "
                      "total_bytes_written = %(total_bytes_written)d, "
                      "bytes_per_second = %(bytes_per_second)d, "
                      "expected_bw = %(expected_bw)d.",
                      {'time_elapsed': time_elapsed,
                       'total_bytes_written': total_bytes_written,
                       'bytes_per_second': bytes_per_second,
                       'expected_bw': expected_bw})
            return bytes_per_second <= expected_bw
        except socket.timeout:
            LOG.warning(
                'Socket timeout while reading the remote file, bytes '
                'read: %s', total_bytes_written)
            return False
        finally:
            client_socket.close()

    @staticmethod
    def get_ncat_server_cmd(port, protocol):
        udp = ''
        if protocol.lower() == neutron_lib_constants.PROTO_NAME_UDP:
            udp = '-u'
        return ("screen -d -m sh -c '"
                "while true; do nc {udp} -p {port} -lk < /dev/zero; "
                "done;'".format(port=port, udp=udp))

    @staticmethod
    def get_ncat_server_cmd_ingress(port, protocol, msg=None):
        udp = ''
        if protocol.lower() == neutron_lib_constants.PROTO_NAME_UDP:
            udp = '-u'
        return ("screen -d -m sh -c '"
                "while true; do nc {udp} -p {port} -l > /dev/null; "
                "done;'".format(port=port, udp=udp))

    def ensure_nc_listen(self, ssh_client, port, protocol, echo_msg=None,
                         servers=None):
        """Ensure that nc server listening on the given TCP/UDP port is up.

        Listener is created always on remote host.
        """
        try:
            # kill existing screen operation
            ssh_client.exec_command("killall -q screen")
        except tempest_exc.SSHExecCommandFailed:
            pass
        try:
            value = ssh_client.exec_command(
                self.get_ncat_server_cmd(port, protocol))
            LOG.debug(str(ssh_client.exec_command("sudo netstat -tln")))
            return value
        except tempest_exc.SSHTimeout as ssh_e:
            LOG.debug(ssh_e)
            self._log_console_output(servers)
            raise

    def ensure_nc_listen_ingress(self, ssh_client, port, protocol,
                                 echo_msg=None, servers=None):
        """Ensure that nc server listening on the given TCP/UDP port is up.

        Listener is created always on remote host.
        """
        try:
            # kill existing screen operation
            ssh_client.exec_command("killall -q screen")
        except tempest_exc.SSHExecCommandFailed:
            pass
        try:
            value = ssh_client.exec_command(
                self.get_ncat_server_cmd_ingress(port, protocol))
            LOG.debug(str(ssh_client.exec_command("sudo netstat -tln")))
            return value
        except tempest_exc.SSHTimeout as ssh_e:
            LOG.debug(ssh_e)
            self._log_console_output(servers)
            raise
