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
from neutron_tempest_plugin.common import utils as common_utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base as neutron_base
from neutron_tempest_plugin.scenario import constants
from neutron_tempest_plugin.scenario import test_qos
from oslo_log import log
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as tempest_exc
from tempest.lib.services.compute import base_compute_client

LOG = log.getLogger(__name__)

CONF = config.CONF


class NuageNovaQosTest(test_qos.QoSTestMixin,
                       neutron_base.BaseTempestTestCase):

    credentials = ['primary', 'admin']

    WRITE_SIZE = 1024 * 1024
    LIMIT_KBPS = 12

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

    def setup_network_and_server(self, router=None, server_name=None,
                                 network=None, **kwargs):
        """Create network resources and a server.

        Creating a network, subnet, router, keypair, security group
        and a server.
        """
        self.network = network or self.create_network()
        LOG.debug("Created network %s", self.network['name'])
        self.subnet = self.create_subnet(self.network)
        LOG.debug("Created subnet %s", self.subnet['id'])

        secgroup = self.os_primary.network_client.create_security_group(
            name=data_utils.rand_name('secgroup'))
        LOG.debug("Created security group %s",
                  secgroup['security_group']['name'])
        self.security_groups.append(secgroup['security_group'])
        if not router:
            router = self.create_router_by_client(**kwargs)
        self.create_router_interface(router['id'], self.subnet['id'])
        self.keypair = self.create_keypair()
        self.create_loginable_secgroup_rule(
            secgroup_id=secgroup['security_group']['id'])

        # Create a flavor with rate limiting
        flavors_client = self.os_admin.compute.FlavorsClient()
        default_flavor = flavors_client.show_flavor(
            CONF.compute.flavor_ref)
        default_flavor = default_flavor['flavor']
        body = flavors_client.create_flavor(
            name='Nova RateLimit',
            disk=default_flavor['disk'],
            ram=default_flavor['ram'],
            vcpus=default_flavor['vcpus']
        )
        flavor = body['flavor']
        self.addCleanup(flavors_client.delete_flavor, flavor['id'])
        default_extra_specs = flavors_client.list_flavor_extra_specs(
            default_flavor['id'])['extra_specs']
        extra_specs = {'quota:vif_outbound_average': str(self.LIMIT_KBPS),
                       'quota:vif_inbound_peak': str(self.LIMIT_KBPS),
                       'quota:vif_outbound_peak': str(self.LIMIT_KBPS),
                       'quota:vif_inbound_average': str(self.LIMIT_KBPS)}
        extra_specs.update(default_extra_specs)
        flavors_client.set_flavor_extra_spec(
            flavor['id'], **extra_specs)

        server_kwargs = {
            'flavor_ref': flavor['id'],
            'image_ref': CONF.compute.image_ref,
            'key_name': self.keypair['name'],
            'networks': [{'uuid': self.network['id']}],
            'security_groups': [{'name': secgroup['security_group']['name']}],
        }
        if server_name is not None:
            server_kwargs['name'] = server_name

        self.server = self.create_server(**server_kwargs)
        self.wait_for_server_active(self.server['server'])
        self.port = self.client.list_ports(network_id=self.network['id'],
                                           device_id=self.server[
                                               'server']['id'])['ports'][0]
        self.fip = self.create_floatingip(port=self.port)

    def _check_bw_ingress(self, ssh_client, host, port,
                          expected_bw=test_qos.QoSTestMixin.LIMIT_BYTES_SEC):
        self.ensure_nc_listen_ingress(ssh_client, port, "tcp")
        # Open TCP socket to remote VM and download big file
        start_time = time.time()
        try:
            client_socket = test_qos._connect_socket(
                host, port, constants.SOCKET_CONNECT_TIMEOUT)
        except AttributeError:
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

    def test_nova_qos(self):
        """Test QOS when using NOVA flavor

        """
        self._test_basic_resources()
        ssh_client = self._create_ssh_client()
        if hasattr(self, 'FILE_SIZE'):
            # Queens & Rocky: create file
            self._create_file_for_bw_tests(ssh_client)

        limit_bytes_sec = self.LIMIT_KBPS * 1024 * 1.5
        # Check bw limited
        common_utils.wait_until_true(
            lambda: self._check_bw(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT,
                expected_bw=limit_bytes_sec),
            timeout=200,
            sleep=1)
        common_utils.wait_until_true(
            lambda: self._check_bw_ingress(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT + 1,
                expected_bw=limit_bytes_sec),
            timeout=200,
            sleep=1)
        # Migrate
        original_host = self.os_primary.servers_client.show_server(
            self.server['server']['id'])['server']['hostId']
        # Set Nova API to latest for better api support
        base_compute_client.COMPUTE_MICROVERSION = 'latest'
        self.os_admin.servers_client.live_migrate_server(
            self.server['server']['id'], block_migration='auto', host=None)
        base_compute_client.COMPUTE_MICROVERSION = None
        self.wait_for_server_active(self.server['server'])
        new_host = self.os_primary.servers_client.show_server(
            self.server['server']['id'])['server']['hostId']
        self.assertNotEqual(original_host, new_host,
                            "Migration did not happen")
        # Check bw limited
        common_utils.wait_until_true(
            lambda: self._check_bw(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT,
                expected_bw=limit_bytes_sec),
            timeout=200,
            sleep=1)
        common_utils.wait_until_true(
            lambda: self._check_bw_ingress(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT + 1,
                expected_bw=limit_bytes_sec),
            timeout=200,
            sleep=1)
