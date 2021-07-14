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

from neutron_tempest_plugin import config
from oslo_log import log
from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils as utils

LOG = log.getLogger(__name__)

CONF = config.CONF

# VRS-35132: Ethernet fragmentation causes QOS to drop packets
# 1400 mtu prevents fragmentation in single and doubly encapsulated vxlan
# Lowered to 1350 to accomodate Wallaby safety margins wrt MTU.
QOS_MTU = 1350


class NuageQosTestmixin(object):
    """NuageQosTestmixin

    Provides all common methods to develop QOS scenario tests

    """
    DOWNLOAD_DURATION = 10
    BUFFER_SIZE = 512  # Bytes
    TOLERANCE_FACTOR_EGRESS = 0.20  # within 20 % of expected bw
    TOLERANCE_FACTOR_INGRESS = 0.50  # within 50 % of expected bw
    DEST_PORT = 1789

    @classmethod
    def skip_checks(cls):
        super(NuageQosTestmixin, cls).skip_checks()
        if Topology.before_nuage('20.10'):
            raise cls.skipException('QOS test are only supported from 20.10')

    @staticmethod
    def kill_process(server, process):
        cmd = 'sudo killall -q {process}'.format(process=process)
        server.send(cmd, one_off_attempt=True)

    @staticmethod
    def _get_socket_to(server_to, port):
        destination = server_to.associated_fip['floating_ip_address']
        client_socket = socket.socket(socket.AF_INET,
                                      socket.SOCK_STREAM)
        client_socket.connect((destination, port))
        client_socket.settimeout(30)
        return client_socket

    def list_qos_rule_types(self):
        uri = '/qos/rule-types'
        body = self.admin_manager.qos_client.list_resources(uri)
        return [rule_type['type'] for rule_type in body['rule_types']]

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

    def create_qos_bandwidth_limit_rule(self, qos_policy_id,
                                        manager=None, **kwargs):
        manager = manager or self.admin_manager
        uri = '/qos/policies/{}/bandwidth_limit_rules'.format(qos_policy_id)
        post_data = {'bandwidth_limit_rule': kwargs}
        rule = manager.qos_client.create_resource(
            uri, post_data)['bandwidth_limit_rule']
        return rule

    def update_qos_bandwidth_limit_rule(self, qos_policy_id, bw_limit_rule_id,
                                        manager=None, **kwargs):
        manager = manager or self.admin_manager
        uri = '/qos/policies/{}/bandwidth_limit_rules/{}'.format(
            qos_policy_id, bw_limit_rule_id)
        post_data = {'bandwidth_limit_rule': kwargs}
        rule = manager.qos_client.update_resource(
            uri, post_data)['bandwidth_limit_rule']
        return rule

    def create_qos_dscp_marking_rule(self, qos_policy_id,
                                     manager=None,
                                     **kwargs):
        manager = manager or self.admin_manager
        uri = '/qos/policies/{}/dscp_marking_rules'.format(qos_policy_id)
        post_data = {'dscp_marking_rule': kwargs}
        rule = manager.qos_client.create_resource(
            uri, post_data)['dscp_marking_rule']
        return rule

    def update_qos_dscp_marking_rule(self, qos_policy_id, dscp_marking_rule_id,
                                     manager=None, **kwargs):
        manager = manager or self.admin_manager
        uri = '/qos/policies/{}/dscp_marking_rules/{}'.format(
            qos_policy_id, dscp_marking_rule_id)
        post_data = {'dscp_marking_rule': kwargs}
        rule = manager.qos_client.update_resource(
            uri, post_data)['dscp_marking_rule']
        return rule

    def nc_run(self, server, port, direction, protocol='tcp'):
        udp = '-u' if protocol.lower() == 'udp' else ''
        if direction == 'egress':
            nc_argument = '-lk < /dev/zero;'
        else:
            nc_argument = ' -l > /dev/null;'
        nc_cmd = ("screen -d -m sh -c '"
                  "while true; do nc {udp} -p {port} {nc_arg} "
                  "done;'".format(port=port, udp=udp, nc_arg=nc_argument))
        server.send(nc_cmd, one_off_attempt=True, as_sudo=True)
        server.send('sudo netstat -tln', one_off_attempt=True)

    def _check_bw(self, host, direction, configured_bw_kbps):
        # configure nc server
        # Kill previous screen or nc processes
        client_socket = None
        try:
            self.kill_process(host, 'screen nc')
            self.nc_run(host, self.DEST_PORT, direction)
            # Open TCP socket to remote VM and download big file
            client_socket = self._get_socket_to(host, self.DEST_PORT)
            write_data = ('x' * (self.BUFFER_SIZE - 1) + '\n').encode()
            start_time = time.time()
            total_bytes = 0
            while time.time() - start_time < self.DOWNLOAD_DURATION:
                if direction == 'egress':
                    # Download file
                    data = client_socket.recv(self.BUFFER_SIZE)
                    total_bytes += len(data)
                else:
                    client_socket.send(write_data)
                    total_bytes += len(write_data)

            time_elapsed = time.time() - start_time
            kbps_measured = (total_bytes / time_elapsed) / 125
            print(kbps_measured)
            if direction == 'egress':
                tolerance_factor = self.TOLERANCE_FACTOR_EGRESS
            else:
                tolerance_factor = self.TOLERANCE_FACTOR_INGRESS
            min_bw = (configured_bw_kbps -
                      configured_bw_kbps * tolerance_factor)
            max_bw = (configured_bw_kbps +
                      configured_bw_kbps * tolerance_factor)
            LOG.debug('time_elapsed = %(time_elapsed).16f, '
                      'kbps_measured = %(kbps_measured)d, '
                      'expected bw = %(min_bw)d-%(max_bw)d.',
                      {'time_elapsed': time_elapsed,
                       'kbps_measured': kbps_measured,
                       'min_bw': min_bw,
                       'max_bw': max_bw})
            return min_bw <= kbps_measured <= max_bw
        except socket.timeout:
            LOG.warning('Socket timeout while reading the remote file')
            return False
        except Exception as e:
            LOG.warning('Failure to measure bw: %s', e)
            return False
        finally:
            if client_socket:
                client_socket.close()

    def _test_bandwidth(self, server, egress_bw=None, ingress_bw=None,
                        test_msg=None):
        error_msg = ('Timed out waiting for traffic to be limited in {} '
                     'direction: {}')
        if egress_bw:
            utils.wait_until_true(
                lambda: self._check_bw(
                    server, configured_bw_kbps=egress_bw, direction='egress'),
                timeout=180,
                exception=utils.WaitTimeout(
                    error_msg.format('egress', test_msg)))
        if ingress_bw:
            utils.wait_until_true(
                lambda: self._check_bw(
                    server, configured_bw_kbps=ingress_bw,
                    direction='ingress'),
                timeout=180,
                exception=utils.WaitTimeout(
                    error_msg.format('ingress', test_msg)))
