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

from neutron_tempest_plugin.common import utils as common_utils
from neutron_tempest_plugin.scenario import base as neutron_base
from neutron_tempest_plugin.scenario import constants
from neutron_tempest_plugin.scenario import test_floatingip
from neutron_tempest_plugin.scenario import test_qos
from oslo_log import log
from tempest.common import utils

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.tests.scenario.qos import base_nuage_qos

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
                port=self.NC_PORT + 1,
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
                port=self.NC_PORT + 1,
                expected_bw=expected_ingress_bw),
            timeout=120,
            sleep=1)


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
