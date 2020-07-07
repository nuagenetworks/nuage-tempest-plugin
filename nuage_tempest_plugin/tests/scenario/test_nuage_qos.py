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

from neutron_tempest_plugin.common import utils as common_utils
from neutron_tempest_plugin.scenario import base as neutron_base
from neutron_tempest_plugin.scenario import constants
from neutron_tempest_plugin.scenario import test_floatingip
from neutron_tempest_plugin.scenario import test_qos

from tempest.common import utils


class NuageFloatingIPProprietaryQosTest(
        test_floatingip.FloatingIpTestCasesMixin, test_qos.QoSTestMixin,
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
        # Check bw not limited
        unlimited_bw = sys.maxsize
        common_utils.wait_until_true(
            lambda: self._check_bw(ssh_client,
                                   self.fip['floating_ip_address'],
                                   port=self.NC_PORT,
                                   expected_bw=unlimited_bw),
            timeout=120)

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
