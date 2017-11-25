# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_log import log as logging

from tempest import config
from tempest.lib import exceptions

import testtools

from nuage_tempest_plugin.lib.release import Release
from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology

import upgrade_external_id_with_cms_id as upgrade_script

CONF = config.CONF
LOG = logging.getLogger(__name__)

current_release = Release(Topology.nuage_release)


class UpgradeScriptTest(testtools.TestCase):

    @nuage_test.header()
    @testtools.skipUnless(current_release < Release('4.0R5'),
                          'No upgrade testing on release %s' % current_release)
    def test_upgrade_script_external_id(self):

        LOG.debug("Release %s", current_release)

        script_cmd = upgrade_script.SCRIPT_PATH + \
            upgrade_script.SET_EXTERNAL_ID_UPGRADE_SCRIPT
        script_args = "--config-file /etc/neutron/neutron.conf " \
                      "/etc/neutron/plugin.ini"

        try:
            response = upgrade_script.execute(
                "python -c 'import sys; print sys.path'")
            self.assertIsInstance(response, unicode)
            self.assertNotEqual('', response)
            self.assertThat(response, testtools.matchers.Contains("python2.7"))

        except exceptions.SSHExecCommandFailed as e:
            LOG.debug("Failed. Exception %s", e)

        try:
            response = upgrade_script.execute("python " + script_cmd + " " +
                                              script_args)
            self.assertIsInstance(response, unicode)
            self.assertNotEqual('', response)
            self.assertThat(response, testtools.matchers.Contains(
                "Setting ExternalID's on VSD is now complete."))

        except exceptions.SSHExecCommandFailed as e:
            LOG.debug("Failed. Exception %s", e)
            raise e
