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

import tempest.test

from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.tests.api.external_id.external_id import ExternalId


class ExternalIdTest(tempest.test.BaseTestCase):
    def test_external_id_format_openstack(self):
        external_id = ExternalId("aa-bb-cc-dd@openstack")
        self.assertEqual(external_id.uuid, "aa-bb-cc-dd")
        self.assertEqual(external_id.cms, "openstack")

    def test_external_id_format_cmsid(self):
        external_id = ExternalId("aa-bb-cc-dd@ee-ff-gg-hh")
        self.assertEqual(external_id.uuid, "aa-bb-cc-dd")
        self.assertEqual(external_id.cms, "ee-ff-gg-hh")

    def test_external_id_format_short(self):
        external_id = ExternalId("aa-bb-cc-dd")
        self.assertEqual(external_id.uuid, "aa-bb-cc-dd")

    def test_external_id_none(self):
        external_id = ExternalId(None)
        self.assertEqual(external_id.uuid, "")

    def test_external_id_empty(self):
        external_id = ExternalId("")
        self.assertEqual(external_id.uuid, "")

    def test_external_id_format_default_security_policy_group(self):
        external_id = ExternalId(n_constants.NUAGE_PLCY_GRP_ALLOW_ALL +
                                 '@1b501982-2da1-48b9-931b-af49b6ee065f')
        self.assertEqual(
            external_id.uuid,
            n_constants.NUAGE_PLCY_GRP_ALLOW_ALL)
