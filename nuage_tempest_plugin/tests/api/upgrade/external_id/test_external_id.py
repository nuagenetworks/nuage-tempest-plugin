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
import testtools

from nuage_tempest_plugin.tests.api.upgrade.external_id.external_id \
    import ExternalId

from nuage_tempest_lib.release import Release


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
        external_id = ExternalId(
            "PG_FOR_LESS_SECURITY_9705383f-3b49-4eb3-9c3e-994bdabbf48e_"
            "VM@1b501982-2da1-48b9-931b-af49b6ee065f")
        self.assertEqual(
            external_id.uuid,
            "PG_FOR_LESS_SECURITY_9705383f-3b49-4eb3-9c3e-994bdabbf48e_VM")


class ReleaseTest(testtools.TestCase):
    def test_release_full(self):
        release = Release("kilo 4.0R3")
        self.assertEqual(release.openstack_release, "kilo")
        self.assertEqual(release.major_release, "4.0")
        self.assertEqual(release.major_list[0], "4")
        self.assertEqual(release.major_list[1], "0")
        self.assertEqual(release.sub_release, "3")

    def test_release_dot_release(self):
        release = Release("4.0R3")
        self.assertEqual(release.openstack_release, "master")
        self.assertEqual(release.major_release, "4.0")
        self.assertEqual(release.major_list[0], "4")
        self.assertEqual(release.major_list[1], "0")
        self.assertEqual(release.sub_release, "3")

    def test_release_branch_release(self):
        release = Release("liberty-PROD-2456-plugin-11")
        self.assertEqual(release.openstack_release, "liberty")
        # self.assertEqual(release.major_release, "4.0")
        # self.assertEqual(release.major_list[0], "4")
        # self.assertEqual(release.major_list[1], "0")
        # self.assertEqual(release.sub_release, 3)

    def test_release_compare(self):
        release = Release('4.0R5')
        current_release = Release('0.0')

        self.assertFalse(current_release == release)
        self.assertFalse(current_release < release)
        self.assertTrue(current_release > release)
        self.assertFalse(current_release <= release)

        self.assertFalse(release == current_release)
        self.assertTrue(release < current_release)
        self.assertFalse(release > current_release)
        self.assertTrue(release <= current_release)
