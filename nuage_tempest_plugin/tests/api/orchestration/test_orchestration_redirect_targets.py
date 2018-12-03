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

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.test import decorators

from nuage_tempest_plugin.tests.api.orchestration import nuage_base


class NeutronRedirectionTargetsTest(nuage_base.NuageBaseOrchestrationTest):
    """Basic tests for Heat Nuage Redirect Targets resources"""
    @classmethod
    def setup_clients(cls):
        super(NeutronRedirectionTargetsTest, cls).setup_clients()

    @classmethod
    def resource_setup(cls):
        super(NeutronRedirectionTargetsTest, cls).resource_setup()

        # temp sanity check
        assert hasattr(cls, 'stacks')

        if not utils.is_extension_enabled('nuage-redirect-target', 'network'):
            msg = "Nuage extension 'nuage-redirect-target' not enabled."
            raise cls.skipException(msg)

        cls.template = cls.load_template('redirect')
        cls.stack_name = data_utils.rand_name('redirecttarget')
        template = cls.read_template('redirect')

        # create the stack
        cls.stack_identifier = cls.create_stack(
            cls.stack_name,
            template)
        cls.stack_id = cls.stack_identifier.split('/')[1]
        cls.client.wait_for_stack_status(cls.stack_id, 'CREATE_COMPLETE')
        resources = (cls.client.list_resources(
            cls.stack_identifier)['resources'])

        cls.test_resources = {}
        for resource in resources:
            cls.test_resources[resource['logical_resource_id']] = resource

    @decorators.attr(type='smoke')
    def test_created_redirect_target_resources(self):
        """Verifies created redirect target resources."""
        resources = [('secgrp', self.template['resources'][
                      'secgrp']['type']),
                     ('rt_l2', self.template['resources'][
                      'rt_l2']['type']),
                     ('rtr_l2', self.template[
                      'resources']['rtr_l2']['type']),
                     ('rt_l3', self.template['resources'][
                      'rt_l3']['type']),
                     ('rtr_l3', self.template[
                      'resources']['rtr_l3']['type']),
                     ('vip_l3', self.template['resources'][
                      'vip_l3']['type'])]
        for resource_name, resource_type in resources:
            resource = self.test_resources.get(resource_name, None)
            self.assertIsInstance(resource, dict)
            self.assertEqual(resource_name, resource['logical_resource_id'])
            self.assertEqual(resource_type, resource['resource_type'])
            self.assertEqual('CREATE_COMPLETE', resource['resource_status'])
