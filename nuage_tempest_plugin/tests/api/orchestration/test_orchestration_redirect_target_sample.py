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
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest.services import orchestration

from nuage_tempest_plugin.tests.api.orchestration import nuage_base

CONF = config.CONF


class NeutronRedirectionTargetsTest(nuage_base.NuageBaseOrchestrationTest):
    """Basic tests for Heat Nuage Redirect Targets resources"""

    @classmethod
    def setup_clients(cls):
        super(NeutronRedirectionTargetsTest, cls).setup_clients()
        cls.orchestration_client = orchestration.OrchestrationClient(
            cls.os_primary.auth_provider,
            CONF.heat_plugin.catalog_type,
            CONF.heat_plugin.region or CONF.identity.region,
            build_interval=CONF.heat_plugin.build_interval,
            build_timeout=CONF.heat_plugin.build_timeout,
            **cls.os_primary.default_params)

    @classmethod
    def create_stack(cls, stack_name, template_data, parameters=None,
                     environment=None, files=None):
        if parameters is None:
            parameters = {}
        body = cls.orchestration_client.create_stack(
            stack_name,
            template=template_data,
            parameters=parameters,
            environment=environment,
            files=files)
        stack_id = body.response['location'].split('/')[-1]
        stack_identifier = '%s/%s' % (stack_name, stack_id)
        cls.stacks.append(stack_identifier)
        return stack_identifier

    @classmethod
    def _clear_stacks(cls):
        for stack_identifier in cls.stacks:
            try:
                cls.orchestration_client.delete_stack(stack_identifier)
            except lib_exc.NotFound:
                pass

        for stack_identifier in cls.stacks:
            try:
                cls.orchestration_client.wait_for_stack_status(
                    stack_identifier, 'DELETE_COMPLETE')
            except lib_exc.NotFound:
                pass

    @classmethod
    def resource_setup(cls):
        super(NeutronRedirectionTargetsTest, cls).resource_setup()

        if not utils.is_extension_enabled('nuage-redirect-target', 'network'):
            msg = "Nuage extension 'nuage-redirect-target' not enabled."
            raise cls.skipException(msg)

        cls.template = cls.load_template('l3_redirect')
        cls.stack_name = data_utils.rand_name('redirecttarget')
        template = cls.read_template('l3_redirect')
        stack_parameters = {
            'image': CONF.compute.image_ref
        }
        # create the stack
        cls.stack_identifier = cls.create_stack(
            cls.stack_name,
            template,
            parameters=stack_parameters)
        cls.stack_id = cls.stack_identifier.split('/')[1]
        cls.orchestration_client.wait_for_stack_status(
            cls.stack_id, 'CREATE_COMPLETE')
        resources = (cls.orchestration_client.list_resources(
            cls.stack_identifier)['resources'])

        cls.test_resources = {}
        for resource in resources:
            cls.test_resources[resource['logical_resource_id']] = resource

    def test_created_redirect_target_resources(self):
        """Verifies created redirect target resources."""
        resources = [('app_to_db', self.template['resources'][
                      'app_to_db']['type']),
                     ('fw_int', self.template['resources'][
                      'fw_int']['type']),
                     ('redirect_fw', self.template[
                      'resources']['redirect_fw']['type']),
                     ('lb', self.template['resources'][
                      'lb']['type']),
                     ('redirect_lb', self.template[
                      'resources']['redirect_lb']['type']),
                     ('lb_vip', self.template['resources'][
                      'lb_vip']['type'])]
        for resource_name, resource_type in resources:
            resource = self.test_resources.get(resource_name, None)
            self.assertIsInstance(resource, dict)
            self.assertEqual(resource_name, resource['logical_resource_id'])
            self.assertEqual(resource_type, resource['resource_type'])
            self.assertEqual('CREATE_COMPLETE', resource['resource_status'])
