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

from nuage_tempest_plugin.tests.api.orchestration import nuage_base

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

LOG = Topology.get_logger(__name__)


class NuageProjectNetpartitionMappingHeatTest(
        nuage_base.NuageBaseOrchestrationTest):

    @classmethod
    def setup_clients(cls):
        super(NuageProjectNetpartitionMappingHeatTest, cls).setup_clients()
        cls.plugin_admin_network_client = NuageNetworkClientJSON(
            cls.os_admin.auth_provider, **cls.os_admin.default_params)

    @decorators.attr(type='smoke')
    def test_project_netpartition_mapping_basic(self):
        """Verifies created neutron resources."""
        neutron_basic_template = self.load_template(
            'project_netpartition_mapping')
        stack_name = data_utils.rand_name('heat')
        template = self.read_template('project_netpartition_mapping')

        name = data_utils.rand_name('test-mapping')
        # create the stack
        project_id = '12345678123456781234567812345678'
        parameters = {
            'netpartition_name': name,
            'project': project_id
        }
        stack_identifier = self.create_stack(stack_name,
                                             template,
                                             parameters=parameters)
        stack_id = stack_identifier.split('/')[1]
        self.client.wait_for_stack_status(stack_id, 'CREATE_COMPLETE')
        resources = (self.client.list_resources(stack_identifier)
                     ['resources'])

        test_resources = {}
        for resource in resources:
            test_resources[resource['logical_resource_id']] = resource

        resources = [('netpartition', neutron_basic_template['resources'][
                      'netpartition']['type']),
                     ('mapping', neutron_basic_template['resources'][
                      'mapping']['type']),
                     ]
        for resource_name, resource_type in resources:
            resource = test_resources.get(resource_name, None)
            self.assertIsInstance(resource, dict)
            self.assertEqual(resource_name, resource['logical_resource_id'])
            self.assertEqual(resource_type, resource['resource_type'])
            self.assertEqual('CREATE_COMPLETE', resource['resource_status'])

        # Verify actual creation
        mapping = self.plugin_admin_network_client.\
            show_project_netpartition_mappings(
                project_id=project_id)['project_net_partition_mapping']
        self.assertEqual(project_id,
                         mapping['project'])
        self.assertEqual(
            test_resources['netpartition']['physical_resource_id'],
            mapping['net_partition_id'])

        # update the stack
        new_project_id = '01234567812345678123456781234567'
        updated_parameters = {
            'netpartition_name': name,
            'project': new_project_id
        }
        self.update_stack(stack_id, name, template_data=template,
                          parameters=updated_parameters)
        self.client.wait_for_stack_status(stack_id, 'UPDATE_COMPLETE')

        # Verify update
        self.assertRaises(exceptions.NotFound,
                          self.plugin_admin_network_client.
                          show_project_netpartition_mappings,
                          project_id=project_id)

        mapping = self.plugin_admin_network_client.\
            show_project_netpartition_mappings(
                project_id=new_project_id)['project_net_partition_mapping']
        self.assertEqual(new_project_id,
                         mapping['project'])
        self.assertEqual(
            test_resources['netpartition']['physical_resource_id'],
            mapping['net_partition_id'])
        self._clear_stacks()
