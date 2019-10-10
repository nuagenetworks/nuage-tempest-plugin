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

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class OrchestrationVMwithFIP(nuage_base.NuageBaseOrchestrationTest):
    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(OrchestrationVMwithFIP, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        super(OrchestrationVMwithFIP, cls).setup_clients()
        cls.floating_ips_client = cls.os_admin.floating_ips_client

    @decorators.attr(type='smoke')
    def test_nuage_concurrent_deployment_of_vms_with_fip(self):
        """Verifies created neutron resources."""
        neutron_basic_template = self.load_template(
            'concurrent_deployment_of_vms_with_fip')
        stack_name = data_utils.rand_name('heat')
        template = self.read_template(
            'concurrent_deployment_of_vms_with_fip')
        parameters = {
            'public_net': CONF.network.public_network_id,
            'private_net_name': data_utils.rand_name('priv_net'),
            'private_net_cidr': '97.0.0.0/24',
            'private_net_gateway': '97.0.0.1',
            'private_net_pool_start': '97.0.0.5',
            'private_net_pool_end': '97.0.0.100',
            'image': CONF.compute.image_ref,
            'flavor': CONF.compute.flavor_ref
        }
        # create the stack
        stack_identifier = self.create_stack(
            stack_name,
            template,
            parameters)
        stack_id = stack_identifier.split('/')[1]
        try:
            self.client.wait_for_stack_status(stack_id, 'CREATE_COMPLETE')
            resources = (self.client.list_resources(stack_identifier)
                         ['resources'])
        except exceptions.TimeoutException:
            raise

        test_resources = {}
        for resource in resources:
            test_resources[resource['logical_resource_id']] = resource

        resources = [
            ('vm1', neutron_basic_template['resources'][
                'vm1']['type']),
            ('vm2', neutron_basic_template['resources'][
                'vm2']['type']),
            ('vm3', neutron_basic_template['resources'][
                'vm3']['type']),
            ('vm4', neutron_basic_template['resources'][
                'vm4']['type']),
            ('vm5', neutron_basic_template['resources'][
                'vm5']['type']),
            ('vm6', neutron_basic_template['resources'][
                'vm6']['type']),
            ('vm7', neutron_basic_template['resources'][
                'vm7']['type'])
        ]
        for resource_name, resource_type in resources:
            resource = test_resources.get(resource_name, None)
            self.assertIsInstance(resource, dict)
            server_id = test_resources.get(
                resource_name)['physical_resource_id']
            server = self.servers_client.show_server(server_id)['server']
            self.assertEqual('ACTIVE', server['status'])
            self.assertEqual(resource_name, resource['logical_resource_id'])
            self.assertEqual(resource_type, resource['resource_type'])
            self.assertEqual('CREATE_COMPLETE', resource['resource_status'])
        self._clear_stacks()
