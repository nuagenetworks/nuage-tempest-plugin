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

import nuage_base

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.tests.api.l2bridge.base_nuage_l2bridge \
    import BaseNuageL2Bridge

LOG = Topology.get_logger(__name__)


class NuageOSManagedDuplexHeatTest(nuage_base.NuageBaseOrchestrationTest,
                                   BaseNuageL2Bridge):
    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(NuageOSManagedDuplexHeatTest, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        super(NuageOSManagedDuplexHeatTest, cls).setup_clients()
        cls.subnets_client = cls.os_admin.subnets_client

    def test_created_resources(self):
        """Verifies created neutron resources."""
        neutron_basic_template = self.load_template('l2_bridge_basic')
        stack_name = data_utils.rand_name('heat')
        template = self.read_template('l2_bridge_basic')

        physnets = [
            {
                'physnet_name': 'physnet1',
                'segmentation_id': 50,
                'segmentation_type': 'vlan'
            },
            {
                'physnet_name': 'physnet1',
                'segmentation_id': 55,
                'segmentation_type': 'vlan'
            }
        ]
        name = data_utils.rand_name('test-l2bridge-')
        bridge = self.create_l2bridge(name, physnets, cleanup=False)
        # create the stack
        stack_identifier = self.create_stack(stack_name,
                                             template,
                                             parameters={'SubNetCidr': str(
                                                         '10.10.100.0/24')}
                                             )
        stack_id = stack_identifier.split('/')[1]
        try:
            self.client.wait_for_stack_status(stack_id, 'CREATE_COMPLETE')
            resources = (self.client.list_resources(stack_identifier)
                         ['resources'])
        except exceptions.TimeoutException as e:
            raise e

        test_resources = {}
        for resource in resources:
            test_resources[resource['logical_resource_id']] = resource

        resources = [('Network1', neutron_basic_template['resources'][
                      'Network1']['type']),
                     ('Subnet1', neutron_basic_template['resources'][
                      'Subnet1']['type']),
                     ('Network2', neutron_basic_template['resources'][
                         'Network2']['type']),
                     ('Subnet2', neutron_basic_template['resources'][
                         'Subnet2']['type'])
                     ]
        for resource_name, resource_type in resources:
            resource = test_resources.get(resource_name, None)
            self.assertIsInstance(resource, dict)
            self.assertEqual(resource_name, resource['logical_resource_id'])
            self.assertEqual(resource_type, resource['resource_type'])
            self.assertEqual('CREATE_COMPLETE', resource['resource_status'])
        self._clear_stacks()
        self.delete_l2bridge(bridge['id'])
