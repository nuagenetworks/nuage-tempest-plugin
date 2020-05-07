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

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.tests.api.orchestration import nuage_base

from tempest.common.utils.linux.remote_client import RemoteClient
from tempest.lib.common.utils import data_utils
from tempest.test import decorators

from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class ConcurrentUserDataTest(
        nuage_base.NuageBaseOrchestrationTest, NuageBaseTest):

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(ConcurrentUserDataTest, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        super(ConcurrentUserDataTest, cls).setup_clients()
        cls.floating_ips_client = cls.os_admin.floating_ips_client

    @decorators.attr(type='smoke')
    def test_metadata_agent_on_concurrent_deployment(self):
        """Verifies created neutron resources."""
        neutron_basic_template = self.load_template(
            'concurrent_deployment_of_vms_with_fip')
        keypair = self.create_keypair(manager=self.admin_manager)
        stack_name = data_utils.rand_name('heat')
        user_data = '#!/bin/sh\necho "pass" > /tmp/userdata.out'
        template = self.read_template(
            'concurrent_deployment_of_vms_with_fip')
        network_name = data_utils.rand_name('priv_net')
        parameters = {
            'public_net': CONF.network.public_network_id,
            'private_net_name': network_name,
            'private_net_cidr': '97.0.0.0/24',
            'private_net_gateway': '97.0.0.1',
            'private_net_pool_start': '97.0.0.5',
            'private_net_pool_end': '97.0.0.100',
            'image': CONF.compute.image_ref,
            'flavor': CONF.compute.flavor_ref,
            'key_name': keypair['name'],
            'user_data': user_data
        }
        # create the stack
        stack_identifier = self.create_stack(
            stack_name,
            template,
            parameters)
        stack_id = stack_identifier.split('/')[1]

        self.client.wait_for_stack_status(stack_id, 'CREATE_COMPLETE')
        resources = (self.client.list_resources(stack_identifier)
                     ['resources'])

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
            server = NuageBaseTest.get_server(
                self, server_id=resource['physical_resource_id'],
                manager=self.admin_manager)
            fip = None
            for net in server['addresses'][network_name]:
                if net['OS-EXT-IPS:type'] == 'floating':
                    fip = net['addr']
            fip_acs = RemoteClient(
                ip_address=fip,
                username=CONF.validation.image_ssh_user,
                pkey=keypair['private_key'])
            result = fip_acs.exec_command('cat /tmp/userdata.out')
            self.assertIn('pass', result)
        self._clear_stacks()
