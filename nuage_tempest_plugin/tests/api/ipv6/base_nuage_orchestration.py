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

import os.path
import yaml

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest.services import orchestration
import tempest.test

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services import nuage_client

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


# TODO(TEAM) - this class should inherit from NuageBaseOrchestrationTest


class NuageBaseOrchestrationTest(tempest.test.BaseTestCase):
    """Base test case class for all Nuage Orchestration API tests."""
    credentials = ['primary']

    @classmethod
    def skip_checks(cls):
        super(NuageBaseOrchestrationTest, cls).skip_checks()
        if not CONF.service_available.heat_plugin:
            raise cls.skipException("Heat support is required")

    @classmethod
    def setup_clients(cls):
        super(NuageBaseOrchestrationTest, cls).setup_clients()
        cls.vsd_client = nuage_client.NuageRestClient()
        cls.os_admin = cls.get_client_manager(roles=['admin'])

        # add ourselves for now as was removed upstream
        cls.orchestration_client = orchestration.OrchestrationClient(
            cls.os_admin.auth_provider,
            CONF.heat_plugin.catalog_type,
            CONF.heat_plugin.region or CONF.identity.region,
            build_interval=CONF.heat_plugin.build_interval,
            build_timeout=CONF.heat_plugin.build_timeout,
            **cls.os_admin.default_params)

        cls.admin_networks_client = cls.os_admin.networks_client
        cls.admin_routers_client = cls.os_admin.routers_client

    @classmethod
    def resource_setup(cls):
        super(NuageBaseOrchestrationTest, cls).resource_setup()

        cls.build_timeout = CONF.heat_plugin.build_timeout
        cls.build_interval = CONF.heat_plugin.build_interval

        cls.net_partition_name = Topology.def_netpartition
        cls.private_net_name = data_utils.rand_name('heat-network-')

        cls.test_resources = {}
        cls.template_resources = {}

    def launch_stack(self, stack_file_name, stack_parameters):
        stack_name = data_utils.rand_name('heat-' + stack_file_name)
        template = self.read_template(stack_file_name)

        self.launch_stack_template(stack_name, template, stack_parameters)

    def launch_stack_template(self, stack_name, template, stack_parameters):
        LOG.debug("Stack launched: %s", template)
        LOG.debug("Stack parameters: %s", stack_parameters)

        # create the stack
        self.stack_identifier = self.create_stack(
            stack_name,
            template,
            stack_parameters
        )
        self.stack_id = self.stack_identifier.split('/')[1]
        self.orchestration_client.wait_for_stack_status(
            self.stack_id, 'CREATE_COMPLETE')

        resources = self.orchestration_client.list_resources(
            self.stack_identifier)
        resources = resources['resources']
        self.test_resources = {}
        for resource in resources:
            self.test_resources[resource['logical_resource_id']] = resource

        # load to dict
        my_dict = yaml.safe_load(template)

        self.template_resources = my_dict['resources']

    # def load_stack_resources(self, stack_file_name):
    #     loaded_template = self.load_template(stack_file_name)
    #     return loaded_template['resources']

    def verify_stack_resources(self, expected_resources,
                               template_resourses, actual_resources):
        for resource_name in expected_resources:
            resource_type = template_resourses[resource_name]['type']
            resource = actual_resources.get(resource_name, None)
            self.assertIsInstance(resource, dict)
            self.assertEqual(resource_name, resource['logical_resource_id'])
            self.assertEqual(resource_type, resource['resource_type'])
            self.assertEqual('CREATE_COMPLETE', resource['resource_status'])

    @classmethod
    def read_template(cls, name, ext='yaml'):
        loc = ["templates", "%s.%s" % (name, ext)]
        fullpath = os.path.join(os.path.dirname(__file__), *loc)

        with open(fullpath, "r") as f:
            content = f.read()
            return content

    @classmethod
    def load_template(cls, name, ext='yaml'):
        loc = ["templates", "%s.%s" % (name, ext)]
        fullpath = os.path.join(os.path.dirname(__file__), *loc)

        with open(fullpath, "r") as f:
            return yaml.safe_load(f)

    def create_stack(self, stack_name, template_data, parameters=None,
                     environment=None, files=None):
        if parameters is None:
            parameters = {}
        body = self.orchestration_client.create_stack(
            stack_name,
            template=template_data,
            parameters=parameters,
            environment=environment,
            files=files)
        stack_id = body.response['location'].split('/')[-1]
        stack_identifier = '%s/%s' % (stack_name, stack_id)

        self.addCleanup(self._clear_stack, stack_identifier)
        return stack_identifier

    def _clear_stack(self, stack_identifier):
        try:
            self.orchestration_client.delete_stack(stack_identifier)
        except lib_exc.NotFound:
            pass

        try:
            self.orchestration_client.wait_for_stack_status(
                stack_identifier, 'DELETE_COMPLETE',
                failure_pattern="DELETE_FAILED")
        except lib_exc.NotFound:
            pass

    @staticmethod
    def stack_output(stack, output_key):
        """Return a stack output value for a given key."""
        return next((o['output_value'] for o in stack['outputs']
                     if o['output_key'] == output_key), None)

    def assert_fields_in_dict(self, obj, *fields):
        for field in fields:
            self.assertIn(field, obj)

    def list_resources(self, stack_identifier):
        """Get a dict mapping of resource names to types."""
        resources = self.client.list_resources(stack_identifier)['resources']
        self.assertIsInstance(resources, list)
        for res in resources:
            self.assert_fields_in_dict(res, 'logical_resource_id',
                                       'resource_type', 'resource_status',
                                       'updated_time')

        return dict((r['resource_name'], r['resource_type'])
                    for r in resources)

    def get_stack_output(self, stack_identifier, output_key):
        body = self.client.show_stack(stack_identifier)['stack']
        return self.stack_output(body, output_key)

    def verify_created_network(self, resource_name):
        """Verifies created network."""
        resource = self.test_resources.get(resource_name)
        network_id = resource['physical_resource_id']
        body = self.admin_networks_client.show_network(network_id)
        network = body['network']

        # basic verifications
        self.assertIsInstance(network, dict)
        self.assertEqual(network_id, network['id'])

        return network

    def verify_created_subnet(self, resource_name, network):
        """Verifies created network."""
        resource = self.test_resources.get(resource_name)

        subnet_id = resource['physical_resource_id']
        # (waelj) response does no longer report the attribute 'vsd_managed'
        # by default
        # Need to list 'vsd_managed' in the fields list in order to get the
        # attribute format: {'fields': ['id', 'name']}
        body = self.os_admin.subnets_client.show_subnet(
            subnet_id, fields=['id', 'network_id', 'ip_version',
                               'vsd_managed', 'enable_dhcp', 'cidr',
                               'gateway_ip', 'allocation_pools'])

        subnet = body['subnet']

        # basic verifications
        self.assertIsInstance(subnet, dict)
        self.assertEqual(subnet_id, subnet['id'])
        self.assertEqual(network['id'], subnet['network_id'])

        self.assertTrue(subnet['vsd_managed'])
        # self.assertEqual(4, subnet['ip_version'])

        return subnet

    def verify_created_router(self, resource_name):
        """Verifies created router."""
        resource = self.test_resources.get(resource_name)
        router_id = resource['physical_resource_id']
        body = self.admin_routers_client.show_router(router_id)
        router = body['router']

        # basic verifications
        self.assertIsInstance(router, dict)
        self.assertEqual(router_id, router['id'])

        return router

    def verify_created_security_group(self, resource_name):
        """Verifies created security_group."""
        resource = self.test_resources.get(resource_name)
        security_group_id = resource['physical_resource_id']
        body = self.os_admin.security_groups_client.show_security_group(
            security_group_id)
        security_group = body['security_group']

        # basic verifications
        self.assertIsInstance(security_group, dict)
        self.assertEqual(security_group_id, security_group['id'])

        return security_group
