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

import uuid

from tempest.common import utils
from tempest.lib.common.utils import data_utils

import nuage_base

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services import nuage_client

LOG = Topology.get_logger(__name__)


class NeutronGatewayResourcesTest(nuage_base.NuageBaseOrchestrationTest):
    """Basic tests for Heat Nuage gateway resources"""

    @classmethod
    def setup_clients(cls):
        super(NeutronGatewayResourcesTest, cls).setup_clients()
        cls.nuage_client = nuage_client.NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(NeutronGatewayResourcesTest, cls).resource_setup()

        if not utils.is_extension_enabled('nuage-gateway', 'network'):
            msg = "Nuage extension 'nuage-gateway' not enabled."
            raise cls.skipException(msg)

        cls.gateways = []
        cls.gateway_ports = []

        cls.gw_name = data_utils.rand_name('tempest-gw')
        gw = cls.nuage_client.create_gateway(
            cls.gw_name, str(uuid.uuid4()), 'VRSG', None)
        cls.gateways.append(gw)
        cls.port_name = data_utils.rand_name('tempest-gw-port')
        gw_port = cls.nuage_client.create_gateway_port(
            cls.port_name, 'test', 'ACCESS', gw[0]['ID'])
        cls.gateway_ports.append(gw_port)

    @classmethod
    def resource_cleanup(cls):
        super(NeutronGatewayResourcesTest, cls).resource_cleanup()
        for port in cls.gateway_ports:
            try:
                cls.nuage_client.delete_gateway_port(port[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)

        for gateway in cls.gateways:
            try:
                cls.nuage_client.delete_gateway(gateway[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)

    # TODO(Team) Can this be made smoke?
    def test_created_gateway_resources(self):

        self.template = self.load_template('gateway')
        self.stack_name = data_utils.rand_name('heat-gateway')
        template = self.read_template('gateway')

        # create the stack
        # TODO(TEAM) fails with
        # 'Resource CREATE failed: StackValidationFailed:
        # resources.l2_bridge_vport_dhcp:
        # Property error: l2_bridge_vport_dhcp.Properties.gatewayvlan:
        # Error validating value 'XXX' :
        # Unable to find nuage_gateway_vlan with name or id 'XXX'

        self.stack_identifier = self.create_stack(
            self.stack_name,
            template,
            parameters={
                'gw_name': self.gw_name,
                'gw_port': self.port_name
            })
        self.stack_id = self.stack_identifier.split('/')[1]
        self.client.wait_for_stack_status(self.stack_id, 'CREATE_COMPLETE')

        for resource in self.client.list_resources(
                self.stack_identifier)['resources']:
            self.test_resources[resource['logical_resource_id']] = resource

        """Verifies created neutron gateway resources."""
        resources = [('gateway', self.template['resources'][
                      'gateway']['type']),
                     ('gateway_port', self.template['resources'][
                      'gateway_port']['type']),
                     ('vlan1', self.template[
                      'resources']['vlan1']['type']),
                     ('vlan2', self.template['resources'][
                      'vlan2']['type'])]
        for resource_name, resource_type in resources:
            resource = self.test_resources.get(resource_name, None)
            self.assertIsInstance(resource, dict)
            self.assertEqual(resource_name, resource['logical_resource_id'])
            self.assertEqual(resource_type, resource['resource_type'])
            self.assertEqual('CREATE_COMPLETE', resource['resource_status'])
