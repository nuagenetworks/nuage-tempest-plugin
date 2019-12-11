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

import netaddr

from nuage_tempest_plugin.tests.api.orchestration import nuage_base

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class OrchestrationNeutronResourcesTest(nuage_base.NuageBaseOrchestrationTest):

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(OrchestrationNeutronResourcesTest, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        super(OrchestrationNeutronResourcesTest, cls).setup_clients()
        cls.routers_client = cls.os_admin.routers_client
        cls.subnets_client = cls.os_admin.subnets_client
        cls.ports_client = cls.os_admin.ports_client

    @classmethod
    def resource_setup(cls):
        super(OrchestrationNeutronResourcesTest, cls).resource_setup()
        cls.neutron_basic_template = cls.load_template('nuage_neutron_basic')
        cls.stack_name = data_utils.rand_name('heat')
        template = cls.read_template('nuage_neutron_basic')
        cls.keypair_name = (CONF.heat_plugin.keypair_name or
                            cls._create_keypair()['name'])
        cls.external_network_id = CONF.network.public_network_id

        tenant_cidr = netaddr.IPNetwork(CONF.network.project_network_cidr)
        mask_bits = CONF.network.project_network_mask_bits
        cls.subnet_cidr = next(tenant_cidr.subnet(mask_bits))

        # create the stack
        cls.stack_identifier = cls.create_stack(
            cls.stack_name,
            template,
            parameters={
                'KeyName': cls.keypair_name,
                'Flavor': CONF.compute.flavor_ref,
                'ImageId': CONF.compute.image_ref,
                'ExternalNetworkId': cls.external_network_id,
                'timeout': CONF.heat_plugin.build_timeout,
                'DNSServers': CONF.network.dns_servers,
                'SubNetCidr': str(cls.subnet_cidr)
            })
        cls.stack_id = cls.stack_identifier.split('/')[1]
        try:
            cls.client.wait_for_stack_status(cls.stack_id, 'CREATE_COMPLETE')
            resources = (cls.client.list_resources(cls.stack_identifier)
                         ['resources'])
        except exceptions.TimeoutException:
            if CONF.compute_feature_enabled.console_output:
                # attempt to log the server console to help with debugging
                # the cause of the server not signalling the waitcondition
                # to heat.
                body = cls.client.show_resource(cls.stack_identifier,
                                                'Server')
                server_id = body['physical_resource_id']
                LOG.debug('Console output for %s', server_id)
                output = cls.servers_client.get_console_output(
                    server_id)['output']
                LOG.debug(output)
            raise

        cls.test_resources = {}
        for resource in resources:
            cls.test_resources[resource['logical_resource_id']] = resource

    @decorators.idempotent_id('f9e2664c-bc44-4eef-98b6-495e4f9d74b3')
    @decorators.attr(type='smoke')
    def test_created_resources(self):
        """Verifies created neutron resources."""
        resources = [('Network', self.neutron_basic_template['resources'][
                      'Network']['type']),
                     ('Subnet', self.neutron_basic_template['resources'][
                      'Subnet']['type']),
                     ('RouterInterface', self.neutron_basic_template[
                      'resources']['RouterInterface']['type']),
                     ('Server', self.neutron_basic_template['resources'][
                      'Server']['type'])]
        for resource_name, resource_type in resources:
            resource = self.test_resources.get(resource_name, None)
            self.assertIsInstance(resource, dict)
            self.assertEqual(resource_name, resource['logical_resource_id'])
            self.assertEqual(resource_type, resource['resource_type'])
            self.assertEqual('CREATE_COMPLETE', resource['resource_status'])

    @decorators.idempotent_id('c572b915-edb1-4e90-b196-c7199a6848c0')
    def test_created_network(self):
        """Verifies created network."""
        network_id = self.test_resources.get('Network')['physical_resource_id']
        body = self.networks_client.show_network(network_id)
        network = body['network']
        self.assertIsInstance(network, dict)
        self.assertEqual(network_id, network['id'])
        self.assertEqual(self.neutron_basic_template['resources'][
            'Network']['properties']['name'], network['name'])

    @decorators.idempotent_id('e8f84b96-f9d7-4684-ad5f-340203e9f2c2')
    def test_created_subnet(self):
        """Verifies created subnet."""
        subnet_id = self.test_resources.get('Subnet')['physical_resource_id']
        body = self.subnets_client.show_subnet(subnet_id)
        subnet = body['subnet']
        network_id = self.test_resources.get('Network')['physical_resource_id']
        self.assertEqual(subnet_id, subnet['id'])
        self.assertEqual(network_id, subnet['network_id'])
        self.assertEqual(self.neutron_basic_template['resources'][
            'Subnet']['properties']['name'], subnet['name'])
        self.assertEqual(sorted(CONF.network.dns_servers),
                         sorted(subnet['dns_nameservers']))
        self.assertEqual(self.neutron_basic_template['resources'][
            'Subnet']['properties']['ip_version'], subnet['ip_version'])
        self.assertEqual(str(self.subnet_cidr), subnet['cidr'])

    @decorators.idempotent_id('96af4c7f-5069-44bc-bdcf-c0390f8a67d1')
    def test_created_router(self):
        """Verifies created router."""
        router_id = self.test_resources.get('Router')['physical_resource_id']
        body = self.routers_client.show_router(router_id)
        router = body['router']
        self.assertEqual(self.neutron_basic_template['resources'][
            'Router']['properties']['name'], router['name'])
        self.assertEqual(self.external_network_id,
                         router['external_gateway_info']['network_id'])
        self.assertEqual(True, router['admin_state_up'])

    @decorators.idempotent_id('89f605bd-153e-43ee-a0ed-9919b63423c5')
    def test_created_router_interface(self):
        """Verifies created router interface."""
        router_id = self.test_resources.get('Router')['physical_resource_id']
        network_id = self.test_resources.get('Network')['physical_resource_id']
        subnet_id = self.test_resources.get('Subnet')['physical_resource_id']
        body = self.ports_client.list_ports()
        ports = body['ports']
        router_ports = [port for port in ports if port['device_id'] ==
                        router_id]
        created_network_ports = [port for port in router_ports
                                 if port['network_id'] == network_id]
        self.assertEqual(1, len(created_network_ports))
        router_interface = created_network_ports[0]
        fixed_ips = router_interface['fixed_ips']
        subnet_fixed_ips = [port for port in fixed_ips if port['subnet_id'] ==
                            subnet_id]
        self.assertEqual(1, len(subnet_fixed_ips))
        router_interface_ip = subnet_fixed_ips[0]['ip_address']
        self.assertEqual(str(next(self.subnet_cidr.iter_hosts())),
                         router_interface_ip)

    @decorators.idempotent_id('75d85316-4ac2-4c0e-a1a9-edd2148fc10e')
    def test_created_server(self):
        """Verifies created sever."""
        server_id = self.test_resources.get('Server')['physical_resource_id']
        server = self.servers_client.show_server(server_id)['server']
        self.assertEqual(self.keypair_name, server['key_name'])
        self.assertEqual('ACTIVE', server['status'])
        network = server['addresses'][self.neutron_basic_template['resources'][
                                      'Network']['properties']['name']][0]
        self.assertEqual(4, network['version'])
        self.assertIn(netaddr.IPAddress(network['addr']), self.subnet_cidr)
