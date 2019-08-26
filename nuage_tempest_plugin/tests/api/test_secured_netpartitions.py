# Copyright 2017 Nokia
# All Rights Reserved.
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
from netaddr import IPNetwork

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON


class SecuredNetpartitionsTest(NuageBaseTest):

    @classmethod
    def setup_clients(cls):
        super(SecuredNetpartitionsTest, cls).setup_clients()
        cls.plugin_admin_network_client = NuageNetworkClientJSON(
            cls.os_admin.auth_provider,
            **cls.os_admin.default_params)

    @decorators.attr(type='smoke')
    def test_create_list_verify_delete_project_netpartition_mapping(self):
        name = data_utils.rand_name('np_mapping', prefix=None)
        netpart = self.plugin_network_client.create_netpartition(
            name)['net_partition']
        self.addCleanup(self.plugin_network_client.delete_netpartition,
                        netpart['id'])
        project_id = self.plugin_network_client.tenant_id
        # Create a mapping
        mapping = self.plugin_admin_network_client.\
            create_project_netpartition_mapping(
                {'project': project_id,
                 'net_partition_id': netpart['id']}
            )['project_net_partition_mapping']
        self.addCleanup(self._try_delete, self.plugin_admin_network_client.
                        delete_project_netpartition_mapping,
                        mapping['project'])
        self.assertEqual(project_id,
                         mapping['project'])
        self.assertEqual(netpart['id'], mapping['net_partition_id'])

        # List the mapping
        mappings = self.plugin_admin_network_client.\
            list_project_netpartition_mappings(
            )['project_net_partition_mappings']
        found = False
        for mapping in mappings:
            if mapping['project'] == project_id:
                self.assertEqual(netpart['id'], mapping['net_partition_id'])
                found = True
                break
        self.assertTrue(found, ('Could not find assigned project {} in '
                                'list of nuage project netpartition '
                                'mapping').format(project_id))

        # Show the mapping
        mapping = self.plugin_admin_network_client.\
            show_project_netpartition_mappings(
                project_id=project_id)['project_net_partition_mapping']
        self.assertEqual(project_id,
                         mapping['project'])
        self.assertEqual(netpart['id'], mapping['net_partition_id'])

        # Delete the mapping
        self.plugin_admin_network_client.\
            delete_project_netpartition_mapping(project_id)

        # Show the deleted mapping
        self.assertRaises(
            exceptions.NotFound,
            self.plugin_admin_network_client.
            show_project_netpartition_mappings,
            project_id)

    @decorators.attr(type='smoke')
    def test_project_netpartition_mapping_list_non_admin(self):
        name = data_utils.rand_name('np_mapping', prefix=None)
        netpart = self.plugin_network_client.create_netpartition(
            name)['net_partition']
        self.addCleanup(self.plugin_network_client.delete_netpartition,
                        netpart['id'])
        # Create a mapping
        project_admin = self.plugin_admin_network_client.tenant_id
        mapping1 = self.plugin_admin_network_client.\
            create_project_netpartition_mapping(
                {'project': project_admin,
                 'net_partition_id': netpart['id']}
            )['project_net_partition_mapping']
        self.addCleanup(self._try_delete, self.plugin_admin_network_client.
                        delete_project_netpartition_mapping,
                        mapping1['project'])
        project_user = self.plugin_network_client.tenant_id
        mapping2 = self.plugin_admin_network_client.\
            create_project_netpartition_mapping(
                {'project': project_user,
                 'net_partition_id': netpart['id']}
            )['project_net_partition_mapping']
        self.addCleanup(self._try_delete, self.plugin_admin_network_client.
                        delete_project_netpartition_mapping,
                        mapping2['project'])

        # List the mapping
        mappings = self.plugin_admin_network_client.\
            list_project_netpartition_mappings(
            )['project_net_partition_mappings']
        proj_np = {m['project']: m['net_partition_id'] for m in mappings}

        self.assertEqual(netpart['id'], proj_np.get(project_admin))
        self.assertEqual(netpart['id'], proj_np.get(project_user))

        # List mappings as non-admin user
        mappings = self.plugin_network_client.\
            list_project_netpartition_mappings(
            )['project_net_partition_mappings']
        proj_np = {m['project']: m['net_partition_id'] for m in mappings}

        self.assertNotIn(project_admin, proj_np)
        self.assertEqual(netpart['id'], proj_np.get(project_user))

    @decorators.attr(type='smoke')
    def test_project_netpartition_mapping_non_admin_neg(self):
        name = data_utils.rand_name('np_mapping', prefix=None)
        netpart = self.plugin_network_client.create_netpartition(
            name)['net_partition']
        self.addCleanup(self.plugin_network_client.delete_netpartition,
                        netpart['id'])
        project_id = self.manager.subnets_client.tenant_id
        # Create a mapping
        self.assertRaises(
            exceptions.Forbidden,
            self.plugin_network_client.create_project_netpartition_mapping,
            {'project': project_id,
             'net_partition_id': netpart['id']})

    @decorators.attr(type='smoke')
    def test_project_netpartition_mapping_update(self):
        name = data_utils.rand_name('np_mapping', prefix=None)
        netpart = self.plugin_network_client.create_netpartition(
            name)['net_partition']
        self.addCleanup(self.plugin_network_client.delete_netpartition,
                        netpart['id'])
        project_id = self.plugin_network_client.tenant_id
        # Create a mapping
        mapping = self.plugin_admin_network_client.\
            create_project_netpartition_mapping(
                {'project': project_id,
                 'net_partition_id': netpart['id']}
            )['project_net_partition_mapping']
        self.addCleanup(self._try_delete, self.plugin_admin_network_client.
                        delete_project_netpartition_mapping,
                        mapping['project'])
        self.assertEqual(project_id,
                         mapping['project'])
        self.assertEqual(netpart['id'], mapping['net_partition_id'])

        # Create new netpartition to update mapping with
        name = data_utils.rand_name('np_mapping', prefix=None)
        netpart = self.plugin_network_client.create_netpartition(
            name)['net_partition']
        self.addCleanup(self.plugin_network_client.delete_netpartition,
                        netpart['id'])
        # Update mapping
        mapping2 = self.plugin_admin_network_client.\
            create_project_netpartition_mapping(
                {'project': project_id,
                 'net_partition_id': netpart['id']}
            )['project_net_partition_mapping']
        self.assertEqual(project_id,
                         mapping2['project'])
        self.assertEqual(netpart['id'], mapping2['net_partition_id'])

        # Show the new mapping
        mapping2 = self.plugin_admin_network_client.\
            show_project_netpartition_mappings(
                project_id=project_id)['project_net_partition_mapping']
        self.assertEqual(project_id,
                         mapping2['project'])
        self.assertEqual(netpart['id'], mapping2['net_partition_id'])

    @decorators.attr(type='smoke')
    def test_create_resource_in_mapped_netpartition(self):
        name = data_utils.rand_name('np_mapping', prefix=None)

        # 1: create resources without any mapping
        network = self.create_network()
        subnet = self.create_subnet(network, no_net_partition=True)
        # Verify port creation is possible
        self.create_port(network)
        # Find subnet on VSD, use default netpartition to find it
        vsd_subnet = self.vsd.get_l2domain(
            by_network_id=network['id'],
            cidr=subnet['cidr'])
        self.assertIsNotNone(vsd_subnet, 'l2domain not found under expected, '
                                         'mapped netpartition.')
        router = self.create_router(name, no_net_partition=True)

        # Find router on VSD in default netpartition
        vsd_domain = self.vsd.get_l3domain(by_router_id=router['id'])
        self.assertIsNotNone(vsd_domain, 'l2domain not found under expected, '
                                         'mapped netpartition.')

        # 2: Create resources with a mapping
        netpart = self.plugin_network_client.create_netpartition(
            name)['net_partition']
        self.addCleanup(self.plugin_network_client.delete_netpartition,
                        netpart['id'])
        # We create subnet and router with self.manager
        project_id = self.manager.subnets_client.tenant_id
        # Create a mapping
        mapping = self.plugin_admin_network_client.\
            create_project_netpartition_mapping(
                {'project': project_id,
                 'net_partition_id': netpart['id']}
            )['project_net_partition_mapping']
        self.addCleanup(self._try_delete, self.plugin_admin_network_client.
                        delete_project_netpartition_mapping,
                        mapping['project'])

        # Create subnet as project of the mapping
        network = self.create_network()
        subnet = self.create_subnet(network, no_net_partition=True)
        # Verify port creation is possible
        self.create_port(network)
        self.assertEqual(netpart['id'], subnet['net_partition'])

        # Find subnet on VSD
        enterprise = self.vsd.get_enterprise_by_name(netpart['name'])
        vsd_subnet = self.vsd.get_l2domain(
            enterprise=enterprise,
            by_network_id=network['id'],
            cidr=subnet['cidr'])
        self.assertIsNotNone(vsd_subnet, 'l2domain not found under expected, '
                                         'mapped netpartition.')

        # Create router
        router = self.create_router(name, no_net_partition=True)
        self.assertEqual(netpart['id'], router['net_partition'])

        # Find router on VSD
        vsd_domain = self.vsd.get_l3domain(by_router_id=router['id'],
                                           enterprise=enterprise)
        self.assertIsNotNone(vsd_domain, 'l2domain not found under expected, '
                                         'mapped netpartition.')

        # 3: Create resources without any mapping again
        # Remove mapping
        self.plugin_admin_network_client.delete_project_netpartition_mapping(
            mapping['project'])
        # Create subnet as project of the deleted mapping
        network = self.create_network()
        subnet = self.create_subnet(network, no_net_partition=True)
        # Verify port creation is possible
        self.create_port(network)
        # Find subnet on VSD, use default netpartition to find it
        vsd_subnet = self.vsd.get_l2domain(
            by_network_id=network['id'],
            cidr=subnet['cidr'])
        self.assertIsNotNone(vsd_subnet, 'l2domain not found under expected, '
                                         'mapped netpartition.')
        router = self.create_router(name, no_net_partition=True)

        # Find router on VSD in default netpartition
        vsd_domain = self.vsd.get_l3domain(by_router_id=router['id'])
        self.assertIsNotNone(vsd_domain, 'l2domain not found under expected, '
                                         'mapped netpartition.')

    @decorators.attr(type='smoke')
    def test_project_netpartition_mapping_vsd_managed(self):
        name = data_utils.rand_name('np_mapping', prefix=None)
        netpart = self.plugin_network_client.create_netpartition(
            name)['net_partition']
        self.addCleanup(self.plugin_network_client.delete_netpartition,
                        netpart['id'])
        # Create a mapping
        project_id = self.manager.subnets_client.tenant_id
        mapping = self.plugin_admin_network_client.\
            create_project_netpartition_mapping(
                {'project': project_id,
                 'net_partition_id': netpart['id']}
            )['project_net_partition_mapping']
        self.addCleanup(self._try_delete, self.plugin_admin_network_client.
                        delete_project_netpartition_mapping,
                        mapping['project'])

        # Create VSD managed resources
        enterprise = self.vsd.get_enterprise_by_name(netpart['name'])

        # l3
        vsd_l3dom_tmplt = self.vsd.create_l3domain_template(
            name=name, enterprise=enterprise)
        self.addCleanup(self.vsd.delete_l3domain_template,
                        vsd_l3dom_tmplt.id)
        vsd_l3dom = self.vsd.create_domain(
            name=name, enterprise=enterprise,
            template_id=vsd_l3dom_tmplt.id)
        self.addCleanup(self.vsd.delete_domain, vsd_l3dom.id)
        vsd_zone = self.vsd.create_zone(
            name=name, domain=vsd_l3dom)
        cidr = IPNetwork('40.40.40.0/24')
        gateway = '40.40.40.1'
        vsd_subnet = self.vsd.create_subnet(
            name=name,
            zone=vsd_zone,
            cidr4=cidr,
            gateway=gateway)
        self.addCleanup(self.vsd.delete_subnet, vsd_subnet.id)
        network = self.create_network(name)
        subnet = self.create_subnet(network,
                                    cidr=cidr,
                                    mask_bits=24,
                                    nuagenet=vsd_subnet.id,
                                    no_net_partition=True)
        self.assertIsNotNone(subnet)

        # l2
        cidr = IPNetwork('50.50.50.0/24')
        gateway = '50.50.50.1'
        vsd_l2dom_tmplt = self.vsd.create_l2domain_template(
            name=name, enterprise=enterprise,
            dhcp_managed=True, cidr4=cidr, gateway4=gateway)
        self.addCleanup(self.vsd.delete_l2domain_template, vsd_l2dom_tmplt.id)
        vsd_l2dom = self.vsd.create_l2domain(
            name=name, enterprise=enterprise, template=vsd_l2dom_tmplt)
        self.addCleanup(self.vsd.delete_l2domain, vsd_l2dom.id)
        network = self.create_network(name)
        subnet = self.create_subnet(
            network, cidr=cidr,
            mask_bits=24, gateway=None,
            nuagenet=vsd_l2dom.id,
            no_net_partition=True)
        self.assertIsNotNone(subnet)

    @decorators.attr(type='smoke')
    def test_project_netpartition_mapping_vsd_managed_neg(self):
        name = data_utils.rand_name('np_mapping', prefix=None)
        netpart = self.plugin_network_client.create_netpartition(
            name)['net_partition']
        self.addCleanup(self.plugin_network_client.delete_netpartition,
                        netpart['id'])
        # Create a mapping
        project_id = self.manager.subnets_client.tenant_id
        mapping = self.plugin_admin_network_client.\
            create_project_netpartition_mapping(
                {'project': project_id,
                 'net_partition_id': netpart['id']}
            )['project_net_partition_mapping']
        self.addCleanup(self._try_delete, self.plugin_admin_network_client.
                        delete_project_netpartition_mapping,
                        mapping['project'])

        # Create VSD managed resources in default enterprise instead of mapped
        enterprise = self.vsd.get_default_enterprise()

        # l3
        vsd_l3dom_tmplt = self.vsd.create_l3domain_template(
            name=name, enterprise=enterprise)
        self.addCleanup(self.vsd.delete_l3domain_template,
                        vsd_l3dom_tmplt.id)
        vsd_l3dom = self.vsd.create_domain(
            name=name, enterprise=enterprise,
            template_id=vsd_l3dom_tmplt.id)
        self.addCleanup(self.vsd.delete_domain, vsd_l3dom.id)
        vsd_zone = self.vsd.create_zone(
            name=name, domain=vsd_l3dom)
        cidr = IPNetwork('40.40.40.0/24')
        gateway = '40.40.40.1'
        vsd_subnet = self.vsd.create_subnet(
            name=name,
            zone=vsd_zone,
            cidr4=cidr,
            gateway=gateway)
        self.addCleanup(self.vsd.delete_subnet, vsd_subnet.id)
        network = self.create_network(name)
        self.assertRaises(exceptions.BadRequest,
                          self.create_subnet,
                          network,
                          cidr=cidr,
                          mask_bits=24,
                          nuagenet=vsd_subnet.id,
                          no_net_partition=True)

        # l2
        cidr = IPNetwork('50.50.50.0/24')
        gateway = '50.50.50.1'
        vsd_l2dom_tmplt = self.vsd.create_l2domain_template(
            name=name, enterprise=enterprise,
            dhcp_managed=True, cidr4=cidr, gateway4=gateway)
        self.addCleanup(self.vsd.delete_l2domain_template, vsd_l2dom_tmplt.id)
        vsd_l2dom = self.vsd.create_l2domain(
            name=name, enterprise=enterprise, template=vsd_l2dom_tmplt)
        self.addCleanup(self.vsd.delete_l2domain, vsd_l2dom.id)
        self.assertRaises(exceptions.BadRequest,
                          self.create_subnet,
                          network, cidr=cidr,
                          mask_bits=24, gateway=None,
                          nuagenet=vsd_l2dom.id,
                          no_net_partition=True)
