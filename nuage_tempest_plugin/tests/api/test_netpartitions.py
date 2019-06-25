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

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.test.nuage_test import NuageAdminNetworksTest
from nuage_tempest_plugin.lib.test import vsd_helper
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.lib.utils import data_utils as nuage_data_utils
from nuage_tempest_plugin.services import nuage_client
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON


class NetpartitionsTest(NuageAdminNetworksTest):

    shared_infrastructure = 'Shared Infrastructure'

    @classmethod
    def setup_clients(cls):
        super(NetpartitionsTest, cls).setup_clients()
        cls.client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)
        cls.nuage_client = nuage_client.NuageRestClient()
        cls.vsd = vsd_helper.VsdHelper()

    @classmethod
    def setup_credentials(cls):
        # Create no network resources for these tests.
        cls.set_network_resources()
        super(NetpartitionsTest, cls).setup_credentials()

    def _create_network(self, external=True):
        post_body = {'name': data_utils.rand_name('network-')}
        if external:
            post_body['router:external'] = external
        body = self.admin_networks_client.create_network(**post_body)
        network = body['network']
        self.addCleanup(self.admin_networks_client.delete_network,
                        network['id'])
        return network

    def create_netpartition(self, name):
        body = self.client.create_netpartition(name)
        self.assertEqual('201', body.response['status'])
        netpart = body['net_partition']
        self.assertEqual(name, netpart['name'])
        return netpart

    @decorators.attr(type='smoke')
    def test_create_list_verify_delete_netpartition(self):
        name = data_utils.rand_name('tempest-np')
        netpart = self.create_netpartition(name)
        if Topology.within_ext_id_release():
            net_partition = self.nuage_client.get_global_resource(
                resource=constants.NET_PARTITION,
                filters='externalID',
                filter_value=name + '@openstack')
            self.assertEqual(name, net_partition[0]['name'])
            default_l2dom_template = self.nuage_client.get_resource(
                resource=constants.L2_DOMAIN_TEMPLATE,
                filters='externalID',
                filter_value=netpart['id'] + '@openstack',
                netpart_name=name)
            self.assertIsNot(default_l2dom_template, "", "Default L2Domain "
                                                         "Template Not Found")
            default_dom_template = self.nuage_client.get_resource(
                resource=constants.DOMAIN_TEMPLATE,
                filters='externalID',
                filter_value=netpart['id'] + '@openstack',
                netpart_name=name)
            self.assertIsNot(default_dom_template, "", "Default Domain "
                                                       "Template Not Found")
            zone_templates = self.nuage_client.get_child_resource(
                resource=constants.DOMAIN_TEMPLATE,
                resource_id=default_dom_template[0]['ID'],
                child_resource=constants.ZONE_TEMPLATE,
                filters='externalID',
                filter_value=netpart['id'] + '@openstack')
            self.assertEqual(2, len(zone_templates))
        body = self.client.list_netpartition()
        netpartition_idlist = list()
        netpartition_namelist = list()
        for netpartition in body['net_partitions']:
            netpartition_idlist.append(netpartition['id'])
            netpartition_namelist.append(netpartition['name'])
        self.assertIn(netpart['id'], netpartition_idlist)
        self.assertIn(netpart['name'], netpartition_namelist)
        body = self.client.delete_netpartition(netpart['id'])
        self.assertEqual('204', body.response['status'])

    @decorators.attr(type='smoke')
    def test_shared_infrastructure(self):
        # check the shared infrastructure is added to neutron DB
        shared_netpart = self.nuage_client.get_net_partition(
            self.shared_infrastructure)[0]
        self.assertEqual(self.shared_infrastructure, shared_netpart['name'])
        netparts = self.client.list_netpartition_by_name(
            self.shared_infrastructure)
        self.assertEqual(1, len(netparts))
        # create shared infrastructure
        name = self.shared_infrastructure
        netpart = self.create_netpartition(name)
        self.assertEqual(shared_netpart['ID'], netpart['id'])
        netparts = self.client.list_netpartition_by_name(
            self.shared_infrastructure)
        self.assertEqual(1, len(netparts))

    @decorators.attr(type='smoke')
    def test_create_external_subnet_within_custom_netpartition(self):
        ext_network = self._create_network(external=True)
        netpart_name = data_utils.rand_name('netpart')
        netpart = self.create_netpartition(netpart_name)
        self.addCleanup(self.client.delete_netpartition,
                        netpart['id'])
        kwargs = {
            "network_id": ext_network['id'],
            "cidr": nuage_data_utils.gimme_a_cidr_address(),
            "ip_version": self._ip_version,
            "net_partition": netpart['name']
        }
        ext_subnet = self.admin_subnets_client.create_subnet(
            **kwargs)['subnet']
        self.addCleanup(self.admin_subnets_client.delete_subnet,
                        ext_subnet['id'])
        # check the vsd
        nuage_subnet = self.vsd.get_subnet(
            by_network_id=ext_subnet['network_id'],
            cidr=ext_subnet['cidr'])
        l3domain = self.vsd.get_l3_domain_by_network_id_and_cidr(
            ext_subnet['network_id'],
            ext_subnet['cidr'])
        self.assertEqual(ext_network['id'] + '_' + ext_subnet['id'],
                         nuage_subnet.name)
        shared_netpart_id = self.nuage_client.get_net_partition(
            self.shared_infrastructure)[0]['ID']
        self.assertEqual(shared_netpart_id, l3domain.parent_id)

    @decorators.attr(type='smoke')
    def test_create_internal_subnet_within_custom_netpartition(self):
        int_network = self._create_network(external=False)
        netpart_name = data_utils.rand_name('netpart')
        netpart = self.create_netpartition(netpart_name)
        self.addCleanup(self.client.delete_netpartition,
                        netpart['id'])
        kwargs = {
            "network_id": int_network['id'],
            "cidr": nuage_data_utils.gimme_a_cidr_address(),
            "ip_version": self._ip_version,
            "net_partition": netpart['name']
        }
        int_subnet = self.admin_subnets_client.create_subnet(
            **kwargs)['subnet']
        self.addCleanup(self.admin_subnets_client.delete_subnet,
                        int_subnet['id'])
        # check the vsd
        nuage_l2dom = self.vsd.get_l2domain(
            enterprise=netpart['name'],
            by_network_id=int_subnet['network_id'],
            cidr=int_subnet['cidr'])
        self.assertEqual(int_network['id'] + '_' + int_subnet['id'],
                         nuage_l2dom.name)
        self.assertEqual(netpart['id'], nuage_l2dom.parent_id)

    @decorators.attr(type='smoke')
    def test_create_router_within_custom_netpartition(self):
        netpart_name = data_utils.rand_name('netpart')
        netpart = self.create_netpartition(netpart_name)
        self.addCleanup(self.client.delete_netpartition,
                        netpart['id'])
        kwargs = {
            'name': data_utils.rand_name('router'),
            'admin_state_up': True,
            'net_partition': netpart['name']
        }
        # Create router in that net-partition
        router = self.admin_routers_client.create_router(**kwargs)['router']
        self.addCleanup(self.admin_routers_client.delete_router,
                        router['id'])

        # Verify Router is created in correct net-partition
        nuage_domain = self.vsd.get_l3domain(enterprise=netpart['name'],
                                             by_router_id=router['id'])
        self.assertEqual(router['id'], nuage_domain.name)
        self.assertEqual(netpart['id'],
                         nuage_domain.parent_id)

    def test_create_external_subnet_within_shared_netpartition(self):
        ext_network = self._create_network(external=True)
        kwargs = {
            "network_id": ext_network['id'],
            "cidr": nuage_data_utils.gimme_a_cidr_address(),
            "ip_version": self._ip_version,
            "net_partition": self.shared_infrastructure
        }
        ext_subnet = self.admin_subnets_client.create_subnet(
            **kwargs)['subnet']
        self.addCleanup(self.admin_subnets_client.delete_subnet,
                        ext_subnet['id'])
        # check the vsd
        nuage_subnet = self.vsd.get_subnet(
            by_network_id=ext_subnet['network_id'],
            cidr=ext_subnet['cidr'])
        l3domain = self.vsd.get_l3_domain_by_network_id_and_cidr(
            ext_subnet['network_id'],
            ext_subnet['cidr'])
        self.assertEqual(ext_network['id'] + '_' + ext_subnet['id'],
                         nuage_subnet.name)
        shared_netpart_id = self.nuage_client.get_net_partition(
            self.shared_infrastructure)[0]['ID']
        self.assertEqual(shared_netpart_id, l3domain.parent_id)

    def test_create_internal_within_shared_netpartition(self):
        netpart_name = self.shared_infrastructure
        msg = ("It is not allowed to create OpenStack managed subnets "
               "in the net_partition {}").format(netpart_name)
        int_net = self._create_network(external=False)
        cidr = nuage_data_utils.gimme_a_cidr_address()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            msg,
            self.admin_subnets_client.create_subnet,
            network_id=int_net['id'],
            cidr=cidr,
            ip_version=self._ip_version,
            net_partition=netpart_name)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            msg,
            self.admin_subnets_client.create_subnet,
            network_id=int_net['id'],
            cidr='fee::/64',
            ip_version=6,
            net_partition=netpart_name)

    def test_create_external_subnet_within_non_existent_netpartition(self):
        ext_network = self._create_network(external=True)
        netpart_name = data_utils.rand_name('nonexistent-netpart')
        kwargs = {
            "network_id": ext_network['id'],
            "cidr": nuage_data_utils.gimme_a_cidr_address(),
            "ip_version": self._ip_version,
            "net_partition": netpart_name
        }
        ext_subnet = self.admin_subnets_client.create_subnet(
            **kwargs)['subnet']
        self.addCleanup(self.admin_subnets_client.delete_subnet,
                        ext_subnet['id'])
        # check the vsd
        nuage_subnet = self.vsd.get_subnet(
            by_network_id=ext_subnet['network_id'],
            cidr=ext_subnet['cidr'])
        l3domain = self.vsd.get_l3_domain_by_network_id_and_cidr(
            ext_subnet['network_id'],
            ext_subnet['cidr'])
        self.assertEqual(ext_network['id'] + '_' + ext_subnet['id'],
                         nuage_subnet.name)
        shared_netpart_id = self.nuage_client.get_net_partition(
            self.shared_infrastructure)[0]['ID']
        self.assertEqual(shared_netpart_id, l3domain.parent_id)

    def test_create_internal_subnet_within_non_existent_netpartition(self):
        int_network = self._create_network(external=False)
        netpart_name = data_utils.rand_name('nonexistent-netpart')
        msg = "Net-partition {} does not exist".format(netpart_name)
        kwargs = {
            "network_id": int_network['id'],
            "cidr": nuage_data_utils.gimme_a_cidr_address(),
            "ip_version": self._ip_version,
            "net_partition": netpart_name
        }
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.admin_subnets_client.create_subnet,
                               **kwargs)

    def test_create_router_within_non_existent_netpartition(self):
        netpart_name = data_utils.rand_name('nonexistent-netpart')
        msg = "Net-partition {} does not exist".format(netpart_name)
        netpart = {
            "net_partition": netpart_name
        }
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.admin_routers_client.create_router,
                               name=data_utils.rand_name('router'),
                               admin_state_up=True,
                               **netpart)
