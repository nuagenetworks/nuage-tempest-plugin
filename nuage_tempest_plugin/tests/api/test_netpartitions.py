# Copyright 2014 OpenStack Foundation
# All Rights Reserved.
#
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

from tempest.api.network import base
from tempest.lib.common.utils.data_utils import rand_name
from tempest.test import decorators

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.lib.utils import exceptions
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

LOG = Topology.get_logger(__name__)


class NetPartitionTestJSON(base.BaseNetworkTest):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(NetPartitionTestJSON, cls).setup_clients()
        cls.client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)
        cls.nuageclient = NuageRestClient()

    @classmethod
    def setUpClass(cls):
        super(NetPartitionTestJSON, cls).setUpClass()
        cls.net_partitions = []

    @classmethod
    def resource_cleanup(cls):
        super(NetPartitionTestJSON, cls).resource_cleanup()
        has_exception = False

        for netpartition in cls.net_partitions:
            try:
                cls.client.delete_netpartition(netpartition['id'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        if has_exception:
            raise exceptions.TearDownException()

    @classmethod
    def create_netpartition(cls, np_name=None):
        """Wrapper utility that returns a test network."""
        np_name = np_name or rand_name('tempest-np-')

        body = cls.client.create_netpartition(np_name)
        netpartition = body['net_partition']
        cls.net_partitions.append(netpartition)
        return netpartition

    @decorators.attr(type='smoke')
    def test_create_list_verify_delete_netpartition(self):
        name = rand_name('tempest-np')
        body = self.client.create_netpartition(name)
        self.assertEqual('201', body.response['status'])
        netpart = body['net_partition']
        self.assertEqual(name, netpart['name'])
        if Topology.within_ext_id_release():
            net_partition = self.nuageclient.get_global_resource(
                resource=n_constants.NET_PARTITION,
                filters='externalID',
                filter_value=netpart['id'] + '@openstack')
            self.assertEqual(name, net_partition[0]['name'])
            default_l2dom_template = self.nuageclient.get_resource(
                resource=n_constants.L2_DOMAIN_TEMPLATE,
                filters='externalID',
                filter_value=netpart['id'] + '@openstack',
                netpart_name=name)
            self.assertIsNot(default_l2dom_template, "", "Default L2Domain "
                                                         "Template Not Found")
            default_dom_template = self.nuageclient.get_resource(
                resource=n_constants.DOMAIN_TEMPLATE,
                filters='externalID',
                filter_value=netpart['id'] + '@openstack',
                netpart_name=name)
            self.assertIsNot(default_dom_template, "", "Default Domain "
                                                       "Template Not Found")
            zone_templates = self.nuageclient.get_child_resource(
                resource=n_constants.DOMAIN_TEMPLATE,
                resource_id=default_dom_template[0]['ID'],
                child_resource=n_constants.ZONE_TEMPLATE,
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
