# Copyright 2016 NOKIA
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

import random
import uuid

from tempest.api.network import base
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

LOG = Topology.get_logger(__name__)


class FloatingIPTestAdminNuage(base.BaseAdminNetworkTest):

    @classmethod
    def setup_clients(cls):
        super(FloatingIPTestAdminNuage, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

        # Overriding cls.client with Nuage network client
        cls.client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)

    @classmethod
    def resource_setup(cls):
        super(FloatingIPTestAdminNuage, cls).resource_setup()
        # resources required for uplink subnet
        cls.gateway = None
        cls.gateway_port = None
        cls.gateway_vlan = None
        cls.uplink_subnet = None

    @classmethod
    def resource_cleanup(cls):
        if cls.uplink_subnet:
            cls.nuage_client.delete_uplink_subnet(
                cls.uplink_subnet[0]['ID'])
        if cls.gateway_vlan:
            cls.nuage_client.delete_gateway_vlan(cls.gateway_vlan[0]['ID'])
        if cls.gateway_port:
            cls.nuage_client.delete_gateway_port(cls.gateway_port[0]['ID'])
        if cls.gateway:
            cls.nuage_client.delete_gateway(cls.gateway[0]['ID'])
        super(FloatingIPTestAdminNuage, cls).resource_cleanup()

    @classmethod
    def create_gateway_port_vlan(cls, gw_type='VRSG', vlan_no=200):
        gw_name = data_utils.rand_name('gw-')
        cls.gateway = cls.nuage_client.create_gateway(
            gw_name, str(uuid.uuid4()), gw_type, None)
        gw_port_name = data_utils.rand_name('gw-port-')
        cls.gateway_port = cls.nuage_client.create_gateway_port(
            gw_port_name, 'test', 'ACCESS', cls.gateway[0]['ID'])
        cls.gateway_vlan = cls.nuage_client.create_gateway_vlan(
            cls.gateway_port[0]['ID'], 'test', vlan_no)
        shared_enterprises = cls.nuage_client.get_net_partition(
            'Shared Infrastructure')
        if len(shared_enterprises) != 0:
            cls.nuage_client.create_vlan_permission(
                cls.gateway_vlan[0]['ID'],
                shared_enterprises[0]['ID'])

    def create_uplink_subnet(self, parent_id=None):
        uplink_subnet_dict = {
            'name': "uplink-sub1",
            'address': "210.20.0.0",
            'netmask': "255.255.255.0",
            'gateway': '210.20.0.1',
            'uplinkVportName': 'vlan1',
            'uplinkInterfaceIP': '210.20.0.2',
            'uplinkInterfaceMAC': "00:11:22:33:44:55",
            'uplinkGWVlanAttachmentID': self.gateway_vlan[0]['ID'],
            'sharedResourceParentID': parent_id
        }
        uplink_subnet = self.nuage_client.create_uplink_subnet(
            **uplink_subnet_dict)
        self.addCleanup(self.delete_uplink_subnet, str(uplink_subnet[0]['ID']))
        return uplink_subnet

    def delete_uplink_subnet(self, subnet_id):
        return self.nuage_client.delete_uplink_subnet(subnet_id)

    def create_fip_subnet(self, cidr, nuage_uplink=None):
        name = data_utils.rand_name('network-')
        kwargs = {'name': name,
                  'router:external': True}
        body = self.admin_networks_client.create_network(**kwargs)
        pubnet = body['network']
        self.addCleanup(
            self.admin_networks_client.delete_network, pubnet['id'])
        fipsub_name = data_utils.rand_name('fipsub-')
        kwargs = {'name': fipsub_name,
                  'network_id': pubnet['id'],
                  'ip_version': 4,
                  'cidr': cidr}
        if nuage_uplink:
            kwargs.update({'nuage_uplink': nuage_uplink})
        body = self.admin_subnets_client.create_subnet(**kwargs)
        self.assertEqual(fipsub_name, body['subnet']['name'])
        self.assertEqual(cidr, body['subnet']['cidr'])
        return body['subnet']

    def delete_fip_subnet(self, fip_sub_id):
        try:
            self.admin_subnets_client.delete_subnet(fip_sub_id)
        except Exception as exc:
            LOG.exception(exc)

    @decorators.attr(type='smoke')
    def test_create_fipsubs_in_shared_domain(self):
        # Create first FIP subnet
        cidr1 = "172.%s.%s.0/24" % (random.randint(0, 255),
                                    random.randint(0, 255))
        fipsub1 = self.create_fip_subnet(cidr1)
        self.addCleanup(self.delete_fip_subnet, fipsub1['id'])

        # Get FIP parentID
        fip_extID = self.nuage_client.get_vsd_external_id(fipsub1['id'])
        nuage_fipsubnet1 = self.nuage_client.get_sharedresource(
            filters='externalID', filter_value=fip_extID)
        self.assertEqual(fipsub1['id'], nuage_fipsubnet1[0]['name'])

        # Create uplink subnet on VSD
        self.create_gateway_port_vlan()

        uplink_subnet = self.create_uplink_subnet(
            nuage_fipsubnet1[0]['parentID'])

        # Verify the uplink-subnet parentID with the FIPsubnet parentID
        self.assertEqual(nuage_fipsubnet1[0]['parentID'],
                         uplink_subnet[0]['sharedResourceParentID'])
        # Create FIP subnet with nuage_uplink option
        cidr2 = "198.%s.%s.0/24" % (random.randint(0, 255),
                                    random.randint(0, 255))
        fipsub2 = self.create_fip_subnet(cidr2,
                                         nuage_fipsubnet1[0]['parentID'])
        self.addCleanup(self.delete_fip_subnet, fipsub2['id'])
        fip_ext_id = self.nuage_client.get_vsd_external_id(fipsub2['id'])
        nuage_fipsubnet2 = self.nuage_client.get_sharedresource(
            filters='externalID', filter_value=fip_ext_id)
        self.assertEqual(fipsub2['id'], nuage_fipsubnet2[0]['name'])
        self.assertEqual(nuage_fipsubnet1[0]['parentID'],
                         nuage_fipsubnet2[0]['parentID'])
        # self.delete_gateway_port_vlan()

    @decorators.attr(type='smoke')
    def test_show_fipsubs_in_shared_domain(self):
        cidr = "172.%s.%s.0/24" % (random.randint(0, 255),
                                   random.randint(0, 255))

        fipsub = self.create_fip_subnet(cidr)
        self.addCleanup(self.delete_fip_subnet, fipsub['id'])
        # Check the nuage_uplink field in subnet-show
        body = self.admin_subnets_client.show_subnet(fipsub['id'])
        fipsub_show = body['subnet']
        # Get FIP parentID in VSD
        fip_extID = self.nuage_client.get_vsd_external_id(fipsub['id'])
        nuage_fipsubnet = self.nuage_client.get_sharedresource(
            filters='externalID', filter_value=fip_extID)
        self.assertEqual(fipsub_show['id'], nuage_fipsubnet[0]['name'])
        self.assertEqual(fipsub_show['nuage_uplink'],
                         nuage_fipsubnet[0]['parentID'])

    def test_fipsubs_in_shared_domain_negative(self):
        # Create fipsub with invalid UUID for nuage_uplink
        name = data_utils.rand_name('network-')
        kwargs = {'name': name,
                  'router:external': True}
        body = self.admin_networks_client.create_network(**kwargs)
        pubnet = body['network']
        self.addCleanup(self.admin_networks_client.delete_network,
                        pubnet['id'])
        fipsub_name = data_utils.rand_name('fipsub-')
        kwargs = {'name': fipsub_name,
                  'network_id': pubnet['id'],
                  'ip_version': 4,
                  'cidr': '160.60.0.0/24',
                  'nuage_uplink': '111111111'}
        self.assertRaises(exceptions.BadRequest,
                          self.admin_subnets_client.create_subnet,
                          **kwargs)

        # Creation FIP subnet with same cidr and nuage_uplink should fail
        fipsub1 = self.create_fip_subnet('172.40.0.0/24')
        self.addCleanup(self.delete_fip_subnet, fipsub1['id'])
        fip_ext_id = self.nuage_client.get_vsd_external_id(fipsub1['id'])
        nuage_fipsubnet1 = self.nuage_client.get_sharedresource(
            filters='externalID', filter_value=fip_ext_id)

        kwargs = {'name': fipsub_name,
                  'network_id': pubnet['id'],
                  'ip_version': 4,
                  'cidr': '172.40.0.0/24',
                  'nuage_uplink': nuage_fipsubnet1[0]['parentID']}
        if Topology.from_openstack('Newton') and Topology.is_ml2:
            self.assertRaisesRegex(
                exceptions.BadRequest,
                "Network 172.40.0.0/255.255.255.0 overlaps with "
                "existing network ",
                self.admin_subnets_client.create_subnet, **kwargs)
        else:
            self.assertRaisesRegex(
                exceptions.ServerFault,
                "Network 172.40.0.0/255.255.255.0 overlaps with "
                "existing network ",
                self.admin_subnets_client.create_subnet, **kwargs)

    def test_fipsub_with_nuage_uplink_and_uplinksub_no_parent_id(self):
        self.skipTest("TODO(KRIS) FIXME getting:Cannot find zone with ID None")

        # Create gateway, port and vlan on VSD
        self.create_gateway_port_vlan()
        # Create uplink subnet without passing parentID
        uplink_subnet = self.create_uplink_subnet()

        fipsub1 = self.create_fip_subnet('172.40.0.0/24',
                                         uplink_subnet[0]['parentID'])
        self.addCleanup(self.delete_fip_subnet, fipsub1['id'])
        fip_ext_id = self.nuage_client.get_vsd_external_id(fipsub1['id'])
        nuage_fipsubnet1 = self.nuage_client.get_sharedresource(
            filters='externalID', filter_value=fip_ext_id)
        self.assertEqual(fipsub1['id'], nuage_fipsubnet1[0]['name'])
        self.assertEqual(uplink_subnet[0]['parentID'],
                         nuage_fipsubnet1[0]['parentID'])
