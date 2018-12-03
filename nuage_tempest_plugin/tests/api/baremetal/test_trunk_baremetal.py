# Copyright 2017 NOKIA
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

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from nuage_commons import constants

from nuage_tempest_lib.common.base_mixin import NuageBaseMixin
from nuage_tempest_lib.vsdclient.nuage_client import NuageRestClient

from nuage_tempest_plugin.mixins import l3
from nuage_tempest_plugin.mixins import network as network_mixin
from nuage_tempest_plugin.mixins import sg as sg_mixin

CONF = config.CONF


class BaremetalTrunkTest(network_mixin.NetworkMixin,
                         l3.L3Mixin, sg_mixin.SGMixin, NuageBaseMixin):
    credentials = ['admin']

    @classmethod
    def setUpClass(cls):
        super(BaremetalTrunkTest, cls).setUpClass()
        if (CONF.nuage_sut.nuage_baremetal_driver ==
                constants.BAREMETAL_DRIVER_BRIDGE):
            cls.expected_vport_type = constants.VPORT_TYPE_BRIDGE
        elif (CONF.nuage_sut.nuage_baremetal_driver ==
              constants.BAREMETAL_DRIVER_HOST):
            cls.expected_vport_type = constants.VPORT_TYPE_HOST
        else:
            raise Exception("Unexpected configuration of "
                            "'nuage_baremetal_driver'")
        cls.expected_vlan_normal = 0
        cls.expected_vlan_transparent = 4095

    @classmethod
    def skip_checks(cls):
        super(BaremetalTrunkTest, cls).skip_checks()
        if not CONF.service_available.neutron:
            # this check prevents this test to be run in unittests
            raise cls.skipException("Neutron support is required")

    @classmethod
    def setup_clients(cls):
        super(BaremetalTrunkTest, cls).setup_clients()
        cls.vsd_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(BaremetalTrunkTest, cls).resource_setup()
        # Only gateway here, to support parallel testing each test makes its
        # own gateway port so no VLAN overlap should occur.
        cls.gateway = cls.vsd_client.create_gateway(
            data_utils.rand_name(name='vsg'),
            data_utils.rand_name(name='sys_id'), 'VSG')[0]

    @classmethod
    def resource_cleanup(cls):
        super(BaremetalTrunkTest, cls).resource_cleanup()
        cls.vsd_client.delete_gateway(cls.gateway['ID'])

    def setUp(self):
        self.name = data_utils.rand_name("test_trunk_baremetal")
        super(BaremetalTrunkTest, self).setUp()
        gw_port_name = data_utils.rand_name(name='gw-port')
        self.gw_port = self.vsd_client.create_gateway_port(
            gw_port_name, gw_port_name, 'ACCESS', self.gateway['ID'],
            extra_params={'VLANRange': '0-4095'})[0]
        self.parent_network = self.create_network(name="parent " + self.name)
        self.parent_subnet = self.create_subnet('10.20.30.0/24',
                                                self.parent_network['id'],
                                                name="parent " + self.name)
        self.security_group = self.create_security_group(name=self.name)
        self.binding_data = {
            'binding:host_id': 'dummy', 'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port['name'],
                     "switch_info": self.gateway['systemID']}]
            }}
        self.unbinding_data = {
            'binding:host_id': None,
            'binding:profile': None,
            'device_owner': ''
        }

    def _get_vsd_vport(self, port, router, subnet):
        if router:
            parent_resource = constants.SUBNETWORK
        else:
            parent_resource = constants.L2_DOMAIN
        vsd_vport_parent = self.vsd_client.get_global_resource(
            parent_resource,
            filters='externalID',
            filter_value=subnet['id'])[0]

        vsd_vports = self.vsd_client.get_vport(
            parent_resource,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        if vsd_vports:
            return vsd_vports[0]
        else:
            return None

    def _get_vsd_vlan(self, vport):
        vsd_vlan = self.vsd_client.get_bridge_port_gateway_vlan(vport)
        return vsd_vlan[0]

    @decorators.attr(type='smoke')
    def test_single_subport_l2(self):
        self._test_trunking(router=False, number_subports=1)

    def test_multiple_subports_l2(self):
        self._test_trunking(router=False, number_subports=2)

    @decorators.attr(type='smoke')
    def test_single_subport_l3(self):
        self._test_trunking(router=True, number_subports=1)

    def test_multiple_subport_l3(self):
        self._test_trunking(router=True, number_subports=2)

    @decorators.attr(type=['negative'])
    def test_single_subport_negative_same_vlan(self):
        self.assertRaises(exceptions.BadRequest,
                          self._test_trunking,
                          router=False, number_subports=1,
                          segmentation_ids=[0])

    @decorators.attr(type=['negative'])
    def test_single_subport_negative_vlan_transparent(self):
        # the network of the parent port cannot be vlan transparent

        temp_network = self.parent_network
        temp_subnet = self.parent_subnet
        try:
            self.parent_network = self.create_network(name="vlan_transparent",
                                                      vlan_transparent=True)
            self.parent_subnet = self.create_subnet(
                '10.20.30.0/24',
                self.parent_network['id'],
                name="vlan_transparent parent")

            self.assertRaises(exceptions.BadRequest,
                              self._test_trunking,
                              router=False, number_subports=1,
                              segmentation_ids=[0])
        finally:
            self.parent_network = temp_network
            self.parent_subnet = temp_subnet

    @decorators.attr(type=['negative'])
    def test_single_subport_negative_no_subnet(self):
        # Note: this test currently seems to fail at the wrong time
        # The parent port must have a fixed ip
        self.delete_subnet(self.parent_subnet['id'])
        try:
            self.assertRaises(exceptions.BadRequest,
                              self._test_trunking,
                              router=False, number_subports=1,
                              segmentation_ids=[0])
        finally:
            self.parent_subnet = self.create_subnet('10.20.30.0/24',
                                                    self.parent_network['id'],
                                                    name="parent " + self.name)

    @decorators.attr(type=['negative'])
    def test_single_subport_negative_different_vnic(self):
        # A subport must have the same vnic type as the parent
        self.assertRaises(exceptions.Conflict,
                          self._test_trunking,
                          router=False, number_subports=1,
                          vnic_type_sub='normal')

    @decorators.attr(type=['negative'])
    def test_single_subport_negative_same_network(self):
        # A subport cannot be on the same network as the parent port
        self.assertRaises(exceptions.Conflict,
                          self._test_trunking,
                          router=False, number_subports=1,
                          create_subnets=False)

    def _test_trunking(self, router, number_subports, segmentation_ids=None,
                       vnic_type_sub=None, create_subnets=True):
        if router:
            router = self.create_router(name='router ' + self.name)
            self.add_router_interface(router['id'], self.parent_subnet['id'])
        create_data = {'security_groups': [self.security_group['id']],
                       'binding:vnic_type': 'baremetal'}
        parent = self.create_port(self.parent_network['id'], **create_data)
        subports = []
        if vnic_type_sub:
            create_data['binding:vnic_type'] = vnic_type_sub
        for i in range(number_subports):
            if not create_subnets:
                network = self.parent_network
                subnet = self.parent_subnet
            else:
                network = self.create_network(name="sub " + self.name)
                subnet = self.create_subnet('11.21.31.0/24',
                                            network['id'],
                                            name="sub " + self.name)
            if router:
                router_sub = self.create_router(name='sub_router ' + self.name)
                self.add_router_interface(router_sub['id'], subnet['id'])
            else:
                router_sub = None
            port = self.create_port(network['id'], **create_data)
            if segmentation_ids:
                segmentation_id = segmentation_ids[i]
            else:
                segmentation_id = i + 10
            subports.append({'network': network,
                             'subnet': subnet,
                             'port': port,
                             'segmentation_id': segmentation_id,
                             'router': router_sub})
        create_data = {
            'name': self.name
        }
        trunk = self.create_trunk(
            parent_port_id=parent['id'],
            subports=None,
            **create_data
        )

        for i in range(number_subports):
            subport = {
                'port_id': subports[i]['port']['id'],
                'segmentation_type': 'vlan',
                'segmentation_id': subports[i]['segmentation_id']
            }
            self.add_subports(trunk['id'], [subport])
            self.assertEqual(
                'trunk:subport',
                self.get_port(subports[i]['port']['id'])['device_owner'])
            # Assert no resources have been created on VSD, unbound trunk!
            self.assertIsNone(self._get_vsd_vport(subports[i]['port'],
                                                  router=router,
                                                  subnet=subports[i]['subnet'])
                              )
        # Assert no resource has been created on VSD for parent, unbound trunk!
        self.assertIsNone(self._get_vsd_vport(parent, router=router,
                                              subnet=self.parent_subnet))

        # Bind trunk parent
        self.update_port(port_id=parent['id'], **self.binding_data)
        self.addCleanup(self.update_port, port_id=parent['id'],
                        **self.unbinding_data)

        # Assert binding of parent and sub port
        self.assertEqual(self.binding_data['binding:host_id'],
                         self.get_port(parent['id'])['binding:host_id'])
        for i in range(number_subports):
            self.assertEqual(
                self.binding_data['binding:host_id'],
                self.get_port(subports[i]['port']['id'])['binding:host_id'])

        # Assert creation of vsd port
        parent_vsd = self._get_vsd_vport(parent, router=router,
                                         subnet=self.parent_subnet)
        self.assertIsNotNone(parent_vsd)
        for i in range(number_subports):
            sub_vsd = self._get_vsd_vport(subports[i]['port'], router=router,
                                          subnet=subports[i]['subnet'])
            self.assertIsNotNone(sub_vsd)
            self.assertEqual(subports[i]['segmentation_id'],
                             self._get_vsd_vlan(sub_vsd)['value'])

        # Check VLAN on VSD
        self.assertEqual(0, self._get_vsd_vlan(parent_vsd)['value'])
