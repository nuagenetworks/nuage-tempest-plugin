# Copyright 2015 Alcatel-Lucent USA Inc.
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

from oslo_log import log as logging
import uuid

from tempest.api.network import base
from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest.test import decorators

from testtools.matchers import Contains
from testtools.matchers import Equals
from testtools.matchers import Not

from nuage_tempest_plugin.lib.mixins.bgpvpn import BGPVPNMixin
from nuage_tempest_plugin.lib.mixins.l3 import L3Mixin
from nuage_tempest_plugin.lib.mixins.network import NetworkMixin
from nuage_tempest_plugin.lib.test import nuage_test

LOG = logging.getLogger(__name__)
CONF = config.CONF


class BgpvpnBase(BGPVPNMixin):

    credentials = ['primary', 'admin']

    @classmethod
    def skip_checks(cls):
        super(BgpvpnBase, cls).skip_checks()
        if not utils.is_extension_enabled('bgpvpn', 'network'):
            msg = "Bgpvpn Extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(BgpvpnBase, cls).resource_setup()
        cls.tenant_id = cls.bgpvpn_client.tenant_id
        cls.admin_tenant_id = cls.bgpvpn_client_admin.tenant_id
        cls.def_net_partition = CONF.nuage.nuage_default_netpartition

    @classmethod
    def resource_cleanup(cls):
        cls.os_data.delete_resource(cls.def_net_partition)
        super(BgpvpnBase, cls).resource_cleanup()


class BgpvpnTest(BgpvpnBase):

    def test_bgpvpn_create_list(self):
        bgpvpns = self.bgpvpn_client.list_bgpvpns()
        pre_ids = [bgpvpn['id'] for bgpvpn in bgpvpns]
        with self.bgpvpn(
                tenant_id=self.tenant_id,
                route_targets=['456:456'],
                route_distinguishers=['456:456']) as created_bgpvpn:
            bgpvpns = self.bgpvpn_client.list_bgpvpns()
            post_ids = [bgpvpn['id'] for bgpvpn in bgpvpns]
            self.assertThat(pre_ids, Not(Contains(created_bgpvpn['id'])))
            self.assertThat(post_ids, Contains(created_bgpvpn['id']))

    def test_bgpvpn_show_invalid(self):
        self.assertRaisesRegex(
            lib_exc.NotFound, "could not be found",
            self.bgpvpn_client.show_bgpvpn, uuid.uuid4())

    def test_bgpvpn_create_unsupported_type(self):
        self.assertRaisesRegex(
            lib_exc.BadRequest, "driver does not support l2",
            self.bgpvpn_client_admin.create, type='l2')

    '''def test_bgpvpn_create_non_admin(self):
        self.assertRaises(lib_exc.Forbidden, self.bgpvpn_client.create)'''

    def test_bgpvpn_delete_invalid(self):
        self.assertRaisesRegex(
            lib_exc.NotFound, "could not be found",
            self.bgpvpn_client.delete_bgpvpn, uuid.uuid4())

    def test_bgpvpn_create_update(self):
        with self.bgpvpn(
                tenant_id=self.tenant_id,
                route_targets=['656:656'],
                route_distinguishers=['656:656']) as created_bgpvpn:
            update_args = {
                'route_targets': ['444:444'],
                'route_distinguishers': ['444:444'],
                'name': 'updated_bgpvpn'
            }
            self.bgpvpn_client.update_bgpvpn(created_bgpvpn['id'],
                                             **update_args)
            updated_bgpvpn = self.bgpvpn_client.show_bgpvpn(
                created_bgpvpn['id'])
            self.assertThat(updated_bgpvpn['route_targets'],
                            Equals(update_args['route_targets']))
            self.assertThat(updated_bgpvpn['route_distinguishers'],
                            Equals(update_args['route_distinguishers']))
            self.assertThat(updated_bgpvpn['name'],
                            Equals(update_args['name']))

    def test_cannot_update_bgpvpn_type(self):
        with self.bgpvpn(tenant_id=self.tenant_id) as created_bgpvpn:
            update_args = {'type': 'l2'}
            self.assertRaisesRegex(
                lib_exc.BadRequest, "Cannot update read-only attribute type",
                self.bgpvpn_client.update_bgpvpn,
                created_bgpvpn['id'], **update_args)

    def test_cannot_create_bgpvpn_invalid_rt_rd(self):
        invalid_rt_rd = \
            {'route_targets': '100000000:10000000',
             'route_distinguishers': '100000000:10000000'}

        self.assertRaisesRegex(
            lib_exc.BadRequest, "Invalid input for",
            self.bgpvpn_client_admin.create, **invalid_rt_rd)


class RouterAssociationTest(BgpvpnBase, L3Mixin):

    def test_router_association_create(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_distinguishers=['123:321'],
                         route_targets=['123:321']) as bgpvpn,\
                self.router() as router,\
                self.router_assocation(router['id'],
                                       bgpvpn['id']) as rtr_assoc:
            router = self.routers_client.show_router(router['id'])['router']
            self.assertThat(router['rd'],
                            Equals(bgpvpn['route_distinguishers'][0]))
            self.assertThat(router['rt'], Equals(bgpvpn['route_targets'][0]))
            rtr_assoc_show = self.rtr_assoc_client.show_router_assocation(
                rtr_assoc['id'], bgpvpn['id'])
            self.assertThat(rtr_assoc_show['router_id'], Equals(router['id']))
            self.os_data.insert_resource('os-router-ra-1',
                                         os_data=router,
                                         parent=self.def_net_partition)
            # tag_name = 'verify_l3domain_rt_rd'
            # nuage_ext.nuage_extension.nuage_components(
            #     nuage_ext._generate_tag(tag_name, self.__class__.__name__),
            #     self)

    def test_router_association_create_list(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_distinguishers=['123:321'],
                         route_targets=['123:321']) as bgpvpn,\
                self.router() as router,\
                self.router_assocation(router['id'],
                                       bgpvpn['id']):  # as rtr_assoc:
            router = self.routers_client.show_router(router['id'])['router']
            self.assertThat(router['rd'],
                            Equals(bgpvpn['route_distinguishers'][0]))
            self.assertThat(router['rt'], Equals(bgpvpn['route_targets'][0]))
            rtr_assoc_list = self.rtr_assoc_client.list_router_assocations(
                bgpvpn['id'])
            self.assertThat(rtr_assoc_list[0]['router_id'],
                            Equals(router['id']))
            self.os_data.insert_resource('os-router-ra-2',
                                         os_data=router,
                                         parent=self.def_net_partition)
            # tag_name = 'verify_l3domain_rt_rd'
            # nuage_ext.nuage_extension.nuage_components(
            #     nuage_ext._generate_tag(tag_name, self.__class__.__name__),
            #     self)

    def test_router_association_missing_rd(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_targets=['123:321']) as bgpvpn,\
                self.router() as router:
            self.assertRaisesRegex(
                lib_exc.BadRequest, "route_distinguisher is required",
                self.rtr_assoc_client.create_router_assocation,
                bgpvpn['id'], router_id=router['id'])

    def test_router_association_missing_rt(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_distinguishers=['123:321']) as bgpvpn, \
                self.router() as router:
            self.assertRaisesRegex(
                lib_exc.BadRequest, "route_target is required",
                self.rtr_assoc_client.create_router_assocation,
                bgpvpn['id'], router_id=router['id'])

    def test_router_association_import_targets(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_distinguishers=['123:321'],
                         route_targets=['123:321'],
                         import_targets=['123:321']) as bgpvpn, \
                self.router() as router:
            self.assertRaisesRegex(
                lib_exc.BadRequest,
                "This bgpvpn can't have any import_targets",
                self.rtr_assoc_client.create_router_assocation,
                bgpvpn['id'], router_id=router['id'])

    def test_router_association_export_targets(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_distinguishers=['123:321'],
                         route_targets=['123:321'],
                         export_targets=['123:321']) as bgpvpn, \
                self.router() as router:
            self.assertRaisesRegex(
                lib_exc.BadRequest,
                "This bgpvpn can't have any export_targets",
                self.rtr_assoc_client.create_router_assocation,
                bgpvpn['id'], router_id=router['id'])

    def test_router_association_invalid_bgpvpn_id(self):
        with self.router() as router:
            self.assertRaisesRegex(
                lib_exc.NotFound,
                "could not be found",
                self.rtr_assoc_client.create_router_assocation,
                uuid.uuid4(), router_id=router['id'])

    def test_router_association_invalid_router(self):
        with self.bgpvpn(tenant_id=self.tenant_id) as bgpvpn:
            self.assertRaisesRegex(
                lib_exc.NotFound,
                "could not be found",
                self.rtr_assoc_client.create_router_assocation,
                bgpvpn['id'], router_id=str(uuid.uuid4()))

    def test_router_association_multiplerouters_singlebgpvpn(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_distinguishers=['123:321'],
                         route_targets=['123:321']) as bgpvpn, \
                self.router() as router, \
                self.router() as router2, \
                self.router_assocation(router['id'],
                                       bgpvpn['id']):
            self.assertRaisesRegex(
                lib_exc.BadRequest,
                "Can not have more than 1 router association per bgpvpn",
                self.rtr_assoc_client.create_router_assocation,
                bgpvpn['id'], router_id=router2['id'])

    def test_router_association_singlerouter_multiplebgpvpn(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_distinguishers=['123:321'],
                         route_targets=['123:321']) as bgpvpn, \
                self.bgpvpn(tenant_id=self.tenant_id,
                            route_distinguishers=['234:432'],
                            route_targets=['234:432']) as bgpvpn2, \
                self.router() as router, \
                self.router_assocation(router['id'],
                                       bgpvpn['id']):
            self.assertRaisesRegex(
                lib_exc.BadRequest,
                "Can not have more than 1 router association per router",
                self.rtr_assoc_client.create_router_assocation,
                bgpvpn2['id'], router_id=router['id'])

    def test_delete_bgpvpn_with_router_association(self):
        bgpvpn = self.bgpvpn_client_admin.create_bgpvpn(
            tenant_id=self.tenant_id,
            route_distinguishers=['256:432'],
            route_targets=['256:432'])
        router = self.routers_client.create_router(name='router-bgpvpn')
        self.rtr_assoc_client.create_router_assocation(
            bgpvpn['id'], router_id=router['router']['id'])
        self.bgpvpn_client_admin.delete_bgpvpn(bgpvpn['id'])
        self.assertRaisesRegex(
            lib_exc.NotFound,
            "could not be found",
            self.bgpvpn_client_admin.show_bgpvpn, bgpvpn['id'])
        self.routers_client.delete_router(router['router']['id'])

    def test_update_rt_rd_after_router_association(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_distinguishers=['878:878'],
                         route_targets=['878:878']) as bgpvpn,\
                self.router() as router,\
                self.router_assocation(router['id'],
                                       bgpvpn['id']):  # as rtr_assoc:
            router = self.routers_client.show_router(router['id'])['router']
            self.assertThat(router['rd'],
                            Equals(bgpvpn['route_distinguishers'][0]))
            self.assertThat(router['rt'], Equals(bgpvpn['route_targets'][0]))
            rtr_assoc_list = self.rtr_assoc_client.list_router_assocations(
                bgpvpn['id'])
            self.assertThat(rtr_assoc_list[0]['router_id'],
                            Equals(router['id']))
            self.os_data.insert_resource('os-router-ra-3',
                                         os_data=router,
                                         parent=self.def_net_partition)
            # tag_name = 'verify_l3domain_rt_rd'
            # nuage_ext.nuage_extension.nuage_components(
            #     nuage_ext._generate_tag(tag_name, self.__class__.__name__),
            #     self)
            self.bgpvpn_client_admin.update_bgpvpn(
                bgpvpn['id'],
                route_distinguishers=['879:879'],
                route_targets=['879:879'])
            router = self.routers_client.show_router(router['id'])['router']
            self.os_data.update_resource('os-router-ra-3',
                                         os_data=router)
            # tag_name = 'verify_l3domain_rt_rd'
            # nuage_ext.nuage_extension.nuage_components(
            #     nuage_ext._generate_tag(tag_name, self.__class__.__name__),
            #     self)

    def test_create_two_router_association_same_rt_rd(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_distinguishers=['343:343'],
                         route_targets=['343:343']) as bgpvpn1, \
                self.bgpvpn(tenant_id=self.tenant_id,
                            route_distinguishers=['343:343'],
                            route_targets=['343:343']) as bgpvpn2, \
                self.router() as router1, \
                self.router() as router2, \
                self.router_assocation(router1['id'],
                                       bgpvpn1['id']):
            self.assertRaisesRegex(
                lib_exc.ServerFault,
                "Nuage API: routeDistinguisher",
                self.rtr_assoc_client.create_router_assocation,
                bgpvpn2['id'], router_id=router2['id'])
            rout_assoc = self.rtr_assoc_client.list_router_assocations(
                bgpvpn2['id'])
            self.assertEqual(rout_assoc, [])

    def test_create_bgpvpn_with_two_rt_rd(self):
        with self.bgpvpn(tenant_id=self.tenant_id,
                         route_distinguishers=['343:343'],
                         route_targets=['343:343']) as bgpvpn1, \
                self.router() as router1, \
                self.router() as router2:
            rout_asso = self.rtr_assoc_client.create_router_assocation(
                bgpvpn1['id'], router_id=router1['id'])
            self.rtr_assoc_client.delete_router_assocation(
                rout_asso['id'],
                bgpvpn1['id'])
            self.assertRaisesRegex(
                lib_exc.ServerFault,
                "Nuage API: routeDistinguisher",
                self.rtr_assoc_client.create_router_assocation,
                bgpvpn1['id'], router_id=router2['id'])


class NetworkAssociationTest(BgpvpnBase, NetworkMixin):

    def test_network_association_unsupported(self):
        with self.network() as net, \
                self.bgpvpn(tenant_id=self.tenant_id) as bgpvpn:
            self.assertRaisesRegex(
                lib_exc.BadRequest, "not support network association",
                self.net_assoc_client.create_network_association,
                bgpvpn['id'], network_id=net['id'])
        self.assertRaisesRegex(
            lib_exc.BadRequest, "not support network association",
            self.net_assoc_client.list_network_associations,
            'dummy')
        self.assertRaisesRegex(
            lib_exc.BadRequest, "not support network association",
            self.net_assoc_client.delete_network_association,
            'dummy', 'dummy')
        self.assertRaisesRegex(
            lib_exc.BadRequest, "not support network association",
            self.net_assoc_client.update_network_association,
            'dummy', 'dummy')


class BgpvpnCliTests(BGPVPNMixin, base.BaseNetworkTest):

    def_net_partition = CONF.nuage.nuage_default_netpartition

    @classmethod
    def skip_checks(cls):
        super(BgpvpnCliTests, cls).skip_checks()
        if not utils.is_extension_enabled('bgpvpn', 'network'):
            msg = "Bgpvpn Extension not enabled."
            raise cls.skipException(msg)

    def _create_verifybgpvpn(self, name, rt, rd):
        params = {}
        params['name'] = name
        params['route_distinguishers'] = rd
        params['route_targets'] = rt
        bgpvpn = self.bgpvpn_client.create_bgpvpn(**params)
        LOG.debug("Verifying BGPVPN")
        self.assertEqual(bgpvpn['name'], params['name'])
        self.assertEqual(bgpvpn['route_distinguishers'],
                         params['route_distinguishers'])
        self.assertEqual(bgpvpn['route_targets'], params['route_targets'])
        LOG.debug("List with %d items", bgpvpn.__len__())
        return bgpvpn

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_create_delete_bgpvpn(self):
        name = data_utils.rand_name('bgpvpn')
        self._create_verifybgpvpn(name, '343:343', '343:343')

    @nuage_test.header()
    def test_create_list_show_delete_multiple_bgpvpn(self):
        name1 = data_utils.rand_name('bgpvpn')
        bgpvpn1 = self._create_verifybgpvpn(name1, '345:345', '345:345')
        name2 = data_utils.rand_name('bgpvpn')
        bgpvpn2 = self._create_verifybgpvpn(name2, '344:344', '344:344')
        self.os_data.insert_resource(name1,
                                     os_data=bgpvpn1,
                                     parent=self.def_net_partition)
        self.os_data.insert_resource(name2,
                                     os_data=bgpvpn2,
                                     parent=self.def_net_partition)
        bgpvpns = self.bgpvpn_client.list_bgpvpn()
        for bgpvpn in bgpvpns:
            get_bgpvpn = self.os_data.get_resource(bgpvpn['name']).os_data
            if not get_bgpvpn:
                raise Exception('Cannot find bgpvpn in list command')
            show_bgpvpn = self.bgpvpn_client.show_bgpvpn(bgpvpn['id'])
            if not show_bgpvpn:
                raise Exception('Cannot find bgpvpn in show command')

    def test_cannot_create_network_assoc(self):
        netname = data_utils.rand_name('network')
        network = self.networks_client.create_network(network_name=netname)
        name1 = data_utils.rand_name('bgpvpn')
        bgpvpn1 = self._create_verifybgpvpn(name1, '350:350', '350:350')
        kwargs = {}
        kwargs['network'] = network['id']
        self.bgpvpn_client.bgpvpn_net_assoc_create(
            bgpvpn1['id'], **kwargs)

    def test_create_list_router_assoication(self):
        name1 = data_utils.rand_name('bgpvpn')
        bgpvpn1 = self._create_verifybgpvpn(name1, '349:349', '349:349')
        routname = data_utils.rand_name('router')
        router = self.routers_client.create_router(router_name=routname)
        self.os_data.insert_resource(name1,
                                     os_data=bgpvpn1,
                                     parent=self.def_net_partition)
        kwargs = {}
        kwargs['router'] = router['id']
        self.bgpvpn_client.bgpvpn_router_assoc_create(
            bgpvpn1['id'], **kwargs)
        listing = self.bgpvpn_client.bgpvpn_router_assoc_list(
            bgpvpn1['id'])
        for list in listing:
            self.assertEqual(list['router_id'], router['id'])

    def tearDown(self):
        super(BgpvpnCliTests, self).tearDown()

    @classmethod
    def tearDownClass(self):
        super(BgpvpnCliTests, self).tearDownClass()
