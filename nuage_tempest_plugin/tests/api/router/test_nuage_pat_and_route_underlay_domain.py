# Copyright 2017 NOKIA
# All Rights Reserved.

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.tests.api.upgrade.external_id.external_id \
    import ExternalId

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class TestNuagePATAndRouteUnderlayDomain(NuageBaseTest):

    @classmethod
    def skip_checks(cls):
        super(NuageBaseTest, cls).skip_checks()
        if not NUAGE_FEATURES.route_to_underlay:
            msg = "Route to underlay not enabled"
            raise cls.skipException(msg)

    @decorators.attr(type='smoke')
    def test_nuage_pat_and_route_to_underlay_domain_create(self):
        """Relevant router interface:

            Router: {
                external_gateway_info: {enable_snat: True/False}
                nuage_underlay: snat, route, off
        """
        # Possible configurations
        # nuage_underlay enable_snat PATEnabled UnderlayEnabled
        configs = [('snat', False, 'ENABLED', 'ENABLED'),
                   ('snat', None, 'ENABLED', 'ENABLED'),
                   ('route', False, 'DISABLED', 'ENABLED'),
                   ('route', None, 'DISABLED', 'ENABLED'),
                   ('off', False, 'DISABLED', 'DISABLED'),
                   ('off', None, 'DISABLED', 'DISABLED')]
        for conf in configs:
            self._router_create_check_vsd(conf[0], conf[1],
                                          conf[2], conf[3])

    @decorators.attr(type='smoke')
    def test_nuage_pat_and_route_to_underlay_domain_update(self):
        """Relevant router interface:

            Router: {
                external_gateway_info: {enable_snat: True/False}
                nuage_underlay: snat, route, enable_snat
                snat_to_underlay: True/False
        """
        # original router, VSD state, updated router
        configs = [

            ('snat', False, 'snat', None, 'ENABLED', 'ENABLED'),
            ('route', False, 'snat', None, 'ENABLED', 'ENABLED'),
            ('route', None, 'snat', None, 'ENABLED', 'ENABLED'),
            ('off', False, 'snat', None, 'ENABLED', 'ENABLED'),
            ('off', None, 'snat', None, 'ENABLED', 'ENABLED'),

            ('snat', None, 'snat', False, 'ENABLED', 'ENABLED'),
            ('route', False, 'snat', False, 'ENABLED', 'ENABLED'),
            ('route', None, 'snat', False, 'ENABLED', 'ENABLED'),
            ('off', False, 'snat', False, 'ENABLED', 'ENABLED'),
            ('off', None, 'snat', False, 'ENABLED', 'ENABLED'),

            ('snat', None, 'route', None, 'DISABLED', 'ENABLED'),
            ('snat', False, 'route', None, 'DISABLED', 'ENABLED'),
            ('route', False, 'route', None, 'DISABLED', 'ENABLED'),
            ('off', False, 'route', None, 'DISABLED', 'ENABLED'),
            ('off', None, 'route', None, 'DISABLED', 'ENABLED'),

            ('snat', None, 'route', False, 'DISABLED', 'ENABLED'),
            ('snat', False, 'route', False, 'DISABLED', 'ENABLED'),
            ('route', None, 'route', False, 'DISABLED', 'ENABLED'),
            ('off', False, 'route', False, 'DISABLED', 'ENABLED'),
            ('off', None, 'route', False, 'DISABLED', 'ENABLED'),

            ('snat', None, 'off', None, 'DISABLED', 'DISABLED'),
            ('snat', False, 'off', None, 'DISABLED', 'DISABLED'),
            ('route', None, 'off', None, 'DISABLED', 'DISABLED'),
            ('route', False, 'off', None, 'DISABLED', 'DISABLED'),
            ('off', False, 'off', None, 'DISABLED', 'DISABLED'),

            ('snat', None, 'off', False, 'DISABLED', 'DISABLED'),
            ('snat', False, 'off', False, 'DISABLED', 'DISABLED'),
            ('route', None, 'off', False, 'DISABLED', 'DISABLED'),
            ('route', False, 'off', False, 'DISABLED', 'DISABLED'),
            ('off', None, 'off', False, 'DISABLED', 'DISABLED')
        ]
        for conf in configs:
            self._router_update_check_vsd(conf[0], conf[1], conf[2], conf[3],
                                          conf[4], conf[5])

    @decorators.attr(type='smoke')
    def test_nuage_pat_and_route_to_underlay_domain_namechange(self):
        configs = [('snat', False, 'ENABLED', 'ENABLED'),
                   ('snat', None, 'ENABLED', 'ENABLED'),
                   ('route', False, 'DISABLED', 'ENABLED'),
                   ('route', None, 'DISABLED', 'ENABLED'),
                   ('off', False, 'DISABLED', 'DISABLED'),
                   ('off', None, 'DISABLED', 'DISABLED')]
        for conf in configs:
            self._router_name_update_check_no_change(conf[0], conf[1],
                                                     conf[2], conf[3])

    @decorators.attr(type='smoke')
    def test_nuage_pat_and_route_to_underlay_domain_no_op(self):
        configs = [('snat', False, 'ENABLED', 'ENABLED', 'snat', None),
                   ('off', False, 'DISABLED', 'DISABLED', 'off', None),
                   ('route', False, 'DISABLED', 'ENABLED', 'route', None),
                   ('snat', False, 'ENABLED', 'ENABLED', None, False),
                   ('off', False, 'DISABLED', 'DISABLED', None, False),
                   ('route', False, 'DISABLED', 'ENABLED', None, False),
                   ('snat', None, 'ENABLED', 'ENABLED', None, False),
                   ('off', None, 'DISABLED', 'DISABLED', None, False),
                   ('route', None, 'DISABLED', 'ENABLED', None, False)
                   ]
        for conf in configs:
            self._router_no_op_update_check_no_change(conf[0], conf[1],
                                                      conf[2], conf[3],
                                                      conf[4], conf[5])

    @decorators.attr(type='smoke')
    def test_nuage_pat_and_route_to_underlay_domain_update_neg(self):
        # nuage_underlay enable_snat
        # updated nuage_underlay updated enable_snat
        configs = [('off', False,
                    None, True),
                   ('snat', False,
                    'off', True),
                   ('off', False,
                    'GARBAGE', None)]
        for conf in configs:
            self._router_update_check_exception(conf[0], conf[1],
                                                conf[2], conf[3])

    def _router_create_check_vsd(self, nuage_underlay, enable_snat,
                                 pat_enabled, underlay_enabled):
        name = data_utils.rand_name('test-NuagePATAndRouteUnderlayDomain-')

        router = self.create_router(
            client=self.admin_manager,
            router_name=name,
            external_network_id=CONF.network.public_network_id,
            enable_snat=enable_snat,
            external_gateway_info_on=enable_snat is not None,
            nuage_underlay=nuage_underlay)
        self.assertIsNotNone(router,
                             "Unable to create router with "
                             "nuage_underlay={}, "
                             "ext_gw_info.enable_snat={}"
                             .format(nuage_underlay, enable_snat))
        nuage_router = self.vsd.get_l3domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(router['id']).at_cms_id()))
        self.assertIsNotNone(nuage_router,
                             "Unable to retrieve router from VSD with "
                             " nuage_underlay={}, "
                             "ext_gw_info.enable_snat={}"
                             .format(nuage_underlay, enable_snat))
        self.assertEqual(pat_enabled, nuage_router.pat_enabled,
                         "PATEnabled excpected to be: {}, but was {} "
                         "for nuage_underlay={}, ext_gw_info.enable_snat={}."
                         .format(pat_enabled,
                                 nuage_router.pat_enabled,
                                 nuage_underlay,
                                 enable_snat))
        self.assertEqual(underlay_enabled, nuage_router.underlay_enabled,
                         "UnderlayEnabled excpected to be: {}, but was {} "
                         "for nuage_underlay ={}, ext_gw_info.enable_snat={}."
                         .format(underlay_enabled,
                                 nuage_router.underlay_enabled,
                                 nuage_underlay,
                                 enable_snat))
        LOG.debug("Verified for nuage_underlay={} ,"
                  "ext_gw_info.enable_snat={}".format(nuage_underlay,
                                                      enable_snat))

    def _router_update_check_vsd(self, nuage_underlay,
                                 enable_snat, update_nuage_underlay,
                                 update_enable_snat, pat_enabled,
                                 underlay_enabled):
        name = data_utils.rand_name('test-NuagePATAndRouteUnderlayDomain-')
        router = self.create_router(
            client=self.admin_manager,
            router_name=name,
            external_network_id=CONF.network.public_network_id,
            enable_snat=enable_snat,
            external_gateway_info_on=enable_snat is not None,
            nuage_underlay=nuage_underlay
        )
        self.assertIsNotNone(router, "Unable to create router.")
        updated = self.update_router(
            router, client=self.admin_manager,
            external_network_id=CONF.network.public_network_id,
            enable_snat=update_enable_snat,
            external_gateway_info_on=update_enable_snat is not None,
            nuage_underlay=update_nuage_underlay)
        self.assertIsNotNone(updated,
                             "Unable to update router with "
                             "nuage_underlay={}, "
                             "ext_gw_info.enable_snat={}"
                             .format(nuage_underlay, enable_snat))
        nuage_router = self.vsd.get_l3domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(router['id']).at_cms_id()))
        self.assertIsNotNone(nuage_router,
                             "Unable to retrieve router from VSD with "
                             " nuage_underlay={}, "
                             "ext_gw_info.enable_snat={}"
                             .format(nuage_underlay, enable_snat))
        self.assertEqual(pat_enabled, nuage_router.pat_enabled,
                         "PATEnabled excpected to be: {}, but was {} "
                         "for nuage_underlay={}, ext_gw_info.enable_snat={}."
                         .format(pat_enabled,
                                 nuage_router.pat_enabled,
                                 nuage_underlay,
                                 enable_snat))
        self.assertEqual(underlay_enabled, nuage_router.underlay_enabled,
                         "UnderlayEnabled excpected to be: {}, but was {} "
                         "for nuage_underlay ={}, ext_gw_info.enable_snat={}."
                         .format(underlay_enabled,
                                 nuage_router.underlay_enabled,
                                 nuage_underlay,
                                 enable_snat))
        LOG.debug("Verified for nuage_underlay={} ,"
                  "ext_gw_info.enable_snat={}".format(nuage_underlay,
                                                      enable_snat))

    def _router_update_check_exception(self, nuage_underlay, enable_snat,
                                       update_nuage_underlay,
                                       update_enable_snat):
        name = data_utils.rand_name('test-NuagePATAndRouteUnderlayDomain-')
        router = self.create_router(
            router_name=name,
            client=self.admin_manager,
            external_network_id=CONF.network.public_network_id,
            enable_snat=enable_snat,
            external_gateway_info_on=enable_snat is not None,
            nuage_underlay=nuage_underlay)
        self.assertIsNotNone(router, "Unable to create router.")
        self.assertRaises(
            exceptions.BadRequest,
            self.update_router,
            router,
            client=self.admin_manager,
            external_network_id=CONF.network.public_network_id,
            enable_snat=update_enable_snat,
            external_gateway_info_on=update_enable_snat is not None,
            nuage_underlay=update_nuage_underlay)
        LOG.debug("Verified for nuage_underlay={}, "
                  "enable_snat={}".format(update_nuage_underlay,
                                          update_enable_snat))

    def _router_name_update_check_no_change(self, nuage_underlay, enable_snat,
                                            pat_enabled, underlay_enabled):
        name = data_utils.rand_name('test-NuagePATAndRouteUnderlayDomain-')
        router = self.create_router(
            client=self.admin_manager,
            router_name=name,
            external_network_id=CONF.network.public_network_id,
            external_gateway_info_on=enable_snat is not None,
            enable_snat=enable_snat,
            nuage_underlay=nuage_underlay)
        self.assertIsNotNone(router, "Unable to create router.")
        name = data_utils.rand_name('test-NuagePATAndRouteUnderlayDomain2-')
        updated = self.update_router(
            router, client=self.admin_manager,
            external_gateway_info_on=False,
            name=name)
        self.assertIsNotNone(updated,
                             "Unable to update router with "
                             "nuage_underlay={}, "
                             "ext_gw_info.enable_snat={}"
                             .format(nuage_underlay, enable_snat))
        nuage_router = self.vsd.get_l3domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(router['id']).at_cms_id()))
        self.assertIsNotNone(nuage_router,
                             "Unable to retrieve router from VSD with "
                             " nuage_underlay={}, "
                             "ext_gw_info.enable_snat={}"
                             .format(nuage_underlay, enable_snat))
        self.assertEqual(pat_enabled, nuage_router.pat_enabled,
                         "PATEnabled excpected to be: {}, but was {} "
                         "for nuage_underlay={}, ext_gw_info.enable_snat={}."
                         .format(pat_enabled,
                                 nuage_router.pat_enabled,
                                 nuage_underlay,
                                 enable_snat))
        self.assertEqual(underlay_enabled, nuage_router.underlay_enabled,
                         "UnderlayEnabled excpected to be: {}, but was {} "
                         "for nuage_underlay ={}, ext_gw_info.enable_snat={}."
                         .format(underlay_enabled,
                                 nuage_router.underlay_enabled,
                                 nuage_underlay,
                                 enable_snat))
        LOG.debug("Verified for nuage_underlay={} ,"
                  "ext_gw_info.enable_snat={}".format(nuage_underlay,
                                                      enable_snat))

    def _router_no_op_update_check_no_change(self, nuage_underlay,
                                             enable_snat,
                                             pat_enabled, underlay_enabled,
                                             no_op_nuage_underlay,
                                             no_op_enable_snat):
        name = data_utils.rand_name('test-NuagePATAndRouteUnderlayDomain-')
        router = self.create_router(
            client=self.admin_manager,
            router_name=name,
            external_network_id=CONF.network.public_network_id,
            external_gateway_info_on=enable_snat is not None,
            enable_snat=enable_snat,
            nuage_underlay=nuage_underlay)
        self.assertIsNotNone(router, "Unable to create router.")
        updated = self.update_router(
            router, client=self.admin_manager,
            external_network_id=CONF.network.public_network_id,
            external_gateway_info_on=no_op_enable_snat is not None,
            enable_snat=no_op_enable_snat,
            nuage_underlay=no_op_nuage_underlay)
        self.assertIsNotNone(updated,
                             "Unable to update router with "
                             "nuage_underlay={}, "
                             "ext_gw_info.enable_snat={}"
                             .format(nuage_underlay, enable_snat))
        nuage_router = self.vsd.get_l3domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(router['id']).at_cms_id()))
        self.assertIsNotNone(nuage_router,
                             "Unable to retrieve router from VSD with "
                             " nuage_underlay={}, "
                             "ext_gw_info.enable_snat={}"
                             .format(nuage_underlay, enable_snat))
        self.assertEqual(pat_enabled, nuage_router.pat_enabled,
                         "PATEnabled excpected to be: {}, but was {} "
                         "for nuage_underlay={}, ext_gw_info.enable_snat={}."
                         .format(pat_enabled,
                                 nuage_router.pat_enabled,
                                 nuage_underlay,
                                 enable_snat))
        self.assertEqual(underlay_enabled, nuage_router.underlay_enabled,
                         "UnderlayEnabled excpected to be: {}, but was {} "
                         "for nuage_underlay ={}, ext_gw_info.enable_snat={}."
                         .format(underlay_enabled,
                                 nuage_router.underlay_enabled,
                                 nuage_underlay,
                                 enable_snat))
        LOG.debug("Verified for nuage_underlay={} ,"
                  "ext_gw_info.enable_snat={}".format(nuage_underlay,
                                                      enable_snat))
