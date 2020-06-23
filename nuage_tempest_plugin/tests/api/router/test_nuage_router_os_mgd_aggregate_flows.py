# Copyright 2017 NOKIA
# All Rights Reserved.

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.tests.api.external_id.external_id \
    import ExternalId

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class TestNuageRouterOSMgdAggregateFlows(NuageBaseTest):

    @classmethod
    def skip_checks(cls):
        super(TestNuageRouterOSMgdAggregateFlows, cls).skip_checks()
        if Topology.before_nuage('20.5'):
            raise cls.skipException('OS managed aggregate flows are '
                                    'unavailable before 20.5')

    @decorators.attr(type='smoke')
    def test_aggregate_flows_create_get_router(self):
        """Relevant router interface:

            Router: {
                nuage_aggregate_flows: off, pbr, route
            }
        """
        # Possible configurations and expected config on VSD
        # nuage_aggregate_flows aggregationFlowsEnabled aggregationFlowType
        configs = [('off', False, None),
                   (None, False, None),
                   ('route', True, 'ROUTE_BASED'),
                   ('pbr', True, 'PBR_BASED')]
        for conf in configs:
            self._router_create_get_check_vsd(conf[0], conf[1], conf[2])

    @decorators.attr(type='smoke')
    def test_aggregate_flows_update_router(self):
        """Relevant router interface:

            Router: {
                nuage_aggregate_flows: off, pbr, route
            }
        """
        # Possible configurations (original and updated) and expected config
        # on VSD
        # nuage_aggregate_flows aggregationFlowsEnabled aggregationFlowType
        configs = [
            ('off', 'off', False, None),
            ('off', 'route', True, 'ROUTE_BASED'),
            ('off', 'pbr', True, 'PBR_BASED'),

            ('route', 'off', False, None),
            ('route', 'route', True, 'ROUTE_BASED'),
            ('route', 'pbr', True, 'PBR_BASED'),

            ('pbr', 'off', False, None),
            ('pbr', 'route', True, 'ROUTE_BASED'),
            ('pbr', 'pbr', True, 'PBR_BASED')
        ]

        for conf in configs:
            self._router_update_check_vsd(conf[0], conf[1], conf[2], conf[3])

    def test_aggregate_flows_noop_update(self):
        configs = [('off', False, None),
                   (None, False, None),
                   ('route', True, 'ROUTE_BASED'),
                   ('pbr', True, 'PBR_BASED')]
        for conf in configs:
            self._router_name_update_check_no_change(conf[0], conf[1], conf[2])

    def test_aggregate_flows_router_update_neg_with_vm(self):
        # nuage_aggregate_flows updated_nuage_aggregate_flows with_vm
        configs = [('off', 'garbage', False),
                   ('off', 'route', True),
                   ('off', 'pbr', True),
                   ('route', 'off', True),
                   ('route', 'pbr', True),
                   ('pbr', 'off', True),
                   ('pbr', 'route', True),
                   ]
        for conf in configs:
            self._router_update_check_exception(conf[0], conf[1], conf[2])

    def _router_create_get_check_vsd(self, nuage_aggregate_flows,
                                     aggregation_flows_enabled,
                                     aggregation_flow_type):
        name = data_utils.rand_name('test-NuageRouterAggregateFlows-')
        if nuage_aggregate_flows:
            router = self.create_router(
                router_name=name,
                external_network_id=CONF.network.public_network_id,
                nuage_aggregate_flows=nuage_aggregate_flows)
        else:
            router = self.create_router(
                router_name=name,
                external_network_id=CONF.network.public_network_id)

        self.assertIsNotNone(router,
                             "Unable to create router with "
                             "nuage_aggregate_flows={}."
                             .format(nuage_aggregate_flows))
        self.assertEqual(
            nuage_aggregate_flows if nuage_aggregate_flows else 'off',
            router.get('nuage_aggregate_flows'),
            "nuage_aggregate_flows in create router should be "
            "{} but was: {}.".format(
                nuage_aggregate_flows if nuage_aggregate_flows else 'off',
                router.get('nuage_aggregate_flows')))

        router_get = self.get_router(router['id'])
        self.assertEqual(router['nuage_aggregate_flows'],
                         router_get.get('nuage_aggregate_flows'),
                         "nuage_aggregate_flows in show router should be "
                         "{} but was: {}."
                         .format(router['nuage_aggregate_flows'],
                                 router_get.get('nuage_aggregate_flows')))
        nuage_router = self.vsd.get_l3domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(router['id']).at_cms_id()))
        self.assertIsNotNone(nuage_router,
                             "Unable to retrieve router from VSD with "
                             "nuage_aggregate_flows={}."
                             .format(nuage_aggregate_flows))
        self.assertEqual(aggregation_flows_enabled,
                         nuage_router.aggregate_flows_enabled,
                         "AggregateFlowsEnabled expected to be: {}, "
                         "but was {} for nuage_aggregate_flows={}."
                         .format(aggregation_flows_enabled,
                                 nuage_router.aggregate_flows_enabled,
                                 nuage_aggregate_flows))
        self.assertEqual(aggregation_flow_type,
                         nuage_router.aggregation_flow_type,
                         "AggregationFlowType expected to be: {}, but was {} "
                         "for nuage_aggregate_flows={}."
                         .format(aggregation_flow_type,
                                 nuage_router.aggregation_flow_type,
                                 nuage_aggregate_flows))
        LOG.debug("Verified for nuage_aggregate_flows={}.".format(
            nuage_aggregate_flows))

    def _router_update_check_vsd(self, original_nuage_aggregate_flows,
                                 updated_nuage_aggregate_flows,
                                 aggregation_flows_enabled,
                                 aggregation_flow_type):
        name = data_utils.rand_name('test-NuageRouterAggregateFlows-')
        if original_nuage_aggregate_flows:
            router = self.create_router(
                router_name=name,
                external_network_id=CONF.network.public_network_id,
                nuage_aggregate_flows=original_nuage_aggregate_flows)
        else:
            router = self.create_router(
                router_name=name,
                external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router.")
        updated = self.update_router(
            router, nuage_aggregate_flows=updated_nuage_aggregate_flows)
        self.assertIsNotNone(updated,
                             "Unable to update router with "
                             "nuage_aggregate_flows={}."
                             .format(updated_nuage_aggregate_flows))
        self.assertEqual(
            updated_nuage_aggregate_flows,
            updated.get('nuage_aggregate_flows'),
            "nuage_aggregate_flows in create router should be "
            "{} but was: {}.".format(
                updated_nuage_aggregate_flows,
                updated.get('nuage_aggregate_flows')))

        nuage_router = self.vsd.get_l3domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(router['id']).at_cms_id()))
        self.assertIsNotNone(nuage_router,
                             "Unable to retrieve router from VSD with "
                             "nuage_aggregate_flows={}."
                             .format(updated_nuage_aggregate_flows))
        self.assertEqual(aggregation_flows_enabled,
                         nuage_router.aggregate_flows_enabled,
                         "AggregateFlowsEnabled expected to be: {}, "
                         "but was {} for nuage_aggregate_flows={}."
                         .format(aggregation_flows_enabled,
                                 nuage_router.aggregate_flows_enabled,
                                 updated_nuage_aggregate_flows))
        self.assertEqual(aggregation_flow_type,
                         nuage_router.aggregation_flow_type,
                         "AggregationFlowType expected to be: {}, but was {} "
                         "for nuage_aggregate_flows={}."
                         .format(aggregation_flow_type,
                                 nuage_router.aggregation_flow_type,
                                 updated_nuage_aggregate_flows))
        LOG.debug("Verified for updated nuage_aggregate_flows={}.".format(
            updated_nuage_aggregate_flows))

    def _router_update_check_exception(self, original_nuage_aggregate_flows,
                                       update_nuage_aggregate_flows, with_vm):
        name = data_utils.rand_name('test-NuageRouterAggregateFlows-')
        if original_nuage_aggregate_flows:
            router = self.create_router(
                router_name=name,
                external_network_id=CONF.network.public_network_id,
                nuage_aggregate_flows=original_nuage_aggregate_flows)
        else:
            router = self.create_router(
                router_name=name,
                external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router.")
        if with_vm:
            network = self.create_network()
            subnet = self.create_subnet(network)
            self.create_router_interface(router['id'], subnet['id'])
            # Aggregate flows does not support stateful ACL
            port = self.create_port(network, port_security_enabled=False)
            self.create_tenant_server(name=name, ports=[port])
        self.assertRaises(
            exceptions.BadRequest,
            self.update_router,
            router,
            nuage_aggregate_flows=update_nuage_aggregate_flows)
        router = self.get_router(router['id'])
        self.assertIsNotNone(router['external_gateway_info'])

        LOG.debug("Verified for updated nuage_aggregate_flows={}, "
                  "with_vm={}.".format(update_nuage_aggregate_flows, with_vm))

    def _router_name_update_check_no_change(self, nuage_aggregate_flows,
                                            aggregation_flows_enabled,
                                            aggregation_flow_type):
        name = data_utils.rand_name('test-NuageRouterAggregateFlows-')
        if nuage_aggregate_flows:
            router = self.create_router(
                router_name=name,
                external_network_id=CONF.network.public_network_id,
                nuage_aggregate_flows=nuage_aggregate_flows)
        else:
            router = self.create_router(
                router_name=name,
                external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router.")
        name = data_utils.rand_name('test-NuageRouterAggregateFlows2-')
        updated = self.update_router(
            router, name=name)
        self.assertIsNotNone(updated,
                             "Unable to update router with new name for "
                             "nuage_aggregate_flows={}."
                             .format(nuage_aggregate_flows))
        nuage_router = self.vsd.get_l3domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(router['id']).at_cms_id()))
        self.assertIsNotNone(nuage_router,
                             "Unable to retrieve router from VSD with "
                             "nuage_aggregate_flows={}."
                             .format(nuage_aggregate_flows))
        self.assertEqual(aggregation_flows_enabled,
                         nuage_router.aggregate_flows_enabled,
                         "AggregateFlowsEnabled expected to be: {}, "
                         "but was {} for nuage_aggregate_flows={}."
                         .format(aggregation_flows_enabled,
                                 nuage_router.aggregate_flows_enabled,
                                 nuage_aggregate_flows))
        self.assertEqual(aggregation_flow_type,
                         nuage_router.aggregation_flow_type,
                         "AggregationFlowType expected to be: {}, but was {} "
                         "for nuage_aggregate_flows={}."
                         .format(aggregation_flow_type,
                                 nuage_router.aggregation_flow_type,
                                 nuage_aggregate_flows))
        LOG.debug("Verified for nuage_aggregate_flows={}.".format(
            nuage_aggregate_flows))
