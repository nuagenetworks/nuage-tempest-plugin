# Copyright 2017 NOKIA
# All Rights Reserved.

from tempest.lib import decorators
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class TestNuagePATAndRouteUnderlaySubnet(NuageBaseTest):

    @decorators.attr(type='smoke')
    def test_nuage_pat_and_underlay_subnet_create_negative(self):
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")
        # Possible configurations
        # nuage_underlay PATEnabled UnderlayEnabled
        configs = ['snat', 'route', 'off', 'inherited', ]
        for conf in configs:
            self._subnet_create_check_exception(conf, network)

    @decorators.attr(type='smoke')
    def test_nuage_pat_and_route_to_underlay_subnet(self):
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")

        # Possible configurations
        # nuage_underlay PATEnabled UnderlayEnabled
        configs = [('snat', 'ENABLED', 'ENABLED'),
                   ('off', 'DISABLED', 'DISABLED'),
                   (None, 'INHERITED', 'INHERITED'),
                   ('route', 'DISABLED', 'ENABLED'),
                   ('inherited', 'INHERITED', 'INHERITED')]
        for conf in configs:
            self._subnet_update_check_vsd(conf[0], conf[1], conf[2],
                                          router, network)

    @decorators.attr(type='smoke')
    def test_nuage_pat_and_route_to_underlay_subnet_negative(self):
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        # Possible invalid configurations for l2 subnet
        configs = ['snat', 'route', 'off', 'inherited', ]
        for conf in configs:
            self._subnet_update_check_exception(conf, network)

    @decorators.attr(type='smoke')
    def test_nuage_pat_and_route_to_underlay_subnet_namechange(self):
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")

        configs = [('snat', 'ENABLED', 'ENABLED'),
                   ('off', 'DISABLED', 'DISABLED'),
                   ('route', 'DISABLED', 'ENABLED'),
                   (None, 'INHERITED', 'INHERITED'),
                   ('inherited', 'INHERITED', 'INHERITED')]
        for conf in configs:
            self._subnet_name_update_check_no_change(conf[0], conf[1], conf[2],
                                                     router, network)

    @decorators.attr(type='smoke')
    def test_nuage_pat_and_route_to_underlay_subnet_no_op(self):
        """Reinforce the value that has been set for nuage_underlay again.

        This should be a no-operation on both VSD and neutron.

        """
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        # (nuage_underlay, PATEnabled, UnderlayEnabled,
        #  no_op_nuage_underlay)
        configs = [('snat', 'ENABLED', 'ENABLED', None),
                   ('off', 'DISABLED', 'DISABLED', None),
                   ('route', 'DISABLED', 'ENABLED', None),
                   ('inherited', 'INHERITED', 'INHERITED', None),
                   ('snat', 'ENABLED', 'ENABLED', 'snat'),
                   ('off', 'DISABLED', 'DISABLED', 'off'),
                   ('route', 'DISABLED', 'ENABLED', 'route'),
                   ('inherited', 'INHERITED', 'INHERITED', 'inherited')]
        for conf in configs:
            self._subnet_no_op_update_check_no_change(conf[0], conf[1],
                                                      conf[2], conf[3],
                                                      router, network)

    def _subnet_name_update_check_no_change(self, nuage_underlay,
                                            pat_enabled, underlay_enabled,
                                            router, network):
        subnet = self.create_subnet(network, cleanup=False)
        self.router_attach(router, subnet, cleanup=False)
        try:
            self.update_subnet(
                subnet,
                nuage_underlay=nuage_underlay)
            self.update_subnet(subnet,
                               name="new-subnetname")
            nuage_subnet = self.vsd.get_subnet(
                by_subnet=subnet)
            self.assertIsNotNone(nuage_subnet,
                                 "Unable to retrieve L3 subnet from VSD")
            self.assertEqual(pat_enabled, nuage_subnet.pat_enabled,
                             "PATEnabled expected to be: {}, but was {}."
                             "for nuage_underlay={}"
                             .format(pat_enabled,
                                     nuage_subnet.pat_enabled,
                                     nuage_underlay))
            self.assertEqual(underlay_enabled, nuage_subnet.underlay_enabled,
                             "UnderlayEnabled expected to be: {}, but was {}."
                             "For nuage_underlay={}"
                             .format(underlay_enabled,
                                     nuage_subnet.underlay_enabled,
                                     nuage_underlay))
        finally:
            self.router_detach(router, subnet)
            self.delete_subnet(subnet=subnet)
        LOG.debug("Verified for nuage_underlay={}".format(nuage_underlay))

    def _subnet_no_op_update_check_no_change(self, nuage_underlay,
                                             pat_enabled, underlay_enabled,
                                             no_op_nuage_underlay,
                                             router, network):
        subnet = self.create_subnet(network, cleanup=False)
        self.router_attach(router, subnet, cleanup=False)
        try:
            self.update_subnet(
                subnet,
                nuage_underlay=nuage_underlay)
            self.update_subnet(
                subnet,
                nuage_underlay=no_op_nuage_underlay)
            nuage_subnet = self.vsd.get_subnet(
                by_subnet=subnet)
            self.assertIsNotNone(nuage_subnet,
                                 "Unable to retrieve L3 subnet from VSD")
            self.assertEqual(pat_enabled, nuage_subnet.pat_enabled,
                             "PATEnabled expected to be: {}, but was {}."
                             "for nuage_underlay={}"
                             .format(pat_enabled,
                                     nuage_subnet.pat_enabled,
                                     no_op_nuage_underlay))
            self.assertEqual(underlay_enabled, nuage_subnet.underlay_enabled,
                             "UnderlayEnabled expected to be: {}, but was {}."
                             "For nuage_underlay={}"
                             .format(underlay_enabled,
                                     nuage_subnet.underlay_enabled,
                                     no_op_nuage_underlay))
        finally:
            self.router_detach(router, subnet)
            self.delete_subnet(subnet=subnet)
        LOG.debug("Verified no-op for nuage_underlay={}"
                  .format(nuage_underlay))

    def _subnet_create_check_exception(self, nuage_underlay, network):
        self.assertRaises(
            exceptions.BadRequest,
            self.create_subnet,
            network,
            nuage_underlay=nuage_underlay
        )

    def _subnet_update_check_exception(self, nuage_underlay, network):
        subnet = self.create_subnet(network, cleanup=False)
        try:
            self.assertRaises(exceptions.BadRequest,
                              self.update_subnet,
                              subnet,
                              nuage_underlay=nuage_underlay)
        finally:
            self.delete_subnet(subnet=subnet)
        LOG.debug("Verified failure for nuage_underlay={}"
                  .format(nuage_underlay))

    def _subnet_update_check_vsd(self, nuage_underlay,
                                 pat_enabled, underlay_enabled,
                                 router, network):
        subnet = self.create_subnet(network, cleanup=False)
        self.router_attach(router, subnet, cleanup=False)
        try:
            self.update_subnet(
                subnet,
                nuage_underlay=nuage_underlay)
            nuage_subnet = self.vsd.get_subnet(
                by_subnet=subnet)
            self.assertIsNotNone(nuage_subnet,
                                 "Unable to retrieve L3 subnet from VSD")
            self.assertEqual(pat_enabled, nuage_subnet.pat_enabled,
                             "PATEnabled expected to be: {}, but was {}."
                             "for nuage_underlay={}"
                             .format(pat_enabled,
                                     nuage_subnet.pat_enabled,
                                     nuage_underlay))
            self.assertEqual(underlay_enabled, nuage_subnet.underlay_enabled,
                             "UnderlayEnabled expected to be: {}, but was {}."
                             "For nuage_underlay={}"
                             .format(underlay_enabled,
                                     nuage_subnet.underlay_enabled,
                                     nuage_underlay))
        finally:
            self.router_detach(router, subnet)
            self.delete_subnet(subnet=subnet)
        LOG.debug("Verified for nuage_underlay={}".format(nuage_underlay))
