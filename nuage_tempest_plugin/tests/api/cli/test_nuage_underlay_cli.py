# Copyright 2017 NOKIA
# All Rights Reserved.

import testtools

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from nuage_tempest_lib.cli.client_testcase \
    import CLIClientTestCase
from nuage_tempest_lib.cli.client_testcase import Role
from nuage_tempest_lib.features import NUAGE_FEATURES
from nuage_tempest_lib.topology import Topology


class TestNuageUnderlayCli(CLIClientTestCase):

    """Nuage Underlay tests using Neutron CLI client.

    """

    @classmethod
    def skip_checks(cls):
        super(TestNuageUnderlayCli, cls).skip_checks()
        if not NUAGE_FEATURES.route_to_underlay:
            msg = "Route to underlay not enabled"
            raise cls.skipException(msg)

    def _verify_router_nuage_underlay(self, router_id, nuage_underlay):
        # When I get the router
        show_router = self.show_router(router_id)

        # Then the router has the mentioned nuage underlay
        self.assertEqual(show_router['nuage_underlay'], nuage_underlay)

    def _verify_subnet_nuage_underlay(self, subnet_id, nuage_underlay):
        # When I get the subnet
        show_subnet = self.show_subnet(subnet_id)

        # Then the router has the mentioned nuage underlay
        self.assertEqual(show_subnet['nuage_underlay'], nuage_underlay)

    @decorators.attr(type='smoke')
    @testtools.skipIf(not Topology.new_route_to_underlay_model_enabled(),
                      'Skipping test as new route-to-UL model is not enabled')
    def test_cli_create_router_with_nuage_underlay_off(self):
        router_name = data_utils.rand_name('test-router')
        created_router = self.create_router_with_args(router_name,
                                                      '--nuage-underlay',
                                                      'off')
        # Then the router has the requested nuge underlay
        self.assertEqual(created_router['nuage_underlay'], 'off')
        self._verify_router_nuage_underlay(created_router['id'], 'off')

    @decorators.attr(type='smoke')
    @testtools.skipIf(not Topology.new_route_to_underlay_model_enabled(),
                      'Skipping test as new route-to-UL model is not enabled')
    def test_cli_update_router_with_nuage_underlay_off(self):
        router_name = data_utils.rand_name('test-router')
        created_router = self.create_router_with_args(router_name,
                                                      '--nuage-underlay',
                                                      'snat')
        self.assertEqual(created_router['nuage_underlay'], 'snat')
        self._verify_router_nuage_underlay(created_router['id'], 'snat')
        self.update_router_with_args(router_name, '--nuage-underlay', 'off')
        self._verify_router_nuage_underlay(created_router['id'], 'off')

    @decorators.attr(type='smoke')
    @testtools.skipIf(not Topology.new_route_to_underlay_model_enabled(),
                      'Skipping test as new route-to-UL model is not enabled')
    def test_cli_update_router_with_nuage_underlay_snat(self):
        router_name = data_utils.rand_name('test-router')
        created_router = self.create_router_with_args(router_name,
                                                      '--nuage-underlay',
                                                      'off')
        self.update_router_with_args(router_name, '--nuage-underlay', 'snat')
        self._verify_router_nuage_underlay(created_router['id'], 'snat')

    @decorators.attr(type='smoke')
    @testtools.skipIf(not Topology.new_route_to_underlay_model_enabled(),
                      'Skipping test as new route-to-UL model is not enabled')
    def test_cli_update_router_with_nuage_underlay_route(self):
        router_name = data_utils.rand_name('test-router')
        created_router = self.create_router_with_args(router_name,
                                                      '--nuage-underlay',
                                                      'off')
        self.update_router_with_args(router_name, '--nuage-underlay', 'route')
        self._verify_router_nuage_underlay(created_router['id'], 'route')

    @decorators.attr(type='smoke')
    @testtools.skipIf(not Topology.new_route_to_underlay_model_enabled(),
                      'Skipping test as new route-to-UL model is not enabled')
    def test_cli_update_subnet_nuage_underlay_route(self):
        network_name = data_utils.rand_name('nuage-underlay-network')
        subnet_name = data_utils.rand_name('nuage-underlay-subnet')
        router_name = data_utils.rand_name('nuage-underlay-router')
        created_router = self.create_router_with_args(router_name,
                                                      '--nuage-underlay',
                                                      'off')
        self._verify_router_nuage_underlay(created_router['id'], 'off')
        self.create_network(network_name)
        created_subnet = self.create_subnet_with_args(network_name,
                                                      '10.6.0.0/24',
                                                      '--name',
                                                      subnet_name)
        self.add_router_interface_with_args(router_name, subnet_name)
        self._verify_subnet_nuage_underlay(created_subnet['id'], 'inherited')
        self.update_subnet_with_args(subnet_name, '--nuage-underlay', 'route')
        self._verify_subnet_nuage_underlay(created_subnet['id'], 'route')

    @decorators.attr(type='smoke')
    @testtools.skipIf(not Topology.new_route_to_underlay_model_enabled(),
                      'Skipping test as new route-to-UL model is not enabled')
    def test_cli_update_subnet_nuage_underlay_snat(self):
        network_name = data_utils.rand_name('nuage-underlay-network')
        subnet_name = data_utils.rand_name('nuage-underlay-subnet')
        router_name = data_utils.rand_name('nuage-underlay-router')
        created_router = self.create_router_with_args(router_name,
                                                      '--nuage-underlay',
                                                      'route')
        self._verify_router_nuage_underlay(created_router['id'], 'route')
        self.create_network(network_name)
        created_subnet = self.create_subnet_with_args(network_name,
                                                      '10.6.0.0/24',
                                                      '--name',
                                                      subnet_name)
        self.add_router_interface_with_args(router_name, subnet_name)
        self._verify_subnet_nuage_underlay(created_subnet['id'], 'inherited')
        self.update_subnet_with_args(subnet_name, '--nuage-underlay', 'snat')
        self._verify_subnet_nuage_underlay(created_subnet['id'], 'snat')

    @decorators.attr(type='smoke')
    @testtools.skipIf(not Topology.new_route_to_underlay_model_enabled(),
                      'Skipping test as new route-to-UL model is not enabled')
    def test_cli_update_subnet_nuage_underlay_off(self):
        network_name = data_utils.rand_name('nuage-underlay-network')
        subnet_name = data_utils.rand_name('nuage-underlay-subnet')
        router_name = data_utils.rand_name('nuage-underlay-router')
        created_router = self.create_router_with_args(router_name,
                                                      '--nuage-underlay',
                                                      'snat')
        self.assertEqual(created_router['nuage_underlay'], 'snat')
        self._verify_router_nuage_underlay(created_router['id'], 'snat')
        self.create_network(network_name)
        created_subnet = self.create_subnet_with_args(network_name,
                                                      '10.6.0.0/24',
                                                      '--name',
                                                      subnet_name)
        self.add_router_interface_with_args(router_name, subnet_name)
        self._verify_subnet_nuage_underlay(created_subnet['id'], 'inherited')
        self.update_subnet_with_args(subnet_name, '--nuage-underlay', 'off')
        self._verify_subnet_nuage_underlay(created_subnet['id'], 'off')


class TestAdminNuageUnderlayCli(TestNuageUnderlayCli):

    @classmethod
    def resource_setup(cls):
        super(TestNuageUnderlayCli, cls).resource_setup()
        cls.me = Role.admin
