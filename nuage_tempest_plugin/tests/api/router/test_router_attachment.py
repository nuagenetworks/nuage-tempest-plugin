# Copyright 2017 - Nokia
# All Rights Reserved.

from tempest.lib import decorators
from tempest.lib import exceptions as tempest_exceptions

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest


class RouterAttachmentTest(NuageBaseTest):
    """Router attachment special cases

    Note: Router attachment is also tested in
    - nuage_tempest_plugin/tests/api/router/test_routers_nuage.py
    - nuage_tempest_plugin/tests/api/ipv6/os_managed/test_os_managed_dualstack_
      l3_subnets.py
    """

    @decorators.attr(type='smoke')
    def test_router_attachment_no_server(self):
        router = self.create_router()
        network = self.create_network()
        subnet = self.create_subnet(network)
        self._validate_is_not_attached_to_router(subnet, router)
        self.router_attach(router, subnet)
        self._validate_is_attached_to_router(subnet, router)

    @decorators.attr(type='smoke')
    def test_router_attachment(self):
        router = self.create_router()
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.create_tenant_server(networks=[network])
        self.router_attach(router, subnet)

    # TODO(KRIS) OPENSTACK-1880 - TAKING OUT OF SMOKE .....
    # @decorators.attr(type='smoke')
    def test_router_attachment_add_server_before_attach(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.create_tenant_server(networks=[network])

        router = self.create_router()
        self.router_attach(router, subnet)

        # TODO(OPENSTACK-1880)
        # this test is failing regularly at deleting the router
        # as part of cleanup, too soon after deleting the router interface.
        # i.e. : vsdclient/resources/domain.py" in delete_router
        # receiving : NuageAPIException: Nuage API: vPort has VMInterface
        # network interfaces associated with it.

    @decorators.attr(type='smoke')
    def test_router_attachment_add_server_before_attach_delayed(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.create_tenant_server(networks=[network])

        # TODO(KRIS) - adding retry_on_router_delete fixes the above test
        router = self.create_router(retry_on_router_delete=True)
        self.router_attach(router, subnet)

    @decorators.attr(type='smoke')
    def test_router_attachment_with_ports(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router1 = self.create_router()
        router2 = self.create_router()
        port1 = self.create_port(network, cleanup=False)
        port2 = self.create_port(network)
        self.router_attach_with_port_id(router1, port1)
        msg = 'Cannot attach Subnet %s to multiple routers. ' \
              'Router-IF add failed' % subnet['id']
        self.assertRaisesRegex(tempest_exceptions.BadRequest,
                               msg,
                               self.router_attach_with_port_id,
                               router2,
                               port2)

    @decorators.attr(type='smoke')
    def test_router_detachment_with_subnet(self):
        network = self.create_network()
        router1 = self.create_router()
        router2 = self.create_router()
        subnet1 = self.create_subnet(network)
        subnet2 = self.create_subnet(network)
        self.router_attach(router1, subnet1, cleanup=False)

        # try to delete non-existing router-interfaces
        should_fail = [(router1, subnet2), (router2, subnet1),
                       (router2, subnet2)]
        for (router, subnet) in should_fail:
            msg = "Router {} has no interface on subnet " \
                  "{}".format(router['id'], subnet['id'])
            self.assertRaisesRegex(tempest_exceptions.NotFound, msg,
                                   self.router_detach, router, subnet)

        # try to delete the existing router interface
        self._validate_is_attached_to_router(subnet1, router1)
        self.router_detach(router1, subnet1)
        self._validate_is_not_attached_to_router(subnet1, router1)

    @decorators.attr(type='smoke')
    def test_router_detachment_with_port(self):
        network = self.create_network()
        router1 = self.create_router()
        router2 = self.create_router()
        subnet1 = self.create_subnet(network)
        subnet2 = self.create_subnet(network)

        port1_subnet1 = self.create_port(
            network, fixed_ips=[{'subnet_id': subnet1['id']}], cleanup=False)
        port2_subnet1 = self.create_port(
            network, fixed_ips=[{'subnet_id': subnet1['id']}])
        port1_subnet2 = self.create_port(
            network, fixed_ips=[{'subnet_id': subnet2['id']}])

        self.router_attach_with_port_id(router1, port1_subnet1, cleanup=False)

        # try to delete non-existing router-interfaces
        should_fail = [(router1, port2_subnet1), (router1, port1_subnet2),
                       (router2, port1_subnet1), (router2, port2_subnet1),
                       (router2, port1_subnet2),
                       (router2, {'id': 'cleary_does_not_exist'})]
        for (router, port) in should_fail:
            msg = "Router {} does not have " \
                  "an interface with id {}".format(router['id'], port['id'])
            self.assertRaisesRegex(
                tempest_exceptions.NotFound, msg,
                self.router_detach_with_port_id, router, port)

        # try to delete the existing router interface
        self._validate_is_attached_to_router(subnet1, router1)
        self.router_detach_with_port_id(router1, port1_subnet1)
        self._validate_is_not_attached_to_router(subnet1, router1)

    def _validate_is_attached_to_router(self, subnet, router):
        # validate that the interface now exists
        router_interface = self.get_router_interface(router['id'],
                                                     subnet['id'])
        self.assertIsNotNone(router_interface)
        observed_subnet_id = router_interface['fixed_ips'][0]['subnet_id']
        self.assertEqual(expected=subnet['id'],
                         observed=observed_subnet_id)

        # validate the vsd configuration
        domain = self.vsd.get_l3_domain_by_subnet_id(subnet['id'])
        self.assertIsNotNone(domain)
        self.assertEqual(expected=self.vsd.external_id(router['id']),
                         observed=domain.external_id)

    def _validate_is_not_attached_to_router(self, subnet, router):
        # validate that the interface does not exists
        router_interface = self.get_router_interface(router['id'],
                                                     subnet['id'])
        self.assertIsNone(router_interface)

        # Check we are at L2 in VSD
        self.assertIsNone(self.vsd.get_l3_domain_by_subnet_id(subnet['id']))
        self.assertIsNotNone(self.vsd.get_l2domain(by_subnet_id=subnet['id']))
