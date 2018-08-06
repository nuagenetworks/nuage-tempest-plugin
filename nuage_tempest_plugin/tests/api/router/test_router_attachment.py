# Copyright 2017 - Nokia
# All Rights Reserved.

from tempest.lib import decorators

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest


class RouterAttachmentTest(NuageBaseTest):

    @decorators.attr(type='smoke')
    def test_router_attachment_no_server(self):
        router = self.create_router()
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.router_attach(router, subnet)

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
