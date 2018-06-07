# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from tempest.lib.common.utils import data_utils
from tempest import test

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services import nuage_client

CONF = Topology.get_conf()


class NuageDomainTunnelTypeBase(test.BaseTestCase):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(NuageDomainTunnelTypeBase, cls).setup_clients()
        cls.os_admin = cls.get_client_manager(credential_type='admin')
        cls.client = cls.os_admin.networks_client
        cls.nuage_client = nuage_client.NuageRestClient()

    def _create_router(self, **kwargs):
        # Create a router
        name = data_utils.rand_name('router-')
        create_body = self.os_admin.routers_client.create_router(
            name=name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=False,
            **kwargs)

        self.addCleanup(self.os_admin.routers_client.delete_router,
                        create_body['router']['id'])
        router = create_body['router']

        self.assertEqual(router['name'], name)
        return router

# TODO(waelj) submit an upstream pull request on
# tempest.services.network.json.network_client to process
# all attributes in kwargs (to support extended attribute updates)

# overrule the parent class in order to allow update of tunnel_type

    def _upstream_update_router(self, router_id, set_enable_snat, **kwargs):
        uri = '/routers/%s' % router_id
        body = self.os_admin.routers_client.show_resource(uri)

        # patch for tunnel_type
        update_body = {'name':
                       kwargs.get('name', body['router']['name']),
                       'admin_state_up':
                       kwargs.get('admin_state_up',
                                  body['router']['admin_state_up']),
                       'tunnel_type':
                       kwargs.get('tunnel_type',
                                  body['router']['tunnel_type'])}
        # end of patch for tunnel_type

        cur_gw_info = body['router']['external_gateway_info']
        if cur_gw_info:
            # TODO(kevinbenton): setting the external gateway info is not
            # allowed for a regular tenant. If the ability to update is also
            # merged, a test case for this will need to be added similar to
            # the SNAT case.
            cur_gw_info.pop('external_fixed_ips', None)
            if not set_enable_snat:
                cur_gw_info.pop('enable_snat', None)
        update_body['external_gateway_info'] = kwargs.get(
            'external_gateway_info', body['router']['external_gateway_info'])
        if 'distributed' in kwargs:
            update_body['distributed'] = kwargs['distributed']
        update_body = dict(router=update_body)
        return self.os_admin.routers_client.update_resource(uri, update_body)

    def upstream_update_router(self, router_id, **kwargs):
        """Update a router leaving enable_snat to its default value."""
        # If external_gateway_info contains enable_snat the request will fail
        # with 404 unless executed with admin client, and therefore we instruct
        # _update_router to not set this attribute
        # NOTE(salv-orlando): The above applies as long as Neutron's default
        # policy is to restrict enable_snat usage to admins only.
        return self._upstream_update_router(
            router_id, set_enable_snat=False, **kwargs)

# end of overruled messages

    def _update_router(self, router_id, **kwargs):
        # Create a router
        # body = self.client.update_router(
        #     router_id,
        #     **kwargs)
        body = self.upstream_update_router(
            router_id,
            **kwargs)

        router = body['router']

        self.assertEqual(router['id'], router_id)
        return router

    def _show_router(self, router_id):
        show_body = self.os_admin.routers_client.show_router(router_id)
        router = show_body['router']

        self.assertEqual(router['id'], router_id)
        return router

    def _list_routers(self):
        body = self.os_admin.routers_client.list_routers()
        return body['routers']

    def _delete_router(self, router_id):
        self.os_admin.routers_client.delete_router(router_id)
        # Asserting that the router is not found in the list
        # after deletion
        list_body = self.os_admin.routers_client.list_routers()
        routers_list = list()
        for router in list_body['routers']:
            routers_list.append(router['id'])
        self.assertNotIn(router_id, routers_list)

    def _do_create_router_with_domain_tunnel_type(self, domain_tunnel_type):
        return self._create_router(tunnel_type=domain_tunnel_type)

    def _verify_router_with_domain_tunnel_type_openstack(
            self, the_router, domain_tunnel_type):
        # Then the router has the requested tunnel type
        self.assertEqual(
            the_router['tunnel_type'], str.upper(domain_tunnel_type))

        # When I get the router
        show_router = self._show_router(the_router['id'])

        # Then the router has the expected tunnel type
        self.assertEqual(
            show_router['tunnel_type'], str.upper(domain_tunnel_type))
