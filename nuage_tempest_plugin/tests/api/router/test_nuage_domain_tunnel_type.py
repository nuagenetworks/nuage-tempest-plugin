# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.utils import constants

import base_nuage_domain_tunnel_type


class NuageDomainTunnelType(
        base_nuage_domain_tunnel_type.NuageDomainTunnelTypeBase):

    @nuage_test.header()
    def test_domain_tunnel_type_first_gre_then_vxlan(self):

        created_router = self._do_create_router_with_domain_tunnel_type(
            constants.DOMAIN_TUNNEL_TYPE_GRE)

        self._verify_router_with_domain_tunnel_type_openstack(
            created_router, constants.DOMAIN_TUNNEL_TYPE_GRE)

        updated_router = self._update_router(
            created_router['id'],
            tunnel_type=constants.DOMAIN_TUNNEL_TYPE_VXLAN)

        self._verify_router_with_domain_tunnel_type_openstack(
            updated_router, constants.DOMAIN_TUNNEL_TYPE_VXLAN)

    @nuage_test.header()
    def test_domain_tunnel_type_first_vxlan_then_gre(self):
        created_router = self._do_create_router_with_domain_tunnel_type(
            constants.DOMAIN_TUNNEL_TYPE_VXLAN)

        self._verify_router_with_domain_tunnel_type_openstack(
            created_router, constants.DOMAIN_TUNNEL_TYPE_VXLAN)

        updated_router = self._update_router(
            created_router['id'],
            tunnel_type=constants.DOMAIN_TUNNEL_TYPE_GRE)

        self._verify_router_with_domain_tunnel_type_openstack(
            updated_router, constants.DOMAIN_TUNNEL_TYPE_GRE)
