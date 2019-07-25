# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants

from . import base_nuage_domain_tunnel_type

CONF = Topology.get_conf()


class NuageDomainTunnelTypeTest(
        base_nuage_domain_tunnel_type.NuageDomainTunnelTypeBase):

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
