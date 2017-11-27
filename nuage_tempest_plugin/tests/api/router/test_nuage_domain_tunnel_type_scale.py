# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from tempest import config

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.utils import constants

import base_nuage_domain_tunnel_type

CONF = config.CONF


class NuageDomainTunnelType(
        base_nuage_domain_tunnel_type.NuageDomainTunnelTypeBase):

    """Scaling """

    @nuage_test.header()
    def test_domain_tunnel_type_scale(self):
        # domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_GRE

        # reduce maximum for regression.
        _max = 4
        for x in range(0, _max):
            if x % 2 == 0:
                domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_GRE
            else:
                domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_VXLAN

            created_router = self._do_create_router_with_domain_tunnel_type(
                domain_tunnel_type)
            self._verify_router_with_domain_tunnel_type_openstack(
                created_router, domain_tunnel_type)

            if x % 2 == 0:
                domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_VXLAN
            else:
                domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_GRE

            updated_router = self._update_router(
                created_router['id'], tunnel_type=domain_tunnel_type)

            # Then I have a router in OpenStack
            # with the requested domain tunnel type
            self._verify_router_with_domain_tunnel_type_openstack(
                updated_router, domain_tunnel_type)
