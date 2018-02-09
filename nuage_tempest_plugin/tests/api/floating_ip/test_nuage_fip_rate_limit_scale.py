# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from tempest.test import decorators

import base_nuage_fip_rate_limit

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology

LOG = Topology.get_logger(__name__)


class TestNuageFipRateLimitBaseScale(
        base_nuage_fip_rate_limit.NuageFipRateLimitBase):

    """TestNuageFipRateLimitBaseScale

    Tests per FIP rate limiting using the neutron REST client

        Scaling
    """

    @classmethod
    def resource_setup(cls):
        super(TestNuageFipRateLimitBaseScale, cls).resource_setup()

    @nuage_test.header()
    @decorators.attr(type='slow')
    # TODO(team) test for 100 or more FIP's.
    def test_floatingip_scale(self):
        for x in range(0, 10):
            port = self.create_port(self.network)
            fip_rate_limit = 123000 + x
            self._do_create_fip_for_port_with_rate_limit(port['id'],
                                                         fip_rate_limit)
            # new_fip_rate_limit = fip_rate_limit + 100000
            # self._do_update_fip_to_rate_limit(fip['id'], new_fip_rate_limit)

        # LOG.info("Complete")
