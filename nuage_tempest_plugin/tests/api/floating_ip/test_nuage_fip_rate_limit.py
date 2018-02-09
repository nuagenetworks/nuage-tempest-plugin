# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from tempest.test import decorators

import base_nuage_fip_rate_limit

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants

LOG = Topology.get_logger(__name__)


class TestNuageFipRateLimit(base_nuage_fip_rate_limit.NuageFipRateLimitBase):
    """TestNuageFipRateLimit

    Tests per FIP rate limiting using the neutron REST client

        Create a Floating IP
        Update a Floating IP
        List all Floating IPs

    v2.0 of the Neutron API is assumed. It is also assumed that the following
    options are defined in the [network] section of etc/tempest.conf:

        public_network_id which is the id for the external network present
    """

    @classmethod
    def resource_setup(cls):
        super(TestNuageFipRateLimit, cls).resource_setup()

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_normal_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 123)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip, 321)

    @nuage_test.header()
    # CLOSED: OPENSTACK-745
    def test_show_floatingip_with_rate_limit_normal_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 123)
        self._show_fip_with_fip_rate_limit(self.ports[0], fip, 123)

    @nuage_test.header()
    # CLOSED: OPENSTACK-739, OPENSTACK-796
    def test_create_floatingip_with_rate_limit_minimal_value(self):
        self._create_fip_with_fip_rate_limit(self.ports[0], 0)

    # No max defined on API
    # @nuage_test.header()
    # def test_create_floatingip_with_rate_limit_maximal_value(self):
    #     self._create_fip_with_fip_rate_limit(self.ports[0],
    #         constants.MAX_INT)

    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_high_value(self):
        self._create_fip_with_fip_rate_limit(self.ports[0], 100000)

    @nuage_test.header()
    # See: OPENSTACK-1105
    def test_create_floatingip_with_rate_limit_fractional_value(self):
        self._create_fip_with_fip_rate_limit(self.ports[0], 0.5)

    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_unlimited_value(self):
        self._create_fip_with_fip_rate_limit(self.ports[0],
                                             constants.UNLIMITED)

    @nuage_test.header()
    # CLOSED: OPENSTACK-739, OPENSTACK-796"
    def test_update_floatingip_with_rate_limit_minimal_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 123)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip, 0)

    @nuage_test.header()
    def test_update_floatingip_with_rate_limit_unlimited_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 123)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip,
                                             constants.UNLIMITED)

    # NO Max value defined in API
    # @nuage_test.header()
    # def test_update_floatingip_with_rate_limit_maximal_value(self):
    #     fip = self._create_fip_with_fip_rate_limit(self.ports[0], 123)
    #     self._update_fip_with_fip_rate_limit(self.ports[0], fip,
    #          constants.MAX_INT)

    def test_update_floatingip_with_rate_limit_high_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 123)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip, 100000)

    @nuage_test.header()
    def test_list_floatingip_does_not_show_rate_limit_value(self):
        def get_attr(_dict, _key):
            return _dict[_key]

        fip1 = self._create_fip_with_fip_rate_limit(self.ports[0], 10)
        fip2 = self._create_fip_with_fip_rate_limit(self.ports[1], 20)

        body = self.floating_ips_client.list_floatingips()
        fip_list = body['floatingips']

        # Floating ips are in the list
        self.assertIn(fip1['id'],
                      [fip['id'] for fip in fip_list])
        self.assertIn(fip2['id'],
                      [fip['id'] for fip in fip_list])

        get_fips = filter(lambda _fip: _fip['id'] == fip1['id'], fip_list)
        self.assertRaises(KeyError, get_attr, get_fips[0], 'nuage_fip_rate')
