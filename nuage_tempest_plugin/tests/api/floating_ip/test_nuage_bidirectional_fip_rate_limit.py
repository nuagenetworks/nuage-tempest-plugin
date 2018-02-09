# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from tempest.test import decorators

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants

import base_nuage_bidirectional_fip_rate_limit

LOG = Topology.get_logger(__name__)


class TestNuageBidirectionalFipRateLimit(
        base_nuage_bidirectional_fip_rate_limit.
        NuageBidirectionalFipRateLimitBase):

    """TestNuageBidirectionalFipRateLimit

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
        super(TestNuageBidirectionalFipRateLimit, cls).resource_setup()

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_normal_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 2000, 3000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip, 5000, 10000)

    @nuage_test.header()
    def test_show_floatingip_with_rate_limit_normal_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 4000, 2000)
        self._show_fip_with_fip_rate_limit(self.ports[0], fip, 4000, 2000)

    @nuage_test.header()
    # OPENSTACK-1583
    def test_create_floatingip_with_rate_limit_minimal_value(self):
        self._create_fip_with_fip_rate_limit(self.ports[0], '0', '0')

    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_maximal_value(self):
        self._create_fip_with_fip_rate_limit(self.ports[0],
                                             constants.MAX_INT,
                                             constants.MAX_INT)

    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_high_value(self):
        self._create_fip_with_fip_rate_limit(self.ports[0], 100000, 900000)

    # @nuage_test.header()
    # this test case will be moved to negative cases for this feature
    # message': u'Bad request: nuage_ingress_fip_rate_kbps value cannot be
    # in fraction'
    # def test_create_floatingip_with_rate_limit_fractional_value(self):
    #    self._create_fip_with_fip_rate_limit(self.ports[0], 0.5, 0.5)

    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_unlimited_value(self):
        self._create_fip_with_fip_rate_limit(self.ports[0],
                                             constants.UNLIMITED,
                                             constants.UNLIMITED)

    @nuage_test.header()
    def test_update_floatingip_with_rate_limit_minimal_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 2000, 5000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip, 0, 0)

    @nuage_test.header()
    def test_update_floatingip_with_rate_limit_unlimited_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 3000, 5000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip,
                                             constants.UNLIMITED,
                                             constants.UNLIMITED)

    @nuage_test.header()
    def test_update_floatingip_with_rate_limit_maximal_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 3000, 5000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip,
                                             constants.MAX_INT,
                                             constants.MAX_INT)

    def test_update_floatingip_with_rate_limit_high_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 3000, 5000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip,
                                             100000, 100000)

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

    # ONLY INGRESS DIRECTION TESTS
    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_normal_value_ingress(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 2000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip, 5000)

    @nuage_test.header()
    def test_show_floatingip_with_rate_limit_normal_value_ingress(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 4000)
        self._show_fip_with_fip_rate_limit(self.ports[0], fip, 4000)

    @nuage_test.header()
    # OPENSTACK-1583
    def test_create_floatingip_with_rate_limit_minimal_value_ingress(self):
        self._create_fip_with_fip_rate_limit(self.ports[0], '0')

    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_maximal_value_ingress(self):
        self._create_fip_with_fip_rate_limit(self.ports[0], constants.MAX_INT)

    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_high_value_ingress(self):
        self._create_fip_with_fip_rate_limit(self.ports[0], 100000)

    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_unlimited_value_ingress(self):
        self._create_fip_with_fip_rate_limit(self.ports[0],
                                             constants.UNLIMITED)

    @nuage_test.header()
    def test_update_floatingip_with_rate_limit_minimal_value_ingress(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 2000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip, 0)

    @nuage_test.header()
    def test_update_floatingip_with_rate_limit_unlimited_value_ingress(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 3000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip,
                                             constants.UNLIMITED)

    @nuage_test.header()
    def test_update_floatingip_with_rate_limit_high_value_ingress(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 3000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip, 100000)

    # ONLY EGRESS DIRECTION TESTS
    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_normal_value_egress(self):
        fip = self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=2000)
        self._update_fip_with_fip_rate_limit(
            self.ports[0], fip, egress_rate_limit=5000)

    @nuage_test.header()
    def test_show_floatingip_with_rate_limit_normal_value_egress(self):
        fip = self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=4000)
        self._show_fip_with_fip_rate_limit(
            self.ports[0], fip, egress_rate_limit=4000)

    @nuage_test.header()
    # OPENSTACK-1583
    def test_create_floatingip_with_rate_limit_minimal_value_egress(self):
        self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit='0')

    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_maximal_value_egress(self):
        self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=constants.MAX_INT)

    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_high_value_egress(self):
        self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=100000)

    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_unlimited_value_egress(self):
        self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=constants.UNLIMITED)

    @nuage_test.header()
    def test_update_floatingip_with_rate_limit_minimal_value_egress(self):
        fip = self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=2000)
        self._update_fip_with_fip_rate_limit(
            self.ports[0], fip, egress_rate_limit=0)

    @nuage_test.header()
    def test_update_floatingip_with_rate_limit_unlimited_value_egress(self):
        fip = self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=3000)
        self._update_fip_with_fip_rate_limit(
            self.ports[0], fip, egress_rate_limit=constants.UNLIMITED)

    @nuage_test.header()
    def test_update_floatingip_with_rate_limit_high_value_egress(self):
        self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=3000)

    @nuage_test.header()
    def test_create_floatingip_with_rate_limit_backward(self):
        self._create_fip_with_fip_rate_limit_backward(
            self.ports[0], rate_limit=3000)
