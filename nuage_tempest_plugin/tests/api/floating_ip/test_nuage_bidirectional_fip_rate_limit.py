# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from tempest.test import decorators

from nuage_commons import constants

from nuage_tempest_plugin.tests.api.floating_ip \
    import base_nuage_bidirectional_fip_rate_limit


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
    def test_create_floatingip_with_rate_limit_normal_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 2000, 3000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip, 5000, 10000)

    def test_show_floatingip_with_rate_limit_normal_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 4000, 2000)
        self._show_fip_with_fip_rate_limit(self.ports[0], fip, 4000, 2000)

    # OPENSTACK-1583
    def test_create_floatingip_with_rate_limit_minimal_value(self):
        self._create_fip_with_fip_rate_limit(self.ports[0], '0', '0')

    def test_create_floatingip_with_rate_limit_maximal_value(self):
        self._create_fip_with_fip_rate_limit(self.ports[0],
                                             constants.MAX_INT,
                                             constants.MAX_INT)

    def test_create_floatingip_with_rate_limit_high_value(self):
        self._create_fip_with_fip_rate_limit(self.ports[0], 100000, 900000)

    # @nuage_test.header()
    # this test case will be moved to negative cases for this feature
    # message': u'Bad request: nuage_ingress_fip_rate_kbps value cannot be
    # in fraction'
    # def test_create_floatingip_with_rate_limit_fractional_value(self):
    #    self._create_fip_with_fip_rate_limit(self.ports[0], 0.5, 0.5)

    def test_create_floatingip_with_rate_limit_unlimited_value(self):
        self._create_fip_with_fip_rate_limit(self.ports[0],
                                             constants.UNLIMITED,
                                             constants.UNLIMITED)

    def test_update_floatingip_with_rate_limit_minimal_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 2000, 5000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip, 0, 0)

    def test_update_floatingip_with_rate_limit_unlimited_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 3000, 5000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip,
                                             constants.UNLIMITED,
                                             constants.UNLIMITED)

    def test_update_floatingip_with_rate_limit_maximal_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 3000, 5000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip,
                                             constants.MAX_INT,
                                             constants.MAX_INT)

    def test_update_floatingip_with_rate_limit_high_value(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 3000, 5000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip,
                                             100000, 100000)

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

        get_fips = [_fip for _fip in fip_list if _fip['id'] == fip1['id']]
        self.assertRaises(KeyError, get_attr, get_fips[0], 'nuage_fip_rate')

    # ONLY INGRESS DIRECTION TESTS
    @decorators.attr(type='smoke')
    def test_create_floatingip_with_rate_limit_normal_value_ingress(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 2000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip, 5000)

    def test_show_floatingip_with_rate_limit_normal_value_ingress(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 4000)
        self._show_fip_with_fip_rate_limit(self.ports[0], fip, 4000)

    # OPENSTACK-1583
    def test_create_floatingip_with_rate_limit_minimal_value_ingress(self):
        self._create_fip_with_fip_rate_limit(self.ports[0], '0')

    def test_create_floatingip_with_rate_limit_maximal_value_ingress(self):
        self._create_fip_with_fip_rate_limit(self.ports[0], constants.MAX_INT)

    def test_create_floatingip_with_rate_limit_high_value_ingress(self):
        self._create_fip_with_fip_rate_limit(self.ports[0], 100000)

    def test_create_floatingip_with_rate_limit_unlimited_value_ingress(self):
        self._create_fip_with_fip_rate_limit(self.ports[0],
                                             constants.UNLIMITED)

    def test_update_floatingip_with_rate_limit_minimal_value_ingress(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 2000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip, 0)

    def test_update_floatingip_with_rate_limit_unlimited_value_ingress(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 3000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip,
                                             constants.UNLIMITED)

    def test_update_floatingip_with_rate_limit_high_value_ingress(self):
        fip = self._create_fip_with_fip_rate_limit(self.ports[0], 3000)
        self._update_fip_with_fip_rate_limit(self.ports[0], fip, 100000)

    # ONLY EGRESS DIRECTION TESTS
    @decorators.attr(type='smoke')
    def test_create_floatingip_with_rate_limit_normal_value_egress(self):
        fip = self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=2000)
        self._update_fip_with_fip_rate_limit(
            self.ports[0], fip, egress_rate_limit=5000)

    def test_show_floatingip_with_rate_limit_normal_value_egress(self):
        fip = self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=4000)
        self._show_fip_with_fip_rate_limit(
            self.ports[0], fip, egress_rate_limit=4000)

    # OPENSTACK-1583
    def test_create_floatingip_with_rate_limit_minimal_value_egress(self):
        self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit='0')

    def test_create_floatingip_with_rate_limit_maximal_value_egress(self):
        self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=constants.MAX_INT)

    def test_create_floatingip_with_rate_limit_high_value_egress(self):
        self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=100000)

    def test_create_floatingip_with_rate_limit_unlimited_value_egress(self):
        self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=constants.UNLIMITED)

    def test_update_floatingip_with_rate_limit_minimal_value_egress(self):
        fip = self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=2000)
        self._update_fip_with_fip_rate_limit(
            self.ports[0], fip, egress_rate_limit=0)

    def test_update_floatingip_with_rate_limit_unlimited_value_egress(self):
        fip = self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=3000)
        self._update_fip_with_fip_rate_limit(
            self.ports[0], fip, egress_rate_limit=constants.UNLIMITED)

    def test_update_floatingip_with_rate_limit_high_value_egress(self):
        self._create_fip_with_fip_rate_limit(
            self.ports[0], egress_rate_limit=3000)

    def test_create_floatingip_with_rate_limit_backward(self):
        self._create_fip_with_fip_rate_limit_backward(
            self.ports[0], rate_limit=3000)
