# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from tempest.lib import exceptions as lib_exc
from tempest.test import decorators

import base_nuage_bidirectional_fip_rate_limit

from nuage_tempest_plugin.lib.test import nuage_test


MSG_INVALID_INPUT_IN = "'nuage_ingress_fip_rate_kbps' should be a " \
                       "number higher than 0, -1 for unlimited or " \
                       "'default' for the configured default value."
MSG_INVALID_INPUT_EG = "'nuage_egress_fip_rate_kbps' should be a number " \
                       "higher than 0, -1 for unlimited or 'default' " \
                       "for the configured default value."
MSG_INVALID_INPUT2 = "Nuage API: Error in REST call to VSD: fipPir\(NaN\) " \
                     "must be a valid Integer greater than zero or set to " \
                     "INFINITY"


MSG_INVALID_INPUT_FOR_OPERATION = "Invalid input for operation: " + \
                                  "'nuage_fip_rate' should be a number " \
                                  "higher than 0, -1 for unlimited " + \
                                  "or 'default' for the configured " \
                                  "default value.."


class TestNuageBidiFipRateLimitBaseCreateNegative(
        base_nuage_bidirectional_fip_rate_limit.
        NuageBidirectionalFipRateLimitBase):

    """TestNuageBidiFipRateLimitBaseCreateNegative

    Negative tests for the per FIP rate limiting based on the neutron REST API.

    Creation of the FIP with rate limiting

    """

    @classmethod
    def resource_setup(cls):
        super(TestNuageBidiFipRateLimitBaseCreateNegative, cls).\
            resource_setup()
        cls.port = cls.ports[0]

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_below_min_value_ingress(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT_IN,
                               self._create_fip_with_fip_rate_limit,
                               self.port, ingress_rate_limit=-2)

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_invalid_value_ingress(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT_IN,
                               self._create_fip_with_fip_rate_limit,
                               self.port, ingress_rate_limit='NaN')

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_no_value_ingress(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT_IN,
                               self._create_fip_with_fip_rate_limit,
                               self.port, ingress_rate_limit='')

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_below_min_value_egress(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT_EG,
                               self._create_fip_with_fip_rate_limit,
                               self.port, egress_rate_limit=-2)

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_invalid_value_egress(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT_EG,
                               self._create_fip_with_fip_rate_limit,
                               self.port, egress_rate_limit='NaN')

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_no_value_egress(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT_EG,
                               self._create_fip_with_fip_rate_limit,
                               self.port, egress_rate_limit='')


class TestNuageBidiFipRateLimitBaseUpdateNegative(
        base_nuage_bidirectional_fip_rate_limit.
        NuageBidirectionalFipRateLimitBase):

    """TestNuageBidiFipRateLimitBaseUpdateNegative

    Negative tests for the per FIP rate limiting based on the neutron REST API.

    Update of the FIP with rate limiting

    """

    @classmethod
    def resource_setup(cls):
        super(TestNuageBidiFipRateLimitBaseUpdateNegative, cls).\
            resource_setup()
        cls.port = cls.ports[1]
        cls.fip = cls._create_fip_for_port_with_rate_limit(
            cls.port['id'], ingress_rate_limit=456, egress_rate_limit=456)

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_below_min_value_ingress(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT_IN,
                               self._update_fip_with_fip_rate_limit,
                               self.port, self.fip, ingress_rate_limit=-2)

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_invalid_value_ingress(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT_IN,
                               self._update_fip_with_fip_rate_limit,
                               self.port, self.fip, ingress_rate_limit='NaN')

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_no_value_ingress(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT_IN,
                               self._update_fip_with_fip_rate_limit,
                               self.port, self.fip, ingress_rate_limit='')

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_below_min_value_egress(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT_EG,
                               self._update_fip_with_fip_rate_limit,
                               self.port, self.fip, egress_rate_limit=-2)

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_invalid_value_egress(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT_EG,
                               self._update_fip_with_fip_rate_limit,
                               self.port, self.fip, egress_rate_limit='NaN')

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_no_value_egress(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT_EG,
                               self._update_fip_with_fip_rate_limit,
                               self.port, self.fip, egress_rate_limit='')


class TestNuageBidiFRLBaseAssociationNegative(
        base_nuage_bidirectional_fip_rate_limit.
        NuageBidirectionalFipRateLimitBase):

    """TestNuageBidiFRLBaseAssociationNegative

    Negative tests for the per FIP rate limiting based on the neutron REST API.

    Create/Update of the FIP with rate limiting without port association

    """

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_fail_to_create_fip_with_rate_limit_wo_port_assoc(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               "Rate limiting requires the floating ip to be "
                               "associated to a port.",
                               self.floating_ips_client.create_floatingip,
                               floating_network_id=self.ext_net_id,
                               nuage_ingress_fip_rate_kbps=321)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_fail_to_update_fip_with_rate_limit_without_port_assoc(self):
        fip2 = self._do_create_fip_for_port_with_rate_limit(
            self.ports[1]['id'], 456)

        # Disassociate the port
        self.floating_ips_client.update_floatingip(fip2['id'], port_id=None)
        self.assertRaisesRegex(lib_exc.BadRequest,
                               "Bad floatingip request: " +
                               "Rate limiting requires the floating ip to be "
                               "associated to a port.",
                               self.floating_ips_client.update_floatingip,
                               fip2['id'],
                               nuage_ingress_fip_rate_kbps=321)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_fail_to_update_fip_with_rate_limit_and_port_disassoc(self):
        fip2 = self._do_create_fip_for_port_with_rate_limit(
            self.ports[1]['id'], 456)
        self.assertRaisesRegex(lib_exc.BadRequest,
                               "Bad floatingip request: " +
                               "Rate limiting requires the floating ip to be "
                               "associated to a port.",
                               self.floating_ips_client.update_floatingip,
                               fip2['id'],
                               port_id=None,
                               nuage_ingress_fip_rate_kbps=321)
