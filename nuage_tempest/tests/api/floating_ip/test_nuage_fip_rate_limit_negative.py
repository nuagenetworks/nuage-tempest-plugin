# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.
#

from tempest import config
from tempest.lib import exceptions as lib_exc
from tempest.test import decorators

import base_nuage_fip_rate_limit

from nuage_tempest.lib.test import nuage_test

CONF = config.CONF

# MSG_INVALID_INPUT = "Invalid input for nuage_fip_rate. " \
#                     "Reason: \'nuage_fip_rate\' " + \
#                     "should be a number higher than 0, -1 for unlimited " + \
#                     "or \'default\' for the configured default value.."

MSG_INVALID_INPUT = "\'nuage_fip_rate\' " + \
                    "should be a number higher than 0, -1 for unlimited " + \
                    "or \'default\' for the configured default value.."

MSG_INVALID_INPUT2 = "Nuage API: Error in REST call to VSD: fipPir\(NaN\) " \
                     "must be a valid Integer greater than zero or set to " \
                     "INFINITY"

MSG_INVALID_INPUT_FOR_OPERATION = "Invalid input for operation: " + \
                                  MSG_INVALID_INPUT


class TestNuageFipRateLimitBaseCreateNegative(
        base_nuage_fip_rate_limit.NuageFipRateLimitBase):

    """TestNuageFipRateLimitBaseCreateNegative

    Negative tests for the per FIP rate limiting based on the neutron REST API.

    Creation of the FIP with rate limiting

    """

    @classmethod
    def resource_setup(cls):
        super(TestNuageFipRateLimitBaseCreateNegative, cls).resource_setup()
        cls.port = cls.ports[0]

    # VSD does not test on maximum anymore
    # @test.attr(type=['negative'])
    # @nuage_test.header()
    # @nuage_test.nuage_skip_because(message="VSD-13397 -
    # FIP rate limiting: no maxim value")
    # def test_create_fip_with_default_rate_limit_above_max_value(self):
    #     self.assertRaisesRegex(lib_exc.BadRequest,
    #                            MSG_INVALID_INPUT,
    #                            self._create_fip_with_fip_rate_limit,
    #                            self.port, constants.MAX_INT + 1)

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_below_min_value(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT,
                               self._create_fip_with_fip_rate_limit,
                               self.port, -2)

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_invalid_value(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT,
                               self._create_fip_with_fip_rate_limit,
                               self.port, 'NaN')

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_create_fip_with_default_rate_limit_no_value(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT,
                               self._create_fip_with_fip_rate_limit,
                               self.port, '')


class TestNuageFipRateLimitBaseUpdateNegative(
        base_nuage_fip_rate_limit.NuageFipRateLimitBase):

    """TestNuageFipRateLimitBaseUpdateNegative

    Negative tests for the per FIP rate limiting based on the neutron REST API.

    Update of the FIP with rate limiting

    """

    @classmethod
    def resource_setup(cls):
        super(TestNuageFipRateLimitBaseUpdateNegative, cls).resource_setup()
        cls.port = cls.ports[1]
        cls.fip = cls._create_fip_for_port_with_rate_limit(cls.port['id'],
                                                           rate_limit=456)

    # VSD does not has maximum !
    # @nuage_test.header()
    # @nuage_test.nuage_skip_because(message="VSD-13397 - FIP rate limiting:
    # no maxim value")
    # def test_update_fip_with_rate_limit_above_maximal_value(self):
    #     self.fip = self._create_fip_for_port_with_rate_limit(self.port['id'],
    #                                                          456)
    #     self.assertRaisesRegex(lib_exc.BadRequest,
    #                            MSG_INVALID_INPUT,
    #                            self._update_fip_with_fip_rate_limit,
    #                            self.port, self.fip, constants.MAX_INT + 1)

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_below_min_value(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT,
                               self._update_fip_with_fip_rate_limit,
                               self.port, self.fip, -2)

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_invalid_value(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT,
                               self._update_fip_with_fip_rate_limit,
                               self.port, self.fip, 'NaN')

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_update_fip_with_default_rate_limit_no_value(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               MSG_INVALID_INPUT,
                               self._update_fip_with_fip_rate_limit,
                               self.port, self.fip, '')


class TestNuageFipRateLimitBaseAssociationNegative(
        base_nuage_fip_rate_limit.NuageFipRateLimitBase):

    """TestNuageFipRateLimitBaseAssociationNegative

    Negative tests for the per FIP rate limiting based on the neutron REST API.

    Create/Update of the FIP with rate limiting without port association

    """

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_fail_to_create_fip_with_rate_limit_without_port_assoc(self):
        self.assertRaisesRegex(lib_exc.BadRequest,
                               "Rate limiting requires the floating ip to be "
                               "associated to a port.",
                               self.floating_ips_client.create_floatingip,
                               floating_network_id=self.ext_net_id,
                               nuage_fip_rate=321)

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
                               nuage_fip_rate=321)

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
                               nuage_fip_rate=321)
