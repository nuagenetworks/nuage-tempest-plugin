# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.tests.api.router import base_nuage_domain_tunnel_type


class NuageDomainTunnelTypeNegativeTest(
        base_nuage_domain_tunnel_type.NuageDomainTunnelTypeBase):

    """NuageDomainTunnelTypeNegativeTest

    Negative tests for the per Domain Tunnel Type based on the
    neutron REST API.

    """

    def _do_test_invalid_value(self, invalid_value):
        reported_value = invalid_value if invalid_value != '' else 'None'
        self.assertRaisesRegex(
            exceptions.BadRequest,
            'Invalid input for tunnel_type. Reason: {} is not in'.format(
                reported_value),
            self._do_create_router_with_domain_tunnel_type,
            invalid_value)

    @decorators.attr(type=['negative'])
    def test_create_with_invalid_value(self):
        self._do_test_invalid_value("BAD CHOICE")

    @decorators.attr(type=['negative'])
    def test_create_with_no_value(self):
        self._do_test_invalid_value("")

    @decorators.attr(type=['negative'])
    def test_create_with_leading_or_trailing_spaces(self):
        self._do_test_invalid_value(" GRE ")

    @decorators.attr(type=['negative'])
    def test_create_with_invalid_attribute(self):
        self.assertRaisesRegex(exceptions.BadRequest,
                               "Unrecognized attribute",
                               self._create_router,
                               tunnnnnel_type="GRE")

    @decorators.attr(type=['negative'])
    def test_create_with_camel_cased_attribute(self):
        self.assertRaisesRegex(exceptions.BadRequest,
                               "Unrecognized attribute",
                               self._create_router,
                               tunnelType="GRE")

    @decorators.attr(type=['negative'])
    def test_create_with_mixed_case_attribute(self):
        self.assertRaisesRegex(exceptions.BadRequest,
                               "Unrecognized attribute",
                               self._create_router,
                               Tunnel_Type="GRE")
