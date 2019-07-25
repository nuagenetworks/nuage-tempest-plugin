# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from nuage_tempest_plugin.lib.cli import client_testcase
from nuage_tempest_plugin.tests.api.floating_ip.base_nuage_fip_underlay \
    import NuageFipUnderlayBase


class TestNuageFipUnderlayConfigurationCliNone(
        client_testcase.CLIClientTestCase, NuageFipUnderlayBase):

    """FIP to Underlay tests using Neutron CLI client. """

    @classmethod
    def resource_setup(cls):
        super(TestNuageFipUnderlayConfigurationCliNone, cls).resource_setup()
        cls.needs_ini_nuage_fip_underlay(None)

    def test_cli_create_delete_external_subnet_without_underlay_default_none(
            self):
        self._as_admin()
        self._cli_create_delete_external_subnet_without_underlay()

    def _test_cli_create_external_fip_subnet_with_underlay_default_none(self):
        self._as_admin()
        self._cli_create_external_fip_subnet_with_underlay()

    def test_cli_show_external_subnet_without_underlay_default_none(self):
        self._as_admin()
        self._cli_show_external_subnet_without_underlay()

    def test_cli_show_external_subnet_with_underlay_default_none(self):
        self._as_admin()
        self._cli_show_external_subnet_with_underlay()

    def test_cli_list_external_subnets_underlay_default_none(self):
        self._as_admin()
        self._cli_list_external_subnets_underlay()


class TestNuageFipUnderlayConfigCliDefaultFalse(
        client_testcase.CLIClientTestCase, NuageFipUnderlayBase):

    """FIP to Underlay tests using Neutron CLI client. """

    @classmethod
    def resource_setup(cls):
        super(TestNuageFipUnderlayConfigCliDefaultFalse, cls).resource_setup()
        cls.needs_ini_nuage_fip_underlay(False)

    def test_cli_create_delete_external_subnet_without_underlay_default_false(
            self):
        self._as_admin()
        self._cli_create_delete_external_subnet_without_underlay()

    def _test_cli_create_external_fip_subnet_with_underlay_default_false(self):
        self._as_admin()
        self._cli_create_external_fip_subnet_with_underlay()

    def test_cli_show_external_subnet_without_underlay_default_false(self):
        self._as_admin()
        self._cli_show_external_subnet_without_underlay()

    def test_cli_show_external_subnet_with_underlay_default_false(self):
        self._as_admin()
        self._cli_show_external_subnet_with_underlay()

    def test_cli_list_external_subnets_underlay_default_false(self):
        self._as_admin()
        self._cli_list_external_subnets_underlay()


class TestNuageFipUnderlayConfigCliDefaultTrue(
        client_testcase.CLIClientTestCase, NuageFipUnderlayBase):

    """FIP to Underlay tests using Neutron CLI client. """

    @classmethod
    def resource_setup(cls):
        super(TestNuageFipUnderlayConfigCliDefaultTrue, cls).resource_setup()
        cls.needs_ini_nuage_fip_underlay(True)  # this will actually be @ devci

    def test_cli_create_delete_external_subnet_without_underlay_default_true(
            self):
        self._as_admin()
        self._cli_create_delete_external_subnet_without_underlay()

    def _test_cli_create_external_fip_subnet_with_underlay_default_true(self):
        self._as_admin()
        self._cli_create_external_fip_subnet_with_underlay()

    def test_cli_show_external_subnet_without_underlay_default_true(self):
        self._as_admin()
        self._cli_show_external_subnet_without_underlay()

    def test_cli_show_external_subnet_with_underlay_default_true(self):
        self._as_admin()
        self._cli_show_external_subnet_with_underlay()

    def test_cli_list_external_subnets_underlay_default_true(self):
        self._as_admin()
        self._cli_list_external_subnets_underlay()
