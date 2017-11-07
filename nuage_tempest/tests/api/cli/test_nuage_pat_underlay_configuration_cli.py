# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from tempest import config
from tempest.lib.common.utils import data_utils

from nuage_tempest.lib.remote_cli.remote_cli_base_testcase \
    import RemoteCliBaseTestCase
from nuage_tempest.lib.test import nuage_test
from nuage_tempest.lib.utils import constants

from nuage_tempest.tests.api.router.base_nuage_pat_underlay \
    import NuagePatUnderlayBase

CONF = config.CONF


class TestNuagePatUnderlayCliConfPatNotAvailable(
        RemoteCliBaseTestCase, NuagePatUnderlayBase):

    @classmethod
    def resource_setup(cls):
        super(TestNuagePatUnderlayCliConfPatNotAvailable, cls).resource_setup()

    @classmethod
    def resource_cleanup(cls):
        super(TestNuagePatUnderlayCliConfPatNotAvailable, cls).\
            resource_cleanup()
        # Remove the nuage_pat setting in the .ini file, as not_available is
        # causing troubles for other tests
        cls.needs_ini_nuage_pat(None)

    # For some strange reason, the cleanup is not called, leaving
    # Nuage_pat = not_available, causing all wubsequent
    # test that need ext_gw_info to fail.
    @nuage_test.header()
    def test_cli_create_router_without_ext_gw_pat_not_available(self):
        self._as_admin()
        self.needs_ini_nuage_pat(constants.NUAGE_PAT_NOTAVAILABLE)
        self._cli_create_router_without_ext_gw_neg()
        self.needs_ini_nuage_pat(None)

    @nuage_test.header()
    def test_cli_create_router_with_ext_gw_without_snat_pat_not_available_neg(
            self):
        self._as_admin()
        self.needs_ini_nuage_pat(constants.NUAGE_PAT_NOTAVAILABLE)
        name = data_utils.rand_name('router-without-ext-gw-with-snat-' +
                                    str(constants.NUAGE_PAT_NOTAVAILABLE))
        network = self.create_network_with_args(name, ' --router:external')
        external_gateway_info = \
            '--external_gateway_info type=dict network_id=' + \
            network['id']
        self.assertCommandFailed(self.PAT_NOTAVAILABLE_EXT_GW_INFO,
                                 self.create_router_with_args, name,
                                 external_gateway_info)
        self.needs_ini_nuage_pat(None)

    @nuage_test.header()
    def test_cli_create_router_without_ext_gw_with_snat_pat_not_available_neg(
            self):
        self._as_admin()
        self.needs_ini_nuage_pat(constants.NUAGE_PAT_NOTAVAILABLE)
        name = data_utils.rand_name('router-without-ext-gw-with-snat-' +
                                    str(constants.NUAGE_PAT_NOTAVAILABLE))
        self.create_network_with_args(name, ' --router:external')
        external_gateway_info = \
            '--external_gateway_info type=dict enable_snat=True'""
        self.assertCommandFailed(self.PAT_NEEDS_EXT_NETWORK,
                                 self.create_router_with_args,
                                 name,
                                 external_gateway_info)
        self.needs_ini_nuage_pat(None)

    @nuage_test.header()
    def test_cli_create_router_with_ext_gw_with_snat_pat_not_available_neg(
            self):
        self._as_admin()
        self.needs_ini_nuage_pat(constants.NUAGE_PAT_NOTAVAILABLE)
        name = data_utils.rand_name('router-without-ext-gw-with-snat-' +
                                    str(constants.NUAGE_PAT_NOTAVAILABLE))
        network = self.create_network_with_args(name, ' --router:external')
        external_gateway_info = \
            '--external_gateway_info type=dict network_id=' + \
            network['id'] + ',enable_snat=True'
        self.assertCommandFailed(self.PAT_NOTAVAILABLE_EXT_GW_INFO,
                                 self.create_router_with_args,
                                 name,
                                 external_gateway_info)
        self.needs_ini_nuage_pat(None)


class TestNuagePatUnderlayCliConfPatNone(
        RemoteCliBaseTestCase, NuagePatUnderlayBase):

    @classmethod
    def resource_setup(cls):
        super(TestNuagePatUnderlayCliConfPatNone, cls).resource_setup()
        cls.needs_ini_nuage_pat(None)

    @nuage_test.header()
    def test_cli_create_router_without_ext_gw_pat_none(self):
        self._as_admin()
        self._cli_create_router_without_ext_gw_neg()

    @nuage_test.header()
    def test_cli_create_router_with_ext_gw_without_snat_pat_none(self):
        self._as_admin()
        self._cli_create_router_with_ext_gw_without_snat()

    @nuage_test.header()
    def test_cli_create_router_without_ext_gw_with_snat_pat_none(self):
        self._as_admin()
        self._cli_create_router_without_ext_gw_with_snat_neg()

    @nuage_test.header()
    def test_cli_create_router_with_ext_gw_with_snat_pat_none(self):
        self._as_admin()
        self._verify_create_router_with_ext_gw_with_snat()

    @nuage_test.header()
    def test_cli_update_router_with_ext_gw_with_snat_pat_none(self):
        self._as_admin()
        self._cli_update_router_with_ext_gw_with_snat()

    @nuage_test.header()
    def test_cli_show_router_without_eternal_gateway_pat_none(self):
        self._as_admin()
        self._cli_show_router_without_external_gw()

    @nuage_test.header()
    def test_cli_show_router_with_ext_gw_with_snat_pat_none(self):
        self._as_admin()
        self._cli_show_router_with_external_gw_with_snat()

    @nuage_test.header()
    def test_cli_list_router_with_ext_gw_with_snat_pat_none(self):
        self._as_admin()
        self._cli_list_router_with_gateway_with_snat()

    @nuage_test.header()
    def test_cli_list_router_without_ext_gw_pat_none(self):
        self._as_admin()
        self._cli_list_router_without_gateway()

    @nuage_test.header()
    def test_cli_add_os_subnet_to_existing_ext_gw_with_snat_pat_none(self):
        self._as_admin()
        self._cli_add_subnet_to_existing_ext_gw_with_snat()

    def test_cli_non_admin_add_os_subnet_to_existing_gw_other_tenant_pat_none(
            self):
        self._cli_add_subnet_to_other_tenant_existing_ext_gw_with_snat()

    @nuage_test.header()
    def test_cli_tenant_create_router_with_ext_gw_pat_none(self):
        self._cli_tenant_create_router_with_external_gateway()


class TestNuagePatUnderlayCliConfPatDefaultDisabled(
        RemoteCliBaseTestCase, NuagePatUnderlayBase):

    @classmethod
    def resource_setup(cls):
        super(TestNuagePatUnderlayCliConfPatDefaultDisabled, cls).\
            resource_setup()
        cls.needs_ini_nuage_pat(constants.NUAGE_PAT_DEFAULTDISABLED)

    @nuage_test.header()
    def test_cli_create_router_without_ext_gw_pat_def_dis(
            self):
        self._as_admin()
        self._cli_create_router_without_ext_gw_neg()

    @nuage_test.header()
    def test_cli_create_router_with_ext_gw_without_snat_pat_def_dis(
            self):
        self._as_admin()
        self._cli_create_router_with_ext_gw_without_snat()

    @nuage_test.header()
    def test_cli_create_router_without_ext_gw_with_snat_pat_def_dis(
            self):
        self._as_admin()
        self._cli_create_router_without_ext_gw_with_snat_neg()

    @nuage_test.header()
    def test_cli_create_router_with_ext_gw_with_snat_pat_def_dis(
            self):
        self._as_admin()
        self._cli_verify_create_router_with_ext_gw_with_snat()

    @nuage_test.header()
    def test_cli_update_router_with_ext_gw_with_snat_pat_def_dis(self):
        self._as_admin()
        self._cli_update_router_with_ext_gw_with_snat()

    @nuage_test.header()
    def test_cli_show_router_without_eternal_gateway_pat_def_dis(self):
        self._as_admin()
        self._cli_show_router_without_external_gw()

    def test_cli_show_router_with_ext_gw_with_snat_pat_def_dis(self):
        self._as_admin()
        self._cli_show_router_with_external_gw_with_snat()

    @nuage_test.header()
    def test_cli_list_router_with_ext_gw_with_snat_pat_def_dis(self):
        self._as_admin()
        self._cli_list_router_with_gateway_with_snat()

    @nuage_test.header()
    def test_cli_list_router_without_ext_gw_pat_def_dis(self):
        self._as_admin()
        self._cli_list_router_without_gateway()

    @nuage_test.header()
    def test_cli_add_os_subnet_to_existing_ext_gw_with_snat_pat_def_dis(self):
        self._as_admin()
        self._cli_add_subnet_to_existing_ext_gw_with_snat()

    @nuage_test.header()
    def test_cli_non_admin_add_os_subnet_to_exist_gw_other_tenant_pat_def_dis(
            self):
        self._cli_add_subnet_to_other_tenant_existing_ext_gw_with_snat()

    @nuage_test.header()
    def test_cli_tenant_create_router_with_ext_gw_pat_def_dis(self):
        self._cli_tenant_create_router_with_external_gateway()


class TestNuagePatUnderlayCliConfPatDefaultEnabled(
        RemoteCliBaseTestCase, NuagePatUnderlayBase):

    @classmethod
    def resource_setup(cls):
        super(TestNuagePatUnderlayCliConfPatDefaultEnabled, cls).\
            resource_setup()
        cls.needs_ini_nuage_pat(constants.NUAGE_PAT_DEFAULTENABLED)

    @nuage_test.header()
    def test_cli_create_router_without_ext_gw_pat_def_en(self):
        self._as_admin()
        self._cli_create_router_without_ext_gw_neg()

    @nuage_test.header()
    def test_cli_create_router_with_ext_gw_without_snat_pat_def_en(self):
        self._as_admin()
        self._cli_create_router_with_ext_gw_without_snat()

    @nuage_test.header()
    def test_cli_create_router_without_ext_gw_with_snat_pat_def_en(self):
        self._as_admin()
        self._cli_create_router_without_ext_gw_with_snat_neg()

    @nuage_test.header()
    def test_cli_create_router_with_ext_gw_with_snat_pat_def_en(self):
        self._as_admin()
        self._cli_verify_create_router_with_ext_gw_with_snat()

    @nuage_test.header()
    def test_cli_update_router_with_ext_gw_with_snat_pat_def_en(self):
        self._as_admin()
        self._cli_update_router_with_ext_gw_with_snat()

    @nuage_test.header()
    def test_cli_show_router_without_eternal_gateway_pat_def_en(self):
        self._as_admin()
        self._cli_show_router_without_external_gw()

    @nuage_test.header()
    def test_cli_show_router_with_ext_gw_with_snat_pat_def_en(self):
        self._as_admin()
        self._cli_show_router_with_external_gw_with_snat()

    @nuage_test.header()
    def test_cli_list_router_with_ext_gw_with_snat_pat_def_en(self):
        self._as_admin()
        self._cli_list_router_with_gateway_with_snat()
        pass

    @nuage_test.header()
    def test_cli_list_router_without_ext_gw_pat_def_en(self):
        self._as_admin()
        self._cli_list_router_without_gateway()

    @nuage_test.header()
    def test_cli_add_os_subnet_to_existing_ext_gw_with_snat_pat_def_en(self):
        self._as_admin()
        self._cli_add_subnet_to_existing_ext_gw_with_snat()

    @nuage_test.header()
    def test_cli_non_admin_add_os_subnet_to_exist_gw_other_tenant_pat_def_en(
            self):
        self._cli_add_subnet_to_other_tenant_existing_ext_gw_with_snat()

    @nuage_test.header()
    def test_cli_tenant_create_router_with_ext_gw_pat_def_en(self):
        self._cli_tenant_create_router_with_external_gateway()
