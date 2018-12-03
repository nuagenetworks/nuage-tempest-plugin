# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from netaddr import IPNetwork

from oslo_log import log as logging

from tempest.common import utils
from tempest.lib.common.utils import data_utils

from nuage_tempest_lib.cli import client_testcase

from nuage_tempest_plugin.tests.api.router.base_nuage_pat_underlay \
    import NuagePatUnderlayBase

LOG = logging.getLogger(__name__)


class TestNuagePatUnderlayCli(client_testcase.CLIClientTestCase,
                              NuagePatUnderlayBase):

    @classmethod
    def resource_setup(cls):
        super(TestNuagePatUnderlayCli, cls).resource_setup()
        nuage_pat = cls.read_nuage_pat_value_ini()
        if nuage_pat == '':
            nuage_pat = None
        cls.nuage_pat_ini = nuage_pat

    def test_cli_create_router_without_ext_gw(self):
        self._as_admin()
        self._cli_create_router_without_ext_gw_neg()

    def test_cli_create_router_with_ext_gw_without_snat(self):
        self._as_admin()
        self._cli_create_router_with_ext_gw_without_snat()

    def test_cli_create_router_without_ext_gw_with_snat_neg(self):
        self._as_admin()
        self._cli_create_router_without_ext_gw_with_snat_neg()

    def test_cli_create_router_with_ext_gw_with_snat(self):
        self._as_admin()
        self._cli_verify_create_router_with_ext_gw_with_snat()

    def test_cli_update_router_with_ext_gw_with_snat(self):
        self._as_admin()
        self._cli_update_router_with_ext_gw_with_snat()

    def test_cli_show_router_without_ext_gw(self):
        self._as_admin()
        self._cli_show_router_without_ext_gw()

    def test_cli_show_router_with_ext_gw_with_snat(self):
        self._as_admin()
        self._cli_show_router_with_ext_gw_with_snat()

    def test_cli_list_router_with_ext_gw_with_snat(self):
        self._as_admin()
        self._cli_list_router_with_gw_with_snat()

    def test_cli_list_router_without_ext_gw(self):
        self._as_admin()
        self._cli_list_router_without_gw()

    def test_cli_add_os_subnet_to_existing_ext_gw_with_snat(self):
        self._as_admin()
        self._cli_add_subnet_to_existing_ext_gw_with_snat()

    def test_cli_create_router_with_snat_invalid_value_neg(self):
        """test_cli_create_router_with_snat_invalid_value_neg

        Create router with external gateway with invalid values
        for 'enable_snat'

        Must fail
        """
        # Create a router enabling snat attributes
        self._as_admin()
        enable_snat_states = ['Ttrue', 'Treu', 'Tru', 'Truet', 'Trrue',
                              'Truue', 'Truee', '=True',
                              'Flase', 'Falsche', 'Fales', 'Flaes',
                              'FFalse', 'fFalse', '=False']
        name = data_utils.rand_name('router-with-snat-invalid-fail')
        network = self.create_network_with_args(name, ' --router:external')
        for enable_snat in enable_snat_states:
            external_gw_info_cli = \
                '--external_gateway_info type=dict network_id=' + \
                network['id'] + ',enable_snat=' + str(enable_snat)
            exp_message = "Invalid input for operation: '" + enable_snat + \
                          "' cannot be converted to boolean."
            LOG.info("exp_message = " + exp_message)
            self.assertCommandFailed(exp_message, self.create_router_with_args,
                                     name, external_gw_info_cli)

    @utils.requires_ext(extension='ext-gw-mode', service='network')
    def test_cli_create_router_with_gw_with_non_existing_ext_network_neg(self):
        """test_cli_create_router_with_gw_with_non_existing_ext_network_neg

        Try to create router with external gateway with a non-existing
        external network uuid

        Must fail
        """
        self._as_admin()
        name = data_utils.rand_name(
            'router-with-external-gateway-non-existing-network')

        # reverse the existing external network id,
        # unlikely that this exists ;-)
        bad_network_id = "11111111-1111-1111-1111-11111111"
        external_gw_info_cli = \
            '--external_gateway_info type=dict network_id=' + \
            bad_network_id + ',enable_snat=True'
        exp_message = "Invalid input for external_gateway_info. Reason: '" + \
                      bad_network_id + "' is not a valid UUID."
        LOG.info("exp_message = " + exp_message)
        self.assertCommandFailed(exp_message, self.create_router_with_args,
                                 name, external_gw_info_cli)

    @utils.requires_ext(extension='ext-gw-mode', service='network')
    def test_cli_create_router_with_ext_gw_with_vsd_managed_subnet_neg(self):
        """test_cli_create_router_with_ext_gw_with_vsd_managed_subnet_neg

        Create router with external gateway, using a VSD managed subnet

        Should fail, as PAT is only for OS managed networks
        """
        self._as_admin()
        name = data_utils.rand_name('vsd-l2domain-')
        cidr = IPNetwork('10.10.99.0/24')
        params = {
            'DHCPManaged': True,
            'address': str(cidr.ip),
            'netmask': str(cidr.netmask),
            'gateway': '10.10.99.1'
        }
        # Create VSD managed subnet
        vsd_l2dom_template = self.nuage_client.create_l2domaintemplate(
            name=name + '-template', extra_params=params)
        template_id = vsd_l2dom_template[0]['ID']
        vsd_l2domain = self.nuage_client.create_l2domain(
            name=name, templateId=template_id)
        self.assertEqual(vsd_l2domain[0]['name'], name)
        # Try to create subnet on OS with nuagenet param set to l2domain UUID
        # Must fails with message = exp+message
        network_name = data_utils.rand_name('ext-pat-network')
        network = self.create_network_with_args(
            network_name, ' --router:external')
        # exp_message = "Bad request: " \
        #               "VSD-Managed Subnet create not allowed " \
        #               "on external network"
        exp_message = "router:external in network must be False"
        LOG.info("exp_message = " + exp_message)
        self.assertCommandFailed(exp_message,
                                 self.create_subnet_with_args,
                                 network['name'],
                                 str(cidr.cidr),
                                 '--name subnet-VSD-managed '
                                 '--net-partition',
                                 self.def_netpartition,
                                 '--nuagenet',
                                 vsd_l2domain[0]['ID'])
        # Delete the VSD manged subnet
        self.nuage_client.delete_l2domain(vsd_l2domain[0]['ID'])
        self.nuage_client.delete_l2domaintemplate(
            vsd_l2dom_template[0]['ID'])

    def test_cli_create_router_with_internal_network_neg(self):
        """test_cli_create_router_with_internal_network_neg

        Try to create a router with external_gw_info and enable_snat,
        using an internal network

        Must fails, as an external network is required
        """
        self._as_admin()
        network = self.create_network()
        name = "pat-router-with-internal-network-neg"
        external_gw_info_cli = \
            '--external_gateway_info type=dict network_id=' + \
            network['id'] + ',enable_snat=True'
        exp_message = "Bad router request: Network " + network['id'] + \
                      " is not an external network"
        LOG.info("exp_message = " + exp_message)
        self.assertCommandFailed(exp_message, self.create_router_with_args,
                                 name, external_gw_info_cli)

    def test_cli_add_subnet_to_existing_pat_router(self):
        """test_cli_add_subnet_to_existing_pat_router

        Add a subnet to an existing external router with snat enabled

        Must succeed
        """
        self._as_admin()
        cidr = IPNetwork('10.10.100.0/24')
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            network_name = data_utils.rand_name('ext-pat-network-admin')
            router_name = data_utils.rand_name('ext-pat-router-admin')
            network = self.create_network_with_args(
                network_name, ' --router:external')
            external_gw_info_cli = \
                '--external_gateway_info type=dict network_id=' + \
                network['id'] + ',enable_snat=' + str(enable_snat)
            router = self.create_router_with_args(router_name,
                                                  external_gw_info_cli)
            compare_snat_str = '"enable_snat": ' + str(enable_snat)
            self.assertIn(compare_snat_str.lower(),
                          router['external_gateway_info'])
            # Now create a subnet and add it to the external network
            subnet_name = data_utils.rand_name("os-subnet")
            self.create_subnet_with_args(
                network['id'], str(cidr.cidr), '--name ', subnet_name)
            show_router = self.show_router(router['id'])
            self.assertIn(compare_snat_str.lower(),
                          show_router['external_gateway_info'])
            cidr = cidr.next(1)

    def test_cli_non_admin_add_os_subnet_to_existing_gw_other_tenant(self):
        self._cli_add_subnet_to_other_tenant_existing_ext_gw_with_snat()

    def test_cli_create_router_with_ext_gw(self):
        self._cli_tenant_create_router_with_ext_gw()
