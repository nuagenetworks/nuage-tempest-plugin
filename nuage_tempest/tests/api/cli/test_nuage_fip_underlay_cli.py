# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from netaddr import IPNetwork

from tempest import config
from tempest.lib.common.utils import data_utils

from nuage_tempest.lib.nuage_tempest_test_loader import Release
from nuage_tempest.lib.remote_cli import remote_cli_base_testcase
from nuage_tempest.lib.test import nuage_test
from nuage_tempest.tests.api.floating_ip.base_nuage_fip_underlay \
    import NuageFipUnderlayBase

CONF = config.CONF


class TestNuageFipUnderlayCli(remote_cli_base_testcase.RemoteCliBaseTestCase,
                              NuageFipUnderlayBase):
    """TestNuageFipUnderlayCli

    FIP to Underlay tests using Neutron CLI client.
    """
    # LOG = logging.getLogger(__name__)

    @classmethod
    def resource_setup(cls):
        super(TestNuageFipUnderlayCli, cls).resource_setup()

    @nuage_test.header()
    def test_cli_create_delete_external_subnet_without_underlay(self):
        self._as_admin()
        self._cli_create_delete_external_subnet_without_underlay()

    @nuage_test.header()
    def _test_cli_create_external_fip_subnet_with_underlay(self):
        self._as_admin()
        self._cli_create_external_fip_subnet_with_underlay()

    @nuage_test.header()
    def test_cli_show_external_subnet_without_underlay(self):
        self._as_admin()
        self._cli_show_external_subnet_without_underlay()

    @nuage_test.header()
    def test_cli_show_external_subnet_with_underlay(self):
        self._as_admin()
        self._cli_show_external_subnet_with_underlay()

    @nuage_test.header()
    def test_cli_list_external_subnets_underlay(self):
        self._as_admin()
        self._cli_list_external_subnets_underlay()

    @nuage_test.header()
    def test_cli_update_external_fip_subnet_neg(self):
        self._as_admin()
        self._cli_update_external_subnet_with_underlay_neg()

    @nuage_test.header()
    def test_cli_update_internal_fip_subnet_neg(self):
        """test_cli_update_internal_fip_subnet_neg

        Create an internal subnet and try to update with underlay=True

        Must fail: verifies OPENSTACK-722
        """
        self._as_admin()
        rand_name_str = data_utils.rand_name()
        int_network_name = "int-fip-network-" + rand_name_str
        int_subnet_name = "int-fip-subnet-" + rand_name_str

        int_network = self.create_network_with_args(int_network_name)
        exp_message = "Cannot update read-only attribute underlay"
        self.LOG.info("exp_message = " + exp_message)
        int_subnet = self.create_subnet_with_args(int_network['name'],
                                                  "100.99.98.0/24",
                                                  "--name ", int_subnet_name)
        self.assertCommandFailed(exp_message,
                                 self.update_subnet_with_args,
                                 int_subnet['id'],
                                 "--underlay=True")

    @nuage_test.header()
    def test_cli_create_external_subnet_with_underlay_invalid_values_neg(self):
        """test_cli_create_external_subnet_with_underlay_invalid_values_neg

        Try to create an external FIP subnet with invalid values for
        underlay=True/False

        Must fail with proper reason
        """
        self._as_admin()
        rand_name_str = data_utils.rand_name()
        ext_network_name = "ext-fip-network-" + rand_name_str
        ext_network = self.create_network_with_args(ext_network_name,
                                                    " --router:external")
        ext_subnet_name = "subnet-invalid-underlay-value-" + rand_name_str
        invalid_underlay_values = ['Ttrue', 'Treu', 'Tru', 'Truet', 'Trrue',
                                   'Truue', 'Truee',
                                   'Flase', 'Falsche', 'Fales', 'Flaes',
                                   'FFalse', 'fFalse']
        # exp_message = "Invalid input for operation: '(.*)' cannot be
        # converted to boolean"
        exp_message = "error: argument --underlay: invalid choice: u'(.*)"
        for underlay in invalid_underlay_values:
            underlay_str = "--underlay=" + str(underlay)
            self.assertCommandFailed(exp_message,
                                     self.create_subnet_with_args,
                                     ext_network['name'],
                                     "98.99.99.0/24",
                                     "--name ", ext_subnet_name,
                                     underlay_str)
        pass

    @nuage_test.header()
    def test_cli_create_external_subnet_with_underlay_invalid_syntax_neg(self):
        """test_cli_create_external_subnet_with_underlay_invalid_syntax_neg

        Try to create an external FIP subnet with invalid values for
        underlay=True/False

        Must fail with proper reason
        """
        self._as_admin()
        rand_name_str = data_utils.rand_name()
        ext_network_name = "ext-fip-network-" + rand_name_str
        ext_network = self.create_network_with_args(ext_network_name,
                                                    " --router:external")
        ext_subnet_name = "subnet-invalid-underlay-value-" + rand_name_str
        underlay_invalid_syntax = ['Underley', 'Overlay', 'under1ay',
                                   'inderlay', 'overlay', 'ollekenbolleke',
                                   'undarlay', 'anderluy', 'etcetera',
                                   '...', '***']
        for invalid_underlay in underlay_invalid_syntax:
            exp_message = "Unrecognized attribute"
            underlay_str = "--" + invalid_underlay + "=True"
            self.assertCommandFailed(exp_message,
                                     self.create_subnet_with_args,
                                     ext_network['name'],
                                     "97.99.99.0/24",
                                     "--name ", ext_subnet_name,
                                     underlay_str)

    @nuage_test.header()
    def test_cli_create_external_fip_subnet_with_vsd_managed_subnet_neg(self):
        """test_cli_create_external_fip_subnet_with_vsd_managed_subnet_neg

        Create external fip subnet using a VSD managed subnet

        Should fail, as PAT is only for OS managed networks
        """
        self._as_admin()
        name = data_utils.rand_name('vsd-l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        params = {
            'DHCPManaged': True,
            'address': str(cidr.ip),
            'netmask': str(cidr.netmask),
            'gateway': '10.10.100.1'
        }
        # Create VSD managed subnet
        vsd_l2dom_template = self.nuage_vsd_client.create_l2domaintemplate(
            name=name + '-template',
            extra_params=params)
        template_id = vsd_l2dom_template[0]['ID']
        vsd_l2domain = self.nuage_vsd_client.create_l2domain(
            name=name, templateId=template_id)
        self.assertEqual(vsd_l2domain[0][u'name'], name)
        # Try to create subnet on OS with nuagenet param set to l2domain UUID
        # Must fails with message = exp+message
        network_name = data_utils.rand_name('ext-pat-network')
        self.network = self.create_network_with_args(network_name,
                                                     ' --router:external')
        if (Release(CONF.nuage_sut.openstack_version) >= Release('Newton') and
                CONF.nuage_sut.nuage_plugin_mode == 'ml2'):
            exp_message = "Bad request: " \
                          "router:external in network must be False"
        else:
            exp_message = "Bad request: " \
                          "VSD-Managed Subnet create not allowed on " \
                          "external network"

        self.LOG.info("exp_message = " + exp_message)
        self.assertCommandFailed(exp_message,
                                 self.create_subnet_with_args,
                                 self.network['name'],
                                 str(cidr.cidr),
                                 '--name subnet-VSD-managed '
                                 '--net-partition',
                                 CONF.nuage.nuage_default_netpartition,
                                 '--nuagenet',
                                 vsd_l2domain[0][u'ID'],
                                 '--underlay=True')
        # Delete the VSD manged subnet
        self.nuage_vsd_client.delete_l2domain(vsd_l2domain[0]['ID'])
        self.nuage_vsd_client.delete_l2domaintemplate(
            vsd_l2dom_template[0]['ID'])

    @nuage_test.header()
    def test_cli_create_external_fip_subnet_with_internal_network_neg(self):
        """test_cli_create_external_fip_subnet_with_internal_network_neg

        Try to create a router with external_gateway_info and enable_snat,
        using an internal network

        Must fails, as an external network is required
        """
        self._as_admin()
        underlay_states = [False, True]
        for underlay in underlay_states:
            network_name = data_utils.rand_name('internal-pat-network-neg-')
            int_network = self.create_network_with_args(network_name)
            exp_message = "Bad request: underlay attribute can not be set " \
                          "for internal subnets"
            self.LOG.info("exp_message = " + exp_message)
            underlay_str = "--underlay=" + str(underlay)
            self.assertCommandFailed(exp_message,
                                     self.create_subnet_with_args,
                                     int_network['name'],
                                     '99.98.97.0/24',
                                     underlay_str)
