# Copyright 2017 NOKIA

from netaddr import IPNetwork
import testtools

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from nuage_tempest_plugin.tests.api.extra_dhcp_option import \
    base_nuage_extra_dhcp_options
from nuage_tempest_plugin.tests.api.extra_dhcp_option\
    .base_nuage_extra_dhcp_options import NUAGE_NETWORK_TYPE

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as constants


class NuageExtraDHCPOptionsBaseL2(
        base_nuage_extra_dhcp_options.NuageExtraDHCPOptionsBase):

    @classmethod
    def resource_setup(cls):
        super(NuageExtraDHCPOptionsBaseL2, cls).resource_setup()

        # Create a L2 OS managed network and find its corresponding VSD peer
        cls.osmgd_l2_network = cls.create_network()
        cls.osmgd_l2_subnet = cls.create_subnet(cls.osmgd_l2_network)
        cls.os_l2_port = cls.create_port(cls.osmgd_l2_network)
        cls.l2domain = cls.nuage_client.get_l2domain(
            by_subnet=cls.osmgd_l2_subnet)

    def _nuage_crud_port_with_dhcp_opts(self, nuage_network_type,
                                        extra_dhcp_opts, new_extra_dhcp_opts):
        # do the test for requested nuage network type
        if nuage_network_type == NUAGE_NETWORK_TYPE['OS_Managed_L2']:
            self._nuage_create_list_show_update_layer_x_port_with_dhcp_opts(
                self.osmgd_l2_network, self.l2domain[0]['ID'],
                nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        elif nuage_network_type == NUAGE_NETWORK_TYPE['VSD_Managed_L2']:
            self._nuage_create_list_show_update_layer_x_port_with_dhcp_opts(
                self.vsdmgd_l2_network, self.vsd_l2dom[0]['ID'],
                nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        else:
            self.assertTrue(False, 'Unknown NUAGE_NETWORK_TYPE detected')
        pass

    def _nuage_delete_port_extra_dhcp_opt(self, nuage_network_type,
                                          extra_dhcp_opts):
        if nuage_network_type == NUAGE_NETWORK_TYPE['OS_Managed_L2']:
            self._nuage_create_list_show_delete_layer_x_port_with_dhcp_opts(
                self.osmgd_l2_network, self.l2domain[0]['ID'],
                nuage_network_type, extra_dhcp_opts)


class NuageExtraDHCPOptionsOSManagedL2Test(NuageExtraDHCPOptionsBaseL2):

    # Openstack Managed Layer 2 networks

    # def __init__(self, *args, **kwargs):
    #     super(NuageExtraDHCPOptionsOSManagedL2Test, self).__init__(
    #         *args, **kwargs)
    #     self.nuage_network_type = NUAGE_NETWORK_TYPE['OS_Managed_L2']
    #     self.vsd_parent_type = constants.L2_DOMAIN
    #
    # def test_nuage_l2_port_with_dhcp_opts_001_netmask(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_001_netmask()
    #
    # def test_nuage_l2_port_with_dhcp_opts_002_time_offset(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_002_time_offset()
    #
    # def test_nuage_l2_port_with_dhcp_opts_003_routers(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_003_routers()
    #
    # def test_nuage_l2_port_with_dhcp_opts_004_time_server(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_004_time_server()
    #
    # def test_nuage_l2_port_with_dhcp_opts_006_dns_server(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_006_dns_server()
    #
    # def test_nuage_l2_port_with_dhcp_opts_007_log_server(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_007_log_server()
    #
    # def test_nuage_l2_port_with_dhcp_opts_009_lpr_server(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_009_lpr_server()

    def test_nuage_l2_port_with_dhcp_opts_012_hostname(self):
        self._check_nuage_crud_port_with_dhcp_opts_012_hostname()

    # def test_nuage_l2_port_with_dhcp_opts_013_boot_file_size(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_013_boot_file_size()
    #
    # def test_nuage_l2_port_with_dhcp_opts_015_domain_name(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_015_domain_name()
    #
    # def test_nuage_l2_port_with_dhcp_opts_016_swap_server(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_016_swap_server()
    #
    # def test_nuage_l2_port_with_dhcp_opts_017_root_path(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_017_root_path()
    #
    # def test_nuage_l2_port_with_dhcp_opts_018_extension_path(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_018_extension_path()
    #
    # def test_nuage_l2_port_with_dhcp_opts_019_ip_forward_enable(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_019_ip_forward_enable()
    #
    # def test_nuage_l2_port_with_dhcp_opts_020_non_local_src_routing(
    #         self):
    #     self.\
    #         _check_nuage_crud_port_with_dhcp_opts_020_non_local_src_routing(
    #         )
    #
    # def test_nuage_l2_port_with_dhcp_opts_021_policy_filter(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_021_policy_filter()
    #
    # def test_nuage_l2_port_with_dhcp_opts_022_max_dgram_reassembly(
    #         self):
    #     self.\
    #     _check_nuage_crud_port_with_dhcp_opts_022_max_datagram_reassembly()
    #
    # def test_nuage_l2_port_with_dhcp_opts_023_default_ttl(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_023_default_ttl()
    #
    # def test_nuage_l2_port_with_dhcp_opts_026_mtu(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_026_mtu()
    #
    # def test_nuage_l2_port_with_dhcp_opts_027_all_subnets_local(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_027_all_subnets_local()
    #
    # def test_nuage_l2_port_with_dhcp_opts_028_broadcast(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_028_broadcast()
    #
    # def test_nuage_l2_port_with_dhcp_opts_031_router_discovery(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_031_router_discovery()
    #
    # def test_nuage_l2_port_with_dhcp_opts_032_rtr_solicitation(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_032_router_solicitation()
    #
    # def test_nuage_l2_port_with_dhcp_opts_033_static_route(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_033_static_route()
    #
    # def test_nuage_l2_port_with_dhcp_opts_034_trailer_encapsulation(
    #         self):
    #     self.\
    #     _check_nuage_crud_port_with_dhcp_opts_034_trailer_encapsulation()
    #
    # def test_nuage_l2_port_with_dhcp_opts_035_arp_timeout(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_035_arp_timeout()
    #
    # def test_nuage_l2_port_with_dhcp_opts_036_ethernet_encap(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_036_ethernet_encap()
    #
    # def test_nuage_l2_port_with_dhcp_opts_037_tcp_ttl(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_037_tcp_ttl()
    #
    # def test_nuage_l2_port_with_dhcp_opts_038_tcp_keepalive(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_038_tcp_keepalive()
    #
    # def test_nuage_l2_port_with_dhcp_opts_040_nis_domain(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_040_nis_domain()
    #
    # def test_nuage_l2_port_with_dhcp_opts_041_nis_server(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_041_nis_server()
    #
    # def test_nuage_l2_port_with_dhcp_opts_042_ntp_server(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_042_ntp_server()
    #
    # def test_nuage_l2_port_with_dhcp_opts_044_netbios_ns(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_044_netbios_ns()
    #
    # def test_nuage_l2_port_with_dhcp_opts_045_netbios_dd(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_045_netbios_dd()
    #
    # def test_nuage_l2_port_with_dhcp_opts_046_netbios_nodetype(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_046_netbios_nodetype()
    #
    # def test_nuage_l2_port_with_dhcp_opts_047_netbios_scope(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_047_netbios_scope()
    #
    # def test_nuage_l2_port_with_dhcp_opts_048_x_windows_fs(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_048_x_windows_fs()
    #
    # def test_nuage_l2_port_with_dhcp_opts_049_x_windows_dm(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_049_x_windows_dm()
    #
    # def test_nuage_l2_port_with_dhcp_opts_050_requested_address(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_050_requested_address()
    #
    # def test_nuage_l2_port_with_dhcp_opts_060_vendor_class(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_060_vendor_class()
    #
    # def test_nuage_l2_port_with_dhcp_opts_064_nisplus_domain(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_064_nisplus_domain()
    #
    # def test_nuage_l2_port_with_dhcp_opts_065_nisplus_server(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_065_nisplus_server()
    #
    # def test_nuage_l2_port_with_dhcp_opts_066_tftp_server(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_066_tftp_server()
    #
    # def test_nuage_l2_port_with_dhcp_opts_067_bootfile_name(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_067_bootfile_name()
    #
    # def test_nuage_l2_port_with_dhcp_opts_068_mobile_ip_home(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_068_mobile_ip_home()
    #
    # def test_nuage_l2_port_with_dhcp_opts_069_smtp_server(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_069_smtp_server()
    #
    # def test_nuage_l2_port_with_dhcp_opts_070_pop3_server(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_070_pop3_server()
    #
    # def test_nuage_l2_port_with_dhcp_opts_071_nntp_server(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_071_nntp_server()
    #
    # def test_nuage_l2_port_with_dhcp_opts_074_irc_server(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_074_irc_server()
    #
    # def test_nuage_l2_port_with_dhcp_opts_077_user_class(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_077_user_class()
    #
    # def test_nuage_l2_port_with_dhcp_opts_093_client_arch(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_093_client_arch()
    #
    # def test_nuage_l2_port_with_dhcp_opts_094_client_itf_id(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_094_client_interface_id()
    #
    # def test_nuage_l2_port_with_dhcp_opts_097_client_machine_id(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_097_client_machine_id()
    #
    # def test_nuage_l2_port_with_dhcp_opts_119_domain_search(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_119_domain_search()
    #
    # def test_nuage_l2_port_with_dhcp_opts_120_sip_server(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_120_sip_server()
    #
    # def test_nuage_l2_port_with_dhcp_opts_121_classless_static_route(
    #         self):
    #     self.\
    #     _check_nuage_crud_port_with_dhcp_opts_121_classless_static_route()
    #
    # def test_nuage_l2_port_with_dhcp_opts_125_vendor_id_encap(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_125_vendor_id_encap()
    #
    # def test_nuage_l2_port_with_dhcp_opts_255_server_ip_address(self):
    #     self._check_nuage_crud_port_with_dhcp_opts_255_server_ip_address()
    #
    # def test_nuage_l2_port_with_16_extra_dhcp_options(self):
    #     self._check_nuage_crud_port_with_16_extra_dhcp_options()

    @decorators.attr(type='smoke')
    @testtools.skipIf(Topology.before_openstack('queens'),
                      'Unsupported pre-queens')
    def test_nuage_l2_port_with_numerical_opt_name(self):
        self._check_nuage_crud_port_with_numerical_opt_name()

    @decorators.attr(type='smoke')
    @testtools.skipIf(Topology.before_openstack('queens'),
                      'Unsupported pre-queens')
    def test_nuage_l2_delete_port_extra_dhcp_opt(self):
        self._check_nuage_delete_port_extra_dhcp_opt()

    @decorators.attr(type='smoke')
    def test_nuage_l2_crud_dhcpv6_dns_server_opt(self):
        self._check_nuage_crud_port_with_dhcpv6_dns_server_opt()

    @decorators.attr(type='smoke')
    def test_nuage_l2_crud_dhcpv6_domain_search_opt(self):
        self._check_nuage_crud_port_with_dhcpv6_domain_search_opt()

    @decorators.attr(type='smoke')
    def test_nuage_l2_crud_multiple_dhcpv6_opts(self):
        self._check_nuage_crud_port_with_multiple_dhcpv6_opts()


class NuageExtraDHCPOptionsVsdManagedL2Test(
        NuageExtraDHCPOptionsOSManagedL2Test):

    #
    # VSD Managed Layer 2 networks
    #
    def __init__(self, *args, **kwargs):
        super(NuageExtraDHCPOptionsVsdManagedL2Test, self).__init__(
            *args, **kwargs)
        self.nuage_network_type = NUAGE_NETWORK_TYPE['VSD_Managed_L2']
        self.vsd_parent_type = constants.L2_DOMAIN

    @classmethod
    def resource_setup(cls):
        super(NuageExtraDHCPOptionsBaseL2, cls).resource_setup()

        cls.vsd_l2dom_template = []
        cls.vsd_l2domain = []

        # Create a L2 VSD managed network and link to its OS network
        name = data_utils.rand_name('l2domain')
        vsd_l2_cidr = IPNetwork('100.100.100.0/24')
        cls.vsd_l2dom_tmpl = cls.create_vsd_dhcpmanaged_l2dom_template(
            name=name,
            cidr=vsd_l2_cidr,
            gateway='100.100.100.1')
        cls.vsd_l2dom = cls.create_vsd_l2domain(
            name=name, tid=cls.vsd_l2dom_tmpl[0]['ID'])
        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network')
        cls.vsdmgd_l2_network = cls.create_network(network_name=net_name)
        netpartition = Topology.def_netpartition
        cls.vsdmgd_l2_subnet = cls.create_subnet(
            cls.vsdmgd_l2_network,
            gateway=None,
            cidr=vsd_l2_cidr,
            mask_bits=24,
            nuagenet=cls.vsd_l2dom[0]['ID'],
            net_partition=netpartition,
            enable_dhcp=True)

    @classmethod
    def resource_cleanup(cls):

        # delete VSD managed OpenStack resources BEFORE deletion of the
        # VSD resources
        # Otherwise, VSD resource won't be able to remove all child resources
        # when these are CMS managed. (e.g. permissions, groups and users)
        cls._try_delete_resource(cls.networks_client.delete_network,
                                 cls.vsdmgd_l2_network['id'])

        for vsd_l2domain in cls.vsd_l2domain:
            cls.nuage_client.delete_l2domain(vsd_l2domain[0]['ID'])

        for vsd_l2dom_template in cls.vsd_l2dom_template:
            cls.nuage_client.delete_l2domaintemplate(
                vsd_l2dom_template[0]['ID'])

        super(NuageExtraDHCPOptionsBaseL2, cls).resource_cleanup()

    @classmethod
    def create_vsd_dhcpmanaged_l2dom_template(cls, **kwargs):
        params = {
            'DHCPManaged': True,
            'address': str(kwargs['cidr'].ip),
            'netmask': str(kwargs['cidr'].netmask),
            'gateway': kwargs['gateway']
        }
        vsd_l2dom_tmplt = cls.nuage_client.create_l2domaintemplate(
            kwargs['name'] + '-template', extra_params=params)
        cls.vsd_l2dom_template.append(vsd_l2dom_tmplt)
        return vsd_l2dom_tmplt

    @classmethod
    def create_vsd_l2domain(cls, **kwargs):
        vsd_l2dom = cls.nuage_client.create_l2domain(
            kwargs['name'], templateId=kwargs['tid'])
        cls.vsd_l2domain.append(vsd_l2dom)
        return vsd_l2dom


class NuageExtraDHCPOptionsOSv6ManagedL2Test(
        NuageExtraDHCPOptionsOSManagedL2Test):

    _ip_version = 6

    @classmethod
    def skip_checks(cls):
        super(NuageExtraDHCPOptionsOSv6ManagedL2Test, cls).skip_checks()
        if not Topology.has_single_stack_v6_support():
            msg = 'There is no single-stack v6 support in current release'
            raise cls.skipException(msg)
