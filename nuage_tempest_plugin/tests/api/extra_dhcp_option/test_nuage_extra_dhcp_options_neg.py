# Copyright 2015 Alcatel-Lucent

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

from . import base_nuage_extra_dhcp_options

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES
from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as constants

VERY_LONG_STRING = '\
kljflkajdfkadjflakfjaklfjadkfkjhfkjdhjklhfjhfnkljfhkjfh,kjhkvjhuhkjhfkjfhkld' \
                   'jfhkljfhaklfhadjklfhakrqrqerqwerqerqerqerq\
lfjhadkljfhfjhadklfjhadklfhafhaklfhfadkjfhadjkfhakljfhakljfhkadjfhkadjfhakdj' \
                   'fhadjkfhakdjfhkadjfhakldjfhakjfhkadjfhkadj\
fhadjklfhakljfhakldjfhakljfhakldjfhakjfhakldhfadjkhfkadjfhdjkfhdjkjjjjjjjjjj' \
                   'jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj\
jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj' \
                   'jjjjjjjj'

# 300 characters in the very big number
VERY_BIG_NUMBER = '\
1234567890123456789012345678901234567890123456789012345678901234567890123456' \
                  '7890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456' \
                  '7890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456' \
                  '7890123456789012345678901234567890\
1234567890123456789012345678901234567890123456789012345678901234567890123456' \
                  '7890123456789012345678901234567890\
1234567890123456789012345678901234567890'

# Use these values for negative tests on ip addresses
BAD_IPV4_ADDRESSES = [
    '10.20.30.400',
    '-1.20.30.40',
    '255.0.0.351',
    'a.b.c.d',
    'we.want.you.now',
    'rubbish',
    VERY_LONG_STRING,
    '10.20.30.40;400.300.200.100'
]

# Bad values for those options treated as string
# numbers will be treated as strings, so no need to specify them here ...
BAD_STRING_TYPE_VALUES = [
    VERY_LONG_STRING,
    ''
]

# Upstream does only type checking, use these 'bad' integer values for all
# options that are int
BAD_INTEGER_TYPE_VALUES = [
    VERY_LONG_STRING,
    VERY_BIG_NUMBER,
    'some_small string'
]


#
# ... THESE ARE SKIPPED! ...
#
class NuageExtraDHCPOptionsNegativeTest(
        base_nuage_extra_dhcp_options.NuageExtraDHCPOptionsBase):

    """NuageExtraDHCPOptionsNegativeTest

    Negative tests on
        port create
        port list
        port show
        port update

    v2.0 of the Neutron API is assumed. It is also assumed that the Extra
    DHCP Options extension (extra_dhcp_opt)is enabled in the
    [network-feature-enabled] section of etc/tempest.conf
    """

    @classmethod
    def resource_setup(cls):
        super(NuageExtraDHCPOptionsNegativeTest, cls).resource_setup()

        # L2 OS managed network
        cls.osmgd_l2_network = cls.create_network()
        cls.osmgd_l2_subnet = cls.create_subnet(cls.osmgd_l2_network)
        cls.os_l2_port = cls.create_port(cls.osmgd_l2_network)
        cls.l2domain = cls.nuage_client.get_l2domain(
            'externalID',
            cls.nuage_client.get_vsd_external_id(cls.osmgd_l2_subnet['id'])
        )

    @classmethod
    def skip_checks(cls):
        raise cls.skipException('Skipping negative DHCP tests.')

    def _assert_nuage_create_port_with_dhcp_opts(self, network_id,
                                                 extra_dhcp_opts):
        # Create a port with valid opt-name but invalid opt-value(s)
        self.assertRaises(exceptions.BadRequest,
                          self._create_port_with_dhcp_opts,
                          network_id,
                          extra_dhcp_opts)

    def _assert_nuage_update_port_with_dhcp_opts(self, port,
                                                 extra_dhcp_opts):
        # Update an existing port with valid opt-name but invalid opt-value(s)
        self.assertRaises(exceptions.BadRequest,
                          self._update_port_with_dhcp_opts,
                          port,
                          extra_dhcp_opts)

    def _assert_create_update_port_with_bad_dhcp_opts_neg(self, network_id,
                                                          bad_values,
                                                          opt_name):
        for opt_value in bad_values:
            extra_dhcp_opts = [
                {'opt_value': opt_value, 'opt_name': opt_name}
            ]
            self.assertRaises(exceptions.BadRequest,
                              self._create_port_with_dhcp_opts,
                              network_id,
                              extra_dhcp_opts)
            self.assertRaises(exceptions.BadRequest,
                              self._update_port_with_dhcp_opts,
                              self.os_l2_port['id'],
                              extra_dhcp_opts)

    def _create_network(self, external=False):
        if external:
            post_body = {'name': data_utils.rand_name('ext-network'),
                         'router:external': external}
        else:
            post_body = {'name': data_utils.rand_name('network')}
        body = self.admin_networks_client.create_network(**post_body)
        network = body['network']
        self.addCleanup(self.admin_networks_client.delete_network,
                        network['id'])
        return network

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_001_netmask_neg(self):
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'netmask')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_002_time_offset_neg(self):
        # Create a port with Extra DHCP Options two's complement 32-bit integer
        network_id = self.osmgd_l2_network['id']
        bad_values = ['rubbish',
                      str(constants.MAX_UNSIGNED_INT32_PLUS_ONE),
                      VERY_LONG_STRING]
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, bad_values, 'netmask')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_003_router_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'router')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_004_time_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        bad_values = ['rubbish',
                      str(constants.MAX_UNSIGNED_INT32_PLUS_ONE),
                      VERY_LONG_STRING]
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, bad_values, 'time-server')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_006_dns_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'dns-server')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_007_log_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'log-server')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_009_lpr_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'lpr-server')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_012_hostname_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        bad_values = [
            VERY_LONG_STRING]
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, bad_values, 'hostname')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_013_boot_file_size_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'boot-file-size')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_015_domain_name_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_STRING_TYPE_VALUES, 'domain-name')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_016_swap_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'swap-server')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_017_root_path_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_STRING_TYPE_VALUES, 'root-path')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_018_extension_path_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_STRING_TYPE_VALUES, 'extension-path')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_019_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'ip-forward-enable')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_020_non_local_source_routing_neg(
            self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad  DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'non-local-source-routing')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_021_policy_filter_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        bad_values = ['10.20.21.200;255.255.256.0',
                      '10.20.21.300;255.255.255.0',
                      '10.20.21.401;255.255.0.',
                      str(constants.MAX_UNSIGNED_INT32_PLUS_ONE),
                      VERY_LONG_STRING]
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, bad_values, 'policy-filter')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_022_max_datagram_reassembly_neg(
            self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'max-datagram-reassembly')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_023_default_ttl_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'default-ttl')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_026_mtu_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'mtu')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_027_all_subnets_local_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'TBD')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_028_broadcast_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'broadcast')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_031_router_discovery_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'router-discovery')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_032_router_solicitation_neg(
            self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'router-solicitation')

    # {'opt_value': '10.33.33.0;10.33.33.33;10.33.34.0;10.33.34.10',
    #  'opt_name': 'static-route'}

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_033_static_route_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad  DHCP option values
        # The minimum length of this option is 8, and the length MUST be a
        # multiple of 8.
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'static-route')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_034_trailer_encapsulation_neg(
            self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'trailer-encapsulation')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_035_arp_timeout_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        # 32-bit unsigned integer
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'arp-timeout')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_036_ethernet_encap_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'ethernet-encap')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_037_tcp_ttl_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        # 8-bit unsigned integer.  The minimum value is 1.
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'tcp-ttl')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_038_tcp_keepalive_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        # 32-bit unsigned integer
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'tcp-keepalive')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_040_nis_domain_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_STRING_TYPE_VALUES, 'nis-domain')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_041_nis_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'nis-server')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_042_ntp_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'ntp-server')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_044_netbios_ns_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'netbios-ns')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_045_netbios_dd_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'netbios-dd')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_046_netbios_nodetype_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        # Valid values: 0x1, 0x2, 0x4, 0x8
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'netbios-nodetype')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_047_netbios_scope_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_STRING_TYPE_VALUES, 'netbios-scope')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_048_x_windows_fs_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'x-windows-fs')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_049_x_windows_dm_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'x-windows-dm')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_050_requested_address_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'requested-address')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_060_vendor_class_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_STRING_TYPE_VALUES, 'vendor-class')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_064_nisplus_domain_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_STRING_TYPE_VALUES, 'nis+-domain')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_065_nisplus_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'nis+-server')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_066_tftp_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_STRING_TYPE_VALUES, 'tftp_server')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_067_bootfile_name_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_STRING_TYPE_VALUES, 'bootfile-name')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_068_mobile_ip_home_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'mobile-ip-home')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_069_smtp_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'smtp-server')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_070_pop3_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'pop3-server')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_071_nntp_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'nntp-server')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_074_irc_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_IPV4_ADDRESSES, 'irc-server')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_077_user_class_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'user-class')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_093_client_arch_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'client-arch')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_094_client_interface_id_neg(
            self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'client-interface-id')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_097_client_machine_id_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'client-machine-id')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_119_domain_search_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_STRING_TYPE_VALUES, 'domain-search')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_120_sip_server_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_STRING_TYPE_VALUES, 'sip-server')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_121_classless_static_route_neg(
            self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'classless-static-route')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_125_vendor_id_encap_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'vendor-id-encap')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_255_server_ip_address_neg(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, BAD_INTEGER_TYPE_VALUES, 'server-ip-address')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_wrong_option(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        bad_values = ['1', '2']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, bad_values, 'non-existing-option')

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_large_option_name(self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        network_id = self.osmgd_l2_network['id']
        some_values = ['1', '2']
        self._assert_create_update_port_with_bad_dhcp_opts_neg(
            network_id, some_values, VERY_LONG_STRING)

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_external_network_neg(self):
        # Try to create a port with  extra dhcp options on an external network
        # Should fail, as DHCP is handled externally
        ext_network = self._create_network(external=True)
        # subnet is needed for trying port creation
        ext_subnet = self.create_subnet(ext_network,
                                        client=self.admin_subnets_client)
        # check whether this subnet is not empty
        self.assertNotEmpty(ext_subnet)
        extra_dhcp_opts = [
            {'opt_value': '12.22.32.42', 'opt_name': 'router'}
        ]
        # TODO(TEAM) - THIS FAILS WITH ML2 - THIS IS A BUG? IS IT TRACKED?
        self.assertRaises(exceptions.BadRequest,
                          self._create_port_with_dhcp_opts,
                          ext_network['id'],
                          extra_dhcp_opts,
                          client=self.admin_ports_client)

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_nuage_l2_to_l3_migr_port_neg(
            self):
        # Try to create a port with bad extra dhcp options values
        # Try to update an existing port with these bad DHCP option values
        extra_dhcp_opts = [
            {'opt_value': '10.20.30.40', 'opt_name': 'router'}
        ]
        # Find the device_owner = 'network:dhcp:nuage' port created by Nuage
        # when the subnet was created
        list_body = self.ports_client.list_ports()
        all_ports = list_body['ports']
        nuage_ports = [p for p in all_ports
                       if p['device_owner'] == 'network:dhcp:nuage']
        # Now fetch the one from our subnet
        our_nuage_port = [p for p in nuage_ports
                          if p['fixed_ips'][0]['subnet_id'] ==
                          self.osmgd_l2_subnet['id']]
        self.assertTrue(our_nuage_port)
        if NUAGE_FEATURES.os_managed_dualstack_subnets:
            new_nuage_port = self._update_port_with_dhcp_opts(
                our_nuage_port[0]['id'],
                extra_dhcp_opts)
            # with ipv6 patchset we don't raise exception on update of
            # nuage:dhcp owned ports (upstream allows this)
            # Openstack-1897
            self.assertIsNone(new_nuage_port)
        else:
            self.assertRaises(exceptions.BadRequest,
                              self._update_port_with_dhcp_opts,
                              our_nuage_port[0]['id'],
                              extra_dhcp_opts)

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_multiple_times_neg(
            self):
        # When specifying the the same option multiple times, it should fail
        network_id = self.osmgd_l2_network['id']
        extra_dhcp_opts = [
            {'opt_value': '19.20.30.40', 'opt_name': 'router'},
            {'opt_value': '19.20.30.41', 'opt_name': 'router'},
            {'opt_value': '19.20.30.42', 'opt_name': 'router'},
            {'opt_value': '19.20.30.43', 'opt_name': 'router'},
            {'opt_value': '19.20.30.44', 'opt_name': 'router'}
        ]

        if Topology.from_openstack('Newton') and Topology.is_ml2:
            self.assertRaises(exceptions.Conflict,
                              self._create_port_with_dhcp_opts,
                              network_id,
                              extra_dhcp_opts)
        else:
            self.assertRaises(exceptions.BadRequest,
                              self._create_port_with_dhcp_opts,
                              network_id,
                              extra_dhcp_opts)

    @nuage_test.header()
    def test_nuage_update_port_with_dhcp_opts_multiple_times_neg(self):
        # When specifying the the same option multiple times, it should fail
        extra_dhcp_opts = [
            {'opt_value': '19.20.30.40', 'opt_name': 'router'},
            {'opt_value': '19.20.30.41', 'opt_name': 'router'},
            {'opt_value': '19.20.30.42', 'opt_name': 'router'},
            {'opt_value': '19.20.30.43', 'opt_name': 'router'},
            {'opt_value': '19.20.30.44', 'opt_name': 'router'}
        ]

        if Topology.from_openstack('Newton') and Topology.is_ml2:
            self.assertRaises(exceptions.Conflict,
                              self._update_port_with_dhcp_opts,
                              self.os_l2_port['id'],
                              extra_dhcp_opts)
        else:
            self.assertRaises(exceptions.BadRequest,
                              self._update_port_with_dhcp_opts,
                              self.os_l2_port['id'],
                              extra_dhcp_opts)

    @nuage_test.header()
    def test_nuage_create_port_with_dhcp_opts_more_than_16_neg(self):
        # When specifying the the same option multiple times, it should fail
        more_than_16_extra_dhcp_opts = [
            {'opt_value': '255.255.255.0', 'opt_name': 'netmask'},
            {'opt_value': '200', 'opt_name': 'time-offset'},
            {'opt_value': '11.33.66.3', 'opt_name': 'router'},
            {'opt_value': '11.33.66.4', 'opt_name': 'time-server'},
            {'opt_value': '11.33.66.6', 'opt_name': 'dns-server'},
            {'opt_value': '11.33.66.7', 'opt_name': 'log-server'},
            {'opt_value': '11.33.66.9', 'opt_name': 'lpr-server'},
            {'opt_value': 'more.than.16-hostname', 'opt_name': 'hostname'},
            {'opt_value': '8192', 'opt_name': 'boot-file-size'},
            {'opt_value': 'more.than.16.domain.com',
             'opt_name': 'domain-name'},
            {'opt_value': '11.33.66.16', 'opt_name': 'swap-server'},
            {'opt_value': '/opt/more-than16/root-path',
             'opt_name': 'root-path'},
            {'opt_value': '/opt/more-than16/extension-path',
             'opt_name': 'extension-path'},
            {'opt_value': '1', 'opt_name': 'ip-forward-enable'},
            {'opt_value': '1', 'opt_name': 'non-local-source-routing'},
            {'opt_value': '1576', 'opt_name': 'max-datagram-reassembly'},
            {'opt_value': '150', 'opt_name': 'default-ttl'},
            {'opt_value': '2104', 'opt_name': 'mtu'}
        ]
        self.assertRaises(exceptions.BadRequest,
                          self._create_port_with_dhcp_opts,
                          self.osmgd_l2_network['id'],
                          more_than_16_extra_dhcp_opts)

    @nuage_test.header()
    def test_nuage_show_port_non_existing_neg(self):
        # Try to show the extra dhcp options of a non-existing port
        bad_port_id = 'blablablabla'
        self.assertRaises(exceptions.NotFound,
                          self.ports_client.show_port,
                          bad_port_id)
