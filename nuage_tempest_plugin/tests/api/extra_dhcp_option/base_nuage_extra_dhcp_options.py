# Copyright 2015 Alcatel-Lucent

from oslo_log import log as logging

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

from nuage_commons import constants

from nuage_tempest_lib.tests.nuage_test import NuageBaseAdminNetworkTest
from nuage_tempest_lib.vsdclient import nuage_client
from nuage_tempest_lib.vsdclient.nuage_network_client \
    import NuageNetworkClientJSON

LOG = logging.getLogger(__name__)


#
# See http://tools.ietf.org/html/rfc2132
#
DHCP_OPTION_NUMBER_TO_NAME = {
    # 'pad': 0,  # In Decimal 0
    1: 'netmask',
    2: 'time-offset',
    3: 'router',
    4: 'time-server',
    6: 'dns-server',
    7: 'log-server',
    8: 'quotes-server',  # not in dnsmasq
    9: 'lpr-server',
    10: 'impress_server',  # not in dnsmasq
    11: 'rlp-server',  # not in dnsmasq
    12: 'hostname',
    13: 'boot-file-size',
    15: 'domain-name',
    16: 'swap-server',
    17: 'root-path',
    18: 'extension-path',
    19: 'ip-forward-enable',
    20: 'non-local-source-routing',
    21: 'policy-filter',
    22: 'max-datagram-reassembly',
    23: 'default-ttl',
    24: 'mtu_timeout',  #
    25: 'mtu_plateau',  #
    26: 'mtu',
    27: 'all-subnets-local',
    28: 'broadcast',
    29: 'mask-discovery',  # not in dnsmasq
    30: 'mask-supplier',  # not in dnsmasq
    31: 'router-discovery',
    32: 'router-solicitation',
    33: 'static-route',
    34: 'trailer-encapsulation',
    35: 'arp-timeout',
    36: 'ethernet-encap',
    37: 'tcp-ttl',
    38: 'tcp-keepalive',
    39: 'keep-alive-data',  # not in dnsmasq
    40: 'nis-domain',
    41: 'nis-server',
    42: 'ntp-server',
    43: 'vendor-specific',  # not in dnsmasq
    44: 'netbios-ns',
    45: 'netbios-dd',
    46: 'netbios-nodetype',
    47: 'netbios-scope',
    48: 'x-windows-fs',
    49: 'x-windows-dm',
    50: 'requested-address',
    51: 'address-time',  # not in dnsmasq
    52: 'overload',  # not in dnsmasq
    53: 'dhcp-msg-type',  # not in dnsmasq
    54: 'dhcp-server-id',  # not in dnsmasq
    55: 'parameter-list',  # not in dnsmasq
    56: 'dhcp-message',  # not in dnsmasq
    57: 'dhcp-max-msg-size',  # not in dnsmasq
    58: 'renewal-time',  # not in dnsmasq
    59: 'rebinding-time',  # not in dnsmasq
    60: 'vendor-class',
    61: 'client-id',  # not in dnsmasq
    62: 'netware/ip_domain',  # not in dnsmasq
    63: 'netware/ip_option',  # not in dnsmasq
    64: 'nis+-domain',
    65: 'nis+-server',
    66: 'tftp-server',
    67: 'bootfile-name',
    68: 'mobile-ip-home',
    69: 'smtp-server',
    70: 'pop3-server',
    71: 'nntp-server',
    72: 'www_server',  # not yet supported,
    73: 'finger_server',  # not yet supported,
    74: 'irc-server',
    75: 'streettalk-server',  # not yet supported,
    76: 'stda-server',  # not yet supported,
    77: 'user-class',
    78: 'directory_agent',  # In Decimal 78 - 0x4E not yet supported
    79: 'service_scope',  # In Decimal 79 - 0x4F not yet supported
    80: 'rapid_commit',  # In Decimal 80 - 0x50 not yet supported
    81: 'client_fqdn',  # In Decimal 81 - 0x51 not yet supported
    82: 'relay_agent_information',  # 0x52 not yet supported
    83: 'isns',  # 0x53 not yet supported
    93: 'client-arch',
    94: 'client-interface-id',
    97: 'client-machine-id',
    119: 'domain-search',
    120: 'sip-server',
    121: 'classless-static-route',
    125: 'vendor-id-encap',
    255: 'server-ip-address'
}

####################################
# Special conversion for 3.2 release
####################################

# Some options need to be treated as int
# (for easier comparison with the VSD dhcp options response)
TREAT_32_DHCP_OPTION_AS_INT = [
    'time-offset',
    'boot-file-size',
    'ip-forward-enable',
    'non-local-source-routing',
    'max-datagram-reassembly',
    'default-ttl',
    'mtu',
    'all-subnets-local',
    'router-discovery',
    'trailer-encapsulation',
    'arp-timeout',
    'ethernet-encap',
    'tcp-ttl',
    'tcp-keepalive',
    'client-arch'
]

# Some options are treated as raw hex
# (for easier comparison with the VSD dhcp options response)
TREAT_32_DHCP_OPTION_AS_RAW_HEX = [
    'netbios-nodetype',
    'client-machine-id',
    'classless-static-route',
    'client-interface-id',
    'vendor-id-encap',
    'server-ip-address'
]

# Some options need to be concatenated
# (for easier comparison with the VSD dhcp options response)
TREAT_32_DHCP_OPTION_AS_CONCAT_STRING = [
    'domain-search',
    'sip-server'
]

####################################
# Special conversion for 4.0 release
####################################

# Some options are treated as raw hex
# (for easier comparison with the VSD dhcp options response)
TREAT_DHCP_OPTION_AS_RAW_HEX = [
    'client-machine-id',
    'classless-static-route',
    'client-interface-id',
    'vendor-id-encap',
    'server-ip-address'
]

# For easier vsd dhcp options comparison
TREAT_DHCP_OPTION_NETBIOS_NODETYPE = [
    'netbios-nodetype'
]

# Distinguish the 4 different cases
NUAGE_NETWORK_TYPE = {
    'OS_Managed_L2': 1,
    'OS_Managed_L3': 2,
    'VSD_Managed_L2': 3,
    'VSD_Managed_L3': 4
}


class NuageExtraDHCPOptionsBase(NuageBaseAdminNetworkTest):

    def __init__(self, *args, **kwargs):
        super(NuageExtraDHCPOptionsBase, self).__init__(*args, **kwargs)
        self.nuage_network_type = NUAGE_NETWORK_TYPE['OS_Managed_L2']

    @classmethod
    def skip_checks(cls):
        super(NuageExtraDHCPOptionsBase, cls).skip_checks()
        if not utils.is_extension_enabled('extra_dhcp_opt', 'network'):
            msg = "Extra DHCP Options extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(NuageExtraDHCPOptionsBase, cls).setup_clients()
        cls.nuage_client = nuage_client.NuageRestClient()

        # TODO(Hendrik) only use admin credentials where required!
        cls.client = NuageNetworkClientJSON(
            cls.os_admin.auth_provider,
            **cls.os_admin.default_params)

    @classmethod
    def resource_setup(cls):
        # create default netpartition if it is not there
        netpartition_name = cls.nuage_client.def_netpart_name
        net_partition = cls.nuage_client.get_net_partition(
            netpartition_name)
        if not net_partition:
            net_partition = cls.nuage_client.create_net_partition(
                netpartition_name, fip_quota=100, extra_params=None)
        super(NuageExtraDHCPOptionsBase, cls).resource_setup()

    @classmethod
    def _try_delete_resource(self, delete_callable, *args, **kwargs):
        """Cleanup resources in case of test-failure

        Some resources are explicitly deleted by the test.
        If the test failed to delete a resource, this method will execute
        the appropriate delete methods. Otherwise, the method ignores NotFound
        exceptions thrown for resources that were correctly deleted by the
        test.

        :param delete_callable: delete method
        :param args: arguments for delete method
        :param kwargs: keyword arguments for delete method
        """
        try:
            delete_callable(*args, **kwargs)
        # if resource is not found, this means it was deleted in the test
        except exceptions.NotFound:
            pass

    def _create_port_with_dhcp_opts(self, network_id, extra_dhcp_opts,
                                    client=None):
        # allow tests to use admin client
        if not client:
            client = self.ports_client

        name = data_utils.rand_name('extra-dhcp-opt-port-name')
        create_body = client.create_port(
            name=name,
            network_id=network_id,
            extra_dhcp_opts=extra_dhcp_opts)
        self.addCleanup(client.delete_port, create_body['port']['id'])

    def _update_port_with_dhcp_opts(self, port_id, extra_dhcp_opts,
                                    client=None):
        # allow tests to use admin client
        if not client:
            client = self.ports_client
        name = data_utils.rand_name('updated-extra-dhcp-opt-port-name')
        update_body = client.update_port(
            port_id,
            name=name,
            extra_dhcp_opts=extra_dhcp_opts)
        # Confirm extra dhcp options were added to the port
        self._confirm_extra_dhcp_options(update_body['port'], extra_dhcp_opts)
        upd_show_body = client.show_port(port_id)
        self._confirm_extra_dhcp_options(upd_show_body['port'],
                                         extra_dhcp_opts)

    def _nuage_create_list_show_update_layer_x_port_with_dhcp_opts(
            self, network_id,
            vsd_network_id,
            nuage_network_type,
            extra_dhcp_opts,
            new_extra_dhcp_opts):
        # Create a port with given extra DHCP Options on an Openstack layer X
        # managed network
        name = data_utils.rand_name('extra-dhcp-opt-port-name')
        create_body = self.ports_client.create_port(
            name=name,
            network_id=network_id,
            extra_dhcp_opts=extra_dhcp_opts)
        port_id = create_body['port']['id']
        self.addCleanup(self.ports_client.delete_port, port_id)
        # Does the response contain the dhcp options we passed in the request
        self._confirm_extra_dhcp_options(create_body['port'], extra_dhcp_opts)
        # Confirm port created has Extra DHCP Options via show
        show_body = self.ports_client.show_port(port_id)
        self._confirm_extra_dhcp_options(show_body['port'], extra_dhcp_opts)
        # Confirm port created has Extra DHCP Options via lis ports
        list_body = self.ports_client.list_ports()
        ports = list_body['ports']
        port = [p for p in ports if p['id'] == port_id]
        self.assertTrue(port)
        self._confirm_extra_dhcp_options(port[0], extra_dhcp_opts)
        # Depending on the network type (L2 or L3) fetch the appropriate
        # domain/subnet from the VSD
        if nuage_network_type in [NUAGE_NETWORK_TYPE['OS_Managed_L3'],
                                  NUAGE_NETWORK_TYPE['VSD_Managed_L3']]:
            parent = constants.DOMAIN
        else:
            parent = constants.L2_DOMAIN
        vports = self.nuage_client.get_vport(
            parent,
            vsd_network_id,
            'externalID',
            self.nuage_client.get_vsd_external_id(port_id))
        vsd_dchp_options = self.nuage_client.get_dhcpoption(
            constants.VPORT, vports[0]['ID'])
        self._verify_vsd_extra_dhcp_options(vsd_dchp_options, extra_dhcp_opts)
        # update
        name = data_utils.rand_name('new-extra-dhcp-opt-port-name')
        update_body = self.ports_client.update_port(
            port_id, name=name, extra_dhcp_opts=new_extra_dhcp_opts)
        # Confirm extra dhcp options were added to the port
        # OPENSTACK-1059: update response contains old dhcp options
        self._confirm_extra_dhcp_options(update_body['port'],
                                         new_extra_dhcp_opts)
        upd_show_body = self.ports_client.show_port(port_id)
        self._confirm_extra_dhcp_options(upd_show_body['port'],
                                         new_extra_dhcp_opts)
        vsd_dchp_options = self.nuage_client.get_dhcpoption(
            constants.VPORT, vports[0]['ID'])
        self._verify_vsd_extra_dhcp_options(vsd_dchp_options,
                                            new_extra_dhcp_opts)
        pass

    def _nuage_crud_port_with_dhcp_opts(
            self, nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts):
        raise exceptions.NotImplemented

    def _confirm_extra_dhcp_options(self, port, extra_dhcp_opts):
        retrieved = port['extra_dhcp_opts']
        self.assertEqual(len(retrieved), len(extra_dhcp_opts))
        for retrieved_option in retrieved:
            for option in extra_dhcp_opts:
                if (retrieved_option['opt_value'] == option['opt_value'] and
                        retrieved_option['opt_name'] == option['opt_name']):
                    break
            else:
                self.fail('Extra DHCP option not found in port %s' %
                          str(retrieved_option))

    # function to be able to convert the value in to a VSD supported hex format
    def _convert_to_hex(self, value):
        hex_val = str(value[2:])
        if len(hex_val) % 2 != 0:
            length = len(hex_val) + 1
        else:
            length = len(hex_val)
        hex_val = hex_val.zfill(length)
        return hex_val

    def _convert_netbios_type(self, value):
        if value == '0x1':
            result = 'B-node'
        elif value == '0x2':
            result = 'P-node'
        elif value == '0x4':
            result = 'M-node'
        elif value == '0x8':
            result = 'H-node'
        else:
            result = 'error'
        return result

    def _convert_to_vsd_opt_values(self, opt_values, opt_name):
        # convert all elements in the openstack extra dhcp option value list
        # into the format return by VSD
        # so we can use easy list comparison
        tmp_var = ""
        if opt_name in TREAT_DHCP_OPTION_AS_RAW_HEX:
            for opt_value in opt_values:
                # opt_values[opt_value.index(opt_value)] = \
                # self.my_convert_to_hex(opt_value)
                tmp_var += self._convert_to_hex(opt_value)
            opt_values = [tmp_var]
        if opt_name in TREAT_DHCP_OPTION_NETBIOS_NODETYPE:
            for opt_value in opt_values:
                # opt_values[opt_value.index(opt_value)] = \
                # self.my_convert_to_hex(opt_value)
                tmp_var += self._convert_netbios_type(opt_value)
            opt_values = [tmp_var]
        return opt_values

    def _verify_vsd_extra_dhcp_options(self, vsd_dchp_options,
                                       extra_dhcp_opts):
        # Verify the contents of the extra dhcp options returned by VSD
        # (vsd_dhcp_options)
        # with the corresponding contents of the extra dhcp options passed to
        # the plugin (extra_dhcp_opt)
        # The format is different, hence a more complex comparison loop
        for retrieved_option in vsd_dchp_options:
            for option in extra_dhcp_opts:
                # VSD returns option numbers, not names: convert
                vsd_opt_name = DHCP_OPTION_NUMBER_TO_NAME[
                    retrieved_option['actualType']]
                vsd_opt_value = retrieved_option['actualValues']
                # Make a local list copy from option['opt_value'],
                # using the separator ";"
                option_value_list = option['opt_value'].split(";")
                # Special trick for opt_name='router' and
                # opt_value='0.0.0.0' which is converted into '00'
                # when sending to VSD,
                if vsd_opt_name == 'router' and \
                        option_value_list == ['0.0.0.0']:
                    if retrieved_option['value'] == '00':
                        vsd_opt_value = ['0.0.0.0']
                elif vsd_opt_name == 'server-ip-address':
                    # option 255 is treated bizarre in openstack.
                    # It should not contain any data, but for OS it does
                    # use that value in 'value' instead of 'actualValues'
                    vsd_opt_value = [retrieved_option['value']]
                elif vsd_opt_name == 'user-class':
                    # in case of 'user-class', the value as passed to OS
                    # is available in the 'value' field
                    # just prepend with '0x' to lign up completely with what
                    # was passed to the plugin
                    vsd_opt_value = ['0x' + str(retrieved_option['value'])]
                elif vsd_opt_name == 'classless-static-route':
                    # 'actualValues' contains a nice UI format
                    # (cidr + ip address).
                    # Use the encode value in the 'value' field
                    vsd_opt_value = [retrieved_option['value']]
                # Compare element by element, as the VSD stores it all in hex
                converted_os_opt_values = self._convert_to_vsd_opt_values(
                    option_value_list, option['opt_name'])
                if converted_os_opt_values == vsd_opt_value and \
                        vsd_opt_name == option['opt_name']:
                    # Now check whether the length of this value > 0
                    if retrieved_option['length'] != '00':
                        break
                    else:
                        # don't fail yet, log to put all zero-length options in
                        # the log file
                        LOG.warn("VSD has extra DHCP option - %s of "
                                 "length zero !", str(vsd_opt_name))
            else:
                self.fail('Extra DHCP option mismatch VSD  and Openstack')

    def _check_nuage_crud_port_with_dhcp_opts_001_netmask(self):
        # Create a port with Extra DHCP Options nbr 1 netmask
        extra_dhcp_opts = [
            {'opt_value': '255.255.255.0', 'opt_name': 'netmask'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '255.255.255.0', 'opt_name': 'netmask'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_002_time_offset(self):
        # Create a port with Extra DHCP Options two's complement 32-bit integer
        extra_dhcp_opts = [
            {'opt_value': '100', 'opt_name': 'time-offset'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '2137', 'opt_name': 'time-offset'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_003_routers(self):
        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '10.20.3.100', 'opt_name': 'router'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.3.200;10.20.3.201', 'opt_name': 'router'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        # Check value 0.0.0.0, which should disable the default route
        extra_dhcp_opts = [
            {'opt_value': '0.0.0.0', 'opt_name': 'router'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1.1.1.1;10.20.3.201', 'opt_name': 'router'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_004_time_server(self):

        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '10.20.4.100', 'opt_name': 'time-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.4.200;10.20.4.201', 'opt_name': 'time-server'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

        # def _check_nuage_crud_port_with_dhcp_opts_005_nameserver(self):
        #     pass

    def _check_nuage_crud_port_with_dhcp_opts_006_dns_server(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.6.100', 'opt_name': 'dns-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '100.20.6.200;10.20.6.201', 'opt_name': 'dns-server'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_007_log_server(self):
        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '10.20.7.100', 'opt_name': 'log-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.7.200;10.20.7.201', 'opt_name': 'log-server'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_009_lpr_server(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.9.100', 'opt_name': 'lpr-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.9.200;10.20.9.201', 'opt_name': 'lpr-server'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_012_hostname(self):
        extra_dhcp_opts = [
            {'opt_value': 'edo.nuagenetworks.net', 'opt_name': 'hostname'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'updated.edo.nuagenetworks.net',
             'opt_name': 'hostname'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_013_boot_file_size(self):
        # Create a port with Extra DHCP Options
        # file length is specified as an unsigned 16-bit integer
        extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'boot-file-size'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '2049', 'opt_name': 'boot-file-size'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        extra_dhcp_opts = [
            {'opt_value': '65535', 'opt_name': 'boot-file-size'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_015_domain_name(self):
        extra_dhcp_opts = [
            {'opt_value': 'nuagenetworks.net', 'opt_name': 'domain-name'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'other.nuagenetworks.net', 'opt_name': 'domain-name'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_016_swap_server(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.16.100', 'opt_name': 'swap-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.16.200', 'opt_name': 'swap-server'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_017_root_path(self):

        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '/opt/nuage/root-path', 'opt_name': 'root-path'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '/opt/other-path/nuage/root-path',
             'opt_name': 'root-path'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_018_extension_path(self):

        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '/opt/nuage/extension-path',
             'opt_name': 'extension-path'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '/opt/other-path/nuage/extension-path',
             'opt_name': 'extension-path'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_019_ip_forward_enable(self):

        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '0', 'opt_name': 'ip-forward-enable'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'ip-forward-enable'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_020_non_local_src_routing(
            self):

        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '0', 'opt_name': 'non-local-source-routing'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'non-local-source-routing'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_021_policy_filter(self):

        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '10.20.21.100;255.255.255.0',
             'opt_name': 'policy-filter'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.21.200;255.255.255.0;'
                          '10.20.21.201;255.255.0.0',
             'opt_name': 'policy-filter'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_022_max_datagram_reassembly(
            self):
        # Create a port with DHCP Options 16 bit unsigned int min value = 576
        extra_dhcp_opts = [
            {'opt_value': '576', 'opt_name': 'max-datagram-reassembly'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '65535', 'opt_name': 'max-datagram-reassembly'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_023_default_ttl(self):
        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'default-ttl'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '255', 'opt_name': 'default-ttl'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_026_mtu(self):

        # Create a port with Extra DHCP Options. 16-bit unsigned integer.
        # The minimum legal value for the MTU is 68.
        extra_dhcp_opts = [
            {'opt_value': '68', 'opt_name': 'mtu'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '9000', 'opt_name': 'mtu'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        extra_dhcp_opts = [
            {'opt_value': '65535', 'opt_name': 'mtu'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_027_all_subnets_local(self):
        extra_dhcp_opts = [
            {'opt_value': '0', 'opt_name': 'all-subnets-local'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'all-subnets-local'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_028_broadcast(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.28.255', 'opt_name': 'broadcast'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.28.28.255', 'opt_name': 'broadcast'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_031_router_discovery(self):
        extra_dhcp_opts = [
            {'opt_value': '0', 'opt_name': 'router-discovery'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'router-discovery'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_032_router_solicitation(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.32.100', 'opt_name': 'router-solicitation'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.32.200', 'opt_name': 'router-solicitation'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_033_static_route(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.33.10;10.33.33.33',
             'opt_name': 'static-route'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.33.33.0;10.33.33.33;10.33.34.0;10.33.34.10',
             'opt_name': 'static-route'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_034_trailer_encapsulation(self):
        extra_dhcp_opts = [
            {'opt_value': '0', 'opt_name': 'trailer-encapsulation'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'trailer-encapsulation'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_035_arp_timeout(self):
        # Create a port with Extra DHCP Options 32-bit unsigned integer
        extra_dhcp_opts = [
            {'opt_value': '1023', 'opt_name': 'arp-timeout'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '123', 'opt_name': 'arp-timeout'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        new_extra_dhcp_opts = [
            {'opt_value': str(constants.MAX_INT), 'opt_name': 'arp-timeout'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_036_ethernet_encap(self):
        extra_dhcp_opts = [
            {'opt_value': '0', 'opt_name': 'ethernet-encap'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'ethernet-encap'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_037_tcp_ttl(self):
        # Create a port with Extra DHCP Options 8 bit unsigned
        extra_dhcp_opts = [
            {'opt_value': '1', 'opt_name': 'tcp-ttl'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '255', 'opt_name': 'tcp-ttl'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_038_tcp_keepalive(self):
        # Create a port with Extra DHCP Options MAX_32BIT_UNSIGNED
        extra_dhcp_opts = [
            {'opt_value': '0', 'opt_name': 'tcp-keepalive'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '1024', 'opt_name': 'tcp-keepalive'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        extra_dhcp_opts = [
            {'opt_value': str(constants.MAX_UNSIGNED_INT32),
             'opt_name': 'tcp-keepalive'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_040_nis_domain(self):
        # Create a port with Extra DHCP Options
        extra_dhcp_opts = [
            {'opt_value': 'nis.nuagenetworks.net', 'opt_name': 'nis-domain'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'new-nis.nuagenetworks.net',
             'opt_name': 'nis-domain'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_041_nis_server(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.41.100', 'opt_name': 'nis-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.41.200;10.20.41.201',
             'opt_name': 'nis-server'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_042_ntp_server(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.42.100', 'opt_name': 'ntp-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.42.200;10.20.42.201',
             'opt_name': 'ntp-server'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_044_netbios_ns(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.44.100', 'opt_name': 'netbios-ns'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.44.200;10.20.44.201',
             'opt_name': 'netbios-ns'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_045_netbios_dd(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.45.100', 'opt_name': 'netbios-dd'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.45.200;10.20.45.201',
             'opt_name': 'netbios-dd'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_046_netbios_nodetype(self):
        extra_dhcp_opts = [
            {'opt_value': '0x1', 'opt_name': 'netbios-nodetype'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0x2', 'opt_name': 'netbios-nodetype'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        extra_dhcp_opts = [
            {'opt_value': '0x4', 'opt_name': 'netbios-nodetype'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0x8', 'opt_name': 'netbios-nodetype'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_047_netbios_scope(self):
        extra_dhcp_opts = [
            {'opt_value': 'nuage.netbios.scope.com',
             'opt_name': 'netbios-scope'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'new.nuage.netbios.scope.com',
             'opt_name': 'netbios-scope'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_048_x_windows_fs(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.47.100', 'opt_name': 'x-windows-fs'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.47.200;10.20.47.201',
             'opt_name': 'x-windows-fs'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_049_x_windows_dm(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.48.100', 'opt_name': 'x-windows-dm'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.48.200;10.20.48.201',
             'opt_name': 'x-windows-dm'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_050_requested_address(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.50.100', 'opt_name': 'requested-address'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.50.200', 'opt_name': 'requested-address'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_060_vendor_class(self):
        extra_dhcp_opts = [
            {'opt_value': '0401020304', 'opt_name': 'vendor-class'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '06010203040506', 'opt_name': 'vendor-class'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_064_nisplus_domain(self):
        extra_dhcp_opts = [
            {'opt_value': 'nisplus.nuagenetworks.net',
             'opt_name': 'nis+-domain'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'newer.nisplus.nuagenetworks.net',
             'opt_name': 'nis+-domain'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_065_nisplus_server(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.65.100', 'opt_name': 'nis+-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.65.200;10.20.65.201',
             'opt_name': 'nis+-server'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_066_tftp_server(self):
        extra_dhcp_opts = [
            {'opt_value': 'tftp-server.nuagenetworks.net',
             'opt_name': 'tftp-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'newer-tftp-server.nuagenetworks.net',
             'opt_name': 'tftp-server'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_067_bootfile_name(self):
        extra_dhcp_opts = [
            {'opt_value': '/opt/nuage/bootfile-name',
             'opt_name': 'bootfile-name'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '/opt/newer-nuage/newer-bootfile-name',
             'opt_name': 'bootfile-name'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_068_mobile_ip_home(self):
        # Create a port with Extra DHCP Options: zero or more addresses
        extra_dhcp_opts = [
            {'opt_value': '10.20.68.100', 'opt_name': 'mobile-ip-home'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.68.20;200.20.68.201',
             'opt_name': 'mobile-ip-home'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_069_smtp_server(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.69.100', 'opt_name': 'smtp-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.69.20;200.20.69.201',
             'opt_name': 'smtp-server'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_070_pop3_server(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.70.10', 'opt_name': 'pop3-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.70.200;10.20.70.201',
             'opt_name': 'pop3-server'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_071_nntp_server(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.71.100', 'opt_name': 'nntp-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.71.200;10.20.71.201',
             'opt_name': 'nntp-server'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_074_irc_server(self):
        extra_dhcp_opts = [
            {'opt_value': '10.20.74.100', 'opt_name': 'irc-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '10.20.74.200;10.20.74.201',
             'opt_name': 'irc-server'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_077_user_class(self):
        extra_dhcp_opts = [
            {'opt_value': '0x080001020304050607', 'opt_name': 'user-class'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0x1000010203040506070809aabbccddeeff',
             'opt_name': 'user-class'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_093_client_arch(self):
        extra_dhcp_opts = [
            {'opt_value': '0;2;5', 'opt_name': 'client-arch'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '3;6;9', 'opt_name': 'client-arch'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_094_client_interface_id(self):
        extra_dhcp_opts = [
            {'opt_value': '0x01020b', 'opt_name': 'client-interface-id'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0x01030f', 'opt_name': 'client-interface-id'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_097_client_machine_id(self):
        # Create a port with Extra DHCP Options: first octet = zero
        # (only valid value for this octet for now)
        extra_dhcp_opts = [
            {'opt_value': '0x000f0e0d0c0b0a09080706050403020100',
             'opt_name': 'client-machine-id'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0x00ffeeddccbbaa99887766554433221100',
             'opt_name': 'client-machine-id'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_119_domain_search(self):
        extra_dhcp_opts = [
            {'opt_value': 'sales.domain.com;eng.domain.org',
             'opt_name': 'domain-search'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'eng.domain.com;marketing.domain.com',
             'opt_name': 'domain-search'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)

    def _check_nuage_crud_port_with_dhcp_opts_120_sip_server(self):
        extra_dhcp_opts = [
            {'opt_value': 'sip.domain.com', 'opt_name': 'sip-server'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': 'sip-updated.domain.com;sip2.domain.com',
             'opt_name': 'sip-server'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_121_classless_static_route(self):
        # Create a port with Extra DHCP Options:
        # see http://tools.ietf.org/html/rfc3442
        # Subnet number   Subnet mask      Destination descriptor
        # 10.17.0.0       255.255.0.0      16.10.17         ->
        #                                           r = 10.11.12.13 0x0a0b0c0d
        # 10.229.0.128    255.255.255.128  25.10.229.0.128  ->
        #                                           r = 10.11.12.14 0x0a0b0c0e
        # 10.198.122.47   255.255.255.255  32.10.198.122.47
        extra_dhcp_opts = [
            {'opt_value': '0x100a110a0b0c0d',
             'opt_name': 'classless-static-route'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0X190ae500800a0b0c0e;0x100a110a0b0c0d',
             'opt_name': 'classless-static-route'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_125_vendor_id_encap(self):
        extra_dhcp_opts = [
            {'opt_value': '0x0a1679000a167901',
             'opt_name': 'vendor-id-encap'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0x0a167a000a167a01;0x0a167b000a167b01',
             'opt_name': 'vendor-id-encap'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_dhcp_opts_255_server_ip_address(self):
        extra_dhcp_opts = [
            {'opt_value': '0x100a110a0b0c0d', 'opt_name': 'server-ip-address'}
        ]
        new_extra_dhcp_opts = [
            {'opt_value': '0X190ae500800a0b0c0e;0x100a110a0b0c0d',
             'opt_name': 'server-ip-address'}
        ]
        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts, new_extra_dhcp_opts)
        pass

    def _check_nuage_crud_port_with_16_extra_dhcp_options(self):
        # Check whether the maximum of 16 dhcp option in one go is ok
        extra_dhcp_opts_16 = [
            {'opt_value': '255.255.255.0', 'opt_name': 'netmask'},
            {'opt_value': '200', 'opt_name': 'time-offset'},
            {'opt_value': '11.33.66.3', 'opt_name': 'router'},
            {'opt_value': '11.33.66.4', 'opt_name': 'time-server'},
            {'opt_value': '11.33.66.6', 'opt_name': 'dns-server'},
            {'opt_value': '11.33.66.7', 'opt_name': 'log-server'},
            {'opt_value': '11.33.66.9', 'opt_name': 'lpr-server'},
            {'opt_value': 'more-than16-hostname', 'opt_name': 'hostname'},
            {'opt_value': '8192', 'opt_name': 'boot-file-size'},
            {'opt_value': 'more-than16.domain.com', 'opt_name': 'domain-name'},
            {'opt_value': '11.33.66.16', 'opt_name': 'swap-server'},
            {'opt_value': '/opt/more-than16/root-path',
             'opt_name': 'root-path'},
            {'opt_value': '/opt/more-than16/extension-path',
             'opt_name': 'extension-path'},
            {'opt_value': '1', 'opt_name': 'ip-forward-enable'},
            {'opt_value': '1', 'opt_name': 'non-local-source-routing'},
            {'opt_value': '1576', 'opt_name': 'max-datagram-reassembly'}
        ]

        self._nuage_crud_port_with_dhcp_opts(
            self.nuage_network_type, extra_dhcp_opts_16, extra_dhcp_opts_16)
