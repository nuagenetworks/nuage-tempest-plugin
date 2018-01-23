# Copyright 2017 - Nokia
# All Rights Reserved.
from netaddr import IPAddress
from oslo_log import log as logging
from testtools.matchers import ContainsDict
from testtools.matchers import Equals

from tempest import config
from tempest.test import decorators

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.lib.utils import constants as nuage_constants
from nuage_tempest_plugin.tests.api.ipv6.base_nuage_networks \
    import NetworkTestCaseMixin
from nuage_tempest_plugin.tests.api.ipv6.base_nuage_networks \
    import VsdTestCaseMixin

CONF = config.CONF

VALID_MAC_ADDRESS = 'fa:fa:3e:e8:e8:01'
VALID_MAC_ADDRESS_2A = 'fa:fa:3e:e8:e8:2a'
VALID_MAC_ADDRESS_2B = 'fa:fa:3e:e8:e8:2b'
IPv6_SUBNET_RANDOM = 'fee::'

###############################################################################
###############################################################################
# MultiVIP . allowed address pairs
###############################################################################
###############################################################################

LOG = logging.getLogger(__name__)


class VSDManagedAllowedAddresPairsTest(NetworkTestCaseMixin,
                                       VsdTestCaseMixin):

    @staticmethod
    def mask_to_prefix(mask):
        return sum([bin(int(x)).count('1') for x in mask.split('.')])

    @classmethod
    def resource_setup(cls):
        super(VSDManagedAllowedAddresPairsTest, cls).resource_setup()

        cls.port_configs = {
            'case-no-aap-fixed-ip4-no-ip6': {  # no fixed-ips, no aap
                'fixed-ips': [],
                'allowed-address-pairs': [],
                'IPV4-VIP': False,
                'l2-disable-anti-spoofing': False,
                'l3-disable-anti-spoofing': False,
                'vip-created-on-vsd': False},
            'case-aap-ipv4': {
                'fixed-ips': [
                    {'ip_address': str(IPAddress(cls.cidr4.first) + 12)},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 12)}
                ],
                'allowed-address-pairs': [
                    {'ip_address': str(IPAddress(cls.cidr4.first) + 10)}
                ],
                'IPV4-VIP': False,
                'l2-disable-anti-spoofing': True,
                'l3-disable-anti-spoofing': False,
                'vip-created-on-vsd': True},
            'case-aap-ipv6': {
                'fixed-ips': [
                    {'ip_address': str(IPAddress(cls.cidr4.first) + 3)},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 3)}
                ],
                'allowed-address-pairs': [
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 10)}
                ],
                'IPV4-VIP': False,
                'l2-disable-anti-spoofing': True,
                'l3-disable-anti-spoofing': False,
                'vip-created-on-vsd': True},
            'case-aap-ipv4-ipv6': {
                'fixed-ips': [
                    {'ip_address': str(IPAddress(cls.cidr4.first) + 4)},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 4)}
                ],
                'allowed-address-pairs': [
                    {'ip_address': str(IPAddress(cls.cidr4.first) + 10)},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 10)}],
                'IPV4-VIP': False,
                'l2-disable-anti-spoofing': True,
                'l3-disable-anti-spoofing': False,
                'vip-created-on-vsd': True},
            'case-aap-ipv4-mac4-ipv6': {
                'fixed-ips': [
                    {'ip_address': str(IPAddress(cls.cidr4.first) + 5)},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 5)}
                ],
                'allowed-address-pairs': [
                    {'ip_address': str(IPAddress(cls.cidr4.first) + 10),
                     'mac_address': VALID_MAC_ADDRESS_2A},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 10)}],
                'IPV4-VIP': False,
                'l2-disable-anti-spoofing': True,
                'l3-disable-anti-spoofing': False,
                'vip-created-on-vsd': True},
            'case-aap-ipv4-ipv6-mac6': {
                'fixed-ips': [
                    {'ip_address': str(IPAddress(cls.cidr4.first) + 6)},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 6)}
                ],
                'allowed-address-pairs': [
                    {'ip_address': str(IPAddress(cls.cidr4.first) + 10)},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 10),
                     'mac_address': VALID_MAC_ADDRESS_2B}],
                'IPV4-VIP': False,
                'l2-disable-anti-spoofing': True,
                'l3-disable-anti-spoofing': False,
                'vip-created-on-vsd': True},
            'case-aap-ipv4-mac4-ipv6-mac6': {
                'fixed-ips': [
                    {'ip_address': str(IPAddress(cls.cidr4.first) + 7)},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 7)}
                ],
                'allowed-address-pairs': [
                    {'ip_address': str(IPAddress(cls.cidr4.first) + 10),
                     'mac_address': VALID_MAC_ADDRESS_2A},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 10),
                     'mac_address': VALID_MAC_ADDRESS_2B}],
                'IPV4-VIP': False,
                'l2-disable-anti-spoofing': True,
                'l3-disable-anti-spoofing': False,
                'vip-created-on-vsd': True},
            # AAP is a range of IP addresses
            'case-aap-ipv4-range': {
                # AAP for range of IPv4 addresses
                # AAP for fixed IPv6 address
                'fixed-ips': [
                    {'ip_address': str(IPAddress(cls.cidr4.first) + 8)},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 8)}
                ],
                'allowed-address-pairs': [
                    {'ip_address': str(cls.cidr4.subnet(24, 1).next())},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 10)}],
                'IPV4-VIP': False,
                'l2-disable-anti-spoofing': True,
                'l3-disable-anti-spoofing': True,
                'vip-created-on-vsd': False},
            # AAP is a range of IP addresses
            'case-aap-ipv4-ipv6-range': {
                # AAP for range of IPv6 addresses
                # AAP for range of  IPv4 address
                'fixed-ips': [
                    {'ip_address': str(IPAddress(cls.cidr4.first) + 8)},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 8)}
                ],
                'allowed-address-pairs': [
                    {'ip_address': str(cls.cidr4.subnet(24, 1).next())},
                    {'ip_address': str(cls.cidr6.subnet(64, 1).next())}],
                'IPV4-VIP': False,
                'l2-disable-anti-spoofing': True,
                'l3-disable-anti-spoofing': True,
                'vip-created-on-vsd': False},
            'case-aap-ipv6-different-cidr': {
                'fixed-ips': [
                    {'ip_address': str(IPAddress(cls.cidr4.first) + 7)},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 7)}
                ],
                'allowed-address-pairs': [
                    {'ip_address': str(IPAddress(IPv6_SUBNET_RANDOM) + 10),
                     'mac_address': VALID_MAC_ADDRESS}],
                'IPV4-VIP': False,
                'l2-disable-anti-spoofing': True,
                'l3-disable-anti-spoofing': True,
                'vip-created-on-vsd': False},
            }

    def _has_ipv6_allowed_address_pairs(self, allowed_address_pairs):
        has_ipv6 = False
        for pair in allowed_address_pairs:
            if 'ip_address' not in pair:
                assert "Must have ip_addres defined for each allowed " \
                       "address pair"
            if str(pair['ip_address']).count(":"):
                has_ipv6 = True
                break
        return has_ipv6

    def _check_crud_port(self, scenario, network, subnet4, subnet6,
                         vsd_subnet, vsd_subnet_type):
        port_config = self.port_configs[scenario]

        params = {}
        allowed_address_pairs = port_config['allowed-address-pairs']
        if len(allowed_address_pairs) > 0:
            params.update({'allowed_address_pairs': allowed_address_pairs})
        if len(port_config['fixed-ips']) > 0:
            params.update({'fixed_ips': port_config['fixed-ips']})

        port = self.create_port(
            network,
            name=scenario,
            cleanup=False,
            **params)
        try:

            kwargs = {}
            expected_allowed_address_pairs = []
            for pair in allowed_address_pairs:
                if 'mac_address' not in pair:
                    expected_allowed_address_pairs.append(
                        {'ip_address': pair['ip_address'],
                         'mac_address': port['mac_address']})
                else:
                    expected_allowed_address_pairs.append(
                        {'ip_address': pair['ip_address'],
                         'mac_address': pair['mac_address']})

            self._verify_port(
                port, subnet4=subnet4, subnet6=subnet6,
                status='DOWN',
                allowed_address_pairs=expected_allowed_address_pairs,
                nuage_policy_groups=None,
                nuage_redirect_targets=[],
                nuage_floatingip=None,
                **kwargs)
            nuage_vports = self.nuage_vsd_client.get_vport(
                vsd_subnet_type, vsd_subnet['ID'],
                filters='externalID', filter_value=port['id'])
            self.assertEqual(
                len(nuage_vports), 1,
                'Must find one VPort matching port: %s' % port['name'])
            nuage_vport = nuage_vports[0]
            self.assertThat(nuage_vport,
                            ContainsDict({'name': Equals(port['id'])}))
            self.assertThat(nuage_vport,
                            ContainsDict({'multiNICVPortID': Equals(None)}))

            # Check the scenario
            if vsd_subnet_type == nuage_constants.L2_DOMAIN:
                attr = 'l2-disable-anti-spoofing'
            else:
                attr = 'l3-disable-anti-spoofing'

            if port_config[attr]:
                expected_address_spoofing = constants.ENABLED
            else:
                expected_address_spoofing = constants.INHERITED
            self.assertThat(nuage_vport,
                            ContainsDict({'addressSpoofing':
                                          Equals(expected_address_spoofing)}),
                            'Scenario %s expected %s.' % (
                                scenario, expected_address_spoofing))
            if (port_config['vip-created-on-vsd'] and
                    vsd_subnet_type == nuage_constants.SUBNETWORK):
                self._verify_vip(nuage_vport, port)
        finally:
            self.ports_client.delete_port(port['id'])

    def _verify_vip(self, nuage_vport, port):
        for aap in port['allowed_address_pairs']:
            ip_address = aap['ip_address']
            nuage_vip = self.nuage_vsd_client.get_virtual_ip(
                constants.VPORT,
                nuage_vport['ID'],
                filters='virtualIP',
                filter_value=str(ip_address))
            self._verify_port_allowed_address_fields(
                aap, nuage_vip[0]['virtualIP'], nuage_vip[0]['MAC'])

    def _verify_port_allowed_address_fields(self, aap,
                                            addrpair_ip, addrpair_mac):
        ip_address = aap['ip_address']
        mac_address = aap['mac_address']
        self.assertEqual(ip_address, addrpair_ip)
        self.assertEqual(mac_address, addrpair_mac)

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_provision_ports_without_address_pairs_in_l2_subnet_unmanaged(
            self):
        # Given I have a VSD-L2-Unmanaged subnet
        vsd_l2_subnet = self._given_vsd_l2domain(dhcp_managed=False)
        network, subnet4, subnet6 = self._given_network_linked_to_vsd_subnet(
            vsd_l2_subnet, cidr4=self.cidr4, cidr6=self.cidr6,
            enable_dhcp=False)

        for scenario, port_config in self.port_configs.iteritems():
            LOG.info("TESTCASE scenario {}".format(scenario))
            self._check_crud_port(scenario, network, subnet4, subnet6,
                                  vsd_l2_subnet, nuage_constants.L2_DOMAIN)

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_provision_ports_with_address_pairs_in_l3_subnet(self):
        # Given I have a VSD-L3-Managed subnet - dhcp-managed
        vsd_l3_domain, vsd_l3_subnet = self._given_vsd_l3subnet(
            cidr4=self.cidr4, cidr6=self.cidr6)
        network, subnet4, subnet6 = self._given_network_linked_to_vsd_subnet(
            vsd_l3_subnet, cidr4=self.cidr4, cidr6=self.cidr6)

        for scenario, port_config in self.port_configs.iteritems():
            LOG.info("TESTCASE scenario {}".format(scenario))
            self._check_crud_port(scenario, network, subnet4, subnet6,
                                  vsd_l3_subnet, nuage_constants.SUBNETWORK)
