# Copyright 2017 - Nokia
# All Rights Reserved.

from testtools.matchers import ContainsDict
from testtools.matchers import Equals

from netaddr import IPAddress

from tempest.common import utils

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

VALID_MAC_ADDRESS = 'fa:fa:3e:e8:e8:01'
VALID_MAC_ADDRESS_2A = 'fa:fa:3e:e8:e8:2a'
VALID_MAC_ADDRESS_2B = 'fa:fa:3e:e8:e8:2b'
IPv6_SUBNET_RANDOM = 'fee::'
MSG_INVALID_INPUT_FOR_AAP_IPS = "'%s' is not a valid IP address."

###############################################################################
###############################################################################
# MultiVIP . allowed address pairs
###############################################################################
###############################################################################

LOG = Topology.get_logger(__name__)


class BaseAllowedAddressPair(NuageBaseTest):
    @classmethod
    def skip_checks(cls):
        super(BaseAllowedAddressPair, cls).skip_checks()
        if not utils.is_extension_enabled('allowed-address-pairs', 'network'):
            msg = "Allowed Address Pairs extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(BaseAllowedAddressPair, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(BaseAllowedAddressPair, cls).resource_setup()

        cls.port_configs = {
            'case-no-aap-fixed-ip4-no-ip6': {  # no fixed-ips, no aap
                'fixed-ips': [],
                'allowed-address-pairs': [],
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
                    {'ip_address': str(next(cls.cidr4.subnet(24, 1)))},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 10)}],
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
                    {'ip_address': str(next(cls.cidr4.subnet(24, 1)))},
                    {'ip_address': str(next(cls.cidr6.subnet(64, 1)))}],
                'l2-disable-anti-spoofing': True,
                'l3-disable-anti-spoofing': True,
                'vip-created-on-vsd': False},
            'case-aap-ipv6-different-cidr': {
                'fixed-ips': [
                    {'ip_address': str(IPAddress(cls.cidr4.first) + 7)},
                    {'ip_address': str(IPAddress(cls.cidr6.first) + 7)},
                ],
                'allowed-address-pairs': [
                    {'ip_address': str(IPAddress(IPv6_SUBNET_RANDOM) + 10),
                     'mac_address': VALID_MAC_ADDRESS}],
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
            name=scenario, cleanup=False,
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
            nuage_vports = self.nuage_client.get_vport(
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
            if vsd_subnet_type == constants.L2_DOMAIN:
                attr = 'l2-disable-anti-spoofing'
            else:
                attr = 'l3-disable-anti-spoofing'

            if port_config[attr]:
                expected_address_spoofing = constants.ENABLED
            else:
                expected_address_spoofing = constants.INHERITED
            self.assertThat(
                nuage_vport,
                ContainsDict({'addressSpoofing': Equals(
                    expected_address_spoofing)}),
                'Scenario %s expected %s.' % (
                    scenario, expected_address_spoofing))
            if (port_config['vip-created-on-vsd'] and
                    vsd_subnet_type == constants.SUBNETWORK):
                self._verify_vip(nuage_vport, port)
        finally:
            self.ports_client.delete_port(port['id'])

    def _verify_vip(self, nuage_vport, port):
        for aap in port['allowed_address_pairs']:
            ip_address = aap['ip_address']
            nuage_vip = self.nuage_client.get_virtual_ip(
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

    def _verify_l2_vport_by_id(self, port, expected_behaviour,
                               subnet4=None, subnet6=None):
        subnet = subnet6 if subnet4 is None else subnet4
        subnet_ext_id = self.nuage_client.get_vsd_external_id(
            subnet['id'])
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])

        vsd_l2_domain = self.nuage_client.get_l2domain(
            filters='externalID',
            filter_value=subnet_ext_id)

        nuage_vports = self.nuage_client.get_vport(
            constants.L2_DOMAIN, vsd_l2_domain[0]['ID'],
            filters='externalID', filter_value=port_ext_id)
        self.assertEqual(
            len(nuage_vports), 1,
            'Must find one VPort matching port: %s' % port['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport, ContainsDict(
            {'addressSpoofing': Equals(expected_behaviour)}))

    def _verify_l3_vport_by_id(self, router, port, expected_behaviour,
                               subnet4=None, subnet6=None):
        subnet = subnet6 if subnet4 is None else subnet4
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID',
            filter_value=self.nuage_client.get_vsd_external_id(
                router['id']))
        subnet_ext_id = (
            self.nuage_client.get_vsd_external_id(
                subnet['id'])
        )

        vsd_subnet = (
            self.nuage_client.get_domain_subnet(
                'domains', nuage_domain[0]['ID'], filters='externalID',
                filter_value=subnet_ext_id)
        )
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vports = self.nuage_client.get_vport(
            constants.SUBNETWORK,
            vsd_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(
            len(nuage_vports), 1,
            'Must find one VPort matching port: %s' % port['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport, ContainsDict(
            {'addressSpoofing': Equals(expected_behaviour)}))
        self._verify_vip(nuage_vport, port)
