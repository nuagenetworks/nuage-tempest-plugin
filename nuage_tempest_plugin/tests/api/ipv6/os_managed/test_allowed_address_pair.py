# Copyright 2014 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


from netaddr import IPAddress

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.tests.api.ipv6.base_nuage_networks \
    import NetworkTestCaseMixin

from tempest.api.network import test_allowed_address_pair as base_tempest
from tempest.common import utils

from tempest import config

from tempest.lib import decorators
from tempest.lib import exceptions as tempest_exceptions

from testtools.matchers import ContainsDict
from testtools.matchers import Equals


CONF = config.CONF
VALID_MAC_ADDRESS = 'fa:fa:3e:e8:e8:01'
MSG_INVALID_IP_ADDRESS_FOR_SUBNET = "IP address %s is not a valid IP for " \
                                    "the specified subnet."
MSG_INVALID_INPUT_FOR_AAP_IPS = "'%s' is not a valid IP address."


class AllowedAddressPairIpV6NuageTest(
    base_tempest.AllowedAddressPairTestJSON):
    _ip_version = 6

    @classmethod
    def resource_setup(cls):
        super(base_tempest.AllowedAddressPairTestJSON, cls).resource_setup()
        cls.network = cls.create_network()
        cls.subnet4 = cls.create_subnet(
            cls.network, ip_version=4, enable_dhcp=True)
        cls.subnet6 = cls.create_subnet(
            cls.network, ip_version=6, enable_dhcp=False)

        port = cls.create_port(cls.network)
        cls.ip_address = port['fixed_ips'][1]['ip_address']
        cls.mac_address = port['mac_address']


class AllowedAddressPairIpV6OSManagedTest(NuageBaseTest, NetworkTestCaseMixin):
    _ip_version = 6

    """Tests the Neutron Allowed Address Pair API extension

    The following API operations are tested with this extension:

        create port
        list ports
        update port
        show port

    v2.0 of the Neutron API is assumed. It is also assumed that the following
    options are defined in the [network-feature-enabled] section of
    etc/tempest.conf

        api_extensions
    """
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(AllowedAddressPairIpV6OSManagedTest, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()

    @classmethod
    def skip_checks(cls):
        super(AllowedAddressPairIpV6OSManagedTest, cls).skip_checks()
        if not utils.is_extension_enabled('allowed-address-pairs', 'network'):
            msg = "Allowed Address Pairs extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(AllowedAddressPairIpV6OSManagedTest, cls).resource_setup()

    def _verify_port_by_id(self, port_id):
        body = self.osc_list_ports()
        ports = body['ports']
        port = [p for p in ports if p['id'] == port_id]
        msg = 'Created port not found in list of ports returned by Neutron'
        self.assertTrue(port, msg)

    def _verify_l2_vport_by_id(self, port, expected_behaviour,
                               subnet4=None, subnet6=None):
        subnet = subnet6 if subnet4 is None else subnet4
        subnet_ext_id = self.nuage_vsd_client.get_vsd_external_id(subnet['id'])
        port_ext_id = self.nuage_vsd_client.get_vsd_external_id(port['id'])

        vsd_l2_domain = self.nuage_vsd_client.get_l2domain(
            filters='externalID',
            filter_value=subnet_ext_id)

        nuage_vports = self.nuage_vsd_client.get_vport(
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
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID',
            filter_value=self.nuage_vsd_client.get_vsd_external_id(
                router['id']))
        subnet_ext_id = (
            self.nuage_vsd_client.get_vsd_external_id(
                subnet['id'])
        )

        vsd_subnet = (
            self.nuage_vsd_client.get_domain_subnet(
                'domains', nuage_domain[0]['ID'], filters='externalID',
                filter_value=subnet_ext_id)
        )
        port_ext_id = self.nuage_vsd_client.get_vsd_external_id(port['id'])
        nuage_vports = self.nuage_vsd_client.get_vport(
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

    @decorators.attr(type='smoke')
    def test_create_port_with_aap_ipv6_moving_from_l2_to_l3_validation(self):
        network = self.create_network()
        # Create port with allowed address pair attribute
        subnet4 = self.create_subnet(
            network, ip_version=4, enable_dhcp=True)
        subnet6 = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        port_args = {'fixed_ips': [
            {'ip_address': str(IPAddress(self.cidr4.first) + 8)},
            {'ip_address': str(IPAddress(self.cidr6.first) + 8)}],
            'allowed_address_pairs': [
            {'ip_address': str(IPAddress(self.cidr6.first) + 10),
             'mac_address': VALID_MAC_ADDRESS}]}
        port = self.create_port(network, **port_args)

        # Confirm port was created with allowed address pair attribute
        self._verify_port(
            port, subnet4=subnet4, subnet6=subnet6)
        self._verify_l2_vport_by_id(port, constants.ENABLED,
                                    subnet4=subnet4)
        router = self.create_router()

        self.assertIsNotNone(router)

        vsd_l3_domain = self.vsd.get_l3domain(by_router_id=router['id'])
        self.assertIsNotNone(vsd_l3_domain)

        self.router_attach(router, subnet4, cleanup=False)

        self._verify_l3_vport_by_id(router, port, constants.INHERITED,
                                    subnet4=subnet4)

        self.router_detach(router, subnet4)
        self._verify_l2_vport_by_id(port, constants.ENABLED,
                                    subnet4=subnet4)

        self.router_attach(router, subnet4)
        self._verify_l3_vport_by_id(router, port, constants.INHERITED,
                                    subnet4=subnet4)
        self.assertRaisesRegex(
            tempest_exceptions.Conflict,
            "One or more ports have an IP allocation from this subnet.",
            self.delete_subnet,
            subnet4)

    @decorators.attr(type='smoke')
    def test_create_port_with_aap_ipv4_moving_from_l2_to_l3_validation(self):
        network = self.create_network()
        # Create port with allowed address pair attribute
        subnet4 = self.create_subnet(
            network, ip_version=4, enable_dhcp=True)

        subnet6 = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        router = self.create_router()
        self.assertIsNotNone(router)
        self.router_attach(router, subnet4)

        port_args = {'fixed_ips': [{'subnet_id': subnet4['id'],
                     'ip_address': str(IPAddress(self.cidr4.first) + 10)}],
                     'allowed_address_pairs':
                         [{'ip_address': str(IPAddress(self.cidr6.first) + 10),
                           'mac_address': VALID_MAC_ADDRESS}]}
        port = self.create_port(network, **port_args)

        msg = 'IPV6 IP %s is in use for nuage VIP, ' \
              'hence cannot delete the subnet' % \
              port['allowed_address_pairs'][0]['ip_address']
        self.assertRaisesRegex(tempest_exceptions.BadRequest,
                               msg,
                               self.delete_subnet,
                               subnet6)

    @decorators.attr(type='smoke')
    def test_create_port_with_invalid_address_formats_neg_l2_and_l3(self):
        # Provision OpenStack network
        network = self.create_network()
        # When I create an IPv4 subnet
        subnet4 = self.create_subnet(
            network, ip_version=4, enable_dhcp=True)
        self.assertIsNotNone(subnet4)
        # When I add an IPv6 subnet
        subnet6 = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)

        # noinspection PyPep8
        reserved_valid_ipv6 = [
            '::1',
            # Loopback
            'FE80::1',
            # Link local address
            'FF00:5f74:c4a5:b82e:ffff:ffff:ffff:ffff',
            # multicast
            'FF00::1',
            # multicast address
            '::',
            # empty string
            '2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
            # valid address, not in subnet
        ]
        invalid_ipv6 = [
            ('', MSG_INVALID_INPUT_FOR_AAP_IPS),
            # empty string
            ("2001:5f74:c4a5:b82e:ffff:ffff:ffff:ffff:ffff",
             MSG_INVALID_INPUT_FOR_AAP_IPS),
            # invalid address, too much segments
            ("2001:5f74:c4a5:b82e:ffff:ffff:ffff",
             MSG_INVALID_INPUT_FOR_AAP_IPS),
            # invalid address, seven segments
            ("2001;5f74.c4a5.b82e:ffff:ffff:ffff",
             MSG_INVALID_INPUT_FOR_AAP_IPS),
            # invalid address, wrong characters
            ("2001:5f74:c4a5:b82e:100.12.13.1",
             MSG_INVALID_INPUT_FOR_AAP_IPS),
            # invalid format: must have :: between hex and decimal part.
        ]
        # ### L2 #####
        for ipv6 in reserved_valid_ipv6:
            port_args = {'allowed_address_pairs': [
                {'ip_address': ipv6,
                 'mac_address': VALID_MAC_ADDRESS}]}
            port = self.create_port(network, **port_args)
            self._verify_port(
                port, subnet4=subnet4, subnet6=subnet6)
            self._verify_l2_vport_by_id(port, constants.ENABLED,
                                        subnet4=subnet4)
        for ipv6, msg in invalid_ipv6:
            port_args = {'allowed_address_pairs': [
                {'ip_address': ipv6,
                 'mac_address': VALID_MAC_ADDRESS}]}
            self.assertRaisesRegex(tempest_exceptions.BadRequest,
                                   msg % ipv6,
                                   self.create_port, network, **port_args)

    @decorators.attr(type='smoke')
    def test_fip2ipv6vip(self):
        # Base resources
        network = self.create_network()
        # Create port with allowed address pair attribute
        subnet4 = self.create_subnet(
            network, ip_version=4, enable_dhcp=True)
        subnet6 = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)

        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id,
            cleanup=True)
        self.assertIsNotNone(router, "Unable to create router")
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet4["id"])

        # Create VIP_port
        fixed_ips = [{'subnet_id': subnet6['id'],
                      'ip_address': str(IPAddress(self.cidr6.first) + 11)}]
        vip_port = self.create_port(network=network, device_owner="nuage:vip",
                                    fixed_ips=fixed_ips)
        self.assertIsNotNone(vip_port, "Unable to create vip port")

        # Create floating ip and attach to VIP_PORT
        floating_ip = self.create_floatingip()
        self.assertIsNotNone(floating_ip, "Unabe to create floating ip")
        msg = 'Cannot add floating IP to port %s that' \
              ' has no fixed IPv4 addresses.' % vip_port['id']
        self.assertRaisesRegex(tempest_exceptions.ClientRestClientException,
                               msg,
                               self.update_floatingip,
                               floatingip=floating_ip,
                               port_id=vip_port['id'])
