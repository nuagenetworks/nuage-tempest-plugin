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
from six import iteritems
import testtools

from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.tests.api.ipv6.test_allowed_address_pair \
    import BaseAllowedAddressPair

from tempest.api.network import test_allowed_address_pair as base_tempest
from tempest.lib import decorators
from tempest.lib import exceptions as tempest_exceptions

from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)

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


class AllowedAddressPairIpV6OSManagedTest(BaseAllowedAddressPair):
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

    @classmethod
    def skip_checks(cls):
        super(AllowedAddressPairIpV6OSManagedTest, cls).skip_checks()

    @classmethod
    def resource_setup(cls):
        super(AllowedAddressPairIpV6OSManagedTest, cls).resource_setup()

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

        self._verify_l3_vport_by_id(router, port, constants.DISABLED,
                                    subnet4=subnet4)

        self.router_detach(router, subnet4)
        self._verify_l2_vport_by_id(port, constants.ENABLED,
                                    subnet4=subnet4)

        self.router_attach(router, subnet4)
        self._verify_l3_vport_by_id(router, port, constants.DISABLED,
                                    subnet4=subnet4)
        self.assertRaisesRegex(
            tempest_exceptions.Conflict,
            "One or more ports have an IP allocation from this subnet.",
            self.delete_subnet,
            subnet4)

    @decorators.attr(type='smoke')
    def test_delete_v6_subnet_with_ip_as_vip_in_v4_subnet_neg(self):
        network = self.create_network()
        subnet4 = self.create_subnet(
            network, ip_version=4, enable_dhcp=True)
        subnet6 = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        router = self.create_router()

        self.create_router_interface(router['id'], subnet4['id'])

        port_args = {'fixed_ips': [{'subnet_id': subnet4['id'],
                     'ip_address': str(IPAddress(self.cidr4.first) + 10)}],
                     'allowed_address_pairs':
                         [{'ip_address': str(IPAddress(self.cidr6.first) + 10),
                           'mac_address': VALID_MAC_ADDRESS}]}
        port = self.create_port(network, **port_args)

        msg = ('IP {} is in use for nuage VIP, hence cannot delete the subnet'
               ).format(port['allowed_address_pairs'][0]['ip_address'])
        self.assertRaisesRegex(tempest_exceptions.BadRequest,
                               msg,
                               self.delete_subnet,
                               subnet6)

    def test_delete_v4_subnet_with_ip_as_vip_in_v6_subnet_neg(self):
        network = self.create_network()
        subnet4 = self.create_subnet(
            network, ip_version=4, enable_dhcp=True)
        subnet6 = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        router = self.create_router()

        self.create_router_interface(router['id'], subnet6['id'])

        port_args = {'fixed_ips': [{'subnet_id': subnet6['id'],
                                    'ip_address': str(
                                        IPAddress(self.cidr6.first) + 10)}],
                     'allowed_address_pairs':
                         [{'ip_address': str(IPAddress(self.cidr4.first) + 10),
                           'mac_address': VALID_MAC_ADDRESS}]}
        port = self.create_port(network, **port_args)

        msg = ('IP {} is in use for nuage VIP, hence cannot delete the subnet'
               ).format(port['allowed_address_pairs'][0]['ip_address'])
        self.assertRaisesRegex(tempest_exceptions.BadRequest,
                               msg,
                               self.delete_subnet,
                               subnet4)

    @decorators.attr(type='smoke')
    def test_create_port_with_invalid_address_formats_neg_l2_and_l3(self):
        network = self.create_network()
        subnet4 = self.create_subnet(
            network, ip_version=4, enable_dhcp=True)
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
    @testtools.skipUnless(Topology.up_to_openstack('train'),
                          'Upstream bug in Ussuri: '
                          'https://bugs.launchpad.net/neutron/+bug/1859163')
    def test_fip2ipv6vip(self):
        # Base resources
        network = self.create_network()
        subnet4 = self.create_subnet(
            network, ip_version=4, enable_dhcp=True)
        subnet6 = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)

        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet4["id"])

        # Create VIP_port
        port_args = {
            'allowed_address_pairs': [
                {'ip_address': str(IPAddress(self.cidr4.first) + 7)},
                {'ip_address': str(IPAddress(self.cidr6.first) + 7)}
            ],
            'fixed_ips': [
                {'subnet_id': subnet6['id'],
                 'ip_address': str(IPAddress(self.cidr6.first) + 11)}],
            'device_owner': "nuage:vip"}
        vip_port = self.create_port(network=network, **port_args)
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

    @decorators.attr(type='smoke')
    def test_provision_ports_without_address_pairs_in_l2_subnet_unmanaged(
            self):
        network = self.create_network()
        subnet4 = self.create_subnet(
            network, ip_version=4, enable_dhcp=True)
        subnet6 = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)

        vsd_l2_domain = self.vsd.get_l2domain(
            by_network_id=subnet4['network_id'], cidr=subnet4['cidr'])
        for scenario, port_config in iteritems(self.port_configs):
            LOG.info("TESTCASE scenario {}".format(scenario))
            self._check_crud_port(scenario, network, subnet4, subnet6,
                                  vsd_l2_domain, constants.L2_DOMAIN)

    @decorators.attr(type='smoke')
    def test_provision_ports_with_address_pairs_in_l3_subnet(self):
        network = self.create_network()
        subnet4 = self.create_subnet(
            network, ip_version=4, enable_dhcp=True)
        subnet6 = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        router = self.create_router()
        self.create_router_interface(router['id'], subnet4['id'])

        domain = self.vsd.get_domain(by_router_id=router['id'])
        zone = self.vsd.get_zone(domain=domain, by_router_id=router['id'])
        vsd_subnet = self.vsd.get_subnet(zone=zone,
                                         by_network_id=subnet4['network_id'],
                                         cidr=subnet4['cidr'])
        for scenario, port_config in iteritems(self.port_configs):
            LOG.info("TESTCASE scenario {}".format(scenario))
            self._check_crud_port(scenario, network, subnet4, subnet6,
                                  vsd_subnet, constants.SUBNETWORK)
