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

from tempest.api.network import test_allowed_address_pair as base_tempest
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as tempest_exceptions

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.tests.api.ipv6.test_allowed_address_pair \
    import BaseAllowedAddressPair

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)

VALID_MAC_ADDRESS = 'fa:fa:3e:e8:e8:01'
MSG_INVALID_IP_ADDRESS_FOR_SUBNET = "IP address %s is not a valid IP for " \
                                    "the specified subnet."
MSG_INVALID_INPUT_FOR_AAP_IPS = "'%s' is not a valid IP address."

SPOOFING_ENABLED = constants.ENABLED
SPOOFING_DISABLED = (constants.INHERITED if Topology.is_v5
                     else constants.DISABLED)


class AllowedAddressPairNuageTest(
        base_tempest.AllowedAddressPairTestJSON):
    """AllowedAddressPairNuageTest

    Inherited class from upstream AllowedAddressPairTestJSON
    This inheritance allows this class to run with the nuage_vsd_managed
    ipam driver, as this driver requires a nuage:vip port to be created
    before using an AAP.
    """
    # TODO(Team): Should this inherit from neutron_tempest_plugin instead?

    @classmethod
    def create_port(cls, network, **kwargs):
        if CONF.network.port_vnic_type and 'binding:vnic_type' not in kwargs:
            kwargs['binding:vnic_type'] = CONF.network.port_vnic_type
        if CONF.network.port_profile and 'binding:profile' not in kwargs:
            kwargs['binding:profile'] = CONF.network.port_profile
        return super(AllowedAddressPairNuageTest,
                     cls).create_port(network, **kwargs)

    @classmethod
    def resource_setup(cls):
        """resource_setup

        The AAP port is created during the resource setup to reserve an AAP ip
        We replace this AAP port with the same AAP port with a nuage:vip
        device owner
        """
        super(AllowedAddressPairNuageTest, cls).resource_setup()
        if CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed':
            port = cls.create_port(cls.network, device_owner='nuage:vip')
            cls.ip_address = port['fixed_ips'][0]['ip_address']
            cls.mac_address = port['mac_address']

    @decorators.idempotent_id('b3f20091-6cd5-472b-8487-3516137df933')
    def test_update_port_with_multiple_ip_mac_address_pair(self):
        """test_update_port_with_multiple_ip_mac_address_pair

        This test creates it's own AAP port, so has to be completely overridden
        The nuage_vsd_managed ipam case is a copy of the test to change the
        device_owner.
        """
        if CONF.nuage_sut.ipam_driver != 'nuage_vsd_managed':
            super(AllowedAddressPairNuageTest,
                  self).test_update_port_with_multiple_ip_mac_address_pair()
        else:
            # Create an ip_address and mac_address through port create
            resp = self.ports_client.create_port(
                network_id=self.network['id'],
                name='vip-port', device_owner='nuage:vip')
            newportid = resp['port']['id']
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.ports_client.delete_port, newportid)
            ipaddress = resp['port']['fixed_ips'][0]['ip_address']
            macaddress = resp['port']['mac_address']

            # Update allowed address pair port with multiple ip and  mac
            allowed_address_pairs = {'ip_address': ipaddress,
                                     'mac_address': macaddress}
            self._update_port_with_address(
                self.ip_address, self.mac_address,
                allowed_address_pairs=allowed_address_pairs)


class AllowedAddressPairIpV6NuageTest(AllowedAddressPairNuageTest):

    _ip_version = 6

    @classmethod
    def skip_checks(cls):
        super(AllowedAddressPairIpV6NuageTest, cls).skip_checks()
        if not Topology.has_single_stack_v6_support():
            raise cls.skipException('There is no single-stack v6 support '
                                    'in current release')


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

    @decorators.attr(type='smoke')
    def test_create_port_with_aap_ipv6_moving_from_l2_to_l3_validation(self):
        network = self.create_network()
        # Create port with allowed address pair attribute
        subnet4 = self.create_subnet(
            network, ip_version=4, enable_dhcp=True)
        subnet6 = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        if CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed':
            # If nuage_vsd_managed ipam is enabled, a nuage:vip port is needed
            port_args = {
                'fixed_ips': [
                    {'ip_address': str(IPAddress(self.cidr6.first) + 10)}],
                'device_owner': 'nuage:vip'
            }
            self.create_port(network, **port_args)

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
        self._verify_l2_vport_by_id(port, SPOOFING_ENABLED,
                                    subnet4=subnet4)
        router = self.create_router()

        self.assertIsNotNone(router)

        vsd_l3_domain = self.vsd.get_l3domain(by_router_id=router['id'])
        self.assertIsNotNone(vsd_l3_domain)

        self.router_attach(router, subnet4)

        self._verify_l3_vport_by_id(router, port, SPOOFING_DISABLED,
                                    subnet4=subnet4)

        self.router_detach(router, subnet4)
        self._verify_l2_vport_by_id(port, SPOOFING_ENABLED,
                                    subnet4=subnet4)

        self.router_attach(router, subnet4)
        self._verify_l3_vport_by_id(router, port, SPOOFING_DISABLED,
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

    @testtools.skipIf(not Topology.has_single_stack_v6_support(),
                      'There is no single-stack v6 support in current release')
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
            self._verify_l2_vport_by_id(port, SPOOFING_ENABLED,
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

        vsd_l2_domain = self.vsd.get_l2domain(by_subnet=subnet4)
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
                                         by_subnet=subnet4)
        for scenario, port_config in iteritems(self.port_configs):
            LOG.info("TESTCASE scenario {}".format(scenario))
            self._check_crud_port(scenario, network, subnet4, subnet6,
                                  vsd_subnet, constants.SUBNETWORK)
