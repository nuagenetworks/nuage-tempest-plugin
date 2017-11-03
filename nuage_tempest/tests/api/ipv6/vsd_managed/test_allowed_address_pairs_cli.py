# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPAddress
from netaddr import IPNetwork

from oslo_log import log as logging
from tempest import config

from nuage_tempest.lib.test import nuage_test
from nuage_tempest.lib.utils import constants

from nuage_tempest.services.nuage_network_client import NuageNetworkClientJSON
from nuage_tempest.tests.api.ipv6.base_nuage_networks \
    import VsdTestCaseMixin
from nuage_tempest.tests.api.ipv6.base_nuage_networks_cli \
    import BaseNuageNetworksCLITestCase

CONF = config.CONF
LOG = logging.getLogger(__name__)

VALID_MAC_ADDRESS = 'fa:fa:3e:e8:e8:01'
VALID_MAC_ADDRESS_2A = 'fa:fa:3e:e8:e8:2a'
VALID_MAC_ADDRESS_2B = 'fa:fa:3e:e8:e8:2b'

###############################################################################
###############################################################################
# MultiVIP . allowed address pairs
###############################################################################
###############################################################################


class VSDManagedAllowedAddresPairsCLITest(
        BaseNuageNetworksCLITestCase, VsdTestCaseMixin):

    @classmethod
    def setup_clients(cls):
        super(VSDManagedAllowedAddresPairsCLITest, cls).setup_clients()
        cls.nuage_network_client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os_primary.default_params)

    @nuage_test.header()
    def test_cli_create_address_pair_l2domain_no_mac(self):
        # Given I have a VSD-L2-Managed subnet
        # vsd_l2_subnet, l2_domtmpl = self._create_vsd_l2_managed_subnet()
        # cli_network, cli_subnet = \
        #     self._cli_create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        cidr4 = IPNetwork('1.1.20.0/24')
        cidr6 = IPNetwork("2001:5f74:c4a5:b82e::/64")
        # vsd_l2_subnet = self._given_vsd_l2domain(cidr4=cidr4, cidr6=cidr6 )
        # cli_network, cli_subnet4, cli_subnet6 = \
        #     self._cli_create_os_l2_vsd_managed_dualstack_subnet(
        #         vsd_l2_subnet)
        vsd_l2_subnet = self._given_vsd_l2domain()
        cli_network, cli_subnet4, cli_subnet6 = \
            self._cli_create_os_l2_vsd_unmanaged_dualstack_subnet(
                vsd_l2_subnet, cidr4=cidr4, cidr6=cidr6)

        # When I create a port in this VSD-L2-Managed-Subnet with
        # - fixed-IP address
        # - allowed-address-pair with
        #     IP@ = fixed-IP+5
        #     no MAC address
        port_fixed_ip = str(IPAddress(
            IPNetwork(cli_subnet4['cidr']).first + 10))
        aap_fixed_ip = str(IPAddress(port_fixed_ip) + 5)

        addrpair_port = self.create_port_with_args(
            cli_network['name'],
            "--name aap-port-1",
            " --fixed-ip ip_address=" + str(port_fixed_ip),
            "--allowed_address-pairs type=dict list=true ip_address=" +
            aap_fixed_ip)
        self.addCleanup(self._delete_port, addrpair_port['id'])
        self.ports.remove(addrpair_port)

        port_fixed_ip4 = str(IPAddress(
            IPNetwork(cli_subnet4['cidr']).first + 20))
        aap_fixed_ip4 = str(IPAddress(port_fixed_ip) + 25)

        port_fixed_ip6 = str(IPAddress(
            IPNetwork(cli_subnet6['cidr']).first + 20))
        aap_fixed_ip6 = str(IPAddress(port_fixed_ip6) + 5)
        addrpair_port_dual = self.create_port_with_args(
            cli_network['name'],
            "--name aap-port6-1",
            " --fixed-ip ip_address=" + str(port_fixed_ip4),
            " --fixed-ip ip_address=" + str(port_fixed_ip6),
            "--allowed_address-pairs type=dict list=true ip_address=" +
            aap_fixed_ip4 + " ip_address=" + aap_fixed_ip6)
        self.addCleanup(self._delete_port, addrpair_port_dual['id'])
        self.ports.remove(addrpair_port_dual)

        # Then I expect the allowed-address-pair the port-show response
        # And the allowed-address-pair MACaddress == port MACaddress
        show_port = self.show_port(addrpair_port['id'])
        self.cli_check_show_port_allowed_address_fields(
            show_port,
            aap_fixed_ip,
            addrpair_port['mac_address'])
        # And no corresponding MultiVIP on the VSD
        port_ext_id = self.nuage_vsd_client.get_vsd_external_id(
            addrpair_port['id'])
        nuage_vport = self.nuage_vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_l2_subnet['ID'],
            filters='externalID',
            filter_value=port_ext_id)

        self.assertIsNone(nuage_vport[0]['multiNICVPortID'],
                          "multiNICVPortID is not empty while it should be")

        # idem for IPv6
        show_port_dual = self.show_port(addrpair_port_dual['id'])
        self.cli_check_show_port_allowed_address_fields(
            show_port_dual,
            aap_fixed_ip4,
            addrpair_port_dual['mac_address'])
        self.cli_check_show_port_allowed_address_fields(
            show_port_dual,
            aap_fixed_ip6,
            addrpair_port_dual['mac_address'])
        # And no corresponding MultiVIP on the VSD
        port_ext_id6 = self.nuage_vsd_client.get_vsd_external_id(
            addrpair_port_dual['id'])
        nuage_vport_dual = self.nuage_vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_l2_subnet['ID'],
            filters='externalID',
            filter_value=port_ext_id6)

        self.assertIsNone(nuage_vport_dual[0]['multiNICVPortID'],
                          "multiNICVPortID is not empty while it should be")

        # And anti-address spoofing is disabled on vport in VSD
        self.assertEqual(constants.ENABLED,
                         nuage_vport_dual[0]['addressSpoofing'])
        # When I delete the allowed address  pair from the port
        self.cli_remove_port_allowed_address_pairs(addrpair_port['id'])

        # I expect it ot be gone fro the show port response
        show_port = self.show_port(addrpair_port['id'])
        self.assertEmpty(show_port['allowed_address_pairs'],
                         "Removed allowed-address-pair still present "
                         "in port (%s)" % addrpair_port['id'])

        # When I delete the allowed address  pair from the port
        self.cli_remove_port_allowed_address_pairs(addrpair_port_dual['id'])

        # I expect it ot be gone fro the show port response
        show_port = self.show_port(addrpair_port_dual['id'])
        self.assertEmpty(show_port['allowed_address_pairs'],
                         "Removed allowed-address-pair still present "
                         "in port (%s)" % addrpair_port_dual['id'])
        pass

    @nuage_test.header()
    def test_cli_create_address_pair_l2domain_with_mac(self):
        # Given I have a VSD-L2-Managed subnet
        cidr4 = IPNetwork('1.1.20.0/24')
        cidr6 = IPNetwork("2001:5f74:c4a5:b82e::/64")
        vsd_l2_subnet = self._given_vsd_l2domain(
            cidr4=cidr4, cidr6=cidr6, dhcp_managed=True)
        cli_network, cli_subnet4, cli_subnet6 = \
            self._cli_create_os_l2_vsd_managed_dualstack_subnet(vsd_l2_subnet)

        # When I create a port in this VSD-L2-Managed-Subnet with
        # - fixed-IP address
        # - allowed-address-pair with
        #     IP@ = fixed-IP+5
        #     valid MAC address (<> port MAC address)
        port_fixed_ip = str(IPAddress(vsd_l2_subnet['address']) + 10)
        aap_fixed_ip = str(IPAddress(port_fixed_ip) + 5)

        addrpair_port = self.create_port_with_args(
            cli_network['name'],
            "--name aap-port-1",
            " --fixed-ip ip_address=" + str(port_fixed_ip),
            "--allowed_address-pairs type=dict list=true ip_address=" +
            aap_fixed_ip +
            ",mac_address=" + VALID_MAC_ADDRESS)
        self.addCleanup(self._delete_port, addrpair_port['id'])
        self.ports.remove(addrpair_port)

        # dual stack port
        port_fixed_ip4 = str(IPAddress(vsd_l2_subnet['address']) + 20)
        aap_fixed_ip4 = str(IPAddress(port_fixed_ip) + 25)
        port_fixed_ip6 = str(IPAddress(
            IPNetwork(vsd_l2_subnet['IPv6Address'])) + 10)
        aap_fixed_ip6 = str(IPAddress(port_fixed_ip6) + 5)
        addrpair_port_dual = self.create_port_with_args(
            cli_network['name'],
            "--name aap-port6-1",
            " --fixed-ip ip_address=" + str(port_fixed_ip4),
            " --fixed-ip ip_address=" + str(port_fixed_ip6),
            "--allowed_address-pairs type=dict list=true" +
            " ip_address=" + aap_fixed_ip4 + ",mac_address=" +
            VALID_MAC_ADDRESS_2A +
            " ip_address=" + aap_fixed_ip6 + ",mac_address=" +
            VALID_MAC_ADDRESS_2B)
        self.addCleanup(self._delete_port, addrpair_port_dual['id'])
        self.ports.remove(addrpair_port_dual)

        # Then I expect the allowed-address-pair the port-show response
        # And the allowed-address-pair MACaddress == port MACaddress
        show_port = self.show_port(addrpair_port['id'])
        self.cli_check_show_port_allowed_address_fields(
            show_port, aap_fixed_ip, VALID_MAC_ADDRESS)

        # And no corresponding MultiVIP on the VSD
        port_ext_id = self.nuage_vsd_client.get_vsd_external_id(
            addrpair_port['id'])
        nuage_vport = self.nuage_vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_l2_subnet['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertIsNone(nuage_vport[0]['multiNICVPortID'],
                          "multiNICVPortID is not empty while it should be")
        # And address address spoofing is disabled on vport in VSD
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])

        # idem for IPv6
        show_port_dual = self.show_port(addrpair_port_dual['id'])
        self.cli_check_show_port_allowed_address_fields(
            show_port_dual,
            aap_fixed_ip4,
            VALID_MAC_ADDRESS_2A)
        self.cli_check_show_port_allowed_address_fields(
            show_port_dual,
            aap_fixed_ip6,
            VALID_MAC_ADDRESS_2B)

        # And no corresponding MultiVIP on the VSD
        port_ext_id6 = self.nuage_vsd_client.get_vsd_external_id(
            addrpair_port_dual['id'])
        nuage_vport_dual = self.nuage_vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_l2_subnet['ID'],
            filters='externalID',
            filter_value=port_ext_id6)
        self.assertIsNone(nuage_vport_dual[0]['multiNICVPortID'],
                          "multiNICVPortID is not empty while it should be")

        # When I delete the allowed address pair from the port
        self.cli_remove_port_allowed_address_pairs(addrpair_port['id'])

        # # I expect it ot be gone fro the show port response
        show_port = self.show_port(addrpair_port['id'])
        self.assertEmpty(show_port['allowed_address_pairs'],
                         "Removed allowed-address-pair stil present "
                         "in port (%s)" % addrpair_port['id'])

        # When I delete the allowed address  pair from the port
        self.cli_remove_port_allowed_address_pairs(addrpair_port_dual['id'])

        # I expect it ot be gone fro the show port response
        show_port = self.show_port(addrpair_port_dual['id'])
        self.assertEmpty(show_port['allowed_address_pairs'],
                         "Removed allowed-address-pair still present "
                         "in port (%s)" % addrpair_port_dual['id'])
        pass

    @nuage_test.header()
    def test_cli_create_address_pair_l3_subnet_no_mac(self):
        # Given I have a VSD-L3-Managed subnet
        cidr4 = IPNetwork('1.1.20.0/24')
        cidr6 = IPNetwork("2001:5f74:1111:b82e::/64")
        vsd_l3_domain, vsd_l3_subnet = self._given_vsd_l3subnet(
            cidr4=cidr4, cidr6=cidr6)
        cli_network, cli_subnet4, cli_subnet6 = \
            self._cli_create_os_l2_vsd_managed_dualstack_subnet(vsd_l3_subnet)

        # When I create a port in this VSD-L3-Managed-Subnet with
        # - fixed-IP address
        # - allowed-address-pair with
        #     IP@ = fixed-IP+5
        #     no MAC address
        port_fixed_ip = str(IPAddress(vsd_l3_subnet['address']) + 10)
        # port_fixed_ip = str(IPAddress(
        #     base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW) + 10)
        aap_fixed_ip = str(IPAddress(port_fixed_ip) + 5)
        addrpair_port = self.create_port_with_args(
            cli_network['name'],
            "--name aap-port-1",
            " --fixed-ip ip_address=" + str(port_fixed_ip),
            "--allowed_address-pairs type=dict list=true ip_address=" +
            aap_fixed_ip)
        self.addCleanup(self._delete_port, addrpair_port['id'])
        self.ports.remove(addrpair_port)

        # Then I expect the allowed-address-pair the port-show response
        # And the allowed-address-pair MACaddress == port MACaddress
        show_port = self.show_port(addrpair_port['id'])
        self.cli_check_show_port_allowed_address_fields(
            show_port, aap_fixed_ip, addrpair_port['mac_address'])
        # And no corresponding MultiVIP on the VSD
        port_ext_id = self.nuage_vsd_client.get_vsd_external_id(
            addrpair_port['id'])
        nuage_vport = self.nuage_vsd_client.get_vport(
            constants.SUBNETWORK, vsd_l3_subnet['ID'],
            filters='externalID', filter_value=port_ext_id)
        self.assertIsNone(nuage_vport[0]['multiNICVPortID'],
                          "multiNICVPortID is not empty while it should be")

        # # And address address spoofing is disabled on vport in VSD
        # self.assertEqual(constants.ENABLED,
        #                  nuage_vport[0]['addressSpoofing'])
        # When I delete the allowed address  pair from the port
        # ToDo: check removal when bug 1351979 is solved in Mitaka
        # self._remove_allowed_addres_pair_from_port(addrpair_port)
        # # I expect it ot be gone fro the show port response
        # show_port = self.ports_client.show_port(addrpair_port['id'])
        # self.assertEmpty(show_port['port']['allowed_address_pairs'],
        #                  "Removed allowed-address-pair stil present " \
        #                  "in port (%s)" % addrpair_port['id'])
        pass
    #
    # @nuage_test.header()
    # def test_cli_create_address_pair_l3domain_with_mac(self):
    #     # Given I have a VSD-L2-Managed subnet
    #     vsd_l3_subnet, l3_domain = self._create_vsd_l3_managed_subnet()
    #     cli_network, cli_subnet = self._cli_create_os_l3_vsd_managed_subnet(
    #          vsd_l3_subnet)
    #     # When I create a port in this VSD-L3-Managed-Subnet with
    #     # - fixed-IP address
    #     # - allowed-address-pair with
    #     #     IP@ = fixed-IP+5
    #     #     valid MAC address (<> port MAC address)
    #     port_fixed_ip = str(IPAddress(
    #          base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW) + 100)
    #     aap_fixed_ip = str(IPAddress(port_fixed_ip) + 5)
    #     addrpair_port = self.create_port_with_args(
    #         cli_network['name'],
    #         "--name aap-port-1",
    #         " --fixed-ip ip_address="+str(port_fixed_ip),
    #         "--allowed_address-pairs type=dict list=true ip_address=" +
    #         aap_fixed_ip +
    #         ",mac_address=" + VALID_MAC_ADDRESS)
    #     # Then I expect the allowed-address-pair the port-show response
    #     # And the allowed-address-pair MACaddress == port MACaddress
    #     show_port = self.show_port(addrpair_port['id'])
    #     self.cli_check_show_port_allowed_address_fields(
    #         show_port, aap_fixed_ip, VALID_MAC_ADDRESS)
    #     # And no corresponding MultiVIP on the VSD
    #     port_ext_id = self.nuage_vsd_client.get_vsd_external_id(
    #         addrpair_port['id'])
    #     nuage_vport = self.nuage_vsd_client.get_vport(
    #         constants.SUBNETWORK,
    #         vsd_l3_subnet[0]['ID'],
    #         filters='externalID',
    #         filter_value=port_ext_id)
    #     self.assertIsNone(nuage_vport[0]['multiNICVPortID'],
    #                       "multiNICVPortID is not empty while it should be")
    #     # And address address spoofing is disabled on vport in VSD
    #     self.assertEqual(constants.INHERITED,
    #                      nuage_vport[0]['addressSpoofing'])
    #     # When I delete the allowed address  pair from the port
    #     # ToDo: check removal when bug 1351979 is solved in Mitaka
    #     # self._remove_allowed_addres_pair_from_port(addrpair_port)
    #     # # I expect it ot be gone fro the show port response
    #     # show_port = self.show_port(addrpair_port['id'])
    #     # self.assertEmpty(show_port['port']['allowed_address_pairs'],
    #     #                  "Removed allowed-address-pair stil present "
    #                        "in port (%s)" % addrpair_port['id'])
    #     pass
    #
    #

    @classmethod
    def resource_setup(cls):
        super(VSDManagedAllowedAddresPairsCLITest, cls).resource_setup()

        cls.cidr4 = IPNetwork('1.1.20.0/24')
        cls.cidr6 = IPNetwork("2001:5f74:1111:b82e::/64")

        cls.port_configs = \
            {'case-1': {'fixedips': [],
                        'allowed-address-pairs': []},
             'case-2': {
                'fixedips':
                    [{'fixedip': None, 'aap': None, 'mac': None}],
                'allowed-address-pairs':
                    [{'ip_address': None, 'mac': None}]}}

    def _check_crud_port(self, scenario, network, subnet4, subnet6):
        port = self.create_port_with_args(
            network['name'],
            "--name " + scenario)
        self.addCleanup(self._delete_port, port['id'])
        self.ports.remove(port)

        # self._verify_port(port, subnet4=subnet4, subnet6=subnet6,
        #                   status='DOWN',
        #                   allowed_address_pairs='[]')

    @nuage_test.header()
    def test_cli_create_address_pair_l3_subnet(self):
        # Given I have a VSD-L3-Managed subnet
        vsd_l3_domain, vsd_l3_subnet = self._given_vsd_l3subnet(
            cidr4=self.cidr4, cidr6=self.cidr6)
        cli_network, cli_subnet4, cli_subnet6 = \
            self._cli_create_os_l2_vsd_managed_dualstack_subnet(vsd_l3_subnet)

        # When I create a port in this VSD-L3-Managed-Subnet with
        # - fixed-IP address
        # - allowed-address-pair with
        #     IP@ = fixed-IP+5
        #     no MAC address

        self._check_crud_port("case-1", cli_network, cli_subnet4, cli_subnet6)
