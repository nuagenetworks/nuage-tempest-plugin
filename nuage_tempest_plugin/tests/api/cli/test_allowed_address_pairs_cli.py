# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPAddress
from netaddr import IPNetwork

from .base_nuage_networks_cli import BaseNuageNetworksCliTestCase
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON
from nuage_tempest_plugin.tests.api.ipv6.vsd_managed.base_nuage_networks \
    import BaseVSDManagedNetworksIPv6Test
from tempest.lib.common.utils import data_utils

LOG = Topology.get_logger(__name__)

VALID_MAC_ADDRESS = 'fa:fa:3e:e8:e8:01'
VALID_MAC_ADDRESS_2A = 'fa:fa:3e:e8:e8:2a'
VALID_MAC_ADDRESS_2B = 'fa:fa:3e:e8:e8:2b'

SPOOFING_ENABLED = constants.ENABLED
SPOOFING_DISABLED = (constants.INHERITED if Topology.is_v5
                     else constants.DISABLED)


###############################################################################
# MultiVIP . allowed address pairs
###############################################################################
class OSManagedAllowedAddressPairsCliTest(
        BaseNuageNetworksCliTestCase, BaseVSDManagedNetworksIPv6Test):

    def _cli_create_os_managed_dualstack_subnet(self):
        network_name = data_utils.rand_name('cli_network')
        network = self.create_network_with_args(network_name)
        self.addCleanup(self._delete_network, network['id'])
        self.networks.remove(network)

        subnet_name = data_utils.rand_name('cli-subnet')

        cidr4 = IPNetwork('1.1.20.0/24')
        cidr6 = IPNetwork("2001:5f74:c4a5:b82e::/64")

        # net_partition = Topology.def_netpartition
        subnet4 = self.create_subnet_with_args(
            network['name'], str(cidr4),
            "--name ", subnet_name + "-4")
        self.addCleanup(self._delete_subnet, subnet4['id'])
        self.subnets.remove(subnet4)

        subnet6 = self.create_subnet_with_args(
            network['name'], str(cidr6),
            "--name ", subnet_name + "-6",
            "--ip-version 6",
            "--disable-dhcp ")
        self.addCleanup(self._delete_subnet, subnet6['id'])
        self.subnets.remove(subnet6)

        return network, subnet4, subnet6

    @classmethod
    def setup_clients(cls):
        super(OSManagedAllowedAddressPairsCliTest, cls).setup_clients()
        cls.nuage_network_client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)

    def test_cli_create_address_pair_l2domain_no_mac(self):
        # Given I have a dual stack network
        cli_network, cli_subnet4, cli_subnet6 = \
            self._cli_create_os_managed_dualstack_subnet()

        # When I create a port in this VSD-L2-Managed-Subnet with
        # - fixed-IP address
        # - allowed-address-pair with
        #     IP@ = fixed-IP+5
        #     no MAC address
        port_fixed_ip = str(IPAddress(
            IPNetwork(cli_subnet4['cidr']).first + 10))
        aap_fixed_ip = str(IPAddress(port_fixed_ip) + 5)

        addr_pair_port = self.create_port_with_args(
            cli_network['name'],
            "--name aap-port-1",
            " --fixed-ip ip_address=" + str(port_fixed_ip),
            "--allowed_address-pairs type=dict list=true ip_address=" +
            aap_fixed_ip)
        self.addCleanup(self._delete_port, addr_pair_port['id'])
        self.ports.remove(addr_pair_port)

        port_fixed_ip4 = str(IPAddress(
            IPNetwork(cli_subnet4['cidr']).first + 20))
        aap_fixed_ip4 = str(IPAddress(port_fixed_ip) + 25)

        port_fixed_ip6 = str(IPAddress(
            IPNetwork(cli_subnet6['cidr']).first + 20))
        aap_fixed_ip6 = str(IPAddress(port_fixed_ip6) + 5)
        addr_pair_port_dual = self.create_port_with_args(
            cli_network['name'],
            "--name aap-port6-1",
            " --fixed-ip ip_address=" + str(port_fixed_ip4),
            " --fixed-ip ip_address=" + str(port_fixed_ip6),
            "--allowed_address-pairs type=dict list=true ip_address=" +
            aap_fixed_ip4 + " ip_address=" + aap_fixed_ip6)
        self.addCleanup(self._delete_port, addr_pair_port_dual['id'])
        self.ports.remove(addr_pair_port_dual)

        # Then I expect the allowed-address-pair the port-show response
        # And the allowed-address-pair MAC address == port MAC address
        show_port = self.show_port(addr_pair_port['id'])
        self.cli_check_show_port_allowed_address_fields(
            show_port,
            aap_fixed_ip,
            addr_pair_port['mac_address'])
        # And no corresponding MultiVIP on the VSD
        vsd_l2_domain = self.nuage_client.get_l2domain(
            by_subnet=cli_subnet4)
        vsd_l2_domain = vsd_l2_domain[0]

        port_ext_id = self.nuage_client.get_vsd_external_id(
            addr_pair_port['id'])
        nuage_vport = self.nuage_client.get_vport(
            constants.L2_DOMAIN,
            vsd_l2_domain['ID'],
            filters='externalID',
            filter_values=port_ext_id)

        self.assertIsNone(nuage_vport[0]['multiNICVPortID'],
                          "multiNICVPortID is not empty while it should be")

        # idem for IPv6
        show_port_dual = self.show_port(addr_pair_port_dual['id'])
        self.cli_check_show_port_allowed_address_fields(
            show_port_dual,
            aap_fixed_ip4,
            addr_pair_port_dual['mac_address'])
        self.cli_check_show_port_allowed_address_fields(
            show_port_dual,
            aap_fixed_ip6,
            addr_pair_port_dual['mac_address'])
        # And no corresponding MultiVIP on the VSD
        port_ext_id6 = self.nuage_client.get_vsd_external_id(
            addr_pair_port_dual['id'])
        nuage_vport_dual = self.nuage_client.get_vport(
            constants.L2_DOMAIN,
            vsd_l2_domain['ID'],
            filters='externalID',
            filter_values=port_ext_id6)

        self.assertIsNone(nuage_vport_dual[0]['multiNICVPortID'],
                          "multiNICVPortID is not empty while it should be")

        # And anti-address spoofing is disabled on vport in VSD
        self.assertEqual(SPOOFING_ENABLED,
                         nuage_vport_dual[0]['addressSpoofing'])
        # When I delete the allowed address  pair from the port
        self.cli_remove_port_allowed_address_pairs(addr_pair_port['id'])

        # I expect it ot be gone fro the show port response
        show_port = self.show_port(addr_pair_port['id'])
        self.assertEmpty(show_port['allowed_address_pairs'],
                         "Removed allowed-address-pair still present "
                         "in port (%s)" % addr_pair_port['id'])

        # When I delete the allowed address  pair from the port
        self.cli_remove_port_allowed_address_pairs(addr_pair_port_dual['id'])

        # I expect it ot be gone fro the show port response
        show_port = self.show_port(addr_pair_port_dual['id'])
        self.assertEmpty(show_port['allowed_address_pairs'],
                         "Removed allowed-address-pair still present "
                         "in port (%s)" % addr_pair_port_dual['id'])
