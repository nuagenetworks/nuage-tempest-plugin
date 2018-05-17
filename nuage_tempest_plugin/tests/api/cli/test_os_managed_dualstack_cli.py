# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPNetwork

from base_nuage_networks_cli import BaseNuageNetworksCliTestCase
from nuage_tempest_plugin.lib.features import NUAGE_FEATURES
from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

LOG = Topology.get_logger(__name__)

VALID_MAC_ADDRESS = 'fa:fa:3e:e8:e8:01'
VALID_MAC_ADDRESS_2A = 'fa:fa:3e:e8:e8:2a'
VALID_MAC_ADDRESS_2B = 'fa:fa:3e:e8:e8:2b'


class OSManagedDualStackCliTest(
        BaseNuageNetworksCliTestCase):

    @classmethod
    def skip_checks(cls):
        super(OSManagedDualStackCliTest, cls).skip_checks()
        if not NUAGE_FEATURES.os_managed_dualstack_subnets:
            raise cls.skipException(
                'OS Managed Dual Stack is not supported in this release')

    @classmethod
    def setup_clients(cls):
        super(OSManagedDualStackCliTest, cls).setup_clients()
        cls.nuage_network_client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_create_update_delete_dualstack(self):
        network_name = data_utils.rand_name('cli_network')
        network = self.create_network_with_args(network_name)
        self.networks.remove(network)

        subnet_name = data_utils.rand_name('cli-subnet')

        cidr4 = IPNetwork('1.1.20.0/24')
        cidr6 = IPNetwork("2001:5f74:c4a5:b82e::/64")

        subnet4 = self.create_subnet_with_args(
            network['name'], str(cidr4),
            "--name ", subnet_name + "-4")
        self.subnets.remove(subnet4)
        show_subnet4 = self.show_subnet(subnet4['id'])
        self.assertEqual(subnet4['id'],
                         show_subnet4['id'], "subnet not found")

        subnet6 = self.create_subnet_with_args(
            network['name'], str(cidr6),
            "--name ", subnet_name + "-6",
            "--ip-version 6",
            "--disable-dhcp ")
        self.subnets.remove(subnet6)
        show_subnet6 = self.show_subnet(subnet6['id'])
        self.assertEqual(subnet6['id'],
                         show_subnet6['id'], "subnet not found")

        # When I delete subnet 4
        self.delete_subnet(subnet4['id'])
        # Then the subnet 4 is no longer there
        self.assertCommandFailed("Unable to find subnet with name or id '{}'"
                                 .format(subnet4['id']),
                                 self.show_subnet,
                                 subnet4['id'])

        # When I delete subnet 6
        self.delete_subnet(subnet6['id'])
        # Then the subnet 6 is no longer there
        self.assertCommandFailed("Unable to find subnet with name or id '{}'"
                                 .format(subnet6['id']),
                                 self.show_subnet,
                                 subnet6['id'])

        # When I delete the network
        self.delete_network(network['id'])
        # Then the network is no longer there
        self.assertCommandFailed("Unable to find network with name or id '{}'"
                                 .format(network['id']),
                                 self.show_network,
                                 network['id'])

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_delete_network_deletes_all_subnets(self):
        network_name = data_utils.rand_name('cli_network')
        network = self.create_network_with_args(network_name)
        self.networks.remove(network)

        subnet_name = data_utils.rand_name('cli-subnet')

        cidr4 = IPNetwork('1.1.20.0/24')
        cidr6 = IPNetwork("2001:5f74:c4a5:b82e::/64")

        subnet4 = self.create_subnet_with_args(
            network['name'], str(cidr4),
            "--name ", subnet_name + "-4")
        self.subnets.remove(subnet4)
        show_subnet4 = self.show_subnet(subnet4['id'])
        self.assertEqual(subnet4['id'],
                         show_subnet4['id'], "subnet not found")

        subnet6 = self.create_subnet_with_args(
            network['name'], str(cidr6),
            "--name ", subnet_name + "-6",
            "--ip-version 6",
            "--disable-dhcp ")
        self.subnets.remove(subnet6)
        show_subnet6 = self.show_subnet(subnet6['id'])
        self.assertEqual(subnet6['id'],
                         show_subnet6['id'], "subnet not found")

        # When I delete the network
        self.delete_network(network['id'])
        # Then the network is no longer there
        self.assertCommandFailed("Unable to find network with name or id '{}'"
                                 .format(network['id']),
                                 self.show_network,
                                 network['id'])
        # And the subnet 4 is no longer there
        self.assertCommandFailed("Unable to find subnet with name or id '{}'"
                                 .format(subnet4['id']),
                                 self.show_subnet,
                                 subnet4['id'])
        # And the subnet 6 is no longer there
        self.assertCommandFailed("Unable to find subnet with name or id '{}'"
                                 .format(subnet6['id']),
                                 self.show_subnet,
                                 subnet6['id'])

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_dualstack_with_reserved_ipv6_address_neg(self):
        network_name = data_utils.rand_name('cli_network')
        network = self.create_network_with_args(network_name)
        self.addCleanup(self._delete_network, network['id'])
        self.networks.remove(network)

        subnet_name = data_utils.rand_name('cli-subnet')

        cidr4 = IPNetwork('1.1.20.0/24')
        cidr6 = IPNetwork("2002:5f74:c4a5:b82e::/64")

        subnet4 = self.create_subnet_with_args(
            network['name'], str(cidr4),
            "--name ", subnet_name + "-4")
        self.subnets.remove(subnet4)
        self.addCleanup(self._delete_subnet, subnet4['id'])
        show_subnet4 = self.show_subnet(subnet4['id'])
        self.assertEqual(subnet4['id'],
                         show_subnet4['id'], "subnet not found")

        self.assertCommandFailed("IP Address {} is not valid"
                                 " or cannot be in reserved address space."
                                 .format(str(cidr6)),
                                 self.create_subnet_with_args,
                                 network['name'], str(cidr6),
                                 "--name ", subnet_name + "-6",
                                 "--ip-version 6",
                                 "--disable-dhcp ")

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_dualstack_with_reserved_ipv6_address_and_ip4v_last_neg(self):
        network_name = data_utils.rand_name('cli_network')
        network = self.create_network_with_args(network_name)
        self.addCleanup(self._delete_network, network['id'])
        self.networks.remove(network)

        subnet_name = data_utils.rand_name('cli-subnet')

        cidr4 = IPNetwork('1.1.20.0/24')
        cidr6 = IPNetwork("2002:5f74:c4a5:b82e::/64")

        subnet6 = self.create_subnet_with_args(
            network['name'], str(cidr6),
            "--name ", subnet_name + "-6",
            "--ip-version 6",
            "--disable-dhcp ")
        self.subnets.remove(subnet6)
        show_subnet6 = self.show_subnet(subnet6['id'])
        self.assertEqual(subnet6['id'],
                         show_subnet6['id'], "subnet not found")

        self.assertCommandFailed("IP Address {} is not valid"
                                 " or cannot be in reserved address space."
                                 .format(str(cidr6)),
                                 self.create_subnet_with_args,
                                 network['name'],
                                 str(cidr4),
                                 "--name ", subnet_name)
