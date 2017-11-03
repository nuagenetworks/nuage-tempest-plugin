# Copyright 2017 - Nokia
# All Rights Reserved.

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

import testtools
from testtools.matchers import ContainsDict
from testtools.matchers import Equals

from nuage_tempest.lib.features import NUAGE_FEATURES
from nuage_tempest.lib.test import nuage_test
from nuage_tempest.lib.test import tags

from nuage_tempest.tests.api.ipv6.base_nuage_networks \
    import NetworkTestCaseMixin
from nuage_tempest.tests.api.ipv6.base_nuage_networks \
    import VsdTestCaseMixin

CONF = config.CONF


@nuage_test.class_header(tags=[tags.ML2])
class DualStackNetworksTest(NetworkTestCaseMixin, VsdTestCaseMixin):

    @staticmethod
    def mask_to_prefix(mask):
        return sum([bin(int(x)).count('1') for x in mask.split('.')])

    ###########################################################################
    #
    # Negative cases in case IPV6 is NOT SUPPORTED (!)
    #
    # THESE TESTS SHD EVENTUALLY DISAPPEAR - ONLY USE IS 4.0 PLUGIN TESTS !
    #
    ###########################################################################
    @decorators.attr(type='smoke')
    @testtools.skipIf(NUAGE_FEATURES.os_managed_dualstack_subnets,
                      'OS Managed Dual Stack ALREADY supported in the release')
    @nuage_test.header()
    def test_os_managed_dual_stack_subnet_neg(self):
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        # create Openstack IPv4 subnet
        ipv4_subnet = self.create_subnet(
            network,
            cidr=self.cidr4,
            mask_bits=self.mask_bits4)

        self.assertThat(ipv4_subnet,
                        ContainsDict({'vsd_managed': Equals(False)}))

        # create Openstack IPv6 subnet
        self.assertRaisesRegex(
            exceptions.BadRequest,
            "Subnet with ip_version 6 is currently not supported for "
            "OpenStack managed subnets.",
            self.create_subnet,
            network,
            ip_version=6,
            cidr=self.cidr6,
            mask_bits=self.mask_bits6,
            enable_dhcp=False)

    @decorators.attr(type='smoke')
    @testtools.skipIf(NUAGE_FEATURES.os_managed_dualstack_subnets,
                      'OS Managed Dual Stack ALREADY supported in the release')
    @nuage_test.header()
    def test_os_managed_ipv6_subnet_neg(self):
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        # create Openstack IPv6 subnet
        self.assertRaisesRegex(
            exceptions.BadRequest,
            "Subnet with ip_version 6 is currently not supported for "
            "OpenStack managed subnets.",
            self.create_subnet,
            network,
            ip_version=6,
            cidr=self.cidr6,
            mask_bits=self.mask_bits6,
            enable_dhcp=False)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    @testtools.skipIf(NUAGE_FEATURES.os_managed_dualstack_subnets,
                      'OS Managed Dual Stack ALREADY supported in the release')
    def test_os_managed_dual_stack_subnet_with_net_partition_neg(self):
        # create Openstack IPv4 subnet on Openstack based on VSD l2domain
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        self.create_subnet(
            network,
            cidr=self.cidr4,
            mask_bits=self.mask_bits4)

        # create Openstack IPv6 subnet
        # In serverlog: "NuageBadRequest: Bad request: nuagenet is
        # required in subnet"
        self.assertRaisesRegex(
            exceptions.BadRequest,
            "Subnet with ip_version 6 is currently not supported for "
            "OpenStack managed subnets.",
            self.create_subnet,
            network,
            ip_version=6,
            cidr=self.cidr6,
            mask_bits=self.mask_bits6,
            enable_dhcp=False,
            net_partition=self.net_partition)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    @testtools.skipIf(NUAGE_FEATURES.os_managed_dualstack_subnets,
                      'OS Managed Dual Stack ALREADY supported in the release')
    def test_os_managed_ipv6_subnet_with_net_partition_neg(self):
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        # create Openstack IPv6 subnet
        self.assertRaisesRegex(
            exceptions.BadRequest,
            "Subnet with ip_version 6 is currently not supported for "
            "OpenStack managed subnets.",
            self.create_subnet,
            network,
            ip_version=6,
            cidr=self.cidr6,
            mask_bits=self.mask_bits6,
            enable_dhcp=False,
            net_partition=self.net_partition)
