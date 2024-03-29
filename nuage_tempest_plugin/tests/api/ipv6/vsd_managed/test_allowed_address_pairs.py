# Copyright 2017 - Nokia
# All Rights Reserved.

from six import iteritems
import testtools

from tempest.test import decorators

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as nuage_constants
from nuage_tempest_plugin.tests.api.ipv6.test_allowed_address_pair \
    import BaseAllowedAddressPair
from nuage_tempest_plugin.tests.api.ipv6.vsd_managed.base_nuage_networks \
    import BaseVSDManagedNetworksIPv6Test

CONF = Topology.get_conf()

###############################################################################
###############################################################################
# MultiVIP . allowed address pairs
###############################################################################
###############################################################################

LOG = Topology.get_logger(__name__)


class VSDManagedAllowedAddressPairsTest(BaseAllowedAddressPair,
                                        BaseVSDManagedNetworksIPv6Test):

    @testtools.skipIf(CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed',
                      'Unmanaged domains not supported with nuage_vsd_managed '
                      'ipam.')
    def test_provision_ports_without_address_pairs_in_l2_subnet_vsd_unmanaged(
            self):
        vsd_l2_subnet = self._given_vsd_l2domain(dhcp_managed=False)
        network, subnet4, subnet6 = self._given_network_linked_to_vsd_subnet(
            vsd_l2_subnet, cidr4=self.cidr4, cidr6=self.cidr6,
            enable_dhcp=False)
        for scenario, port_config in iteritems(self.port_configs):
            LOG.info("TESTCASE scenario {}".format(scenario))
            self._check_crud_port(scenario, network, subnet4, subnet6,
                                  vsd_l2_subnet, nuage_constants.L2_DOMAIN)

    @decorators.attr(type='smoke')
    def test_provision_ports_without_address_pairs_in_l2_subnet_vsd_managed(
            self):
        vsd_l2_subnet = self._given_vsd_l2domain(
            cidr4=self.cidr4, cidr6=self.cidr6, dhcp_managed=True,
            enable_dhcpv4=False, enable_dhcpv6=False)
        network, subnet4, subnet6 = self._given_network_linked_to_vsd_subnet(
            vsd_l2_subnet, cidr4=self.cidr4, cidr6=self.cidr6,
            enable_dhcp=Topology.is_v5)  # in v5, set enable_dhcp = True
        for scenario, port_config in iteritems(self.port_configs):
            LOG.info("TESTCASE scenario {}".format(scenario))
            self._check_crud_port(scenario, network, subnet4, subnet6,
                                  vsd_l2_subnet, nuage_constants.L2_DOMAIN)

    @decorators.attr(type='smoke')
    def test_provision_ports_with_address_pairs_in_l3_subnet(self):
        # Given I have a VSD-L3-Managed subnet - dhcp-managed
        vsd_l3_domain, vsd_l3_subnet = self._given_vsd_l3subnet(
            cidr4=self.cidr4, cidr6=self.cidr6,
            enable_dhcpv4=True, enable_dhcpv6=True)
        network, subnet4, subnet6 = self._given_network_linked_to_vsd_subnet(
            vsd_l3_subnet, cidr4=self.cidr4, cidr6=self.cidr6)

        for scenario, port_config in iteritems(self.port_configs):
            LOG.info("TESTCASE scenario {}".format(scenario))
            self._check_crud_port(scenario, network, subnet4, subnet6,
                                  vsd_l3_subnet, nuage_constants.SUBNETWORK)
