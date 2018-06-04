# Copyright 2017 - Nokia
# All Rights Reserved.

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as nuage_constants
from nuage_tempest_plugin.tests.api.ipv6.test_allowed_address_pair \
    import BaseAllowedAddressPair
from nuage_tempest_plugin.tests.api.ipv6.vsd_managed.base_nuage_networks \
    import BaseVSDManagedNetworksIPv6Test
from tempest.test import decorators

###############################################################################
###############################################################################
# MultiVIP . allowed address pairs
###############################################################################
###############################################################################

LOG = Topology.get_logger(__name__)


class VSDManagedAllowedAddresPairsTest(BaseAllowedAddressPair,
                                       BaseVSDManagedNetworksIPv6Test):

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_provision_ports_without_address_pairs_in_l2_subnet_unmanaged(
            self):
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
