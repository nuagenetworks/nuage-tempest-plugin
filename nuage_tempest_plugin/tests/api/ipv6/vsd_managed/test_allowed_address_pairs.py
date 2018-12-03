# Copyright 2017 - Nokia
# All Rights Reserved.

from oslo_log import log as logging
from six import iteritems

from tempest.test import decorators

from nuage_commons import constants as nuage_constants

from nuage_tempest_plugin.tests.api.ipv6.test_allowed_address_pair \
    import BaseAllowedAddressPair
from nuage_tempest_plugin.tests.api.ipv6.vsd_managed.base_nuage_networks \
    import BaseVSDManagedNetworksIPv6Test

LOG = logging.getLogger(__name__)


###############################################################################
###############################################################################
# MultiVIP . allowed address pairs
###############################################################################
###############################################################################


class VSDManagedAllowedAddresPairsTest(BaseAllowedAddressPair,
                                       BaseVSDManagedNetworksIPv6Test):

    @decorators.attr(type='smoke')
    def test_provision_ports_without_address_pairs_in_l2_subnet_unmanaged(
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
    def test_provision_ports_with_address_pairs_in_l3_subnet(self):
        # Given I have a VSD-L3-Managed subnet - dhcp-managed
        vsd_l3_domain, vsd_l3_subnet = self._given_vsd_l3subnet(
            cidr4=self.cidr4, cidr6=self.cidr6)
        network, subnet4, subnet6 = self._given_network_linked_to_vsd_subnet(
            vsd_l3_subnet, cidr4=self.cidr4, cidr6=self.cidr6)

        for scenario, port_config in iteritems(self.port_configs):
            LOG.info("TESTCASE scenario {}".format(scenario))
            self._check_crud_port(scenario, network, subnet4, subnet6,
                                  vsd_l3_subnet, nuage_constants.SUBNETWORK)
