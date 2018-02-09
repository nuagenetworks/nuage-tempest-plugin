# Copyright 2017 - Nokia
# All Rights Reserved.

from testtools.matchers import ContainsDict
from testtools.matchers import Equals

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology

from nuage_tempest_plugin.tests.api.ipv6.base_nuage_networks \
    import NetworkTestCaseMixin
from nuage_tempest_plugin.tests.api.ipv6.base_nuage_networks \
    import VsdTestCaseMixin

VALID_MAC_ADDRESS = 'fa:fa:3e:e8:e8:01'
VALID_MAC_ADDRESS_2A = 'fa:fa:3e:e8:e8:2a'
VALID_MAC_ADDRESS_2B = 'fa:fa:3e:e8:e8:2b'

###############################################################################
###############################################################################
# MultiVIP . allowed address pairs)
###############################################################################
###############################################################################


class VSDManagedFloatingIpTest(NetworkTestCaseMixin, VsdTestCaseMixin):

    @nuage_test.header()
    def test_create_port_with_vsd_floatingip(self):
        # Given I have a VSD-FloatingIP-pool
        vsd_fip_pool = self._create_vsd_floatingip_pool()

        # Given I have a VSD-L3-Managed subnet
        vsd_l3_domain, vsd_l3_subnet = self._given_vsd_l3subnet(
            cidr4=self.cidr4, cidr6=self.cidr6)
        network, subnet4, subnet6 = self._given_network_linked_to_vsd_subnet(
            vsd_l3_subnet, cidr4=self.cidr4, cidr6=self.cidr6)

        # And I have claimed a VSD-FloatingIP in the VSD-L3-Domain
        fip1 = self.nuage_vsd_client.claim_floatingip(
            vsd_l3_domain['ID'], vsd_fip_pool['ID'])[0]
        fip2 = self.nuage_vsd_client.claim_floatingip(
            vsd_l3_domain['ID'], vsd_fip_pool['ID'])[0]

        # When I retrieve the nuage-floatingIP-list of the OS IPv4 subnet
        fip_list = self.nuage_network_client.list_nuage_floatingip_by_subnet(
            subnet4['id'])
        # Then I expect the VSD-floatingIP in my list
        fip_present = self._check_fip_in_list(fip1['ID'], fip_list)
        self.assertTrue(fip_present,
                        msg="nuage floatingip not present in list, "
                            "while expected to be")

        # When I retrieve the nuage-floatingIP-list of the OS IPv6 subnet
        fip_list = self.nuage_network_client.list_nuage_floatingip_by_subnet(
            subnet6['id'])
        # Then I expect the VSD-floatingIP in my list
        self._check_fip_in_list(fip1['ID'], fip_list)
        self.assertTrue(fip_present,
                        msg="nuage floatingip not present in list, "
                            "while expected to be")

        self._check_fip_in_list(fip2['ID'], fip_list)
        self.assertTrue(fip_present,
                        msg="nuage floatingip not present in list, "
                            "while expected to be")

        # When I create a port in the network with FIP assigned
        kwargs = {"nuage_floatingip": {'id': fip1['ID']}}
        port = self.create_port(network, **kwargs)
        # Then this FIP is assigned to the port
        self.assertThat(port['nuage_floatingip'],
                        ContainsDict({'id': Equals(fip1['ID'])}))

        # And I associate this port to the claimed floating ip (via update)
        # self._associate_fip_to_port(port, claimed_fip[0]['ID'])

        # Then I expect the claimed floating ip in the port show response
        if not Topology.is_ml2:
            fip_present = self._check_fip_in_port_show(
                port['id'], fip1['ID'])
            self.assertTrue(fip_present,
                            msg="associated VSD claimed FIP (%s) not found "
                                "in port (%s)" %
                                (fip1['ID'], port['id']))

        # When I disassociate the claimed fip from the port
        self._disassociate_fip_from_port(port)
        # Then I no longer expect the claimed floating ip in the
        # port show response
        if not Topology.is_ml2:
            fip_present = self._check_fip_in_port_show(
                port['id'], fip1[0]['ID'])
            self.assertFalse(fip_present,
                             msg="disassociated VSD claimed FIP (%s) "
                                 "still found in port (%s)" %
                                 (fip1[0]['ID'], port['id']))
