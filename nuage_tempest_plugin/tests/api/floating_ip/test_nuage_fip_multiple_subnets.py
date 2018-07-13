# Copyright 2018 NOKIA
# All Rights Reserved.

from netaddr import IPNetwork

from tempest.lib import exceptions

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.utils import data_utils


class NuageMultipleSubnetsInExternalNetworkTest(nuage_test.NuageBaseTest):

    def test_nuage_uplink_subsequent_subnets(self):
        """test_nuage_uplink_subsequent_subnets

        Check that when providing --nuage-uplink, all subsequent subnets also
        go into the same domain
        """
        kwargs = {'router:external': True}
        n1 = self.create_network(client=self.admin_manager, **kwargs)
        n2 = self.create_network(client=self.admin_manager, **kwargs)
        s1 = self.create_subnet(n1, cidr=IPNetwork('10.0.0.0/24'),
                                mask_bits=24, underlay=False,
                                client=self.admin_manager)
        s2 = self.create_subnet(n2, cidr=IPNetwork('20.0.0.0/24'),
                                mask_bits=24, underlay=False,
                                nuage_uplink=s1['nuage_uplink'],
                                client=self.admin_manager)
        s3 = self.create_subnet(n2, cidr=IPNetwork('30.0.0.0/24'),
                                mask_bits=24, underlay=False,
                                client=self.admin_manager)
        self.assertEqual(s1['nuage_uplink'], s2['nuage_uplink'],
                         "Subnet not created with provided nuage_uplink")
        self.assertEqual(s2['nuage_uplink'], s3['nuage_uplink'],
                         "Subsequent subnet not connected to nuage_uplink "
                         "of previous subnets in the network.")

    def test_no_nuage_uplink_subsequent_subnets(self):
        """test_no_nuage_uplink_subsequent_subnets

        Check that when not providing --nuage-uplink a new domain is
        created where all subsequent subnets go into
        """
        kwargs = {'router:external': True}
        n1 = self.create_network(client=self.admin_manager, **kwargs)
        s1 = self.create_subnet(n1, cidr=IPNetwork('10.0.0.0/24'),
                                mask_bits=24, underlay=False,
                                client=self.admin_manager)
        # No more than one domain should be found in the zone
        # Make sure session is initialized
        self.vsd.session()
        zone = self.vsd.vspk.NUZone(id=s1['nuage_uplink']).fetch()[0]
        subnets = zone.subnets.get()
        self.assertEqual(len(subnets), 1, "Number of subnets in shared domain "
                                          "should be exactly 1.")
        s2 = self.create_subnet(n1, cidr=IPNetwork('20.0.0.0/24'),
                                mask_bits=24, underlay=False,
                                client=self.admin_manager)
        self.assertEqual(s1['nuage_uplink'], s2['nuage_uplink'],
                         "Subnet not created with implicit same nuage_uplink")

    def test_nuage_underlay_on_off(self):
        """test_nuage_underlay_on_off

        Check that when providing --underlay True subsequent subnets cannot be
        created using --underlay False
        """
        kwargs = {'router:external': True}
        n1 = self.create_network(client=self.admin_manager, **kwargs)
        s1 = self.create_subnet(n1, cidr=data_utils.gimme_a_cidr()[0],
                                mask_bits=24, underlay=True,
                                client=self.admin_manager)
        self.assertRaises(
            exceptions.BadRequest,
            self.create_subnet,
            n1, cidr=IPNetwork('20.0.0.0/24'),
            mask_bits=24, underlay=False,
            nuage_uplink=s1['nuage_uplink'],
            client=self.admin_manager)

    def test_nuage_underlay_on(self):
        """test_nuage_underlay_on

        Check that when providing --underlay True, subnets accross networks
        go into the same domain.
        """
        kwargs = {'router:external': True}
        n1 = self.create_network(client=self.admin_manager, **kwargs)
        n2 = self.create_network(client=self.admin_manager, **kwargs)
        s1 = self.create_subnet(n1, cidr=data_utils.gimme_a_cidr()[0],
                                mask_bits=24, underlay=True,
                                client=self.admin_manager)
        s2 = self.create_subnet(n1, cidr=data_utils.gimme_a_cidr()[0],
                                mask_bits=24, underlay=True,
                                client=self.admin_manager)
        s3 = self.create_subnet(n2, cidr=data_utils.gimme_a_cidr()[0],
                                mask_bits=24, underlay=True,
                                client=self.admin_manager)
        self.assertEqual(s1['nuage_uplink'], s2['nuage_uplink'],
                         "Subnet not going into same underlay domain")
        self.assertEqual(s2['nuage_uplink'], s3['nuage_uplink'],
                         "Not all underlay=True subnets are in the same "
                         "underlay domain.")

    def test_nuage_different_nuage_uplink(self):
        """test_nuage_different_nuage_uplink

        Check that when providing --nuage-uplink that is not the parent
        of an existing subnet on the network an error is thrown
        """
        kwargs = {'router:external': True}
        n1 = self.create_network(client=self.admin_manager, **kwargs)
        n2 = self.create_network(client=self.admin_manager, **kwargs)
        s1 = self.create_subnet(n1, cidr=IPNetwork('10.0.0.0/24'),
                                mask_bits=24, underlay=False,
                                client=self.admin_manager)
        self.create_subnet(n2, cidr=IPNetwork('20.0.0.0/24'),
                           mask_bits=24, underlay=False,
                           client=self.admin_manager)
        # Create subnet in n2 with nuage uplink of n1
        self.assertRaises(
            exceptions.BadRequest,
            self.create_subnet,
            n2, cidr=IPNetwork('30.0.0.0/24'),
            nuage_uplink=s1['nuage_uplink'],
            mask_bits=24, underlay=False,
            client=self.admin_manager)

    def test_nuage_uplink_provided_redundantly(self):
        """test_nuage_uplink_subsequent_subnets

        Check that when providing --nuage-uplink that is the same as the
        parent of an existing subnet on the network no error is thrown.
        """
        kwargs = {'router:external': True}
        n1 = self.create_network(client=self.admin_manager, **kwargs)
        s1 = self.create_subnet(n1, cidr=IPNetwork('10.0.0.0/24'),
                                mask_bits=24, underlay=False,
                                client=self.admin_manager)
        s2 = self.create_subnet(n1, cidr=IPNetwork('20.0.0.0/24'),
                                mask_bits=24, underlay=False,
                                client=self.admin_manager)
        self.assertEqual(s1['nuage_uplink'], s2['nuage_uplink'],
                         "Subnet not created with provided nuage_uplink")

    def test_nuage_network_update_to_external(self):
        """test_nuage_network_update_to_external

        Check that when providing --nuage-uplink that is the same as the
        parent of an existing subnet on the network no error is thrown.
        """
        if self.is_dhcp_agent_present():
            raise self.skipException(
                'Multiple subnets in a network not supported when DHCP agent '
                'is enabled.')
        n1 = self.create_network(client=self.admin_manager)
        s1 = self.create_subnet(n1, cidr=data_utils.gimme_a_cidr()[0],
                                mask_bits=24,
                                client=self.admin_manager)
        s2 = self.create_subnet(n1, cidr=data_utils.gimme_a_cidr()[0],
                                mask_bits=24,
                                client=self.admin_manager)
        kwargs = {'router:external': True}
        self.update_network(n1['id'], client=self.admin_manager, **kwargs)
        s1 = self.os_admin.subnets_client.show_subnet(s1['id'])['subnet']
        s2 = self.os_admin.subnets_client.show_subnet(s2['id'])['subnet']
        self.assertEqual(s1['nuage_uplink'], s2['nuage_uplink'],
                         "Subnet not created with provided nuage_uplink")

    def test_nuage_network_multiple_gw(self):
        """test_nuage_network_multiple_gw

        Check that when a router can have a gateway to multiple subnets
        in the same network.
        """
        kwargs = {'router:external': True}
        n1 = self.create_network(client=self.admin_manager, **kwargs)
        s1 = self.create_subnet(n1, cidr=data_utils.gimme_a_cidr()[0],
                                mask_bits=24,
                                client=self.admin_manager)
        s2 = self.create_subnet(n1, cidr=data_utils.gimme_a_cidr()[0],
                                mask_bits=24,
                                client=self.admin_manager)
        self.assertEqual(s1['nuage_uplink'], s2['nuage_uplink'],
                         "Subnet not created in same domain")
        kwargs = {'external_gateway_info':
                  {'network_id': n1['id'],
                   'external_fixed_ips': [{'subnet_id': s1['id']},
                                          {'subnet_id': s2['id']}]}}
        self.create_router(client=self.admin_manager,
                           external_gateway_info_on=False, **kwargs)
