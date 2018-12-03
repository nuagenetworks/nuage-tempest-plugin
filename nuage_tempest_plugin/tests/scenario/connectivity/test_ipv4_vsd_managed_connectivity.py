# Copyright 2017 - Nokia
# All Rights Reserved.

from tempest.lib import decorators

from nuage_tempest_lib.tests.nuage_test import NuageBaseTest


class Ipv4VsdManagedConnectivityTest(NuageBaseTest):

    def test_icmp_connectivity_l2_vsd_managed(self):
        # Provision VSD managed network resources
        l2domain_template = self.vsd_create_l2domain_template(
            cidr4=self.cidr4,
            gateway4=self.gateway4,
            mask_bits=self.mask_bits4)
        l2domain = self.vsd_create_l2domain(template=l2domain_template)

        self.vsd.define_any_to_any_acl(l2domain)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        self.create_l2_vsd_managed_subnet(network, l2domain)

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            networks=[network])

        server1 = self.create_tenant_server(
            networks=[network],
            make_reachable=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_vsd_managed(self):
        # Provision VSD managed network resources
        vsd_l3domain_template = self.vsd_create_l3domain_template()
        vsd_l3domain = self.vsd_create_l3domain(
            template_id=vsd_l3domain_template.id)
        vsd_zone = self.vsd_create_zone(domain=vsd_l3domain)
        vsd_subnet = self.create_vsd_subnet(
            zone=vsd_zone,
            cidr4=self.cidr4,
            gateway4=self.gateway4)

        self.vsd.define_any_to_any_acl(vsd_l3domain)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        self.create_l3_vsd_managed_subnet(network, vsd_l3domain, vsd_subnet)

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(networks=[network])
        server1 = self.create_tenant_server(networks=[network],
                                            make_reachable=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)
