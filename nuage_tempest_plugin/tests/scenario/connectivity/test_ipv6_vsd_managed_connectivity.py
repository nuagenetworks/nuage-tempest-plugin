# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPAddress
from netaddr import IPNetwork

from tempest.lib import decorators

from nuage_tempest_lib.tests.nuage_test import NuageBaseTest


class Ipv6VsdManagedConnectivityTest(NuageBaseTest):

    def test_icmp_connectivity_l2_vsd_managed_dualstack(self):
        # Provision VSD managed network resources
        l2domain_template = self.vsd_create_l2domain_template(
            ip_type="DUALSTACK",
            cidr4=self.cidr4,
            gateway4=self.gateway4,
            cidr6=self.cidr6,
            gateway6=self.gateway6)
        vsd_l2domain = self.vsd_create_l2domain(template=l2domain_template)

        self.vsd.define_any_to_any_acl(vsd_l2domain, allow_ipv6=True)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        self.create_l2_vsd_managed_subnet(network, vsd_l2domain)
        self.create_l2_vsd_managed_subnet(
            network, vsd_l2domain, ip_version=6, dhcp_managed=False)

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            networks=[network],
            make_reachable=True,
            configure_dualstack_itf=True)

        server1 = self.create_tenant_server(
            networks=[network],
            make_reachable=True,
            configure_dualstack_itf=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

        # Test IPv6 connectivity between peer servers
        self.assert_ping6(server1, server2, network)

    def icmp_connectivity_l3_vsd_managed(
            self, cidr4, cidr6,
            vsd_gateway4=None, gateway4=None, pool4=None,
            vsd_gateway6=None, gateway6=None, pool6=None,
            vsd_domain=None, vsd_subnet=None,
            skip_server2_and_ping_tests=False,
            server2_pre_set_up=None, incl_negative_ping_test=False):

        if not vsd_domain:
            vsd_domain_template = self.vsd_create_l3domain_template()
            vsd_domain = self.vsd_create_l3domain(
                template_id=vsd_domain_template.id)
            vsd_zone = self.vsd_create_zone(domain=vsd_domain)
            vsd_subnet = self.create_vsd_subnet(
                zone=vsd_zone,
                ip_type="DUALSTACK",
                cidr4=cidr4,
                gateway4=(vsd_gateway4 if vsd_gateway4
                          else gateway4 if gateway4
                          else str(IPAddress(cidr4) + 1)),
                cidr6=cidr6,
                gateway6=(vsd_gateway6 if vsd_gateway6
                          else gateway6 if gateway6
                          else str(IPAddress(cidr6) + 1)))

            self.vsd.define_any_to_any_acl(vsd_domain,
                                           allow_ipv4=True,
                                           allow_ipv6=True)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()

        # v4
        kwargs = {'allocation_pools': [pool4]} if pool4 else {}
        ipv4_subnet = self.create_l3_vsd_managed_subnet(
            network, vsd_domain, vsd_subnet, gateway=gateway4, **kwargs)
        self.assertEqual(str(cidr4), ipv4_subnet['cidr'])
        if pool4:
            subnet_pool4 = ipv4_subnet['allocation_pools']
            self.assertEqual(1, len(subnet_pool4))
            self.assertEqual(pool4, subnet_pool4[0])

        # v6
        kwargs = {'allocation_pools': [pool6]} if pool6 else {}
        ipv6_subnet = self.create_l3_vsd_managed_subnet(
            network, vsd_domain, vsd_subnet, dhcp_managed=False, ip_version=6,
            gateway=gateway6, **kwargs)
        self.assertEqual(str(cidr6), ipv6_subnet['cidr'])
        if pool6:
            subnet_pool6 = ipv6_subnet['allocation_pools']
            self.assertEqual(1, len(subnet_pool6))
            self.assertEqual(pool6, subnet_pool6[0])

        # Launch tenant server in OpenStack network
        server1 = self.create_tenant_server(networks=[network],
                                            make_reachable=True,
                                            configure_dualstack_itf=True)

        if skip_server2_and_ping_tests:
            return vsd_domain, vsd_subnet, server1

        if server2_pre_set_up:
            server2 = server2_pre_set_up
            network2 = server2.networks[0] if server2.networks else network
        else:
            # Launch tenant server in OpenStack network
            server2 = self.create_tenant_server(
                networks=[network],
                make_reachable=True,
                configure_dualstack_itf=True)
            network2 = network

        self.assert_ping(server1, server2, network2)

        # Test IPv6 connectivity between peer servers
        self.assert_ping6(server1, server2, network2)

        if incl_negative_ping_test:
            # Allow IPv6 only
            self.vsd.define_any_to_any_acl(vsd_domain,
                                           allow_ipv4=False,
                                           allow_ipv6=True)

            self.assert_ping(server1, server2, network2, should_pass=False)
            self.assert_ping6(server1, server2, network2)

        if incl_negative_ping_test:
            # Allow IPv4 only
            self.vsd.define_any_to_any_acl(vsd_domain,
                                           allow_ipv4=True,
                                           allow_ipv6=False)

            self.assert_ping(server1, server2, network2)
            self.assert_ping6(server1, server2, network2, should_pass=False)

        return vsd_domain, vsd_subnet, server1

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_vsd_managed_dualstack(self):
        self.icmp_connectivity_l3_vsd_managed(
            cidr4=self.cidr4, cidr6=self.cidr6)

    def test_icmp_connectivity_l3_vsd_managed_dualstack_linked_networks(self):
        vsd_domain, vsd_subnet, server = self.icmp_connectivity_l3_vsd_managed(
            cidr4=IPNetwork('10.10.100.0/24'),
            cidr6=IPNetwork('cafe:babe::/64'),
            pool4={'start': '10.10.100.100', 'end': '10.10.100.109'},
            pool6={'start': 'cafe:babe::100', 'end': 'cafe:babe::109'},
            skip_server2_and_ping_tests=True)

        self.icmp_connectivity_l3_vsd_managed(
            cidr4=IPNetwork('10.10.100.0/24'),
            cidr6=IPNetwork('cafe:babe::/64'),
            pool4={'start': '10.10.100.110', 'end': '10.10.100.119'},
            vsd_gateway6='cafe:babe:0:0:0:0:0:1',  # mind
            gateway6='cafe:babe::1',  # not syntactically same (extra test)
            pool6={'start': 'cafe:babe::110', 'end': 'cafe:babe::119'},
            vsd_domain=vsd_domain, vsd_subnet=vsd_subnet,
            server2_pre_set_up=server)
