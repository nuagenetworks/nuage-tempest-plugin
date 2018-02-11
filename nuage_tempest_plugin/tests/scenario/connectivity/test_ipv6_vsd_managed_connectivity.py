# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPAddress
from netaddr import IPNetwork
from oslo_log import log as logging
import testtools
import time

from tempest.lib import decorators

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology


class Ipv6VsdManagedConnectivityTest(NuageBaseTest):

    LOG = logging.getLogger(__name__)

    include_negative_testing = False  # TODO(Kris) FIXME

    ###########################################################################
    # Typical cases - DualStack
    ###########################################################################
    @testtools.skipIf(not Topology.access_to_l2_supported(),
                      'Access to vm\'s in l2 networks is unsupported.')
    def test_icmp_connectivity_vsd_managed_dualstack_l2_domain(self):
        # Provision VSD managed network resources
        l2domain_template = self.vsd.create_l2domain_template(
            ip_type="DUALSTACK",
            cidr4=self.cidr4,
            gateway4=self.gateway4,
            cidr6=self.cidr6,
            gateway6=self.gateway6)
        self.addCleanup(l2domain_template.delete)

        vsd_l2domain = self.vsd.create_l2domain(template=l2domain_template)
        self.addCleanup(vsd_l2domain.delete)

        self.vsd.define_any_to_any_acl(vsd_l2domain,
                                       allow_ipv4=True,
                                       allow_ipv6=True)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        ipv4_subnet = self.create_l2_vsd_managed_subnet(
            network, vsd_l2domain)
        ipv6_subnet = self.create_l2_vsd_managed_subnet(
            network, vsd_l2domain, ip_version=6, dhcp_managed=False)
        self.assertIsNotNone(ipv4_subnet)
        self.assertIsNotNone(ipv6_subnet)

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(tenant_networks=[network])
        server2 = self.create_tenant_server(tenant_networks=[network])

        # Test IPv4 connectivity between peer servers

        # -- In dev CI this will make this test skip itself as there is no --
        # -- console access --

        self.assert_ping(server1, server2, network)

        # Define IPv6 interface in the guest VM's
        # as VSP does not support DHCPv6 for IPv6 addresses
        server1_ipv6 = server1.get_server_ip_in_network(
            network['name'], ip_type=6)
        server2_ipv6 = server2.get_server_ip_in_network(
            network['name'], ip_type=6)

        server1.configure_dualstack_interface(
            server1_ipv6, subnet=ipv6_subnet, device="eth0", )
        server2.configure_dualstack_interface(
            server2_ipv6, subnet=ipv6_subnet, device="eth0", )

        # TODO(team): find out why we need 5 seconds sleep for stable success?
        time.sleep(5)

        # Test IPv6 connectivity between peer servers
        self.assert_ping6(server1, server2, network)

        if self.include_negative_testing:
            # Allow IPv6 only
            self.vsd.define_any_to_any_acl(
                vsd_l2domain, allow_ipv4=False, allow_ipv6=True)
            time.sleep(3)

            self.assert_ping(server1, server2, network, should_pass=False)
            self.assert_ping6(server1, server2, network, should_pass=True)

            # Allow IPv4 only
            self.vsd.define_any_to_any_acl(
                vsd_l2domain, allow_ipv4=True, allow_ipv6=False)
            time.sleep(3)

            self.assert_ping(server1, server2, network, should_pass=True)
            self.assert_ping6(server1, server2, network, should_pass=False)

    def icmp_connectivity_l3_vsd_managed(
            self, cidr4, vsd_gateway4=None, gateway4=None,
            cidr6=None, vsd_gateway6=None, gateway6=None,
            pool4=None, pool6=None,
            vsd_domain=None, vsd_subnet=None,
            skip_server1=False, skip_server2_and_ping_tests=False,
            server2_pre_set_up=None, incl_negative_ping_test=False):

        if not vsd_domain:
            vsd_domain_template = self.vsd.create_l3domain_template()
            self.addCleanup(vsd_domain_template.delete)

            vsd_domain = self.vsd.create_l3domain(
                template_id=vsd_domain_template.id)
            self.addCleanup(vsd_domain.delete)

            vsd_zone = self.vsd.create_zone(domain=vsd_domain)
            self.addCleanup(vsd_zone.delete)

            if cidr6:
                vsd_subnet = self.vsd.create_subnet(
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
            else:
                vsd_subnet = self.vsd.create_subnet(
                    zone=vsd_zone,
                    ip_type="IPV4",
                    cidr4=cidr4,
                    gateway4=(vsd_gateway4 if vsd_gateway4
                              else gateway4 if gateway4
                              else str(IPAddress(cidr4) + 1)))
            self.addCleanup(vsd_subnet.delete)

            self.vsd.define_any_to_any_acl(vsd_domain,
                                           allow_ipv4=True,
                                           allow_ipv6=True)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()

        # v4
        if cidr4:  # which currently would be always
            if pool4:
                kwargs = {'allocation_pools': [pool4]}
            else:
                kwargs = {}
            ipv4_subnet = self.create_l3_vsd_managed_subnet(
                network, vsd_subnet, gateway=gateway4, **kwargs)
            self.assertIsNotNone(ipv4_subnet)
            self.assertEqual(str(cidr4), ipv4_subnet['cidr'])
            if pool6:
                subnet_pool4 = ipv4_subnet['allocation_pools']
                self.assertEqual(1, len(subnet_pool4))
                self.assertEqual(pool4, subnet_pool4[0])

        # v6
        if cidr6:
            if pool6:
                kwargs = {'allocation_pools': [pool6]}
            else:
                kwargs = {}
            ipv6_subnet = self.create_l3_vsd_managed_subnet(
                network, vsd_subnet, dhcp_managed=False, ip_version=6,
                gateway=gateway6, **kwargs)
            self.assertIsNotNone(ipv6_subnet)
            self.assertEqual(str(cidr6), ipv6_subnet['cidr'])
            if pool6:
                subnet_pool6 = ipv6_subnet['allocation_pools']
                self.assertEqual(1, len(subnet_pool6))
                self.assertEqual(pool6, subnet_pool6[0])
        else:
            ipv6_subnet = None

        if skip_server1:
            return vsd_domain, vsd_subnet, None

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(tenant_networks=[network])

        if cidr6:
            server1_ipv6 = server1.get_server_ip_in_network(
                network['name'], ip_type=6)

            self.prepare_for_nic_provisioning(server1, vsd_domain=vsd_domain,
                                              vsd_subnet=vsd_subnet)

            server1.configure_dualstack_interface(
                server1_ipv6, subnet=ipv6_subnet, device="eth0", )

        if skip_server2_and_ping_tests:
            return vsd_domain, vsd_subnet, server1

        if server2_pre_set_up:
            server2 = server2_pre_set_up
            network2 = server2.networks[0] if server2.networks else network
        else:
            server2 = self.create_tenant_server(tenant_networks=[network])
            network2 = network

        time.sleep(5)

        # Test IPv4 connectivity between peer servers
        self.prepare_for_ping_test(server1, vsd_domain=vsd_domain,
                                   vsd_subnet=vsd_subnet)

        self.assert_ping(server1, server2, network2)

        if cidr6:
            if not server2_pre_set_up:
                server2_ipv6 = server2.get_server_ip_in_network(
                    network2['name'], ip_type=6)

                self.prepare_for_nic_provisioning(
                    server2, vsd_domain=vsd_domain, vsd_subnet=vsd_subnet)

                server2.configure_dualstack_interface(
                    server2_ipv6, subnet=ipv6_subnet, device="eth0", )

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
    def test_l3_vsd_managed_dualstack_networks(self):
        self.icmp_connectivity_l3_vsd_managed(
            cidr4=IPNetwork('10.10.100.0/24'),
            pool4={'start': '10.10.100.100', 'end': '10.10.100.109'},
            cidr6=IPNetwork('cafe:babe::/64'),
            pool6={'start': 'cafe:babe::100', 'end': 'cafe:babe::109'},
            skip_server1=True, skip_server2_and_ping_tests=True)

    @decorators.attr(type='smoke')
    def test_l3_vsd_managed_dualstack_syntactically_different_v6_gw(self):
        self.icmp_connectivity_l3_vsd_managed(
            cidr4=IPNetwork('10.10.100.0/24'),
            vsd_gateway4='10.10.100.1', gateway4='10.10.100.1',  # same
            pool4={'start': '10.10.100.100', 'end': '10.10.100.109'},
            cidr6=IPNetwork('cafe:babe::/64'),
            vsd_gateway6='cafe:babe:0:0:0:0:0:1',
            gateway6='cafe:babe::1',  # not same
            pool6={'start': 'cafe:babe::100', 'end': 'cafe:babe::109'},
            skip_server1=True, skip_server2_and_ping_tests=True)

    @testtools.skipIf(not Topology.run_connectivity_tests(),
                      'Connectivity tests are disabled.')
    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_vsd_managed(self):
        self.icmp_connectivity_l3_vsd_managed(
            cidr4=self.cidr4, cidr6=self.cidr6)
        # FIXME(Kris) incl_negative_ping_test=True

    @testtools.skipIf(not Topology.run_connectivity_tests(),
                      'Connectivity tests are disabled.')
    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_vsd_managed_no_gw(self):
        self.icmp_connectivity_l3_vsd_managed(
            cidr4=self.cidr4, gateway4='', cidr6=self.cidr6, gateway6='')

    @testtools.skipIf(not Topology.run_connectivity_tests(),
                      'Connectivity tests are disabled.')
    @testtools.skipIf(not NUAGE_FEATURES.multi_linked_vsdmgd_subnets,
                      'Multi-linked VSD mgd subnets are not supported in this '
                      'release')
    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_vsd_managed_linked_v4_networks(self):
        vsd_domain, vsd_subnet, server = self.icmp_connectivity_l3_vsd_managed(
            cidr4=IPNetwork('10.10.100.0/24'),
            pool4={'start': '10.10.100.100', 'end': '10.10.100.109'},
            skip_server2_and_ping_tests=True)

        self.icmp_connectivity_l3_vsd_managed(
            cidr4=IPNetwork('10.10.100.0/24'),
            pool4={'start': '10.10.100.110', 'end': '10.10.100.119'},
            vsd_domain=vsd_domain, vsd_subnet=vsd_subnet,
            server2_pre_set_up=server)

    @testtools.skipIf(not Topology.run_connectivity_tests(),
                      'Connectivity tests are disabled.')
    @testtools.skipIf(not NUAGE_FEATURES.multi_linked_vsdmgd_subnets,
                      'Multi-linked VSD mgd subnets are not supported in this '
                      'release')
    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_vsd_managed_linked_dualstack_networks(self):
        vsd_domain, vsd_subnet, server = self.icmp_connectivity_l3_vsd_managed(
            cidr4=IPNetwork('10.10.100.0/24'),
            pool4={'start': '10.10.100.100', 'end': '10.10.100.109'},
            cidr6=IPNetwork('cafe:babe::/64'),
            pool6={'start': 'cafe:babe::100', 'end': 'cafe:babe::109'},
            skip_server2_and_ping_tests=True)

        self.icmp_connectivity_l3_vsd_managed(
            cidr4=IPNetwork('10.10.100.0/24'),
            pool4={'start': '10.10.100.110', 'end': '10.10.100.119'},
            cidr6=IPNetwork('cafe:babe::/64'),
            pool6={'start': 'cafe:babe::110', 'end': 'cafe:babe::119'},
            vsd_domain=vsd_domain, vsd_subnet=vsd_subnet,
            server2_pre_set_up=server)
