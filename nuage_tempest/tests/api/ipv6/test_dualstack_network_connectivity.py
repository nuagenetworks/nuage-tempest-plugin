# Copyright 2017 - Nokia
# All Rights Reserved.

from oslo_log import log as logging

import time

from nuage_tempest.lib.test.nuage_test import NuageBaseTest


class DualStackConnectivityTest(NuageBaseTest):

    LOG = logging.getLogger(__name__)

    ###########################################################################
    # Typical cases - DualStack
    ###########################################################################
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

        # Allow IPv4 and IPv6 again
        self.vsd.define_any_to_any_acl(
            vsd_l2domain, allow_ipv4=True, allow_ipv6=True)
        time.sleep(3)

        self.assert_ping(server1, server2, network, should_pass=True)
        self.assert_ping6(server1, server2, network, should_pass=True)
        pass

    def test_icmp_connectivity_vsd_managed_dualstack_l3_domain(self):
        # Provision VSD managed network
        vsd_l3domain_template = self.vsd.create_l3domain_template()
        self.addCleanup(vsd_l3domain_template.delete)

        vsd_l3domain = self.vsd.create_l3domain(
            template_id=vsd_l3domain_template.id)
        self.addCleanup(vsd_l3domain.delete)

        vsd_zone = self.vsd.create_zone(domain=vsd_l3domain)
        self.addCleanup(vsd_zone.delete)

        vsd_l3domain_subnet = self.vsd.create_subnet(
            zone=vsd_zone,
            ip_type="DUALSTACK",
            cidr4=self.cidr4,
            gateway4=self.gateway4,
            cidr6=self.cidr6,
            gateway6=self.gateway6)
        self.addCleanup(vsd_l3domain_subnet.delete)

        self.vsd.define_any_to_any_acl(vsd_l3domain,
                                       allow_ipv4=True,
                                       allow_ipv6=True)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        ipv4_subnet = self.create_l3_vsd_managed_subnet(
            network, vsd_l3domain_subnet)
        ipv6_subnet = self.create_l3_vsd_managed_subnet(
            network, vsd_l3domain_subnet, ip_version=6, dhcp_managed=False)
        self.assertIsNotNone(ipv4_subnet)
        self.assertIsNotNone(ipv6_subnet)

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(tenant_networks=[network])
        server2 = self.create_tenant_server(tenant_networks=[network])

        # Attach FIP if possible
        self.prepare_for_ping_test(server1, vsd_domain=vsd_l3domain,
                                   vsd_subnet=vsd_l3domain_subnet)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

        # Define IPv6 interface in the guest VM's
        # as VSP does not support DHCPv6 for IPv6 addresses
        server1_ipv6 = server1.get_server_ip_in_network(
            network['name'], ip_type=6)
        server2_ipv6 = server2.get_server_ip_in_network(
            network['name'], ip_type=6)

        self.prepare_for_nic_provisioning(server1, vsd_domain=vsd_l3domain,
                                          vsd_subnet=vsd_l3domain_subnet)
        self.prepare_for_nic_provisioning(server2, vsd_domain=vsd_l3domain,
                                          vsd_subnet=vsd_l3domain_subnet)

        server1.configure_dualstack_interface(
            server1_ipv6, subnet=ipv6_subnet, device="eth0", )
        server2.configure_dualstack_interface(
            server2_ipv6, subnet=ipv6_subnet, device="eth0", )

        # TODO(team): find out why we need 5 seconds sleep for stable success?
        time.sleep(5)

        # Test IPv6 connectivity between peer servers
        self.assert_ping6(server1, server2, network)

        # Allow IPv6 only
        self.vsd.define_any_to_any_acl(vsd_l3domain,
                                       allow_ipv4=False,
                                       allow_ipv6=True)

        self.assert_ping(server1, server2, network, should_pass=False)
        self.assert_ping6(server1, server2, network, should_pass=True)

        # Allow IPv4 only
        self.vsd.define_any_to_any_acl(vsd_l3domain,
                                       allow_ipv4=True,
                                       allow_ipv6=False)

        self.assert_ping(server1, server2, network, should_pass=True)
        self.assert_ping6(server1, server2, network, should_pass=False)

        # Allow IPv4 and IPv6 again
        self.vsd.define_any_to_any_acl(vsd_l3domain,
                                       allow_ipv4=True,
                                       allow_ipv6=True)

        self.assert_ping(server1, server2, network, should_pass=True)
        self.assert_ping6(server1, server2, network, should_pass=True)
