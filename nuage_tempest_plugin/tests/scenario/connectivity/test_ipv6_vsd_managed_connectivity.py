# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPAddress
from netaddr import IPNetwork

from tempest.lib import decorators

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest


class Ipv6VsdManagedConnectivityTest(NuageBaseTest):

    def test_icmp_connectivity_l2_vsd_managed_dualstack(self):
        # Provision VSD managed network resources
        l2domain_template = self.vsd_create_l2domain_template(
            ip_type="DUALSTACK",
            cidr4=self.cidr4,
            gateway4=self.gateway4,
            cidr6=self.cidr6,
            gateway6=self.gateway6,
            enable_dhcpv6=True)
        vsd_l2domain = self.vsd_create_l2domain(template=l2domain_template)

        self.vsd.define_any_to_any_acl(vsd_l2domain, allow_ipv6=True)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        self.create_l2_vsd_managed_subnet(network, vsd_l2domain)
        self.create_l2_vsd_managed_subnet(
            network, vsd_l2domain, ip_version=6)

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            [network],
            prepare_for_connectivity=True)

        server1 = self.create_tenant_server(
            [network],
            prepare_for_connectivity=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network, ip_type=6)

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
        server1 = self.create_tenant_server(
            [network],
            prepare_for_connectivity=True)

        if skip_server2_and_ping_tests:
            return vsd_domain, vsd_subnet, server1

        if server2_pre_set_up:
            server2 = server2_pre_set_up
            network2 = server2.networks[0] if server2.networks else network
        else:
            # Launch tenant server in OpenStack network
            server2 = self.create_tenant_server(
                [network],
                prepare_for_connectivity=True)
            network2 = network

        self.assert_ping(server1, server2, network2)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network2, ip_type=6)

        if incl_negative_ping_test:
            # Allow IPv6 only
            self.vsd.define_any_to_any_acl(vsd_domain,
                                           allow_ipv4=False,
                                           allow_ipv6=True)

            self.assert_ping(server1, server2, network2, should_pass=False)
            self.assert_ping(server1, server2, network2, ip_type=6)

        if incl_negative_ping_test:
            # Allow IPv4 only
            self.vsd.define_any_to_any_acl(vsd_domain,
                                           allow_ipv4=True,
                                           allow_ipv6=False)

            self.assert_ping(server1, server2, network2)
            self.assert_ping(server1, server2, network2,
                             ip_type=6, should_pass=False)

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

    def test_icmp_connectivity_l2_vsd_managed_pure_v6(self):
        # Provision VSD managed network resources
        l2domain_template = self.vsd_create_l2domain_template(
            ip_type="IPV6",
            cidr6=self.cidr6,
            gateway6=self.gateway6,
            enable_dhcpv6=True)
        vsd_l2domain = self.vsd_create_l2domain(template=l2domain_template)

        self.vsd.define_any_to_any_acl(vsd_l2domain, allow_ipv6=True)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        self.create_l2_vsd_managed_subnet(
            network, vsd_l2domain, ip_version=6, dhcp_managed=True)

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            [network],
            prepare_for_connectivity=True)

        server1 = self.create_tenant_server(
            [network],
            prepare_for_connectivity=True)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network, ip_type=6)

    def test_icmp_connectivity_l3_vsd_managed_pure_v6(self):
        # provision nuage resource
        vsd_l3domain_template = self.vsd_create_l3domain_template()
        vsd_l3domain = self.vsd_create_l3domain(
            template_id=vsd_l3domain_template.id)
        vsd_zone = self.vsd_create_zone(domain=vsd_l3domain)

        subnet_ipv6_1_cidr = IPNetwork("2000:5f74:c4a5:b82e::/64")
        subnet_ipv6_1_gateway = str(IPAddress(subnet_ipv6_1_cidr) + 1)
        vsd_l3domain_subnet6_1 = self.create_vsd_subnet(
            zone=vsd_zone,
            ip_type="IPV6",
            cidr6=subnet_ipv6_1_cidr,
            gateway6=subnet_ipv6_1_gateway,
            enable_dhcpv6=True)

        subnet_ipv6_2_cidr = IPNetwork("2001:5f74:c4a5:b82e::/64")
        subnet_ipv6_2_gateway = str(IPAddress(subnet_ipv6_2_cidr) + 1)
        vsd_l3domain_subnet6_2 = self.create_vsd_subnet(
            zone=vsd_zone,
            ip_type="IPV6",
            cidr6=subnet_ipv6_2_cidr,
            gateway6=subnet_ipv6_2_gateway,
            enable_dhcpv6=True)

        subnet_ipv4_cidr = IPNetwork("10.10.10.0/24")
        subnet_ipv4_gateway = str(IPAddress(subnet_ipv4_cidr) + 1)
        vsd_l3domain_subnet4 = self.create_vsd_subnet(
            zone=vsd_zone,
            ip_type="IPV4",
            cidr4=subnet_ipv4_cidr,
            gateway4=subnet_ipv4_gateway)

        self.vsd.define_any_to_any_acl(vsd_l3domain, allow_ipv6=True)

        # Provision OpenStack network linked to VSD network resources
        network6_1 = self.create_network()
        self.create_l3_vsd_managed_subnet(
            network6_1, vsd_l3domain, vsd_l3domain_subnet6_1, ip_version=6)
        network6_2 = self.create_network()
        self.create_l3_vsd_managed_subnet(
            network6_2, vsd_l3domain, vsd_l3domain_subnet6_2, ip_version=6)
        network4 = self.create_network()
        self.create_l3_vsd_managed_subnet(
            network4, vsd_l3domain, vsd_l3domain_subnet4, ip_version=4)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # provision ports
        portv6_1 = self.create_port(network6_1,
                                    security_groups=[ssh_security_group['id']])
        portv6_2 = self.create_port(network6_2,
                                    security_groups=[ssh_security_group['id']])
        portv4 = self.create_port(network4,
                                  security_groups=[ssh_security_group['id']])

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            ports=[portv6_2],
            prepare_for_connectivity=False)

        server1 = self.create_tenant_server(
            ports=[portv4, portv6_1],
            prepare_for_connectivity=False)

        # as VSD managed, simulate a FIP to be present
        self.create_fip_to_server(
            server1, portv4,
            vsd_domain=network4.get('vsd_l3_domain'),
            vsd_subnet=network4.get('vsd_l3_subnet'))

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network6_2, ip_type=6)

    def test_icmp_connectivity_l3_vsd_managed_dualstack_link_shared_subnet(
            self):
        # Provision shared dualstack subnet in shared infrastructure
        shared_vsd_l3domain_template = self.vsd_create_l3domain_template(
            enterprise=self.shared_infrastructure)
        shared_vsd_l3domain = self.vsd_create_l3domain(
            enterprise=self.shared_infrastructure,
            template_id=shared_vsd_l3domain_template.id)
        vsd_zone = self.vsd_create_zone(domain=shared_vsd_l3domain)
        subnet1_cidr = IPNetwork('10.10.1.0/24')
        subnet1_gateway = str(IPAddress(subnet1_cidr) + 1)
        subnet1_ipv6_cidr = IPNetwork('cafe:babe::/64')
        subnet1_ipv6_gateway = str(IPAddress(subnet1_ipv6_cidr) + 1)

        subnet2_cidr = IPNetwork('10.10.2.0/24')
        subnet2_gateway = str(IPAddress(subnet2_cidr) + 1)
        subnet2_ipv6_cidr = IPNetwork('cafe:bab1::/64')
        subnet2_ipv6_gateway = str(IPAddress(subnet2_ipv6_cidr) + 1)

        vsd_shared_subnet1 = self.create_vsd_subnet(
            ip_type='DUALSTACK',
            zone=vsd_zone,
            cidr4=subnet1_cidr,
            gateway4=subnet1_gateway,
            cidr6=subnet1_ipv6_cidr,
            gateway6=subnet1_ipv6_gateway,
            resource_type='PUBLIC')
        vsd_shared_subnet2 = self.create_vsd_subnet(
            ip_type='DUALSTACK',
            zone=vsd_zone,
            cidr4=subnet2_cidr,
            gateway4=subnet2_gateway,
            cidr6=subnet2_ipv6_cidr,
            gateway6=subnet2_ipv6_gateway,
            resource_type='PUBLIC')
        self.vsd.define_any_to_any_acl(shared_vsd_l3domain)

        # Provision vsd managed subnets linking to shared subnet
        vsd_l3domain_template = self.vsd_create_l3domain_template()
        vsd_l3domain1 = self.vsd_create_l3domain(
            template_id=vsd_l3domain_template.id)
        vsd_shared_zone1 = self.vsd_create_zone(domain=vsd_l3domain1,
                                                public_zone=True)
        vsd_subnet1 = self.create_vsd_subnet(
            zone=vsd_shared_zone1,
            associated_shared_network_resource_id=vsd_shared_subnet1.id)
        vsd_l3domain2 = self.vsd_create_l3domain(
            template_id=vsd_l3domain_template.id)
        vsd_shared_zone2 = self.vsd_create_zone(domain=vsd_l3domain2,
                                                public_zone=True)
        vsd_subnet2 = self.create_vsd_subnet(
            zone=vsd_shared_zone2,
            associated_shared_network_resource_id=vsd_shared_subnet2.id)

        self.vsd.define_any_to_any_acl(vsd_l3domain1)
        self.vsd.define_any_to_any_acl(vsd_l3domain2)

        # Provision OpenStack network linked to VSD network resources
        network1 = self.create_network()
        network2 = self.create_network()

        self.create_subnet(
            network1,
            cidr=subnet1_cidr,
            mask_bits=24,
            nuagenet=vsd_subnet1.id,
            gateway=subnet1_gateway)

        self.create_subnet(
            network1,
            ip_version=6,
            cidr=subnet1_ipv6_cidr,
            mask_bits=64,
            nuagenet=vsd_subnet1.id,
            gateway=subnet1_ipv6_gateway,
            enable_dhcp=False)

        self.create_subnet(
            network2,
            cidr=subnet2_cidr,
            mask_bits=24,
            nuagenet=vsd_subnet2.id,
            gateway=subnet2_gateway)

        self.create_subnet(
            network2,
            ip_version=6,
            cidr=subnet2_ipv6_cidr,
            mask_bits=64,
            nuagenet=vsd_subnet2.id,
            gateway=subnet2_ipv6_gateway,
            enable_dhcp=False)

        network1['vsd_l3_domain'] = vsd_l3domain1
        network1['vsd_l3_subnet'] = vsd_subnet1
        network2['vsd_l3_domain'] = vsd_l3domain2
        network2['vsd_l3_subnet'] = vsd_subnet2

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server([network2],
                                            prepare_for_connectivity=True)
        server1 = self.create_tenant_server([network1],
                                            prepare_for_connectivity=True)

        # Test dualstack connectivity between peer servers
        self.assert_ping(server1, server2, network2)

    def test_icmp_connectivity_l3_vsd_managed_link_shared_subnet_pure_v6(self):
        # Provision shared v6 subnet in shared infrastructure
        shared_vsd_l3domain_template = self.vsd_create_l3domain_template(
            enterprise=self.shared_infrastructure)
        shared_vsd_l3domain = self.vsd_create_l3domain(
            enterprise=self.shared_infrastructure,
            template_id=shared_vsd_l3domain_template.id)
        vsd_zone = self.vsd_create_zone(domain=shared_vsd_l3domain)
        subnet1_cidr = IPNetwork('cafe:babe::/64')
        subnet1_gateway = str(IPAddress(subnet1_cidr) + 1)
        subnet2_cidr = IPNetwork('cafe:baba::/64')
        subnet2_gateway = str(IPAddress(subnet2_cidr) + 1)
        vsd_shared_subnet1 = self.create_vsd_subnet(
            ip_type='IPV6',
            zone=vsd_zone,
            cidr6=subnet1_cidr, gateway6=subnet1_gateway,
            resource_type='PUBLIC',
            enable_dhcpv6=True)
        vsd_shared_subnet2 = self.create_vsd_subnet(
            ip_type='IPV6',
            zone=vsd_zone,
            cidr6=subnet2_cidr, gateway6=subnet2_gateway,
            resource_type='PUBLIC',
            enable_dhcpv6=True)
        self.vsd.define_any_to_any_acl(shared_vsd_l3domain, allow_ipv6=True)

        # Provision vsd managed subnets linking to shared subnet
        vsd_l3domain_template = self.vsd_create_l3domain_template()
        vsd_l3domain1 = self.vsd_create_l3domain(
            template_id=vsd_l3domain_template.id)
        vsd_shared_zone1 = self.vsd_create_zone(domain=vsd_l3domain1,
                                                public_zone=True)
        vsd_subnet1 = self.create_vsd_subnet(
            zone=vsd_shared_zone1,
            associated_shared_network_resource_id=vsd_shared_subnet1.id)
        vsd_l3domain2 = self.vsd_create_l3domain(
            template_id=vsd_l3domain_template.id)
        vsd_shared_zone2 = self.vsd_create_zone(domain=vsd_l3domain2,
                                                public_zone=True)
        vsd_subnet2 = self.create_vsd_subnet(
            zone=vsd_shared_zone2,
            associated_shared_network_resource_id=vsd_shared_subnet2.id)

        self.vsd.define_any_to_any_acl(vsd_l3domain1, allow_ipv6=True)
        self.vsd.define_any_to_any_acl(vsd_l3domain2, allow_ipv6=True)

        # Provision OpenStack network linked to VSD network resources
        network1 = self.create_network()
        network2 = self.create_network()
        self.create_subnet(
            network1,
            cidr=subnet1_cidr, mask_bits=64, gateway=subnet1_gateway,
            nuagenet=vsd_subnet1.id, ip_version=6)
        self.create_subnet(
            network2,
            cidr=subnet2_cidr, mask_bits=64, gateway=subnet2_gateway,
            nuagenet=vsd_subnet2.id, ip_version=6)

        network1['vsd_l3_domain'] = vsd_l3domain1
        network1['vsd_l3_subnet'] = vsd_subnet1
        network2['vsd_l3_domain'] = vsd_l3domain2
        network2['vsd_l3_subnet'] = vsd_subnet2

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server([network2],
                                            prepare_for_connectivity=True)
        server1 = self.create_tenant_server([network1],
                                            prepare_for_connectivity=True)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network2, ip_type=6)
