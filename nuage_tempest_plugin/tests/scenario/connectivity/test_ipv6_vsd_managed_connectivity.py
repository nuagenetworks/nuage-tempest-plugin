# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPAddress
from netaddr import IPNetwork
import testtools

from tempest.lib import decorators

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.test.nuage_test import unstable_test
from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()


class Ipv6L2VsdManagedConnectivityTest(NuageBaseTest):

    default_prepare_for_connectivity = True

    def _test_icmp_connectivity_l2_vsd_managed_pure_v6(self, stateful):
        # Provision VSD managed network resources
        l2domain_template = self.vsd_create_l2domain_template(
            ip_type="IPV6",
            cidr6=self.cidr6,
            gateway6=self.gateway6,
            enable_dhcpv6=True)
        vsd_l2domain = self.vsd_create_l2domain(template=l2domain_template)

        self.vsd.define_any_to_any_acl(vsd_l2domain, allow_ipv6=True,
                                       stateful=stateful)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        self.create_l2_vsd_managed_subnet(
            network, vsd_l2domain, ip_version=6, dhcp_managed=True)

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            [network])

        server1 = self.create_tenant_server(
            [network],
            prepare_for_connectivity=True)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network, ip_version=6)

    @testtools.skipIf(not Topology.has_single_stack_v6_support(),
                      'No singe-stack v6 supported')
    def test_icmp_connectivity_stateful_acl_l2_vsd_managed_pure_v6(self):
        self._test_icmp_connectivity_l2_vsd_managed_pure_v6(stateful=True)

    @testtools.skipIf(not Topology.has_single_stack_v6_support(),
                      'No singe-stack v6 supported')
    def test_icmp_connectivity_stateless_acl_l2_vsd_managed_pure_v6(self):
        self._test_icmp_connectivity_l2_vsd_managed_pure_v6(stateful=False)

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
            network, vsd_l2domain, ip_version=6, dhcp_managed=True)

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
        self.assert_ping(server1, server2, network, ip_version=6)


class Ipv6L3VsdManagedConnectivityTest(NuageBaseTest):

    default_prepare_for_connectivity = True

    @classmethod
    def skip_checks(cls):
        super(Ipv6L3VsdManagedConnectivityTest, cls).skip_checks()
        if not Topology.has_single_stack_v6_support():
            msg = 'There is no single-stack v6 support in current release'
            raise cls.skipException(msg)

    @staticmethod
    def get_static_route_data(remote_cidr, local_gw, nic):
        # no static route needed if l3domain has aggregateflows disabled on vsd
        return ''

    def _create_vsd_managed_resources(self):
        # Provision VSD network resources
        vsd_l3domain_template = self.vsd_create_l3domain_template()
        vsd_l3domain = self.vsd_create_l3domain(
            template_id=vsd_l3domain_template.id)
        vsd_zone = self.vsd_create_zone(domain=vsd_l3domain)
        vsd_l3domain_subnet1 = self.create_vsd_subnet(
            zone=vsd_zone,
            ip_type="IPV6",
            cidr6=self.cidr6,
            gateway6=self.gateway6,
            enable_dhcpv6=True)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        self.create_l3_vsd_managed_subnet(
            network, vsd_l3domain_subnet1, ip_version=6)
        return network, vsd_l3domain

    def _test_icmp_connectivity_l3_vsd_managed_pure_v6(self, stateful):
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

        self.vsd.define_any_to_any_acl(vsd_l3domain, allow_ipv6=True,
                                       stateful=stateful)

        # Provision OpenStack network linked to VSD network resources
        network6_1 = self.create_network()
        self.create_l3_vsd_managed_subnet(
            network6_1, vsd_l3domain_subnet6_1, ip_version=6)
        network6_2 = self.create_network()
        self.create_l3_vsd_managed_subnet(
            network6_2, vsd_l3domain_subnet6_2, ip_version=6)

        jump_network = self.create_network()
        jump_subnet = self.create_subnet(jump_network)
        jump_router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.router_attach(jump_router, jump_subnet)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # provision ports
        port6_1 = self.create_port(
            network6_1, security_groups=[ssh_security_group['id']])
        port6_2 = self.create_port(
            network6_2, security_groups=[ssh_security_group['id']])
        j_port_1 = self.create_port(
            jump_network, security_groups=[ssh_security_group['id']])
        j_port_2 = self.create_port(
            jump_network, security_groups=[ssh_security_group['id']])

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            ports=[j_port_2, port6_2])

        server1 = self.create_tenant_server(
            ports=[j_port_1, port6_1],
            prepare_for_connectivity=True)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network6_2, ip_version=6)

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
            network, vsd_subnet, gateway=gateway4, **kwargs)
        self.assertEqual(str(cidr4), ipv4_subnet['cidr'])
        if pool4:
            subnet_pool4 = ipv4_subnet['allocation_pools']
            self.assertEqual(1, len(subnet_pool4))
            self.assertEqual(pool4, subnet_pool4[0])

        # v6
        kwargs = {'allocation_pools': [pool6]} if pool6 else {}
        ipv6_subnet = self.create_l3_vsd_managed_subnet(
            network, vsd_subnet, dhcp_managed=False, ip_version=6,
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
        self.assert_ping(server1, server2, network2, ip_version=6)

        if incl_negative_ping_test:
            # Allow IPv6 only
            self.vsd.define_any_to_any_acl(vsd_domain,
                                           allow_ipv4=False,
                                           allow_ipv6=True)

            self.assert_ping(server1, server2, network2, should_pass=False)
            self.assert_ping(server1, server2, network2, ip_version=6)

        if incl_negative_ping_test:
            # Allow IPv4 only
            self.vsd.define_any_to_any_acl(vsd_domain,
                                           allow_ipv4=True,
                                           allow_ipv6=False)

            self.assert_ping(server1, server2, network2)
            self.assert_ping(server1, server2, network2,
                             ip_version=6, should_pass=False)

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

    def test_icmp_connectivity_stateful_acl_l3_vsd_managed_pure_v6(self):
        self._test_icmp_connectivity_l3_vsd_managed_pure_v6(stateful=True)

    def test_icmp_connectivity_stateless_acl_l3_vsd_managed_pure_v6(self):
        self._test_icmp_connectivity_l3_vsd_managed_pure_v6(stateful=False)

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

        user_data1 = self.get_static_route_data(
            subnet2_cidr, subnet1_gateway, 'eth1')
        user_data2 = self.get_static_route_data(
            subnet1_cidr, subnet2_gateway, 'eth1')

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server([network2],
                                            user_data=user_data2)
        server1 = self.create_tenant_server([network1],
                                            prepare_for_connectivity=True,
                                            user_data=user_data1)

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

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server([network2])
        server1 = self.create_tenant_server([network1],
                                            prepare_for_connectivity=True)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network2, ip_version=6)

    @decorators.attr(type='smoke')
    @unstable_test(bug='OPENSTACK-2782')
    def test_tcp_connectivity_stateful_acl_l3_vsd_managed_ipv6(self):
        network, vsd_l3domain = self._create_vsd_managed_resources()
        ingress_tpl, egress_tpl = self.vsd.create_acl_templates(vsd_l3domain)

        # Launch tenant servers in OpenStack network
        web_server = self.create_tenant_server(
            [network], prepare_for_connectivity=True)
        client_server = self.create_tenant_server(
            [network], prepare_for_connectivity=True)

        self.vsd.define_ssh_acl(ingress_tpl=ingress_tpl, egress_tpl=egress_tpl)
        self.start_web_server(web_server, port=80)

        self.assert_tcp_connectivity(client_server, web_server,
                                     is_connectivity_expected=False,
                                     source_port=None,
                                     destination_port=80,
                                     ip_version=6,
                                     network_name=network['name'])
        self.vsd.define_tcp_acl(direction='egress', acl_template=egress_tpl,
                                ip_version=6)
        self.assert_tcp_connectivity(client_server, web_server,
                                     is_connectivity_expected=False,
                                     source_port=None,
                                     destination_port=80,
                                     ip_version=6,
                                     network_name=network['name'])
        self.vsd.define_tcp_acl(direction='ingress', acl_template=ingress_tpl,
                                ip_version=6, s_port='*', d_port='80')
        self.assert_tcp_connectivity(client_server, web_server,
                                     is_connectivity_expected=True,
                                     source_port=None,
                                     destination_port=80,
                                     ip_version=6,
                                     network_name=network['name'])

    @decorators.attr(type='smoke')
    @unstable_test(bug='OPENSTACK-2782')
    def test_tcp_connectivity_stateless_acl_l3_vsd_managed_ipv6(self):
        network, vsd_l3domain = self._create_vsd_managed_resources()
        ingress_tpl, egress_tpl = self.vsd.create_acl_templates(vsd_l3domain)

        client_port = self.create_port(network)
        web_server_port = self.create_port(network)

        # Launch tenant servers in OpenStack network
        web_server = self.create_tenant_server(
            ports=[web_server_port], prepare_for_connectivity=True)
        client_server = self.create_tenant_server(
            ports=[client_port], prepare_for_connectivity=True)

        self.vsd.define_ssh_acl(ingress_tpl=ingress_tpl, egress_tpl=egress_tpl,
                                stateful=False)
        self.start_web_server(web_server, port=80)

        self.assert_tcp_connectivity(client_server, web_server,
                                     is_connectivity_expected=False,
                                     source_port=None,
                                     destination_port=80,
                                     ip_version=6,
                                     network_name=network['name'])

        client_pg = self.vsd.create_policy_group(vsd_l3domain,
                                                 name="client_pg")
        web_server_pg = self.vsd.create_policy_group(vsd_l3domain,
                                                     name="web_server_pg")
        self.update_port(client_port,
                         **{'nuage_policy_groups': [client_pg.id]})
        self.update_port(web_server_port,
                         **{'nuage_policy_groups': [web_server_pg.id]})

        self.vsd.define_tcp_acl(
            direction='egress', acl_template=egress_tpl, ip_version=6,
            s_port='80', d_port='*', stateful=False,
            location_type='POLICYGROUP', location_id=client_pg.id)
        self.vsd.define_tcp_acl(
            direction='ingress', acl_template=ingress_tpl, ip_version=6,
            s_port='*', d_port='80', stateful=False,
            location_type='POLICYGROUP', location_id=client_pg.id)
        self.vsd.define_tcp_acl(
            direction='egress', acl_template=egress_tpl, ip_version=6,
            s_port='*', d_port='80', stateful=False,
            location_type='POLICYGROUP', location_id=web_server_pg.id)
        self.vsd.define_tcp_acl(
            direction='ingress', acl_template=ingress_tpl, ip_version=6,
            s_port='80', d_port='*', stateful=False,
            location_type='POLICYGROUP', location_id=web_server_pg.id)

        self.assert_tcp_connectivity(client_server, web_server,
                                     is_connectivity_expected=True,
                                     source_port=None,
                                     destination_port=80,
                                     ip_version=6,
                                     network_name=network['name'])


class Ipv6L3VsdManagedConnectivityWithAggrFlowsTest(
        Ipv6L3VsdManagedConnectivityTest):

    enable_aggregate_flows_on_vsd_managed = True

    @staticmethod
    def get_static_route_data(remote_cidr, local_gw, nic):
        return 'route add -net {} gw {} {}\n'.format(remote_cidr,
                                                     local_gw, nic)

    def test_icmp_connectivity_l3_vsd_managed_dualstack_linked_networks(self):
        self.skipTest('Skip for aggregate flows')   # not worth it, skip

    def test_tcp_connectivity_stateful_acl_l3_vsd_managed_ipv6(self):
        self.skipTest('Stateful acl entry not supported in aggregate flow '
                      'enabled Domain')

    def test_icmp_connectivity_stateful_acl_l3_vsd_managed_pure_v6(self):
        self.skipTest('Stateful acl entry not supported in aggregate flow '
                      'enabled Domain')
