# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPAddress
from netaddr import IPNetwork

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.test.nuage_test import unstable_test
from nuage_tempest_plugin.lib.topology import Topology

from tempest.lib import decorators

LOG = Topology.get_logger(__name__)


class Ipv4L2VsdManagedConnectivityTest(NuageBaseTest):

    default_prepare_for_connectivity = True

    def _test_icmp_connectivity_l2_vsd_managed(self, stateful):
        # Provision VSD managed network resources
        l2domain_template = self.vsd_create_l2domain_template(
            cidr4=self.cidr4,
            gateway4=self.gateway4,
            mask_bits=self.mask_bits4)
        l2domain = self.vsd_create_l2domain(template=l2domain_template)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        self.create_l2_vsd_managed_subnet(network, l2domain)

        self.vsd.define_any_to_any_acl(l2domain, stateful=stateful)
        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server([network])
        server1 = self.create_tenant_server([network],
                                            prepare_for_connectivity=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

    def test_icmp_connectivity_stateful_acl_l2_vsd_managed(self):
        self._test_icmp_connectivity_l2_vsd_managed(stateful=True)

    def test_icmp_connectivity_stateless_acl_l2_vsd_managed(self):
        self._test_icmp_connectivity_l2_vsd_managed(stateful=False)


class Ipv4L3VsdManagedConnectivityTest(NuageBaseTest):

    default_prepare_for_connectivity = True

    @staticmethod
    def get_static_route_data(remote_cidr, local_gw, nic):
        # no static route needed if l3domain has aggregateflows disabled on vsd
        return ''

    def _create_vsd_managed_resources(self):
        # Provision VSD managed network resources
        vsd_l3domain_template = self.vsd_create_l3domain_template()
        vsd_l3domain = self.vsd_create_l3domain(
            template_id=vsd_l3domain_template.id)
        vsd_zone = self.vsd_create_zone(domain=vsd_l3domain)
        vsd_subnet = self.create_vsd_subnet(
            zone=vsd_zone,
            cidr4=self.cidr4, gateway4=self.gateway4)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        self.create_l3_vsd_managed_subnet(network, vsd_subnet)
        return vsd_l3domain, network

    def _test_icmp_connectivity_l3_vsd_managed(self, stateful):
        vsd_l3domain, network = self._create_vsd_managed_resources()
        self.vsd.define_any_to_any_acl(vsd_l3domain, stateful=stateful)

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server([network],
                                            prepare_for_connectivity=True)
        server1 = self.create_tenant_server([network],
                                            prepare_for_connectivity=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_stateful_acl_l3_vsd_managed(self):
        self._test_icmp_connectivity_l3_vsd_managed(stateful=True)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_stateless_acl_l3_vsd_managed(self):
        self._test_icmp_connectivity_l3_vsd_managed(stateful=False)

    def test_icmp_connectivity_l3_vsd_managed_link_shared_subnet(
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
        subnet2_cidr = IPNetwork('10.10.2.0/24')
        subnet2_gateway = str(IPAddress(subnet2_cidr) + 1)
        vsd_shared_subnet1 = self.create_vsd_subnet(
            ip_type='IPV4',
            zone=vsd_zone,
            cidr4=subnet1_cidr, gateway4=subnet1_gateway,
            resource_type='PUBLIC')
        vsd_shared_subnet2 = self.create_vsd_subnet(
            ip_type='IPV4',
            zone=vsd_zone,
            cidr4=subnet2_cidr, gateway4=subnet2_gateway,
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
            cidr=subnet1_cidr, mask_bits=24, gateway=subnet1_gateway,
            nuagenet=vsd_subnet1.id)
        self.create_subnet(
            network2,
            cidr=subnet2_cidr, mask_bits=24, gateway=subnet2_gateway,
            nuagenet=vsd_subnet2.id)

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

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network2)

    @decorators.attr(type='smoke')
    @unstable_test(bug='OPENSTACK-2782')
    def test_tcp_connectivity_stateful_acl_l3_vsd_managed(self):
        vsd_l3domain, network = self._create_vsd_managed_resources()
        ingress_tpl, egress_tpl = self.vsd.create_acl_templates(vsd_l3domain)

        # Launch tenant servers in OpenStack network
        web_server = self.create_tenant_server(
            [network], prepare_for_connectivity=True)
        client_server = self.create_tenant_server(
            [network], prepare_for_connectivity=True)

        self.vsd.define_ssh_acl(ingress_tpl=ingress_tpl, egress_tpl=egress_tpl,
                                stateful=True)
        self.start_web_server(web_server, port=80)

        self.assert_tcp_connectivity(client_server, web_server,
                                     is_connectivity_expected=False,
                                     source_port=None,
                                     destination_port=80,
                                     ip_version=4,
                                     network_name=network['name'])
        self.vsd.define_tcp_acl(direction='egress', acl_template=egress_tpl,
                                ip_version=4)
        self.assert_tcp_connectivity(client_server, web_server,
                                     is_connectivity_expected=False,
                                     source_port=None,
                                     destination_port=80,
                                     ip_version=4,
                                     network_name=network['name'])
        self.vsd.define_tcp_acl(direction='ingress', acl_template=ingress_tpl,
                                ip_version=4)
        self.assert_tcp_connectivity(client_server, web_server,
                                     is_connectivity_expected=True,
                                     source_port=None,
                                     destination_port=80,
                                     ip_version=4,
                                     network_name=network['name'])

    @decorators.attr(type='smoke')
    @unstable_test(bug='OPENSTACK-2782')
    def test_tcp_connectivity_stateless_acl_l3_vsd_managed(self):
        vsd_l3domain, network = self._create_vsd_managed_resources()
        ingress_tpl, egress_tpl = self.vsd.create_acl_templates(vsd_l3domain)

        # Launch tenant servers in OpenStack network
        web_server = self.create_tenant_server(
            [network], prepare_for_connectivity=True)
        client_server = self.create_tenant_server(
            [network], prepare_for_connectivity=True)

        self.vsd.define_ssh_acl(ingress_tpl=ingress_tpl, egress_tpl=egress_tpl,
                                stateful=False)
        self.start_web_server(web_server, port=80)

        self.assert_tcp_connectivity(client_server, web_server,
                                     is_connectivity_expected=False,
                                     source_port=None,
                                     destination_port=80,
                                     ip_version=4,
                                     network_name=network['name'])
        client_port = self.get_server_port_in_network(client_server,
                                                      network)
        web_server_port = self.get_server_port_in_network(web_server,
                                                          network)
        client_pg = self.vsd.create_policy_group(vsd_l3domain,
                                                 name="client_pg")
        web_server_pg = self.vsd.create_policy_group(vsd_l3domain,
                                                     name="web_server_pg")
        self.update_port(client_port,
                         **{'nuage_policy_groups': [client_pg.id]})
        self.update_port(web_server_port,
                         **{'nuage_policy_groups': [web_server_pg.id]})

        self.vsd.define_tcp_acl(
            direction='egress', acl_template=egress_tpl, ip_version=4,
            s_port='80', d_port='*', stateful=False,
            location_type='POLICYGROUP', location_id=client_pg.id)
        self.vsd.define_tcp_acl(
            direction='ingress', acl_template=ingress_tpl, ip_version=4,
            s_port='*', d_port='80', stateful=False,
            location_type='POLICYGROUP', location_id=client_pg.id)
        self.vsd.define_tcp_acl(
            direction='egress', acl_template=egress_tpl, ip_version=4,
            s_port='*', d_port='80', stateful=False,
            location_type='POLICYGROUP', location_id=web_server_pg.id)
        self.vsd.define_tcp_acl(
            direction='ingress', acl_template=ingress_tpl, ip_version=4,
            s_port='80', d_port='*', stateful=False,
            location_type='POLICYGROUP', location_id=web_server_pg.id)

        self.assert_tcp_connectivity(client_server, web_server,
                                     is_connectivity_expected=True,
                                     source_port=None,
                                     destination_port=80,
                                     ip_version=4,
                                     network_name=network['name'])


class Ipv4L3VsdManagedConnectivityWithAggrFlowsTest(
        Ipv4L3VsdManagedConnectivityTest):

    enable_aggregate_flows_on_vsd_managed = True

    @staticmethod
    def get_static_route_data(remote_cidr, local_gw, nic):
        return 'route add -net {} gw {} {}\n'.format(remote_cidr,
                                                     local_gw, nic)

    def test_tcp_connectivity_stateful_acl_l3_vsd_managed(self):
        self.skipTest('Stateful acl entry not supported in aggregate flow '
                      'enabled Domain')

    def test_icmp_connectivity_stateful_acl_l3_vsd_managed(self):
        self.skipTest('Stateful acl entry not supported in aggregate flow '
                      'enabled Domain')
