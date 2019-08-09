# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPAddress
from netaddr import IPNetwork

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology

from tempest.lib import decorators

LOG = Topology.get_logger(__name__)


class Ipv4L2VsdManagedConnectivityTest(NuageBaseTest):

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
        server2 = self.create_tenant_server([network])
        server1 = self.create_tenant_server([network],
                                            prepare_for_connectivity=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)


class Ipv4L3VsdManagedConnectivityTest(NuageBaseTest):

    @staticmethod
    def get_static_route_data(remote_cidr, local_gw, nic):
        # no static route needed if l3domain has aggregateflows disabled on vsd
        return ''

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_vsd_managed(self):
        # Provision VSD managed network resources
        vsd_l3domain_template = self.vsd_create_l3domain_template()
        vsd_l3domain = self.vsd_create_l3domain(
            template_id=vsd_l3domain_template.id)
        vsd_zone = self.vsd_create_zone(domain=vsd_l3domain)
        vsd_subnet = self.create_vsd_subnet(
            zone=vsd_zone,
            cidr4=self.cidr4, gateway4=self.gateway4)

        self.vsd.define_any_to_any_acl(vsd_l3domain)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        self.create_l3_vsd_managed_subnet(network, vsd_l3domain, vsd_subnet)

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server([network],
                                            prepare_for_connectivity=True)
        server1 = self.create_tenant_server([network],
                                            prepare_for_connectivity=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

    def test_icmp_connectivity_l3_vsd_managed_link_shared_subnet(self):
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

        network1['vsd_l3_domain'] = vsd_l3domain1
        network1['vsd_l3_subnet'] = vsd_subnet1
        network2['vsd_l3_domain'] = vsd_l3domain2
        network2['vsd_l3_subnet'] = vsd_subnet2

        user_data1 = self.get_static_route_data(
            subnet2_cidr, subnet1_gateway, 'eth1')
        user_data2 = self.get_static_route_data(
            subnet1_cidr, subnet2_gateway, 'eth1')

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server([network2],
                                            prepare_for_connectivity=True,
                                            user_data=user_data2)
        server1 = self.create_tenant_server([network1],
                                            prepare_for_connectivity=True,
                                            user_data=user_data1)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network2)


class Ipv4L3VsdManagedConnectivityWithAggrFlowsTest(
        Ipv4L3VsdManagedConnectivityTest):

    enable_aggregate_flows_on_vsd_managed = True

    @staticmethod
    def get_static_route_data(remote_cidr, local_gw, nic):
        return 'route add -net {} gw {} {}\n'.format(remote_cidr,
                                                     local_gw, nic)
