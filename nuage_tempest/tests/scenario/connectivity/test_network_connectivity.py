# Copyright 2017 - Nokia
# All Rights Reserved.

import testtools

from netaddr import IPNetwork
from oslo_log import log as logging

from nuage_tempest.lib.test.nuage_test import NuageBaseTest
from nuage_tempest.lib.topology import Topology

from tempest.lib import decorators


class Ipv4ConnectivityTest(NuageBaseTest):

    LOG = logging.getLogger(__name__)

    @testtools.skipIf(Topology.is_devstack(),
                      'Access to vm\'s in l2 networks is unsupported.')
    def test_icmp_connectivity_os_managed_l2_domain(self):
        # Provision OpenStack network resources
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.assertIsNotNone(subnet)

        # Create open-ssh sg (allow icmp and ssh from anywhere)
        ssh_security_group = self._create_security_group(
            namestart='tempest-open-ssh')

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])
        server2 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_os_managed_l3_domain(self):
        # Provision OpenStack network resources
        router = self.create_test_router()
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.router_attach(router, subnet)

        # Create open-ssh sg (allow icmp and ssh from anywhere)
        ssh_security_group = self._create_security_group(
            namestart='tempest-open-ssh')

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])
        server2 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])

        self.prepare_for_ping_test(server1)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

    @decorators.attr(type='smoke')
    @testtools.skipIf(Topology.is_devstack(),
                      'Test is duplicate.')  # in dev ci,this test == above one
    def test_icmp_connectivity_os_managed_l3_domain_using_fip(self):
        # This is same test as above but also on testbed enforces use of FIP
        # Provision OpenStack network resources
        router = self.create_test_router()
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.router_attach(router, subnet)

        # Create open-ssh sg (allow icmp and ssh from anywhere)
        ssh_security_group = self._create_security_group(
            namestart='tempest-open-ssh')

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])
        server2 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])

        # create FIP
        self.create_fip_to_server(server1)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

    def test_icmp_connectivity_os_managed_l3_domain_neg(self):
        # Provision OpenStack network resources
        router = self.create_test_router()
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.router_attach(router, subnet)

        # create open-ssh sg (allow icmp and ssh from anywhere)
        ssh_security_group = self._create_security_group(
            namestart='tempest-open-ssh')

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])
        server2 = self.create_tenant_server(
            tenant_networks=[network])  # in default sg - so not accessible!

        self.prepare_for_ping_test(server1)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network, should_pass=False)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_os_managed_l3_domain_dual_nic(self):
        # Provision OpenStack network resources
        router = self.create_test_router()
        network1 = self.create_network()
        subnet1 = self.create_subnet(network1,
                                     gateway='10.10.1.1',
                                     cidr=IPNetwork('10.10.1.0/24'),
                                     mask_bits=24)
        self.router_attach(router, subnet1)

        network2 = self.create_network()
        self.create_subnet(network2,
                           gateway='10.10.2.1',
                           cidr=IPNetwork('10.10.2.0/24'),
                           mask_bits=24)

        # Create open-ssh sg (allow icmp and ssh from anywhere)
        ssh_security_group = self._create_security_group(
            namestart='tempest-open-ssh')

        # Launch tenant servers in OpenStack network
        server12 = self.create_tenant_server(
            tenant_networks=[network1, network2],
            security_groups=[{'name': ssh_security_group['name']}])

        server12_p1 = self.osc_get_server_port_in_network(server12, network1)

        server1 = self.create_tenant_server(
            tenant_networks=[network1],
            security_groups=[{'name': ssh_security_group['name']}])
        server2 = self.create_tenant_server(
            tenant_networks=[network2],
            security_groups=[{'name': ssh_security_group['name']}])

        self.prepare_for_ping_test(server12, server12_p1)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server12, server1, network1)
        self.assert_ping(server12, server2, network2)

    def test_icmp_connectivity_vsd_managed_l2_domain(self):
        # Provision VSD managed network resources
        l2domain_template = self.vsd.create_l2domain_template(
            cidr4=self.cidr4,
            gateway4=self.gateway4,
            mask_bits=self.mask_bits4)
        self.addCleanup(l2domain_template.delete)

        l2domain = self.vsd.create_l2domain(template=l2domain_template)
        self.addCleanup(l2domain.delete)

        self.vsd.define_any_to_any_acl(l2domain)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        subnet = self.create_l2_vsd_managed_subnet(network, l2domain)
        self.assertIsNotNone(subnet)

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(tenant_networks=[network])
        server2 = self.create_tenant_server(tenant_networks=[network])

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

    def test_icmp_connectivity_vsd_managed_l3_domain(self):
        # Provision VSD managed network resources
        vsd_l3domain_template = self.vsd.create_l3domain_template()
        self.addCleanup(vsd_l3domain_template.delete)

        vsd_l3domain = self.vsd.create_l3domain(
            template_id=vsd_l3domain_template.id)
        self.addCleanup(vsd_l3domain.delete)

        vsd_zone = self.vsd.create_zone(domain=vsd_l3domain)
        self.addCleanup(vsd_zone.delete)

        vsd_l3domain_subnet = self.vsd.create_subnet(
            zone=vsd_zone,
            cidr4=self.cidr4,
            gateway4=self.gateway4)
        self.addCleanup(vsd_l3domain_subnet.delete)

        self.vsd.define_any_to_any_acl(vsd_l3domain)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        cidr = IPNetwork(vsd_l3domain_subnet.address + "/" +
                         vsd_l3domain_subnet.netmask)

        subnet = self.create_subnet(
            network,
            cidr=cidr,
            mask_bits=cidr.prefixlen,
            gateway=vsd_l3domain_subnet.gateway,
            nuagenet=vsd_l3domain_subnet.id,
            net_partition=self.vsd.default_netpartition_name)
        self.assertIsNotNone(subnet)

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(tenant_networks=[network])
        server2 = self.create_tenant_server(tenant_networks=[network])

        server1_port = self.osc_get_server_port_in_network(server1, network)
        self.prepare_for_ping_test(server1, server1_port,
                                   vsd_domain=vsd_l3domain,
                                   vsd_subnet=vsd_l3domain_subnet)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)
