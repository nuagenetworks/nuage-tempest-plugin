# Copyright 2017 - Nokia
# All Rights Reserved.

import testtools

from netaddr import IPNetwork

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology

from tempest.lib import decorators

LOG = Topology.get_logger(__name__)


class Ipv4VsdManagedConnectivityTest(NuageBaseTest):

    @decorators.attr(type='smoke')
    @testtools.skipIf(not Topology.run_connectivity_tests(),
                      'Connectivity tests are disabled.')
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
        subnet = self.create_l2_vsd_managed_subnet(network, l2domain,
                                                   dhcp_option_3=None)
        self.assertIsNotNone(subnet)

        # Create open-ssh sg (allow icmp and ssh from anywhere)
        ssh_security_group = self._create_security_group(
            namestart='tempest-open-ssh')

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])

        server3 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])

        server4 = self.create_tenant_server(
            tenant_networks=[network],
            security_groups=[{'name': ssh_security_group['name']}])

        server1 = self.create_reachable_tenant_server_in_l2_network(
            network, ssh_security_group)

        # Test IPv4 connectivity between peer servers
        success_rate = int(self.assert_ping(
            server1, server2, network,
            return_boolean_to_indicate_success=True))
        success_rate += int(self.assert_ping(
            server1, server3, network,
            return_boolean_to_indicate_success=True))
        success_rate += int(self.assert_ping(
            server1, server4, network,
            return_boolean_to_indicate_success=True))

        self.assertEqual(3, success_rate, 'Success rate not met!')

    @testtools.skipIf(not Topology.run_connectivity_tests(),
                      'Connectivity tests are disabled.')
    @decorators.attr(type='smoke')
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
