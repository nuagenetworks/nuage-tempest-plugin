# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

import os

from netaddr import IPAddress

from tempest.lib.common.utils import data_utils
from tempest.test import decorators

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES
from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseOrchestrationTest
from nuage_tempest_plugin.lib.test.nuage_test import TenantServer
from nuage_tempest_plugin.lib.topology import Topology

LOG = Topology.get_logger(__name__)


class OsManagedDualStackOrchestrationTest(NuageBaseOrchestrationTest):

    @classmethod
    def skip_checks(cls):
        super(OsManagedDualStackOrchestrationTest, cls).skip_checks()
        if not NUAGE_FEATURES.os_managed_dualstack_subnets:
            raise cls.skipException(
                'OS Managed Dual Stack is not supported in this release')

    @classmethod
    def get_full_template_path(cls, name, ext='yaml'):
        loc = ["templates", "%s.%s" % (name, ext)]
        return os.path.join(os.path.dirname(__file__), *loc)

    def get_resource_network(self, resource_name):
        resource = self.test_resources.get(resource_name)
        network_id = resource['physical_resource_id']
        network = self.admin_manager.networks_client.show_network(network_id)
        network = network['network']
        return network

    def get_resource_subnet(self, resource_name):
        resource = self.test_resources.get(resource_name)
        subnet_id = resource['physical_resource_id']
        subnet = self.admin_manager.subnets_client.show_subnet(subnet_id)
        return subnet['subnet']

    def get_resource_server(self, resource_name):
        resource = self.test_resources.get(resource_name)
        server_id = resource['physical_resource_id']
        server = TenantServer(self, self.manager.servers_client,
                              self.admin_manager.servers_client)
        server.sync_with(server_id)
        return server

    @decorators.attr(type='slow')
    @nuage_test.header()
    def test_dualstack_openstack_managed_subnets(self):
        # launch a heat stack
        stack_file_name = 'nuage_os_managed_network_dualstack_vm_on_port'
        stack_parameters = {
            'net_name': self.private_net_name,
            'cidr4': str(self.cidr4),
            'gateway4': self.gateway4,
            'maskbits4': self.mask_bits4,
            'cidr6': str(self.cidr6),
            'gateway6': self.gateway6,
            'maskbits6': self.mask_bits6,
            'pool_start6': str(IPAddress(self.gateway6) + 1),
            'pool_end6': str(IPAddress(self.cidr6.last))
        }

        self.launch_stack(stack_file_name, stack_parameters)

        # Verifies created resources
        expected_resources = ['dualstack_net', 'subnet4', 'subnet6', 'port1',
                              'vm1', 'port2', 'vm2']
        self.verify_stack_resources(
            expected_resources, self.template_resources, self.test_resources)

        network = self.get_resource_network('dualstack_net')
        ipv6_subnet = self.get_resource_subnet('subnet6')
        server1 = self.get_resource_server('vm1')
        server2 = self.get_resource_server('vm2')

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network, should_pass=True)

        # Define IPv6 interface in the guest VMs
        # as VSP does not support DHCPv6 for IPv6 addresses
        server1_ipv6 = server1.get_server_ip_in_network(
            network['name'], ip_type=6)
        server2_ipv6 = server2.get_server_ip_in_network(
            network['name'], ip_type=6)

        server1.configure_dualstack_interface(
            server1_ipv6, subnet=ipv6_subnet, device="eth0", )
        server2.configure_dualstack_interface(
            server2_ipv6, subnet=ipv6_subnet, device="eth0", )

        # Test IPv6 connectivity between peer servers
        self.assert_ping6(server1, server2, network)

        pass

    @decorators.attr(type='slow')
    @decorators.attr(type='scale')
    @nuage_test.header()
    def test_dualstack_openstack_managed_ports_scale(self):
        # launch a heat stack
        stack_file_name = 'nuage_os_managed_network_dualstack_vm_on_port'
        stack_parameters = {
            'net_name': self.private_net_name,
            'cidr4': str(self.cidr4),
            'gateway4': self.gateway4,
            'maskbits4': self.mask_bits4,
            'cidr6': str(self.cidr6),
            'gateway6': self.gateway6,
            'maskbits6': self.mask_bits6,
            'pool_start6': str(IPAddress(self.gateway6) + 1),
            'pool_end6': str(IPAddress(self.cidr6.last))
        }

        stack_name = data_utils.rand_name('heat-' + stack_file_name)
        template = self.read_template(stack_file_name)

        ports_template = ""
        port_resources = []
        port_template = """  port%s:
    type: OS::Neutron::Port
    properties:
      network: { get_resource: dualstack_net }
      name: 'dualstack-port'
      fixed_ips: [ { subnet: { get_resource: subnet4 } },
                   { subnet: { get_resource: subnet6 } } ]
"""
        for i in range(1, 50):
            ports_template = ports_template + (port_template % i)
            port_resources.append("port%s" % i)

        template = template + ports_template

        self.launch_stack_template(stack_name, template, stack_parameters)

        # Verifies created resources
        expected_resources = ['dualstack_net', 'subnet4', 'subnet6', 'port1',
                              'vm1', 'port2', 'vm2']
        self.verify_stack_resources(
            expected_resources, self.template_resources, self.test_resources)

        # Verifies created ports
        self.verify_stack_resources(
            port_resources, self.template_resources, self.test_resources)

        pass

    @decorators.attr(type='slow')
    @nuage_test.header()
    def test_dualstack_openstack_managed_l3_subnets(self):
        # launch a heat stack
        stack_file_name = 'nuage_os_managed_network_l3_dualstack_vm_on_port'
        stack_parameters = {
            'net_name': self.private_net_name,
            'cidr4': str(self.cidr4),
            'gateway4': self.gateway4,
            'maskbits4': self.mask_bits4,
            'cidr6': str(self.cidr6),
            'gateway6': self.gateway6,
            'maskbits6': self.mask_bits6,
            'pool_start6': str(IPAddress(self.gateway6) + 1),
            'pool_end6': str(IPAddress(self.cidr6.last))
        }

        stack_name = data_utils.rand_name('heat-' + stack_file_name)
        template = self.read_template(stack_file_name)

        ports_template = ""
        port_resources = []
        port_template = """  port%s:
    type: OS::Neutron::Port
    properties:
      network: { get_resource: dualstack_net }
      name: 'dualstack-port'
      fixed_ips: [ { subnet: { get_resource: subnet4 } },
                   { subnet: { get_resource: subnet6 } } ]
"""
        for i in range(3, 10):
            ports_template = ports_template + (port_template % i)
            port_resources.append("port%s" % i)

        template = template + ports_template

        self.launch_stack_template(stack_name, template, stack_parameters)

        # Verifies created resources
        expected_resources = ['dualstack_net', 'subnet4', 'subnet6', 'port1',
                              'vm1', 'port2', 'vm2', 'router',
                              "vm_security_group"]
        self.verify_stack_resources(
            expected_resources, self.template_resources, self.test_resources)

        # Verifies created ports
        self.verify_stack_resources(
            port_resources, self.template_resources, self.test_resources)

        pass
