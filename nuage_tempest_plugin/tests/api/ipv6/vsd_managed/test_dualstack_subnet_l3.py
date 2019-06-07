# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPAddress
from netaddr import IPNetwork

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.test import tags
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.tests.api.ipv6.vsd_managed.base_nuage_networks \
    import BaseVSDManagedNetworksIPv6Test

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as tempest_exceptions

MSG_INVALID_GATEWAY = "Invalid IPv6 network gateway"
MSG_INVALID_IPV6_ADDRESS = "Invalid network IPv6 address"
MSG_IP_ADDRESS_INVALID_OR_RESERVED = "IP Address is not valid or cannot be " \
                                     "in reserved address space"


@nuage_test.class_header(tags=[tags.ML2])
class VSDManagedDualStackSubnetL3Test(BaseVSDManagedNetworksIPv6Test):

    ###########################################################################
    # Typical cases
    ###########################################################################
    @decorators.attr(type='smoke')
    def test_create_ipv6_subnet_in_vsd_managed_l3domain(self):
        name = data_utils.rand_name('l3domain-')
        vsd_l3domain_template = self.vsd_create_l3domain_template(
            name=name)
        vsd_l3domain = self.vsd_create_l3domain(
            name=name, template_id=vsd_l3domain_template.id)

        self.assertEqual(vsd_l3domain.name, name)
        zone_name = data_utils.rand_name('zone-')
        vsd_zone = self.vsd_create_zone(name=zone_name,
                                        domain=vsd_l3domain)

        subnet_name = data_utils.rand_name('l3domain-subnet-')
        subnet_cidr = IPNetwork('10.10.100.0/24')
        subnet_gateway = str(IPAddress(subnet_cidr) + 1)

        subnet_ipv6_cidr = IPNetwork("2001:5f74:c4a5:b82e::/64")
        subnet_ipv6_gateway = str(IPAddress(subnet_ipv6_cidr) + 1)

        vsd_l3domain_subnet = self.create_vsd_subnet(
            name=subnet_name,
            zone=vsd_zone,
            ip_type="DUALSTACK",
            cidr4=subnet_cidr,
            gateway4=subnet_gateway,
            cidr6=subnet_ipv6_cidr,
            gateway6=subnet_ipv6_gateway)

        self.assertEqual(vsd_l3domain_subnet.name, subnet_name)

        # create Openstack IPv4 subnet on Openstack based on VSD l3dom subnet
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        ipv4_subnet = self.create_subnet(
            network,
            gateway=subnet_gateway,
            cidr=subnet_cidr,
            enable_dhcp=True,
            mask_bits=IPNetwork(subnet_cidr).prefixlen,
            nuagenet=vsd_l3domain_subnet.id,
            net_partition=Topology.def_netpartition)
        self.assertEqual(ipv4_subnet['cidr'], str(subnet_cidr))

        # create Openstack IPv6 subnet on Openstack based on VSD l3dom subnet
        ipv6_subnet = self.create_subnet(
            network,
            ip_version=6,
            gateway=vsd_l3domain_subnet.ipv6_gateway,
            cidr=IPNetwork(vsd_l3domain_subnet.ipv6_address),
            mask_bits=IPNetwork(vsd_l3domain_subnet.ipv6_address).prefixlen,
            enable_dhcp=False,
            nuagenet=vsd_l3domain_subnet.id,
            net_partition=Topology.def_netpartition)

        self.assertEqual(
            ipv6_subnet['cidr'], vsd_l3domain_subnet.ipv6_address)

        # create a port in the network
        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=ipv6_subnet,
                          status='DOWN',
                          nuage_policy_groups=None,
                          nuage_redirect_targets=[],
                          nuage_floatingip=None)
        self._verify_vport_in_l3_subnet(port, vsd_l3domain_subnet)

    ###########################################################################
    # Special cases
    ###########################################################################

    ########################################
    # backwards compatibility
    ########################################
    def test_create_ipv4_subnet_in_vsd_managed_l3domain_ipv4(self):
        name = data_utils.rand_name('l3domain-')
        vsd_l3domain_template = self.vsd_create_l3domain_template(
            name=name)
        vsd_l3domain = self.vsd_create_l3domain(
            name=name, template_id=vsd_l3domain_template.id)

        self.assertEqual(vsd_l3domain.name, name)
        zone_name = data_utils.rand_name('zone-')
        vsd_zone = self.vsd_create_zone(name=zone_name,
                                        domain=vsd_l3domain)

        subnet_name = data_utils.rand_name('l3domain-subnet-')
        subnet_cidr = IPNetwork('10.10.100.0/24')
        subnet_gateway = str(IPAddress(subnet_cidr) + 1)

        vsd_l3domain_subnet = self.create_vsd_subnet(
            name=subnet_name,
            zone=vsd_zone,
            cidr4=subnet_cidr,
            gateway4=subnet_gateway,
            ip_type="IPV4")

        self.assertEqual("IPV4", vsd_l3domain_subnet.ip_type)
        self.assertIsNone(vsd_l3domain_subnet.external_id)
        self.assertIsNone(vsd_l3domain_subnet.ipv6_address)
        self.assertIsNone(vsd_l3domain_subnet.ipv6_gateway)
        self.assertEqual(str(subnet_cidr.ip), vsd_l3domain_subnet.address)
        self.assertEqual(subnet_gateway, vsd_l3domain_subnet.gateway)

    def test_create_ipv4_subnet_in_vsd_managed_l3domain_no_type(self):
        name = data_utils.rand_name('l3domain-')
        vsd_l3domain_template = self.vsd_create_l3domain_template(
            name=name)
        vsd_l3domain = self.vsd_create_l3domain(
            name=name, template_id=vsd_l3domain_template.id)

        self.assertEqual(vsd_l3domain.name, name)
        zone_name = data_utils.rand_name('zone-')
        vsd_zone = self.vsd_create_zone(name=zone_name,
                                        domain=vsd_l3domain)

        subnet_name = data_utils.rand_name('l3domain-subnet-')
        subnet_cidr = IPNetwork('10.10.100.0/24')
        subnet_gateway = str(IPAddress(subnet_cidr) + 1)

        vsd_l3domain_subnet = self.create_vsd_subnet(
            name=subnet_name,
            zone=vsd_zone,
            cidr4=subnet_cidr,
            gateway4=subnet_gateway)

        self.assertEqual("IPV4", vsd_l3domain_subnet.ip_type)
        self.assertIsNone(vsd_l3domain_subnet.external_id)
        self.assertIsNone(vsd_l3domain_subnet.ipv6_address)
        self.assertIsNone(vsd_l3domain_subnet.ipv6_gateway)
        self.assertEqual(str(subnet_cidr.ip), vsd_l3domain_subnet.address)
        self.assertEqual(subnet_gateway, vsd_l3domain_subnet.gateway)

    ########################################
    # minimal attributes - default values
    ########################################

    ###########################################################################
    # Negative cases
    ###########################################################################

    @decorators.attr(type='smoke')
    def test_create_ipv6_subnet_in_vsd_managed_l3domain_ipv4(self):
        name = data_utils.rand_name('l3domain-')
        vsd_l3domain_template = self.vsd_create_l3domain_template(
            name=name)
        vsd_l3domain = self.vsd_create_l3domain(
            name=name, template_id=vsd_l3domain_template.id)

        self.assertEqual(vsd_l3domain.name, name)
        zone_name = data_utils.rand_name('zone-')
        vsd_zone = self.vsd_create_zone(name=zone_name,
                                        domain=vsd_l3domain)

        subnet_name = data_utils.rand_name('l3domain-subnet-')
        subnet_cidr = IPNetwork('10.10.100.0/24')
        subnet_gateway = str(IPAddress(subnet_cidr) + 1)

        vsd_l3domain_subnet = self.create_vsd_subnet(
            name=subnet_name,
            zone=vsd_zone,
            cidr4=subnet_cidr,
            gateway4=subnet_gateway,
            ip_type="IPV4")

        # create Openstack IPv4 subnet on Openstack based on VSD l3dom subnet
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        subnet_ipv6_cidr = IPNetwork("2001:5f74:c4a5:b82e::/64")
        subnet_ipv6_gateway = str(IPAddress(subnet_ipv6_cidr) + 1)

        # shall not create Openstack IPv6 subnet on Openstack based on
        # VSD l3domain subnet with type IPV4
        if Topology.from_openstack('Newton'):
            expected_exception = tempest_exceptions.BadRequest
            expected_message = "Subnet with ip_version 6 can't be linked to " \
                               "vsd subnet with IPType IPV4"
        else:
            expected_exception = tempest_exceptions.ServerFault
            expected_message = "create_subnet_postcommit failed."

        self.assertRaisesRegex(
            expected_exception,
            expected_message,
            self.create_subnet,
            network,
            ip_version=6,
            gateway=subnet_ipv6_gateway,
            cidr=subnet_ipv6_cidr,
            mask_bits=subnet_ipv6_cidr.prefixlen,
            enable_dhcp=False,
            nuagenet=vsd_l3domain_subnet.id,
            net_partition=Topology.def_netpartition)

    @decorators.attr(type='smoke')
    def test_create_ipv4_subnet_without_dhcp_in_vsd_managed_l3domain(self):
        name = data_utils.rand_name('l3domain-')
        vsd_l3domain_template = self.vsd_create_l3domain_template(
            name=name)
        vsd_l3domain = self.vsd_create_l3domain(
            name=name, template_id=vsd_l3domain_template.id)

        self.assertEqual(vsd_l3domain.name, name)
        zone_name = data_utils.rand_name('zone-')
        vsd_zone = self.vsd_create_zone(name=zone_name,
                                        domain=vsd_l3domain)

        subnet_name = data_utils.rand_name('l3domain-subnet-')
        subnet_cidr = IPNetwork('10.10.100.0/24')
        subnet_gateway = str(IPAddress(subnet_cidr) + 1)

        vsd_l3domain_subnet = self.create_vsd_subnet(
            name=subnet_name,
            zone=vsd_zone,
            cidr4=subnet_cidr,
            gateway4=subnet_gateway,
            ip_type="IPV4")

        # create Openstack IPv4 subnet on Openstack based on VSD l3dom subnet
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        # create Openstack IPv4 subnet on Openstack based on VSD l3dom subnet
        if Topology.from_openstack('Newton'):
            expected_exception = tempest_exceptions.BadRequest
            expected_message = "enable_dhcp in subnet must be True"
        else:
            expected_exception = tempest_exceptions.ServerFault
            expected_message = "create_subnet_postcommit failed."

        self.assertRaisesRegex(
            expected_exception,
            expected_message,
            self.create_subnet,
            network,
            gateway=subnet_gateway,
            cidr=subnet_cidr,
            mask_bits=subnet_cidr.prefixlen,
            enable_dhcp=False,
            nuagenet=vsd_l3domain_subnet.id,
            net_partition=Topology.def_netpartition)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_os_managed_v6_conversions_l2_l3_v6_dualstack(self):
        # Provision OpenStack network/subnet/router
        network = self.create_network()
        ipv6_subnet = self.create_subnet(network, ip_version=6)

        # verify l2 dom
        vsd_l2_domain = self.vsd.get_l2domain(
            by_network_id=ipv6_subnet['network_id'],
            cidr=ipv6_subnet['cidr'], ip_type=6)
        self.assertEqual(vsd_l2_domain.ip_type, 'IPV6')

        router = self.create_router()
        vsd_l3_domain = self.vsd.get_l3domain(by_router_id=router['id'])

        # attach v6 subnet to router / verify l3 dom
        self.router_attach(router, ipv6_subnet, cleanup=False)
        vsd_l3_subnet = self.vsd.get_subnet_from_domain(
            domain=vsd_l3_domain, by_network_id=ipv6_subnet['network_id'],
            cidr=ipv6_subnet['cidr'], ip_type=6)
        self.assertEqual(vsd_l3_subnet.ip_type, 'IPV6')

        # create/verify port
        port = self.create_port(network)
        self._verify_port(port, subnet6=ipv6_subnet),
        self._verify_vport_in_l3_subnet(port, vsd_l3_subnet)

        # pure ipv6 to dualstack
        ipv4_subnet = self.create_subnet(network, cleanup=False)
        vsd_l3_subnet = self.vsd.get_subnet_from_domain(
            domain=vsd_l3_domain, by_network_id=ipv6_subnet['network_id'],
            cidr=ipv6_subnet['cidr'], ip_type=6)
        self.assertEqual(vsd_l3_subnet.ip_type, 'DUALSTACK')

        # dualstack to ipv6
        self.delete_subnet(ipv4_subnet)
        vsd_l3_subnet = self.vsd.get_subnet_from_domain(
            domain=vsd_l3_domain, by_network_id=ipv6_subnet['network_id'],
            cidr=ipv6_subnet['cidr'], ip_type=6)
        self.assertEqual(vsd_l3_subnet.ip_type, 'IPV6')

        # v6L3 to v6L2
        self.router_detach(router, ipv6_subnet)
        vsd_l2_domain = self.vsd.get_l2domain(
            by_network_id=ipv6_subnet['network_id'],
            cidr=ipv6_subnet['cidr'], ip_type=6)
        self.assertEqual(vsd_l2_domain.ip_type, 'IPV6')
