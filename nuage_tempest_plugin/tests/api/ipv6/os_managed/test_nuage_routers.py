# Copyright 2013 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import netaddr

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES

from tempest.api.network import test_routers as tempest_test_routers
from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

CONF = config.CONF


class NuageRoutersIpV6Test(tempest_test_routers.RoutersIpV6Test):

    @classmethod
    def skip_checks(cls):
        super(NuageRoutersIpV6Test, cls).skip_checks()
        if not NUAGE_FEATURES.os_managed_dualstack_subnets:
            raise cls.skipException(
                'OS Managed Dual Stack is not supported in this release')

    @classmethod
    def create_subnet(cls, network, gateway='', cidr=None, mask_bits=None,
                      ip_version=None, client=None, **kwargs):

        if "enable_dhcp" not in kwargs:
            # NUAGE non-compliance: enforce enable_dhcp = False as
            # the default option
            return super(NuageRoutersIpV6Test, cls).create_subnet(
                network, gateway, cidr, mask_bits,
                ip_version, client, enable_dhcp=False, **kwargs)
        else:
            return super(NuageRoutersIpV6Test, cls).create_subnet(
                network, gateway, cidr, mask_bits,
                ip_version, client, **kwargs)

    @decorators.attr(type='smoke')
    # OPENSTACK-1886: fails to remove router with only IPv6 subnet interface
    def test_add_remove_router_interface_with_subnet_id(self):
        network = self.create_network()

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet4 = self.create_subnet(network, ip_version=4, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet4['id'])

        subnet = self.create_subnet(network)
        router = self._create_router()

        # Add router interface with subnet id
        interface = self.routers_client.add_router_interface(
            router['id'], subnet_id=subnet['id'])
        self.addCleanup(self._remove_router_interface_with_subnet_id,
                        router['id'], subnet['id'])
        self.assertIn('subnet_id', interface.keys())
        self.assertIn('port_id', interface.keys())
        # Verify router id is equal to device id in port details
        show_port_body = self.ports_client.show_port(
            interface['port_id'])
        self.assertEqual(show_port_body['port']['device_id'],
                         router['id'])

    @decorators.attr(type='smoke')
    def test_add_remove_router_interface_with_port_id(self):
        network = self.create_network()

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet4 = self.create_subnet(network, ip_version=4, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet4['id'])

        self.create_subnet(network)
        router = self._create_router()
        port_body = self.ports_client.create_port(
            network_id=network['id'])
        # add router interface to port created above
        interface = self.routers_client.add_router_interface(
            router['id'],
            port_id=port_body['port']['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        router['id'], port_id=port_body['port']['id'])
        self.assertIn('subnet_id', interface.keys())
        self.assertIn('port_id', interface.keys())
        # Verify router id is equal to device id in port details
        show_port_body = self.ports_client.show_port(
            interface['port_id'])
        self.assertEqual(show_port_body['port']['device_id'],
                         router['id'])

    @utils.requires_ext(extension='extraroute', service='network')
    # OPENSTACK-1887
    def test_update_delete_extra_route(self):
        # Create different cidr for each subnet to avoid cidr duplicate
        # The cidr starts from project_cidr
        next_cidr = netaddr.IPNetwork(self.cidr)
        # Prepare to build several routes
        test_routes = []
        routes_num = 4
        # Create a router
        router = self._create_router(admin_state_up=True)
        self.addCleanup(
            self._delete_extra_routes,
            router['id'])
        # Update router extra route, second ip of the range is
        # used as next hop
        for i in range(routes_num):
            network = self.create_network()
            subnet = self.create_subnet(network, cidr=next_cidr)
            next_cidr = next_cidr.next()

            # Add router interface with subnet id
            self.create_router_interface(router['id'], subnet['id'])

            cidr = netaddr.IPNetwork(subnet['cidr'])
            next_hop = str(cidr[2])
            destination = str(subnet['cidr'])
            test_routes.append(
                {'nexthop': next_hop, 'destination': destination}
            )

        test_routes.sort(key=lambda x: x['destination'])
        extra_route = self.routers_client.update_router(
            router['id'], routes=test_routes)
        show_body = self.routers_client.show_router(router['id'])
        # Assert the number of routes
        self.assertEqual(routes_num, len(extra_route['router']['routes']))
        self.assertEqual(routes_num, len(show_body['router']['routes']))

        routes = extra_route['router']['routes']
        routes.sort(key=lambda x: x['destination'])
        # Assert the nexthops & destination
        for i in range(routes_num):
            self.assertEqual(test_routes[i]['destination'],
                             routes[i]['destination'])
            self.assertEqual(test_routes[i]['nexthop'], routes[i]['nexthop'])

        routes = show_body['router']['routes']
        routes.sort(key=lambda x: x['destination'])
        for i in range(routes_num):
            self.assertEqual(test_routes[i]['destination'],
                             routes[i]['destination'])
            self.assertEqual(test_routes[i]['nexthop'], routes[i]['nexthop'])

        self._delete_extra_routes(router['id'])
        show_body_after_deletion = self.routers_client.show_router(
            router['id'])
        self.assertEmpty(show_body_after_deletion['router']['routes'])

    @decorators.attr(type='smoke')
    # OPENSTACK-1886: fails to remove router with only IPv6 subnet interface
    def test_add_multiple_router_interfaces(self):
        network01 = self.create_network(
            network_name=data_utils.rand_name('router-network01-'))

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet01_ipv4 = self.create_subnet(
            network01, ip_version=4, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet01_ipv4['id'])

        network02 = self.create_network(
            network_name=data_utils.rand_name('router-network02-'))

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet02_ipv4_cidr = netaddr.IPNetwork(subnet01_ipv4['cidr']).next()
        subnet02_ipv4 = self.create_subnet(
            network02, ip_version=4, cidr=subnet02_ipv4_cidr, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet02_ipv4['id'])

        subnet01 = self.create_subnet(network01)
        sub02_cidr = netaddr.IPNetwork(self.cidr).next()
        subnet02 = self.create_subnet(network02, cidr=sub02_cidr)
        router = self._create_router()
        interface01 = self._add_router_interface_with_subnet_id(router['id'],
                                                                subnet01['id'])
        self._verify_router_interface(router['id'], subnet01['id'],
                                      interface01['port_id'])
        interface02 = self._add_router_interface_with_subnet_id(router['id'],
                                                                subnet02['id'])
        self._verify_router_interface(router['id'], subnet02['id'],
                                      interface02['port_id'])
        pass

    # OPENSTACK-1886: fails to remove router with only IPv6 subnet interface
    def test_router_interface_port_update_with_fixed_ip(self):
        network = self.create_network()

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet_ipv4 = self.create_subnet(
            network, ip_version=4, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet_ipv4['id'])

        subnet = self.create_subnet(network)
        router = self._create_router()
        fixed_ip = [{'subnet_id': subnet['id']}]
        interface = self._add_router_interface_with_subnet_id(router['id'],
                                                              subnet['id'])
        self.assertIn('port_id', interface)
        self.assertIn('subnet_id', interface)
        port = self.ports_client.show_port(interface['port_id'])
        self.assertEqual(port['port']['id'], interface['port_id'])
        router_port = self.ports_client.update_port(port['port']['id'],
                                                    fixed_ips=fixed_ip)
        self.assertEqual(subnet['id'],
                         router_port['port']['fixed_ips'][0]['subnet_id'])
