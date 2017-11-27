# Copyright 2012 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
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
import testtools

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES
from tempest.api.network import test_ports as tempest_test_ports
from tempest.common import custom_matchers
from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

CONF = config.CONF


class NuagePortsIpV6Test(tempest_test_ports.PortsIpV6TestJSON):

    @classmethod
    def skip_checks(cls):
        super(NuagePortsIpV6Test, cls).skip_checks()
        if not NUAGE_FEATURES.os_managed_dualstack_subnets:
            raise cls.skipException(
                'OS Managed Dual Stack is not supported in this release')

    @classmethod
    def resource_setup(cls):
        super(NuagePortsIpV6Test, cls).resource_setup()
        cls.subnet4 = cls.create_subnet(
            cls.network, ip_version=4, enable_dhcp=True)

    @classmethod
    def create_subnet(cls, network, gateway='', cidr=None, mask_bits=None,
                      ip_version=None, client=None, **kwargs):

        if "enable_dhcp" not in kwargs:
            # NUAGE non-compliance: enforce enable_dhcp = False
            # as the default option
            return super(NuagePortsIpV6Test, cls).create_subnet(
                network, gateway, cidr, mask_bits,
                ip_version, client, enable_dhcp=False, **kwargs)
        else:
            return super(NuagePortsIpV6Test, cls).create_subnet(
                network, gateway, cidr, mask_bits,
                ip_version, client, **kwargs)

    @decorators.attr(type='smoke')
    def test_create_port_in_allowed_allocation_pools(self):
        network = self.create_network()

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet4 = self.create_subnet(network, ip_version=4, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet4['id'])

        net_id = network['id']
        address = self.cidr
        address.prefixlen = self.mask_bits
        if ((address.version == 4 and address.prefixlen >= 30) or
                (address.version == 6 and address.prefixlen >= 126)):
            msg = ("Subnet %s isn't large enough for the test" % address.cidr)
            raise exceptions.InvalidConfiguration(msg)
        allocation_pools = {'allocation_pools': [{'start': str(address[2]),
                                                  'end': str(address[-2])}]}
        subnet = self.create_subnet(network, cidr=address,
                                    mask_bits=address.prefixlen,
                                    **allocation_pools)
        self.addCleanup(self.subnets_client.delete_subnet, subnet['id'])
        body = self.ports_client.create_port(network_id=net_id)
        self.addCleanup(self.ports_client.delete_port, body['port']['id'])
        port = body['port']
        ip_address = port['fixed_ips'][1]['ip_address']
        start_ip_address = allocation_pools['allocation_pools'][0]['start']
        end_ip_address = allocation_pools['allocation_pools'][0]['end']
        ip_range = netaddr.IPRange(start_ip_address, end_ip_address)
        self.assertIn(ip_address, ip_range)

    def test_port_list_filter_by_ip(self):
        # Create network and subnet
        network = self.create_network()

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet4 = self.create_subnet(network, ip_version=4, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet4['id'])

        subnet = self.create_subnet(network)
        self.addCleanup(self.subnets_client.delete_subnet, subnet['id'])
        # Create two ports
        port_1 = self.ports_client.create_port(network_id=network['id'])
        self.addCleanup(self.ports_client.delete_port, port_1['port']['id'])
        port_2 = self.ports_client.create_port(network_id=network['id'])
        self.addCleanup(self.ports_client.delete_port, port_2['port']['id'])
        # List ports filtered by fixed_ips
        port_1_fixed_ip = port_1['port']['fixed_ips'][1]['ip_address']
        fixed_ips = 'ip_address=' + port_1_fixed_ip
        port_list = self.ports_client.list_ports(fixed_ips=fixed_ips)
        # Check that we got the desired port
        ports = port_list['ports']
        tenant_ids = set([port['tenant_id'] for port in ports])
        self.assertEqual(len(tenant_ids), 1,
                         'Ports from multiple tenants are in the list resp')
        port_ids = [port['id'] for port in ports]
        fixed_ips = [port['fixed_ips'] for port in ports]
        port_ips = []
        for addr in fixed_ips:
            port_ips.extend([port['ip_address'] for port in addr])

        port_net_ids = [port['network_id'] for port in ports]
        self.assertIn(port_1['port']['id'], port_ids)
        self.assertIn(port_1_fixed_ip, port_ips)
        self.assertIn(network['id'], port_net_ids)

    def test_port_list_filter_by_router_id(self):
        # Create a router
        network = self.create_network()
        self.addCleanup(self.networks_client.delete_network, network['id'])

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet4 = self.create_subnet(network, ip_version=4, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet4['id'])

        subnet = self.create_subnet(network)
        self.addCleanup(self.subnets_client.delete_subnet, subnet['id'])
        router = self.create_router()
        self.addCleanup(self.routers_client.delete_router, router['id'])
        port = self.ports_client.create_port(network_id=network['id'])
        # Add router interface to port created above
        self.routers_client.add_router_interface(router['id'],
                                                 port_id=port['port']['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        router['id'], port_id=port['port']['id'])
        # List ports filtered by router_id
        port_list = self.ports_client.list_ports(device_id=router['id'])
        ports = port_list['ports']
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0]['id'], port['port']['id'])
        self.assertEqual(ports[0]['device_id'], router['id'])

    def test_create_update_port_with_second_ip(self):

        self.assertRaisesRegex(
            exceptions.BadRequest,
            "A network with an ipv6 subnet may only have maximum 1 ipv4 "
            "and 1 ipv6 subnet",
            super(NuagePortsIpV6Test,
                  self).test_create_update_port_with_second_ip)

    def _update_port_with_security_groups(self, security_groups_names):

        subnet_1 = self.create_subnet(self.network)
        self.addCleanup(self.subnets_client.delete_subnet, subnet_1['id'])

        # NUAGE non-compliance: Must have IP address in both networks
        fixed_ip_1 = [{'subnet_id': subnet_1['id']},
                      {'subnet_id': self.subnet4['id']}]

        security_groups_list = list()
        sec_grps_client = self.security_groups_client
        for name in security_groups_names:
            group_create_body = sec_grps_client.create_security_group(
                name=name)
            self.addCleanup(self.security_groups_client.delete_security_group,
                            group_create_body['security_group']['id'])
            security_groups_list.append(
                group_create_body['security_group']['id'])

        # Create a port
        sec_grp_name = data_utils.rand_name('secgroup')
        security_group = sec_grps_client.create_security_group(
            name=sec_grp_name)
        self.addCleanup(self.security_groups_client.delete_security_group,
                        security_group['security_group']['id'])
        post_body = {
            "name": data_utils.rand_name('port-'),
            "security_groups": [security_group['security_group']['id']],
            "network_id": self.network['id'],
            "admin_state_up": True,
            "fixed_ips": fixed_ip_1}
        body = self.ports_client.create_port(**post_body)
        self.addCleanup(self.ports_client.delete_port, body['port']['id'])
        port = body['port']

        # Update the port with security groups
        subnet_2 = self.create_subnet(self.network)
        fixed_ip_2 = [{'subnet_id': subnet_2['id']}]
        update_body = {"name": data_utils.rand_name('port-'),
                       "admin_state_up": False,
                       "fixed_ips": fixed_ip_2,
                       "security_groups": security_groups_list}
        body = self.ports_client.update_port(port['id'], **update_body)
        port_show = body['port']
        # Verify the security groups and other attributes updated to port
        exclude_keys = set(port_show).symmetric_difference(update_body)
        exclude_keys.add('fixed_ips')
        exclude_keys.add('security_groups')
        self.assertThat(port_show, custom_matchers.MatchesDictExceptForKeys(
            update_body, exclude_keys))
        self.assertEqual(fixed_ip_2[0]['subnet_id'],
                         port_show['fixed_ips'][0]['subnet_id'])

        for security_group in security_groups_list:
            self.assertIn(security_group, port_show['security_groups'])

    @testtools.skipUnless(
        utils.is_extension_enabled('security-group', 'network'),
        'security-group extension not enabled.')
    def test_update_port_with_security_group_and_extra_attributes(self):
        self.assertRaisesRegex(
            exceptions.BadRequest,
            "A network with an ipv6 subnet may only have maximum 1 ipv4 "
            "and 1 ipv6 subnet",
            self._update_port_with_security_groups,
            [data_utils.rand_name('secgroup')])

    @testtools.skipUnless(
        utils.is_extension_enabled('security-group', 'network'),
        'security-group extension not enabled.')
    def test_update_port_with_two_security_groups_and_extra_attributes(self):
        self.assertRaisesRegex(
            exceptions.BadRequest,
            "A network with an ipv6 subnet may only have maximum 1 ipv4 "
            "and 1 ipv6 subnet",
            self._update_port_with_security_groups,
            [data_utils.rand_name('secgroup'),
             data_utils.rand_name('secgroup')])

    @decorators.attr(type='smoke')
    @testtools.skipUnless(
        utils.is_extension_enabled('security-group', 'network'),
        'security-group extension not enabled.')
    def test_create_port_with_no_securitygroups(self):
        network = self.create_network()
        self.addCleanup(self.networks_client.delete_network, network['id'])

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet4 = self.create_subnet(network, ip_version=4, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet4['id'])

        subnet = self.create_subnet(network)
        self.addCleanup(self.subnets_client.delete_subnet, subnet['id'])
        port = self.create_port(network, security_groups=[])
        self.addCleanup(self.ports_client.delete_port, port['id'])
        self.assertIsNotNone(port['security_groups'])
        self.assertEmpty(port['security_groups'])
