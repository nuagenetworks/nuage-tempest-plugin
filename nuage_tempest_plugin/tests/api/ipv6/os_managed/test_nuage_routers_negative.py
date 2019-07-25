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

from tempest.api.network import test_routers_negative as test_routers_negative
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES


class NuageRoutersNegativeIpV6Test(test_routers_negative.RoutersNegativeTest):
    _ip_version = 6

    @classmethod
    def skip_checks(cls):
        super(NuageRoutersNegativeIpV6Test, cls).skip_checks()
        if not NUAGE_FEATURES.os_managed_dualstack_subnets:
            raise cls.skipException(
                'OS Managed Dual Stack is not supported in this release')

    @classmethod
    def create_subnet(cls, network, gateway='', cidr=None, mask_bits=None,
                      ip_version=None, client=None, **kwargs):

        if "enable_dhcp" not in kwargs:
            # NUAGE non-compliance: enforce enable_dhcp = False as
            # the default option
            return super(NuageRoutersNegativeIpV6Test, cls).create_subnet(
                network, gateway, cidr, mask_bits,
                ip_version, client, enable_dhcp=False, **kwargs)
        else:
            return super(NuageRoutersNegativeIpV6Test, cls).create_subnet(
                network, gateway, cidr, mask_bits,
                ip_version, client, **kwargs)

    @decorators.attr(type=['negative'])
    # OPENSTACK-1886: fails to remove router with only IPv6 subnet interface
    def test_add_router_interfaces_on_overlapping_subnets_returns_400(self):
        network01 = self.create_network(
            network_name=data_utils.rand_name('router-network01-'))

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet01_ipv4 = self.create_subnet(
            network01, ip_version=4, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet01_ipv4['id'])

        network02 = self.create_network(
            network_name=data_utils.rand_name('router-network02-'))

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet02_ipv4 = self.create_subnet(
            network02, ip_version=4, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet02_ipv4['id'])

        subnet01 = self.create_subnet(network01)
        subnet02 = self.create_subnet(network02)
        interface = self.routers_client.add_router_interface(
            self.router['id'], subnet_id=subnet01['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        self.router['id'], subnet_id=subnet01['id'])
        self.assertEqual(subnet01['id'], interface['subnet_id'])
        self.assertRaises(lib_exc.BadRequest,
                          self.routers_client.add_router_interface,
                          self.router['id'],
                          subnet_id=subnet02['id'])
