# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
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
import random

from tempest.api.network import base
from tempest.api.network import test_networks
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

CONF = Topology.get_conf()


class NetworksTestJSONNuage(test_networks.NetworksTest):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(NetworksTestJSONNuage, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(NetworksTestJSONNuage, cls).resource_setup()

    @staticmethod
    def convert_dec_hex(ip_address):
        ip_address_hex = "0x" + \
            "".join([(hex(int(x))[2:].zfill(2))
                     for x in ip_address.split('.')])
        return ip_address_hex

    @classmethod
    def delete_router_interface(cls, router_id, subnet_id):
        cls.routers_client.remove_router_interface(
            router_id, subnet_id=subnet_id)

    def _verify_vsd_dhcp_options(self, nuage_dhcpopt, subnet):
        # VSD validation
        if subnet.get('gateway_ip', None):
            # Verify L2Domain dhcp options are set on VSD
            self.assertEqual(self.convert_dec_hex(
                subnet['gateway_ip'])[2:], nuage_dhcpopt[0]['value'])
            self.assertEqual(nuage_dhcpopt[0]['type'], "03")
            if Topology.within_ext_id_release():
                self.assertEqual(nuage_dhcpopt[0]['externalID'],
                                 self.nuage_client.get_vsd_external_id(
                                     subnet.get('id')))
        if subnet.get('dns_nameservers'):
            self.assertEqual(nuage_dhcpopt[1]['type'],
                             "06")
            dns1 = self.convert_dec_hex(subnet['dns_nameservers'][0])[2:]
            dns2 = self.convert_dec_hex(subnet['dns_nameservers'][1])[2:]
            dhcp_dns = [nuage_dhcpopt[1]['value'][
                0:8], nuage_dhcpopt[1]['value'][8:]]
            status = False
            if dns1 in dhcp_dns and dns2 in dhcp_dns:
                status = True
            self.assertTrue(
                status, "subnet dns_nameservers do not match dhcp options")

            self.assertEqual(nuage_dhcpopt[2]['type'],
                             "79")
            if Topology.within_ext_id_release():
                self.assertEqual(nuage_dhcpopt[2]['externalID'],
                                 self.nuage_client.get_vsd_external_id(
                                     subnet.get('id')))
        if subnet.get('host_routes'):
            self.assertEqual(
                self.convert_dec_hex(
                    subnet['host_routes'][0]['nexthop'])[2:],
                nuage_dhcpopt[2]['value'][-8:])
            if Topology.within_ext_id_release():
                self.assertEqual(nuage_dhcpopt[2]['externalID'],
                                 self.nuage_client.get_vsd_external_id(
                                     subnet.get('id')))

    def _create_verify_delete_subnet(self, cidr=None, mask_bits=None,
                                     **kwargs):
        network = self.create_network()
        net_id = network['id']
        gateway = kwargs.pop('gateway', None)
        subnet = self.create_subnet(network, gateway, cidr, mask_bits,
                                    **kwargs)
        compare_args_full = dict(gateway_ip=gateway, cidr=cidr,
                                 mask_bits=mask_bits, **kwargs)
        compare_args = dict((k, v) for k, v in compare_args_full.items()
                            if v is not None)

        if 'dns_nameservers' in set(subnet).intersection(compare_args):
            self.assertEqual(sorted(compare_args['dns_nameservers']),
                             sorted(subnet['dns_nameservers']))
            del subnet['dns_nameservers'], compare_args['dns_nameservers']

        # VSD validation inserted - only for ipv4 though
        # (with ipv6 subnet, no l2domain is created yet)
        if self._ip_version == 4:

            nuage_l2dom = self.nuage_client.get_l2domain(
                filters='externalID',
                filter_value=self.nuage_client.get_vsd_external_id(
                    subnet['id']))
            nuage_dhcpopt = self.nuage_client.get_dhcpoption(
                n_constants.L2_DOMAIN, nuage_l2dom[0]['ID'])

            permissions = self.nuage_client.get_permissions(
                parent=n_constants.L2_DOMAIN,
                parent_id=nuage_l2dom[0]['ID'])

            self._verify_vsd_dhcp_options(nuage_dhcpopt, subnet)
            if Topology.within_ext_id_release():
                self.assertEqual(len(permissions), 1)
                self.assertEqual(permissions[0]['externalID'],
                                 self.nuage_client.get_vsd_external_id(
                                     subnet['tenant_id']))
                if network['shared']:
                    self.assertEqual(permissions[0]['permittedEntityName'],
                                     "Everybody")
                else:
                    self.assertEqual(permissions[0]['permittedEntityName'],
                                     self.subnets_client.tenant_id)
                    group_resp = self.nuage_client.get_resource(
                        resource=n_constants.GROUP,
                        filters='externalID',
                        filter_value=self.subnets_client.tenant_id +
                        '@openstack',
                        netpart_name=self.nuage_client.def_netpart_name)
                    self.assertIsNot(group_resp, "",
                                     "User Group on VSD for the user who "
                                     "created the Subnet was not Found")
                    self.assertEqual(group_resp[0]['name'],
                                     self.subnets_client.tenant_id)
                user_resp = self.nuage_client.get_user(
                    filters='externalID',
                    filter_value=self.subnets_client.tenant_id + '@openstack',
                    netpart_name=self.nuage_client.def_netpart_name)
                self.assertIsNot(user_resp, "",
                                 "Corresponding user on VSD who created "
                                 "the Subnet was not Found")
                self.assertEqual(user_resp[0]['userName'],
                                 self.subnets_client.tenant_id)
                default_egress_tmpl = self.nuage_client.get_child_resource(
                    resource=n_constants.L2_DOMAIN,
                    resource_id=nuage_l2dom[0]['ID'],
                    child_resource=n_constants.EGRESS_ACL_TEMPLATE,
                    filters='externalID',
                    filter_value=self.nuage_client.get_vsd_external_id(
                        subnet['id']))
                self.assertIsNot(default_egress_tmpl, "",
                                 "Could not Find Default EGRESS Template "
                                 "on VSD For Subnet")
                default_ingress_tmpl = \
                    self.nuage_client.get_child_resource(
                        resource=n_constants.L2_DOMAIN,
                        resource_id=nuage_l2dom[0]['ID'],
                        child_resource=n_constants.INGRESS_ACL_TEMPLATE,
                        filters='externalID',
                        filter_value=self.nuage_client.get_vsd_external_id(
                            subnet['id']))
                self.assertIsNot(default_ingress_tmpl, "",
                                 "Could not Find Default INGRESS Template "
                                 "on VSD For Subnet")
                default_ingress_awd_tmpl = \
                    self.nuage_client.get_child_resource(
                        resource=n_constants.L2_DOMAIN,
                        resource_id=nuage_l2dom[0]['ID'],
                        child_resource=n_constants.INGRESS_ADV_FWD_TEMPLATE,
                        filters='externalID',
                        filter_value=self.nuage_client.get_vsd_external_id(
                            subnet['id']))
                self.assertIsNot(default_ingress_awd_tmpl, "",
                                 "Could not Find Default Forward INGRESS"
                                 " Template on VSD For Subnet")

        self._compare_resource_attrs(subnet, compare_args)
        self.networks_client.delete_network(net_id)
        self.subnets.pop()

    @decorators.attr(type='smoke')
    def test_create_update_delete_network_subnet(self):
        super(NetworksTestJSONNuage,
              self).test_create_update_delete_network_subnet()

        # # ipv4 only as for ipv6 subnet we don't create on vsd yet
        if self._ip_version == 4:
            # VSD validation
            # Validate that an L2Domain is created on VSD at subnet creation
            nuage_l2dom = self.nuage_client.get_l2domain(
                filters='externalID', filter_value=self.subnets[-1]['id'])

            self.assertEqual(nuage_l2dom[0]['name'], self.subnets[-1]['id'])

    @decorators.attr(type='smoke')
    def test_delete_network_with_subnet(self):
        # Creates a network
        name = data_utils.rand_name('network-')
        body = self.networks_client.create_network(name=name)
        network = body['network']
        net_id = network['id']

        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.networks_client.delete_network, net_id)

        # Find a cidr that is not in use yet and create a subnet with it
        subnet = self.create_subnet(network)
        subnet_id = subnet['id']

        if self._ip_version == 4:
            # VSD validation
            # Validate that an L2Domain is created on VSD at subnet creation
            nuage_l2dom = self.nuage_client.get_l2domain(
                filters='externalID', filter_value=subnet['id'])

            self.assertEqual(nuage_l2dom[0]['name'], subnet['id'])

        # Delete network while the subnet still exists
        body = self.networks_client.delete_network(net_id)

        # Verify that the subnet got automatically deleted.
        self.assertRaises(exceptions.NotFound, self.subnets_client.show_subnet,
                          subnet_id)

        if self._ip_version == 4:
            # VSD validation
            # Validate that an L2Domain is deleted on VSD at subnet deletion
            nuage_dell2dom = self.nuage_client.get_l2domain(
                filters='externalID',
                filter_value=subnet['id'])

            self.assertEqual(nuage_dell2dom, '')

        # Since create_subnet adds the subnet to the delete list, and it is
        # is actually deleted here - this will create and issue, hence remove
        # it from the list.
        self.subnets.pop()

    @decorators.attr(type='smoke')
    def test_create_delete_subnet_with_gw(self):
        self._create_verify_delete_subnet(
            **self.subnet_dict(['gateway']))

    @decorators.attr(type='smoke')
    def test_create_delete_subnet_with_gw_and_allocation_pools(self):
        self._create_verify_delete_subnet(**self.subnet_dict(
            ['gateway', 'allocation_pools']))

    @decorators.attr(type='smoke')
    def test_create_delete_subnet_with_host_routes_and_dns_nameservers(self):
        self._create_verify_delete_subnet(
            **self.subnet_dict(['host_routes', 'dns_nameservers']))

    @decorators.attr(type='smoke')
    def test_update_subnet_gw_dns_host_routes_dhcp(self):

        if self._ip_version == 6:
            # this test does not make much sense to my view for ipv6 as
            # we don't support dhcp options on v6
            self.skipTest('Skipped for ipv6.')

        network = self.create_network()
        subnet = self.create_subnet(
            network, **self.subnet_dict(['gateway', 'host_routes',
                                         'dns_nameservers',
                                         'allocation_pools']))
        subnet_id = subnet['id']
        new_gateway = str(netaddr.IPAddress(
                          self._subnet_data[self._ip_version]['gateway']) + 1)

        # Verify subnet update
        new_host_routes = self._subnet_data[self._ip_version][
            'new_host_routes']

        new_dns_nameservers = self._subnet_data[self._ip_version][
            'new_dns_nameservers']
        kwargs = {'host_routes': new_host_routes,
                  'dns_nameservers': new_dns_nameservers,
                  'gateway_ip': new_gateway, 'enable_dhcp': True}

        new_name = "New_subnet"
        body = self.subnets_client.update_subnet(subnet_id, name=new_name,
                                                 **kwargs)
        updated_subnet = body['subnet']
        kwargs['name'] = new_name

        self.assertEqual(sorted(updated_subnet['dns_nameservers']),
                         sorted(kwargs['dns_nameservers']))
        del subnet['dns_nameservers'], kwargs['dns_nameservers']

        self._compare_resource_attrs(updated_subnet, kwargs)

    @decorators.attr(type='smoke')
    def test_update_routed_subnet_gw_dns_host_routes(self):

        if self._ip_version == 6:
            # this test does not make much sense to my view for ipv6 as
            # we don't support dhcp options on v6
            self.skipTest('Skipped for ipv6.')

        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        network = self.create_network()
        subnet_args = self.subnet_dict(['gateway', 'host_routes',
                                        'dns_nameservers',
                                        'allocation_pools'])
        subnet = self.create_subnet(network, **subnet_args)
        self.create_router_interface(router['id'], subnet['id'])

        subnet_id = subnet['id']

        # Verify subnet update
        new_host_routes = self._subnet_data[self._ip_version][
            'new_host_routes']

        new_dns_nameservers = self._subnet_data[self._ip_version][
            'new_dns_nameservers']
        kwargs = {'host_routes': new_host_routes,
                  'dns_nameservers': new_dns_nameservers}

        new_name = "New_subnet"
        body = self.subnets_client.update_subnet(subnet_id, name=new_name,
                                                 **kwargs)
        updated_subnet = body['subnet']
        kwargs['name'] = new_name

        self.assertEqual(sorted(updated_subnet['dns_nameservers']),
                         sorted(kwargs['dns_nameservers']))
        del subnet['dns_nameservers'], kwargs['dns_nameservers']

        self._compare_resource_attrs(updated_subnet, kwargs)

        # cleanup router itf ...
        self.delete_router_interface(router['id'], subnet['id'])

    @decorators.attr(type='smoke')
    def test_create_delete_subnet_all_attributes(self):
        self._create_verify_delete_subnet(
            **self.subnet_dict(['gateway', 'host_routes', 'dns_nameservers']))


class NetworkNuageAdminTest(base.BaseAdminNetworkTest):
    @classmethod
    def setup_clients(cls):
        super(NetworkNuageAdminTest, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    def _create_network(self, external=True):
        post_body = {'name': data_utils.rand_name('network-')}
        if external:
            post_body['router:external'] = external
        body = self.admin_networks_client.create_network(**post_body)
        network = body['network']
        self.addCleanup(
            self.admin_networks_client.delete_network, network['id'])
        return network

    @decorators.attr(type='smoke')
    def test_create_delete_external_subnet_with_underlay(self):
        subname = 'underlay-subnet'
        ext_network = self._create_network()
        cidr = "135.%s.%s.0/24" % (random.randint(0, 255),
                                   random.randint(0, 255))
        body = self.admin_subnets_client.create_subnet(
            network_id=ext_network['id'],
            cidr=cidr,
            ip_version=self._ip_version,
            name=subname, underlay=True)
        subnet = body['subnet']
        self.assertEqual(subnet['name'], subname)
        # TODO(team) - Add VSD check here
        nuage_fippool = self.nuage_client.get_sharedresource(
            filters='externalID', filter_value=subnet['id'])
        self.assertEqual(nuage_fippool[0]['underlay'], True)
        self.admin_subnets_client.delete_subnet(subnet['id'])
        nuage_fippool = self.nuage_client.get_sharedresource(
            filters='externalID', filter_value=subnet['id'])
        self.assertEqual(nuage_fippool, '')

    @decorators.attr(type='smoke')
    def test_create_delete_external_subnet_without_underlay(self):
        subname = 'non-underlay-subnet'
        ext_network = self._create_network()
        cidr = "135.%s.%s.0/24" % (random.randint(0, 255),
                                   random.randint(0, 255))
        body = self.admin_subnets_client.create_subnet(
            network_id=ext_network['id'],
            cidr=cidr,
            ip_version=self._ip_version,
            name=subname, underlay=False)
        subnet = body['subnet']
        self.assertEqual(subnet['name'], subname)
        # TODO(team) - Add VSD check here
        # TODO(team) - Add VSD check here
        nuage_fippool = self.nuage_client.get_sharedresource(
            filters='externalID', filter_value=subnet['id'])
        self.assertEqual(nuage_fippool[0]['underlay'], False)
        self.admin_subnets_client.delete_subnet(subnet['id'])
        nuage_fippool = self.nuage_client.get_sharedresource(
            filters='externalID', filter_value=subnet['id'])
        self.assertEqual(nuage_fippool, '')


class NuageNetworksIpV6Test(NetworksTestJSONNuage):
    _ip_version = 6
