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

from future.utils import listitems

import netaddr

from tempest.api.network import base
from tempest.api.network import test_networks
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.lib.utils import data_utils as nuage_data_utils
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

CONF = Topology.get_conf()


class NetworksTestJSONNuage(test_networks.NetworksTest):
    _interface = 'json'
    _vsd_address = 'address'

    @classmethod
    def resource_setup(cls):
        super(NetworksTestJSONNuage, cls).resource_setup()
        cls.nuage_client = NuageRestClient()

    @staticmethod
    def convert_dec_hex(ip_address):
        hex_ip = hex(int(netaddr.IPAddress(ip_address)))[2:]
        if hex_ip.endswith('L'):
            hex_ip = hex_ip[:-1]
        if len(hex_ip) % 2:  # odd amount of characters
            return '0' + hex_ip  # make it even
        else:
            return hex_ip

    @classmethod
    def delete_router_interface(cls, router_id, subnet_id):
        cls.routers_client.remove_router_interface(
            router_id, subnet_id=subnet_id)

    def _verify_vsd_dhcp_options(self, nuage_dhcpopt, subnet, l2=True):
        # VSD validation
        opt_index = 0
        if self._ip_version == 4 and subnet.get('gateway_ip', None) and l2:
            self.assertGreater(len(nuage_dhcpopt), opt_index)
            self.assertEqual(self.convert_dec_hex(
                subnet['gateway_ip']), nuage_dhcpopt[opt_index]['value'])
            self.assertEqual(nuage_dhcpopt[opt_index]['type'], "03")
            self.assertEqual(nuage_dhcpopt[opt_index]['externalID'],
                             self.nuage_client.get_vsd_external_id(
                                 subnet.get('id')))
            opt_index += 1

        if subnet.get('dns_nameservers'):
            self.assertGreater(len(nuage_dhcpopt), opt_index)
            self.assertEqual(nuage_dhcpopt[opt_index]['type'],
                             "06" if self._ip_version == 4 else "17")
            dns1 = self.convert_dec_hex(subnet['dns_nameservers'][0])
            dns2 = self.convert_dec_hex(subnet['dns_nameservers'][1])
            ip_length = 8 if subnet['ip_version'] == 4 else 32
            dhcp_dns = ([nuage_dhcpopt[opt_index]['value'][0:ip_length],
                         nuage_dhcpopt[opt_index]['value'][ip_length:]])
            self.assertIn(dns1, dhcp_dns)
            self.assertIn(dns2, dhcp_dns)
            opt_index += 1

        if self._ip_version == 4 and subnet.get('host_routes'):
            self.assertGreater(len(nuage_dhcpopt), opt_index)
            self.assertEqual(nuage_dhcpopt[opt_index]['type'],
                             "79")  # classless-static-route
            self.assertEqual(nuage_dhcpopt[opt_index]['externalID'],
                             self.nuage_client.get_vsd_external_id(
                                 subnet.get('id')))
            self.assertEqual(
                self.convert_dec_hex(
                    subnet['host_routes'][0]['nexthop']),
                nuage_dhcpopt[opt_index]['value'][-8:])
            self.assertEqual(nuage_dhcpopt[opt_index]['externalID'],
                             self.nuage_client.get_vsd_external_id(
                                 subnet.get('id')))

    def _create_verify_delete_subnet(self, cidr=None, mask_bits=None,
                                     **kwargs):
        network = self.create_network()
        net_id = network['id']
        gateway = kwargs.pop('gateway', None)
        subnet = self.create_subnet(network, gateway, cidr, mask_bits,
                                    **kwargs)

        nuage_l2dom = self.nuage_client.get_l2domain(
            filters=['externalID', self._vsd_address],
            filter_value=[subnet['network_id'],
                          subnet['cidr']])

        nuage_dhcpopt = self.nuage_client.get_dhcpoption(
            n_constants.L2_DOMAIN, nuage_l2dom[0]['ID'], subnet['ip_version'])
        self._verify_vsd_dhcp_options(nuage_dhcpopt, subnet)

        permissions = self.nuage_client.get_permissions(
            parent=n_constants.L2_DOMAIN,
            parent_id=nuage_l2dom[0]['ID'])

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
            filter_value=subnet['network_id'])
        self.assertIsNot(default_egress_tmpl, "",
                         "Could not Find Default EGRESS Template "
                         "on VSD For Subnet")
        default_ingress_tmpl = \
            self.nuage_client.get_child_resource(
                resource=n_constants.L2_DOMAIN,
                resource_id=nuage_l2dom[0]['ID'],
                child_resource=n_constants.INGRESS_ACL_TEMPLATE,
                filters='externalID',
                filter_value=subnet['network_id'])
        self.assertIsNot(default_ingress_tmpl, "",
                         "Could not Find Default INGRESS Template "
                         "on VSD For Subnet")
        default_ingress_awd_tmpl = \
            self.nuage_client.get_child_resource(
                resource=n_constants.L2_DOMAIN,
                resource_id=nuage_l2dom[0]['ID'],
                child_resource=n_constants.INGRESS_ADV_FWD_TEMPLATE,
                filters='externalID',
                filter_value=subnet['network_id'])
        self.assertIsNot(default_ingress_awd_tmpl, "",
                         "Could not Find Default Forward INGRESS"
                         " Template on VSD For Subnet")

        compare_args_full = dict(gateway_ip=gateway, cidr=cidr,
                                 mask_bits=mask_bits, **kwargs)
        compare_args = dict((k, v) for k, v in listitems(compare_args_full)
                            if v is not None)

        if 'dns_nameservers' in set(subnet).intersection(compare_args):
            self.assertEqual(sorted(compare_args['dns_nameservers']),
                             sorted(subnet['dns_nameservers']))
            del subnet['dns_nameservers'], compare_args['dns_nameservers']

        self._compare_resource_attrs(subnet, compare_args)
        self.networks_client.delete_network(net_id)

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

        # VSD validation
        # Validate that an L2Domain is created on VSD at subnet creation

        nuage_l2dom = self.nuage_client.get_l2domain(
            filters=['externalID', self._vsd_address],
            filter_value=[subnet['network_id'],
                          subnet['cidr']])

        self.assertEqual(nuage_l2dom[0]['name'],
                         network['id'] + '_' + subnet['id'])
        self.assertEqual(nuage_l2dom[0]['description'], subnet['name'])

        # Delete network while the subnet still exists
        self.networks_client.delete_network(net_id)

        # Verify that the subnet got automatically deleted.
        self.assertRaises(exceptions.NotFound, self.subnets_client.show_subnet,
                          subnet_id)

        # VSD validation
        # Validate that an L2Domain is deleted on VSD at subnet deletion
        nuage_dell2dom = self.nuage_client.get_l2domain(
            filters=['externalID', self._vsd_address],
            filter_value=[subnet['network_id'],
                          subnet['cidr']])

        self.assertEqual(nuage_dell2dom, '')

    @decorators.attr(type='smoke')
    def test_update_subnet_gw_dns_host_routes_dhcp(self):
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

        nuage_l2dom = self.nuage_client.get_l2domain(
            filters=['externalID', self._vsd_address],
            filter_value=[subnet['network_id'],
                          subnet['cidr']])

        nuage_dhcpopt = self.nuage_client.get_dhcpoption(
            n_constants.L2_DOMAIN, nuage_l2dom[0]['ID'], subnet['ip_version'])
        self._verify_vsd_dhcp_options(nuage_dhcpopt, updated_subnet)

        del subnet['dns_nameservers'], kwargs['dns_nameservers']

        self._compare_resource_attrs(updated_subnet, kwargs)

    def test_update_subnet_with_no_gw(self):
        network = self.create_network()
        subnet = self.create_subnet(
            network, **self.subnet_dict(['gateway']))
        subnet_id = subnet['id']
        nuage_l2dom = self.nuage_client.get_l2domain(
            filters=['externalID', self._vsd_address],
            filter_value=[subnet['network_id'],
                          subnet['cidr']])
        nuage_dhcpopt = self.nuage_client.get_dhcpoption(
            n_constants.L2_DOMAIN, nuage_l2dom[0]['ID'], subnet['ip_version'])
        self._verify_vsd_dhcp_options(nuage_dhcpopt, subnet)
        # Verify subnet update
        kwargs = {'gateway_ip': None}

        new_name = "New_subnet"
        body = self.subnets_client.update_subnet(subnet_id, name=new_name,
                                                 **kwargs)
        updated_subnet = body['subnet']
        kwargs['name'] = new_name

        self._compare_resource_attrs(updated_subnet, kwargs)

        nuage_dhcpopt = self.nuage_client.get_dhcpoption(
            n_constants.L2_DOMAIN, nuage_l2dom[0]['ID'], subnet['ip_version'])

        self.assertEmpty(nuage_dhcpopt, msg="gateway DHCP option not deleted")

    @decorators.attr(type='smoke')
    def test_update_routed_subnet_gw_dns_host_routes(self):
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

        nuage_subnet = self.nuage_client.get_domain_subnet(
            parent=None, parent_id=None,
            filters=['externalID', self._vsd_address],
            filter_value=[subnet['network_id'], subnet['cidr']])

        nuage_dhcpopt = self.nuage_client.get_dhcpoption(
            n_constants.SUBNETWORK, nuage_subnet[0]['ID'],
            subnet['ip_version'])
        self._verify_vsd_dhcp_options(nuage_dhcpopt, updated_subnet, l2=False)

        del subnet['dns_nameservers'], kwargs['dns_nameservers']

        self._compare_resource_attrs(updated_subnet, kwargs)

        # cleanup router itf ...
        self.delete_router_interface(router['id'], subnet['id'])

    @decorators.idempotent_id('d830de0a-be47-468f-8f02-1fd996118289')
    def test_create_delete_subnet_with_dns_nameservers(self):
        self._create_verify_delete_subnet(
            **self.subnet_dict(['dns_nameservers']))

    @decorators.attr(type='smoke')
    def test_single_stack_dhcp_option_deleted_l2(self):
        self._test_single_stack_dhcp_option_deleted(with_router=False)

    @decorators.attr(type='smoke')
    def test_single_stack_dhcp_option_deleted_l3(self):
        self._test_single_stack_dhcp_option_deleted(with_router=True)

    def _test_single_stack_dhcp_option_deleted(self, with_router):
        network = self.create_network()
        subnet1 = self.create_subnet(
            network, **self.subnet_dict(['gateway', 'host_routes',
                                         'dns_nameservers',
                                         'allocation_pools']))
        # Reverse ip version for second subnet
        self._ip_version = 4 if self._ip_version == 6 else 6
        subnet2 = self.create_subnet(
            network, ip_version=self._ip_version,
            **self.subnet_dict(['gateway', 'host_routes',
                                'dns_nameservers',
                                'allocation_pools']))
        # Reverse ip version again for normal flow
        self._ip_version = 4 if self._ip_version == 6 else 6
        if with_router:
            router = self.create_router()
            self.create_router_interface(router['id'], subnet1['id'])
            self.addCleanup(self.delete_router_interface, router['id'],
                            subnet1['id'])
        # Delete subnet and check that there are no dhcp options left
        self.subnets_client.delete_subnet(subnet2['id'])

        if with_router:
            nuage_dom_sub = self.nuage_client.get_domain_subnet(
                None, None, filters=['externalID', self._vsd_address],
                filter_value=[subnet1['network_id'],
                              subnet1['cidr']])
        else:
            nuage_dom_sub = self.nuage_client.get_l2domain(
                filters=['externalID', self._vsd_address],
                filter_value=[subnet1['network_id'],
                              subnet1['cidr']])
        # Deleted subnet version should not have any options left:
        vsd_resource = (n_constants.SUBNETWORK if
                        with_router else n_constants.L2_DOMAIN)
        nuage_dhcpopt = self.nuage_client.get_dhcpoption(
            vsd_resource, nuage_dom_sub[0]['ID'], subnet2['ip_version'])
        self.assertEmpty(nuage_dhcpopt,
                         "No DHCP options of version {} should "
                         "be found on l2domain but found "
                         "{}.".format(subnet2['ip_version'], nuage_dhcpopt))
        # Not deleted ip_version subnet should have all options intact
        nuage_dhcpopt = self.nuage_client.get_dhcpoption(
            vsd_resource, nuage_dom_sub[0]['ID'], subnet1['ip_version'])
        self._verify_vsd_dhcp_options(nuage_dhcpopt, subnet1,
                                      l2=not with_router)


class NetworkNuageAdminTest(base.BaseAdminNetworkTest):
    _vsd_address = 'address'

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
        cidr = nuage_data_utils.gimme_a_cidr_address()
        body = self.admin_subnets_client.create_subnet(
            network_id=ext_network['id'],
            cidr=cidr,
            ip_version=self._ip_version,
            name=subname, underlay=True)
        subnet = body['subnet']
        self.assertEqual(subnet['name'], subname)
        # TODO(team) - Add VSD check here
        subnet_ext_id = self.nuage_client.get_vsd_external_id(
            subnet['network_id'])
        nuage_fippool = self.nuage_client.get_sharedresource(
            filters=['externalID', self._vsd_address],
            filter_value=[subnet_ext_id, subnet['cidr']])
        self.assertEqual(nuage_fippool[0]['underlay'], True)
        self.admin_subnets_client.delete_subnet(subnet['id'])
        nuage_fippool = self.nuage_client.get_sharedresource(
            filters='externalID', filter_value=subnet['id'])
        self.assertEqual(nuage_fippool, '')

    @decorators.attr(type='smoke')
    def test_create_delete_external_subnet_without_underlay(self):
        subname = 'non-underlay-subnet'
        ext_network = self._create_network()
        cidr = nuage_data_utils.gimme_a_cidr_address()
        body = self.admin_subnets_client.create_subnet(
            network_id=ext_network['id'],
            cidr=cidr,
            ip_version=self._ip_version,
            name=subname, underlay=False)
        subnet = body['subnet']
        self.assertEqual(subnet['name'], subname)
        # TODO(team) - Add VSD check here
        # TODO(team) - Add VSD check here
        subnet_ext_id = self.nuage_client.get_vsd_external_id(
            subnet['network_id'])
        nuage_fippool = self.nuage_client.get_sharedresource(
            filters=['externalID', self._vsd_address],
            filter_value=[subnet_ext_id, subnet['cidr']])
        self.assertEqual(nuage_fippool[0]['underlay'], False)
        self.admin_subnets_client.delete_subnet(subnet['id'])
        nuage_fippool = self.nuage_client.get_sharedresource(
            filters=['externalID', self._vsd_address],
            filter_value=[subnet_ext_id, subnet['cidr']])
        self.assertEqual(nuage_fippool, '')

    @decorators.attr(type='smoke')
    def test_switch_network_external_vs_internal_without_subnets(self):
        int_network = self.create_network()
        self.assertFalse(int_network['router:external'])
        kwargs = {'router:external': True}
        ext_network = self.admin_networks_client.update_network(
            int_network['id'], **kwargs)['network']
        self.assertTrue(ext_network['router:external'])
        kwargs = {'router:external': False}
        int_network = self.admin_networks_client.update_network(
            ext_network['id'], **kwargs)['network']
        self.assertFalse(int_network['router:external'])

    @decorators.attr(type='smoke')
    def test_make_network_with_routed_subnet_external(self):
        int_network = self.create_network()
        cidr = nuage_data_utils.gimme_a_cidr()
        subnet = self.create_subnet(network=int_network,
                                    cidr=cidr,
                                    mask_bits=24,
                                    ip_version=self._ip_version)
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        # Attach subnet
        self.create_router_interface(router_id=router['id'],
                                     subnet_id=subnet['id'])
        kwargs = {'router:external': True}
        msg = ('Network {} cannot be updated. There are one or more ports '
               'still in use on the network.').format(int_network["id"])
        self.assertRaisesRegex(
            exceptions.BadRequest,
            msg,
            self.admin_networks_client.update_network,
            int_network['id'],
            **kwargs)


class NuageNetworksIpV6Test(NetworksTestJSONNuage):
    _ip_version = 6
    _vsd_address = 'IPv6Address'
