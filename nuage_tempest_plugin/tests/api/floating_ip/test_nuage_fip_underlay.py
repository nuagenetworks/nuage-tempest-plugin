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

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.utils import data_utils as nuage_data_utils
from nuage_tempest_plugin.tests.api.floating_ip import base_nuage_fip_underlay


class FIPtoUnderlayTestNuage(base_nuage_fip_underlay.NuageFipUnderlayBase):

    def test_create_external_subnet_without_underlay(self):
        """test_create_external_subnet_without_underlay

        Create an external FIP subnet without underlay without
        nuage_fip+underlay in .ini

        Response must include underlay = False
        """
        self._verify_create_delete_external_subnet_without_underlay()

    def test_create_external_subnet_with_underlay_default_none(self):
        """test_create_external_subnet_with_underlay_default_none

        Create an external FIP subnet with underlay without
        nuage_fip+underlay in .ini

        Response must include same underlay status as used in creation
        """
        self._verify_create_external_fip_subnet_with_underlay()

    def test_show_external_subnet_without_underlay(self):
        """test_show_external_subnet_without_underlay

        Show an external fip subnet created without underlay without
        nuage_fip_underlay in .ini

        Response must include underlay = False
        """
        self._verify_show_external_subnet_without_underlay()

    def test_show_external_subnet_with_underlay(self):
        """test_show_external_subnet_with_underlay

        Show external fip subnet with underlay without nuage_fip_underlay
        in .ini file

        Response must include underlay - False
        """
        self._verify_show_external_subnet_with_underlay()

    def test_list_external_subnets_underlay(self):
        """test_list_external_subnets_underlay

        List external fip subnets with underlay without nuage_fip_underlay
        in .ini file

        Response must include underlay True for those subnets created with
        underlay True
        and False otherwise
        """
        self._verify_list_external_subnets_underlay()

    def test_multiple_subnets_with_underlay(self):
        """test_multiple_subnets_with_underlay

        Check that when using underlay=True,
        two subnets on two different networks go into the same domain
        """
        ext_network1 = self._create_network(external=True)
        ext_network2 = self._create_network(external=True)
        subnet_name = data_utils.rand_name(
            'create-external-fip-subnet-with-underlay')
        sub1 = self.admin_subnets_client.create_subnet(
            network_id=ext_network1['id'],
            cidr=nuage_data_utils.gimme_a_cidr_address(),
            ip_version=self._ip_version,
            name=subnet_name, underlay=True)['subnet']
        sub2 = self.admin_subnets_client.create_subnet(
            network_id=ext_network2['id'],
            cidr=nuage_data_utils.gimme_a_cidr_address(),
            ip_version=self._ip_version,
            name=subnet_name, underlay=True)['subnet']
        self.assertEqual(sub1['nuage_uplink'], sub2['nuage_uplink'])
        self.admin_subnets_client.delete_subnet(sub2['id'])
        self.admin_subnets_client.delete_subnet(sub1['id'])

    def test_multiple_subnets_with_underlay_disabled(self):
        """test_multiple_subnets_with_underlay_disabled

        Check that when using underlay=False,
        two subnets on two external network go into different domains
        """
        ext_network1 = self._create_network(external=True)
        ext_network2 = self._create_network(external=True)
        sub1 = self.admin_subnets_client.create_subnet(
            network_id=ext_network1['id'],
            cidr=nuage_data_utils.gimme_a_cidr_address(),
            ip_version=self._ip_version,
            underlay=False)['subnet']
        sub2 = self.admin_subnets_client.create_subnet(
            network_id=ext_network2['id'],
            cidr=nuage_data_utils.gimme_a_cidr_address(),
            ip_version=self._ip_version,
            underlay=False)['subnet']
        self.assertNotEqual(sub1['nuage_uplink'], sub2['nuage_uplink'])
        self.admin_subnets_client.delete_subnet(sub2['id'])
        self.admin_subnets_client.delete_subnet(sub1['id'])

    def test_update_external_subnet_with_gateway(self):
        underlay_states = [False, True]
        for underlay in underlay_states:
            ext_network = self._create_network(external=True)
            cidr = nuage_data_utils.gimme_a_cidr()
            allocation_pools = [{'start': str(netaddr.IPAddress(cidr) + 3),
                                 'end': str(netaddr.IPAddress(cidr) + 6)}]
            sub = self.admin_subnets_client.create_subnet(
                network_id=ext_network['id'],
                cidr=cidr,
                ip_version=self._ip_version,
                underlay=underlay,
                allocation_pools=allocation_pools
                )['subnet']
            old_gateway = sub['gateway_ip']
            new_gateway = str(netaddr.IPAddress(cidr) + 2)
            updated_sub = self.admin_subnets_client.update_subnet(
                sub['id'], gateway_ip=new_gateway)['subnet']
            curr_gateway = updated_sub['gateway_ip']
            self.assertNotEqual(old_gateway, curr_gateway)
            self.assertEqual(new_gateway, curr_gateway)
            self.admin_subnets_client.delete_subnet(sub['id'])

    def test_update_external_subnet_with_wrong_gateway(self):
        underlay_states = [False, True]
        for underlay in underlay_states:
            ext_network = self._create_network(external=True)
            cidr = nuage_data_utils.gimme_a_cidr()
            sub = self.admin_subnets_client.create_subnet(
                network_id=ext_network['id'],
                cidr=cidr,
                ip_version=self._ip_version,
                underlay=underlay
            )['subnet']
            new_gateway = '100.0.0.1'
            msg = "Network Gateway IP Address {} is out of range.".format(
                new_gateway)
            self.assertRaisesRegex(
                exceptions.BadRequest,
                msg,
                self.admin_subnets_client.update_subnet,
                sub['id'],
                gateway_ip=new_gateway)
            self.admin_subnets_client.delete_subnet(sub['id'])

    #
    #
    #  Negative test cases
    #
    #
    @decorators.attr(type=['negative'])
    def test_create_external_subnet_with_underlay_invalid_values_neg(self):
        """test_create_external_subnet_with_underlay_invalid_values_neg

        Try to create an external FIP subnet with invalid values for
        underlay=True/False

        Must fail with proper reason
        """
        ext_network = self._create_network(external=True)
        invalid_underlay_values = ['Ttrue', 'Treu', 'Tru', 'Truet', 'Trrue',
                                   'Truue', 'Truee',
                                   'Flase', 'Falsche', 'Fales', 'Flaes',
                                   'FFalse', 'fFalse']
        subnet_name = data_utils.rand_name('subnet-invalid-underlay-value')
        for underlay in invalid_underlay_values:
            kwargs = {
                'network_id': ext_network['id'],
                'cidr': '135.99.99.0/24',
                'ip_version': self._ip_version,
                'name': subnet_name,
                'underlay': underlay
            }
            self.assertRaises(exceptions.BadRequest,
                              self.admin_subnets_client.create_subnet,
                              **kwargs)

    @decorators.attr(type=['negative'])
    def test_create_internal_subnet_with_underlay_neg(self):
        """test_create_internal_subnet_with_underlay_neg

        Try to create an internal subnet while specifying underlay=True/False

        Must fail
        """
        int_network = self.create_network()
        underlay_states = [False, True]
        for underlay in underlay_states:
            subnet_name = data_utils.rand_name(
                'internal-fip-subnet-with-underlay-neg')
            kwargs = {
                'network_id': int_network['id'],
                'cidr': '135.66.66.0/24',
                'ip_version': self._ip_version,
                'name': subnet_name,
                'underlay': underlay
            }
            self.assertRaises(exceptions.BadRequest,
                              self.admin_subnets_client.create_subnet,
                              **kwargs)

    @decorators.attr(type=['negative'])
    def test_update_internal_subnet_with_underlay_neg(self):
        """test_update_internal_subnet_with_underlay_neg

        Try to update an internal subnet while specifying underlay=True/False

        Must fail: verifies OPENSTACK-722
        """
        int_network = self.create_network()
        subnet_name = data_utils.rand_name(
            'underlay-update-internal-subnet-not-allowed')
        create_body = self.admin_subnets_client.create_subnet(
            network_id=int_network['id'],
            cidr="99.97.95.0/24",
            ip_version=self._ip_version,
            name=subnet_name)
        subnet = create_body['subnet']
        new_name = subnet_name + '-updated'
        kwargs = {
            'name': new_name,
            'underlay': True
        }
        self.assertRaises(exceptions.BadRequest,
                          self.admin_subnets_client.update_subnet,
                          subnet['id'],
                          **kwargs)
        self.admin_subnets_client.delete_subnet(subnet['id'])

    @decorators.attr(type=['negative'])
    def test_create_external_subnet_with_underlay_invalid_syntax_neg(self):
        """test_create_external_subnet_with_underlay_invalid_syntax_neg

        Try to create an external FIP subnet with invalid values for "underlay'

        Must fail with proper reason
        """
        ext_network = self._create_network(external=True)
        underlay_invalid_syntax = ['Underley', 'Overlay', 'under1ay',
                                   'inderlay', 'overlay', 'ollekenbolleke',
                                   'undarlay', 'anderluy', 'etcetera', '...',
                                   '***']
        subnet_name = data_utils.rand_name('subnet-invalid-underlay-syntax')
        for underlay in underlay_invalid_syntax:
            kwargs = {
                'network_id': ext_network['id'],
                'cidr': '135.99.99.0/24',
                'ip_version': self._ip_version,
                'name': subnet_name,
                underlay: True
            }
            self.assertRaises(exceptions.BadRequest,
                              self.admin_subnets_client.create_subnet,
                              **kwargs)

    @decorators.attr(type=['negative'])
    def test_update_external_subnet_with_snat_neg(self):
        self._verify_update_external_subnet_with_underlay_neg()


class NuageFipTest(NuageBaseTest):

    def _create_associate_fip(self, fip_to_underlay):
        ext_network = self.create_public_subnet(fip_to_underlay)

        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(external_network_id=ext_network['id'])
        self.router_attach(router, subnet)

        port = self.create_port(network)

        floating_ip = self.create_floatingip(
            external_network_id=ext_network['id'])
        self.update_floatingip(floating_ip, port_id=port['id'])

        nuage_subnet = self.vsd.get_subnet(by_subnet=subnet)
        nuage_vport = self.vsd.get_vport(subnet=nuage_subnet,
                                         by_port_id=port['id'])
        self.assertIsNotNone(nuage_vport.associated_floating_ip_id,
                             'No floating ip associated to the vport on VSD')

    @decorators.attr(type='smoke')
    def test_fip_no_underlay(self):
        self._create_associate_fip(fip_to_underlay=False)

    @decorators.attr(type='smoke')
    def test_fip_with_underlay(self):
        self._create_associate_fip(fip_to_underlay=True)
