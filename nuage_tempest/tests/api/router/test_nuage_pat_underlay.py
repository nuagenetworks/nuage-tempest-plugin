# Copyright 2013 OpenStack Foundation
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

from netaddr import IPNetwork
from oslo_log import log as logging

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

import base_nuage_pat_underlay

from nuage_tempest.lib.test import nuage_test
from nuage_tempest.lib.utils import constants

CONF = config.CONF


class TestNuagePatUnderlay(base_nuage_pat_underlay.NuagePatUnderlayBase):
    _interface = 'json'

    LOG = logging.getLogger(__name__)

    @classmethod
    def resource_setup(cls):
        super(TestNuagePatUnderlay, cls).resource_setup()

    @nuage_test.header()
    def test_create_router_without_external_gateway_pat(self):
        self._verify_create_router_without_ext_gw()

    @nuage_test.header()
    def test_create_router_with_external_gateway_without_snat(self):
        self._verify_create_router_with_ext_gw_without_snat()

    @nuage_test.header()
    def test_create_router_without_external_gateway_with_snat_neg(self):
        self._verify_create_router_without_ext_gw_with_snat_neg()

    @nuage_test.header()
    def test_create_router_with_external_gateway_with_snat(self):
        self._verify_create_router_with_ext_gw_with_snat()

    @nuage_test.header()
    def test_update_router_with_external_gateway_with_snat(self):
        self._verify_update_router_with_ext_gw_with_snat()

    @nuage_test.header()
    def test_show_router_without_external_gateway(self):
        self._verify_show_router_without_ext_gw()

    @nuage_test.header()
    def test_show_router_with_external_gateway_with_snat(self):
        self._verify_show_router_with_ext_gw_with_snat()

    @nuage_test.header()
    def test_list_router_with_external_gateway_with_snat(self):
        self._verify_list_router_with_gw_with_snat()

    @nuage_test.header()
    def test_create_router_with_snat_invalid_neg(self):
        """test_create_router_with_snat_invalid_neg

        Create router with external gateway with invalid values for '
        enable_snat'

        Must fail
        """
        # Create a router enabling snat attributes
        enable_snat_states = ['Ttrue', 'Treu', 'Tru', 'Truet', 'Trrue',
                              'Truue', 'Truee',
                              'Flase', 'Falsche', 'Fales', 'Flaes',
                              'FFalse', 'fFalse']
        name = data_utils.rand_name('router-with-snat-invalid-fail')
        for enable_snat in enable_snat_states:
            external_gateway_info = {
                'enable_snat': enable_snat}
            # Create the router: must fail
            kwargs = {
                'name': name,
                'external_gateway_info': external_gateway_info
            }
            self.assertRaises(exceptions.BadRequest,
                              self.admin_routers_client.create_router,
                              **kwargs)

    @nuage_test.header()
    def test_create_router_with_snat_invalid_syntax_neg(self):
        """test_create_router_with_snat_invalid_syntax_neg

        Create router with external gateway with invalid syntax for
        'enable_snat'

        Must fail
        """
        name = data_utils.rand_name('snat-router-invalid-syntax')
        enable_snat_typos = ['enabel_snat', 'enablesnat', 'enable-snat',
                             'Enable_Snat', 'enable_sant',
                             'eeeennnnnaaaabahajhjakjakfjhadkfjhadkjfhadkadjk']
        for enable_snat_syntax_err in enable_snat_typos:
            external_gateway_info = {
                enable_snat_syntax_err: 'True'}
            kwargs = {
                'name': name,
                'external_gateway_info': external_gateway_info
            }
            # Try to create the router: must fail
            self.assertRaises(exceptions.BadRequest,
                              self.admin_routers_client.create_router,
                              **kwargs)

    @nuage_test.header()
    def test_create_router_with_gateway_with_non_existing_ext_network_neg(
            self):
        """test_create_router_with_gateway_with_non_existing_ext_network_neg

        Try to create router with external gateway with a non-existing
        external network uuid

        Must fail
        """
        name = data_utils.rand_name(
            'router-with-external-gateway-non-existing-networkid')
        # reverse the existing ext network id, unlikely that this exists ;-)
        bad_network_id = '11111111-1111-1111-1111-111111111111'
        external_gateway_info = {
            'network_id': bad_network_id,
            'enable_snat': True}
        kwargs = {
            'name': name,
            'external_gateway_info': external_gateway_info
        }
        self.assertRaises(exceptions.NotFound,
                          self.admin_routers_client.create_router,
                          **kwargs)

    @nuage_test.header()
    def test_create_router_with_external_gw_with_vsd_managed_subnet_neg(self):
        """test_create_router_with_external_gw_with_vsd_managed_subnet_neg

        Create router with external gateway, using a VSD managed subnet

        Should fail, as PAT is only for OS managed networks
        """
        name = data_utils.rand_name('vsd-l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        params = {
            'DHCPManaged': True,
            'address': str(cidr.ip),
            'netmask': str(cidr.netmask),
            'gateway': '10.10.100.1'
        }
        vsd_l2dom_template = self.nuage_vsd_client.create_l2domaintemplate(
            name=name + '-template',
            extra_params=params)

        template_id = vsd_l2dom_template[0]['ID']
        vsd_l2domain = self.nuage_vsd_client.create_l2domain(
            name=name, templateId=template_id)
        self.assertEqual(vsd_l2domain[0][u'name'], name)
        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('os-ext-network-')
        # create the external network
        post_body = {'name': net_name,
                     'router:external': True}
        body = self.admin_networks_client.create_network(**post_body)
        ext_network = body['network']
        self.addCleanup(
            self.admin_networks_client.delete_network, ext_network['id'])
        # Create the external FIP subnet with underlay and referring to the
        # VSD managed subnet
        # Must fail as VSD managed subnets cannot be linked to an ext network
        subnet_name = data_utils.rand_name('external-vsd-fip-subnet-neg')
        kwargs = {
            'network_id': ext_network['id'],
            'cidr': str(cidr),
            'ip_version': self._ip_version,
            'name': subnet_name,
            'net_partition': CONF.nuage.nuage_default_netpartition,
            'nuagenet': vsd_l2domain[0][u'ID']
        }
        self.assertRaises(exceptions.BadRequest,
                          self.admin_subnets_client.create_subnet,
                          **kwargs)
        self.nuage_vsd_client.delete_l2domain(
            vsd_l2domain[0]['ID'])
        self.nuage_vsd_client.delete_l2domaintemplate(
            vsd_l2dom_template[0]['ID'])

    @nuage_test.header()
    def test_create_router_with_internal_network_neg(self):
        """test_create_router_with_internal_network_neg

        Try to create router with ext gateway with an internal network uuid

        Must fail
        """
        network_name = name = data_utils.rand_name('pat-int-network')
        int_network = self.create_network(network_name=network_name)
        name = data_utils.rand_name(
            'router-with-external-gateway-internal-network')
        external_gateway_info = {
            'network_id': int_network['id'],
            'enable_snat': True}
        kwargs = {
            'name': name,
            'external_gateway_info': external_gateway_info
        }
        self.assertRaises(exceptions.BadRequest,
                          self.admin_routers_client.create_router,
                          **kwargs)

    @nuage_test.header()
    def test_add_subnet_to_existing_pat_router_neg(self):
        """test_add_subnet_to_existing_pat_router_neg

        Add a subnet to an existing external router with snat enabled

        Must succeed
        """
        cidr = IPNetwork('10.10.9.0/24')
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            # create an  external network
            post_body = {'name': data_utils.rand_name('external-network'),
                         'router:external': True}
            body = self.admin_networks_client.create_network(**post_body)
            ext_network = body['network']
            self.addCleanup(
                self.admin_networks_client.delete_network, ext_network['id'])
            # create the router
            router_name = data_utils.rand_name('router-with-ext-gw-with-snat')
            external_gateway_info = {
                'network_id': ext_network['id'],
                'enable_snat': enable_snat}
            create_body = self.admin_routers_client.create_router(
                name=router_name, external_gateway_info=external_gateway_info)
            # Verify snat attributes after router creation
            self._verify_router_gateway(create_body['router']['id'],
                                        exp_ext_gw_info=external_gateway_info)
            # Showing this router also return the proper value of snat
            show_body = self.admin_routers_client.show_router(
                create_body['router']['id'])
            self.assertEqual(
                show_body['router']['external_gateway_info']['enable_snat'],
                enable_snat)
            # Add a subnet
            subnet_body = self.admin_subnets_client.create_subnet(
                network_id=ext_network['id'],
                cidr=str(cidr.cidr),
                ip_version=self._ip_version)
            # subnet = self.create_subnet(ext_network, None, cidr)
            # Check patEnabled flag on VSD: should be accordingly
            nuage_domain = self.nuage_vsd_client.get_l3domain(
                filters='externalID',
                filter_value=self.nuage_vsd_client.get_vsd_external_id(
                    create_body['router']['id']))
            self.assertEqual(
                nuage_domain[0]['PATEnabled'],
                constants.NUAGE_PAT_VSD_ENABLED if enable_snat else
                constants.NUAGE_PAT_VSD_DISABLED)
            cidr = cidr.next(1)
            # Delete the router and subnet here to prevent the issues with
            # deleting subnets while still having IP
            # ports in use, until the router is deleted
            self.admin_routers_client.delete_router(
                create_body['router']['id'])
            self.admin_subnets_client.delete_subnet(
                subnet_body['subnet']['id'])
