# Copyright 2019 NOKIA
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

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON


class NuageApiTest(NuageBaseTest):

    @classmethod
    def setup_clients(cls):
        super(NuageApiTest, cls).setup_clients()
        cls.NuageNetworksClient = NuageNetworkClientJSON(
            cls.os_admin.auth_provider,
            **cls.os_admin.default_params)
        cls.NuageNetworksClientNonAdmin = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)

    def _verify_l2domain(self, domain_json, vspk_domain):
        self.assertEqual(vspk_domain.id, domain_json.get('id'))
        self.assertEqual(vspk_domain.name, domain_json.get('name'))
        self.assertEqual('L2', domain_json.get('type'))
        self.assertEqual(vspk_domain.parent_id,
                         domain_json.get('net_partition_id'))
        if Topology.has_full_dhcp_control_in_vsd():
            self.assertEqual(vspk_domain.dhcp_managed,
                             domain_json.get('dhcp_managed'))
            self.assertEqual(vspk_domain.ip_type,
                             domain_json.get('ip_version'))
            l2dom_address = netaddr.IPNetwork(
                vspk_domain.address + '/' + vspk_domain.netmask)
            self.assertEqual(str(l2dom_address), domain_json.get('cidr'))
            self.assertEqual(vspk_domain.ipv6_address,
                             domain_json.get('ipv6_cidr'))
            self.assertEqual(vspk_domain.ipv6_gateway,
                             domain_json.get('ipv6_gateway'))

            dhcp_option = vspk_domain.dhcp_options.get_first()
            if dhcp_option:
                self.assertEqual(dhcp_option.actual_values[0],
                                 domain_json['gateway'])
            else:
                self.assertIsNone(domain_json.get('gateway'))

    def _verify_l3domain(self, domain_json, vspk_domain):
        self.assertEqual(vspk_domain.id, domain_json.get('id'))
        self.assertEqual(vspk_domain.name, domain_json.get('name'))
        self.assertEqual('L3', domain_json.get('type'))
        self.assertEqual(vspk_domain.parent_id,
                         domain_json.get('net_partition_id'))

    def _verify_l3_subnet(self, vsd_api_subnet, vspk_subnet,
                          with_enterprise=True):
        self.assertEqual(vspk_subnet.id, vsd_api_subnet.get('id'))
        self.assertEqual(vspk_subnet.name, vsd_api_subnet.get('name'))
        if vspk_subnet.address:
            cidr = netaddr.IPNetwork(vspk_subnet.address + '/' +
                                     vspk_subnet.netmask)
            self.assertEqual(str(cidr), vsd_api_subnet.get('cidr'))
        else:
            self.assertIsNone(vsd_api_subnet.get('cidr'))
        self.assertEqual(vspk_subnet.ipv6_address,
                         vsd_api_subnet.get('ipv6_cidr'))
        self.assertEqual(vspk_subnet.gateway, vsd_api_subnet.get('gateway'))
        self.assertEqual(vspk_subnet.ipv6_gateway,
                         vsd_api_subnet.get('ipv6_gateway'))
        self.assertEqual(vspk_subnet.ip_type,
                         vsd_api_subnet.get('ip_version'))
        if with_enterprise:
            self.assertEqual(self.vsd.get_default_enterprise().name,
                             vsd_api_subnet.get('net_partition'))

    def test_verify_vsd_domains(self):
        name = data_utils.rand_name('test-verify-domains')
        enterprise = self.NuageNetworksClient.create_netpartition(
            name)['net_partition']
        self.addCleanup(self.NuageNetworksClient.delete_netpartition,
                        enterprise['id'])
        domains = self.NuageNetworksClient.get_domains(
            enterprise['id'])['vsd_domains']
        self.assertEmpty(domains, 'Empty enterprise should not contain any '
                                  'domains but contained {}'.format(domains))
        # Create l2domain
        enterprise = self.vsd.get_enterprise_by_name(name)
        l2dom_temp = self.vsd_create_l2domain_template(enterprise=enterprise,
                                                       cidr4=self.cidr4)
        l2dom = self.vsd.create_l2domain(name, enterprise, l2dom_temp)

        # Create l3domain
        l3template = enterprise.domain_templates.get_first()
        l3dom = self.vsd.create_domain(name, enterprise, l3template.id)
        self.addCleanup(l3dom.delete)

        domains = self.NuageNetworksClient.get_domains(
            enterprise.id)['vsd_domains']
        for domain in domains:
            if domain.get('type') == 'L2':
                self._verify_l2domain(domain, l2dom)
            else:
                self._verify_l3domain(domain, l3dom)

    def test_l2domain_gateway(self):
        name = data_utils.rand_name('test-verify-domains')
        enterprise = self.NuageNetworksClient.create_netpartition(
            name)['net_partition']
        self.addCleanup(self.NuageNetworksClient.delete_netpartition,
                        enterprise['id'])
        domains = self.NuageNetworksClient.get_domains(
            enterprise['id'])['vsd_domains']
        self.assertEmpty(domains, 'Empty enterprise should not contain any '
                                  'domains but contained {}'.format(domains))
        # Create l2domain
        enterprise = self.vsd.get_enterprise_by_name(name)
        l2dom_temp = self.vsd_create_l2domain_template(enterprise=enterprise,
                                                       cidr4=self.cidr4)
        l2dom = self.vsd.create_l2domain(name, enterprise, l2dom_temp)

        # Gateway = DHCP option 3
        dhcp_option = self.vsd.vspk.nudhcpoption.NUDHCPOption(
            actual_type=3, actual_values=[str(self.cidr4[1])])
        l2dom.create_child(dhcp_option)

        domains = self.NuageNetworksClient.get_domains(
            enterprise.id)['vsd_domains']
        # Check that l2domain is found
        self.assertNotEmpty(domains, 'Enterprise should contain domains')
        self.assertEqual(1, len(domains),
                         'Exactly one l2domain should be found, but '
                         'found: {}'.format(len(domains)))
        self._verify_l2domain(domains[0], l2dom)

    def test_get_domains_with_only_l2domains_in_enterprise(self):
        name = data_utils.rand_name('test-get-domains-l2dom')
        enterprise = self.NuageNetworksClient.create_netpartition(
            name)['net_partition']
        self.addCleanup(self.NuageNetworksClient.delete_netpartition,
                        enterprise['id'])
        domains = self.NuageNetworksClient.get_domains(
            enterprise['id'])['vsd_domains']
        self.assertEmpty(domains, 'Empty enterprise should not contain any '
                                  'domains but contained {}'.format(domains))
        # Create l2domain
        enterprise = self.vsd.get_enterprise_by_name(name)
        l2dom_temp = self.vsd_create_l2domain_template(enterprise=enterprise,
                                                       cidr4=self.cidr4)
        l2dom = self.vsd.create_l2domain(name, enterprise, l2dom_temp)
        domains = self.NuageNetworksClient.get_domains(
            enterprise.id)['vsd_domains']
        # Check that l2domain is found
        self.assertNotEmpty(domains, 'Enterprise should contain domains')
        self.assertEqual(1, len(domains),
                         'Exactly one l2domain should be found, but '
                         'found: {}'.format(len(domains)))
        domain = domains[0]
        # check attributes
        self._verify_l2domain(domain, l2dom)

        dhcp_option = self.vsd.vspk.nudhcpoption.NUDHCPOption(
            actual_type=3, actual_values=[str(self.cidr4[1])])
        l2dom.create_child(dhcp_option)
        domain = self.NuageNetworksClient.get_domains(
            enterprise.id)['vsd_domains'][0]
        self._verify_l2domain(domain, l2dom)

    def test_get_vsd_subnet(self):
        router = self.create_router()
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.router_attach(router, subnet)
        vspk_subnet = self.vsd.get_subnet(by_subnet=subnet)
        vsd_api_subnet = self.NuageNetworksClient.get_vsd_subnet(
            vspk_subnet.id)['vsd_subnet']
        # Find the zone
        domain = self.vsd.get_domain(by_router_id=router['id'])
        zone = self.vsd.get_zone(
            domain=domain,
            vspk_filter="not(name BEGINSWITH 'def_zone-pub') and "
                        "(name BEGINSWITH 'def_zone')")
        self._verify_l3_subnet(vsd_api_subnet, vspk_subnet, zone)

        subnets = self.NuageNetworksClient.get_vsd_subnets(
            vsd_zone_id=zone.id)['vsd_subnets']
        self.assertNotEmpty(subnets, 'zone should contain subnets')
        self.assertEqual(1, len(subnets),
                         'Exactly one subnet should be found, but '
                         'found: {}'.format(len(subnets)))
        self._verify_l3_subnet(subnets[0], vspk_subnet, with_enterprise=False)
