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

from netaddr import IPAddress
from netaddr import IPNetwork

from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils as nuage_utils
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

    def _verify_l2domain(self, domain_json, vspk_domain,
                         vspk_backend_domain=None):
        # The backend l2domain is only relevant when the l2 domain is linked
        # to a backend domain in Shared Infrastructure.
        vspk_backend_domain = vspk_backend_domain or vspk_domain
        self.assertEqual(vspk_domain.id, domain_json.get('id'))
        self.assertEqual(vspk_domain.name, domain_json.get('name'))
        self.assertEqual('L2', domain_json.get('type'))
        self.assertEqual(vspk_domain.parent_id,
                         domain_json.get('net_partition_id'))
        if Topology.has_full_dhcp_control_in_vsd():
            self.assertEqual(vspk_backend_domain.dhcp_managed,
                             domain_json.get('dhcp_managed'))
            self.assertEqual(vspk_backend_domain.ip_type,
                             domain_json.get('ip_version'))
            l2dom_address = IPNetwork(
                vspk_backend_domain.address + '/' +
                vspk_backend_domain.netmask)
            self.assertEqual(str(l2dom_address), domain_json.get('cidr'))
            self.assertEqual(vspk_backend_domain.ipv6_address,
                             domain_json.get('ipv6_cidr'))
            self.assertEqual(vspk_backend_domain.ipv6_gateway,
                             domain_json.get('ipv6_gateway'))

            dhcp_option = vspk_backend_domain.dhcp_options.get_first()
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
                          vspk_backend_subnet=None, with_enterprise=True):
        # The backend subnet is only relevant when the l3 subnet is linked
        # to a backend subnet in Shared Infrastructure.
        vspk_backend_subnet = vspk_backend_subnet or vspk_subnet
        self.assertEqual(vspk_subnet.id, vsd_api_subnet.get('id'))
        self.assertEqual(vspk_subnet.name, vsd_api_subnet.get('name'))
        if vspk_backend_subnet.address:
            cidr = IPNetwork(vspk_backend_subnet.address + '/' +
                             vspk_backend_subnet.netmask)
            self.assertEqual(str(cidr), vsd_api_subnet.get('cidr'))
        else:
            self.assertIsNone(vsd_api_subnet.get('cidr'))
        self.assertEqual(vspk_backend_subnet.ipv6_address,
                         vsd_api_subnet.get('ipv6_cidr'))
        self.assertEqual(vspk_backend_subnet.gateway,
                         vsd_api_subnet.get('gateway'))
        self.assertEqual(vspk_backend_subnet.ipv6_gateway,
                         vsd_api_subnet.get('ipv6_gateway'))
        self.assertEqual(vspk_backend_subnet.ip_type,
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
            vsd_organisation_id=enterprise['id'])['vsd_domains']
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
            vsd_organisation_id=enterprise.id)['vsd_domains']
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
            vsd_organisation_id=enterprise['id'])['vsd_domains']
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
            vsd_organisation_id=enterprise.id)['vsd_domains']
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
            vsd_organisation_id=enterprise['id'])['vsd_domains']
        self.assertEmpty(domains, 'Empty enterprise should not contain any '
                                  'domains but contained {}'.format(domains))
        # Create l2domain
        enterprise = self.vsd.get_enterprise_by_name(name)
        l2dom_temp = self.vsd_create_l2domain_template(enterprise=enterprise,
                                                       cidr4=self.cidr4)
        l2dom = self.vsd.create_l2domain(name, enterprise, l2dom_temp)
        domains = self.NuageNetworksClient.get_domains(
            vsd_organisation_id=enterprise.id)['vsd_domains']
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
            vsd_organisation_id=enterprise.id)['vsd_domains'][0]
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
        self._verify_l3_subnet(vsd_api_subnet, vspk_subnet)

        subnets = self.NuageNetworksClient.get_vsd_subnets(
            vsd_zone_id=zone.id)['vsd_subnets']
        self.assertNotEmpty(subnets, 'zone should contain subnets')
        self.assertEqual(1, len(subnets),
                         'Exactly one subnet should be found, but '
                         'found: {}'.format(len(subnets)))
        self._verify_l3_subnet(subnets[0], vspk_subnet, with_enterprise=False)

    def test_get_vsd_domains_neg(self):
        router = self.create_router()

        l3dom = self.vsd.get_l3domain(by_router_id=router['id'])
        l3dom.delete()

        vsd_api_domains = self.NuageNetworksClient.get_domains(
            os_router_ids=router['id'])['vsd_domains']
        self.assertEmpty(vsd_api_domains)

    def test_get_linked_shared_resource_l2_domains(self):
        """test_get_linked_shared_resource_l2_domains

        Test that when linked a shared subnet to a private l2domain
        the attributes returned are those of the shared subnet.

        """
        # Create private enterprise
        enterprise_name = data_utils.rand_name('test-verify-linked-domains')
        enterprise = self.NuageNetworksClient.create_netpartition(
            enterprise_name)['net_partition']
        self.addCleanup(self.NuageNetworksClient.delete_netpartition,
                        enterprise['id'])

        # Create shared resources
        cidr4 = nuage_utils.gimme_a_cidr()
        cidr6 = nuage_utils.gimme_a_cidr(ip_version=6)
        shared_l2dom_template = self.vsd.create_l2domain_template(
            enterprise='Shared Infrastructure',
            ip_type='DUALSTACK',
            cidr4=cidr4, cidr6=cidr6,
            enable_dhcpv4=True, enable_dhcpv6=True
        )
        self.addCleanup(shared_l2dom_template.delete)
        shared_l2dom = self.vsd.create_l2domain(
            enterprise='Shared Infrastructure', template=shared_l2dom_template)
        self.addCleanup(shared_l2dom.delete)

        # Link in created enterprise
        l2dom_template = self.vsd.create_l2domain_template(
            enterprise=enterprise_name, dhcp_managed=False)
        self.addCleanup(l2dom_template.delete)
        l2dom = self.vsd.create_l2domain(
            enterprise=enterprise_name,
            template=l2dom_template,
            associated_shared_network_resource_id=shared_l2dom.id)
        self.addCleanup(l2dom.delete)

        # Get l2domain
        domains = self.NuageNetworksClient.get_domains(
            vsd_organisation_id=enterprise['id'])['vsd_domains']
        # Check that l2domain is found
        self.assertNotEmpty(domains, 'Enterprise should contain domains')
        self.assertEqual(1, len(domains),
                         'Exactly one l2domain should be found, but '
                         'found: {}'.format(len(domains)))
        domain_json = domains[0]

        # Verify
        self._verify_l2domain(domain_json, l2dom, shared_l2dom)

        # SET DHCP option 3: gateway
        dhcp_option = self.vsd.vspk.NUDHCPOption(
            actual_type=3, actual_values=[str(IPAddress(cidr4.first) + 1)])
        shared_l2dom.create_child(dhcp_option)
        domains = self.NuageNetworksClient.get_domains(
            vsd_organisation_id=enterprise['id'])['vsd_domains']
        domain_json = domains[0]
        self._verify_l2domain(domain_json, l2dom, shared_l2dom)

    def test_get_linked_shared_resource_l3_domains(self):
        """test_get_linked_shared_resource_l3_domains

        Test that when linked a shared subnet to a private l3subnet
        the attributes returned are those of the shared subnet.

        :return:
        """
        # Create private enterprise
        enterprise_name = data_utils.rand_name('test-verify-linked-domains')
        enterprise = self.NuageNetworksClient.create_netpartition(
            enterprise_name)['net_partition']
        self.addCleanup(self.NuageNetworksClient.delete_netpartition,
                        enterprise['id'])

        # Create shared resources
        cidr4 = nuage_utils.gimme_a_cidr()
        cidr6 = nuage_utils.gimme_a_cidr(ip_version=6)
        shared_l3dom_template = self.vsd.create_l3domain_template(
            enterprise='Shared Infrastructure')
        self.addCleanup(shared_l3dom_template.delete)
        shared_l3dom = self.vsd.create_l3domain(
            enterprise='Shared Infrastructure',
            template_id=shared_l3dom_template.id)
        self.addCleanup(shared_l3dom.delete)
        shared_zone = self.vsd.create_zone(domain=shared_l3dom)
        self.addCleanup(shared_zone.delete)
        shared_l3subnet = self.vsd.create_subnet(
            zone=shared_zone,
            ip_type='DUALSTACK',
            cidr4=cidr4, cidr6=cidr6,
            enable_dhcpv4=True, enable_dhcpv6=True,
            resource_type='PUBLIC'
        )
        self.addCleanup(shared_l3subnet.delete)

        # Link in created enterprise
        l3dom_template = self.vsd.create_l3domain_template(
            enterprise=enterprise_name)
        self.addCleanup(l3dom_template.delete)
        l3dom = self.vsd.create_l3domain(
            enterprise=enterprise_name,
            template_id=l3dom_template.id)
        self.addCleanup(l3dom.delete)
        public_zone = self.vsd.create_zone(domain=l3dom,
                                           public_zone=True)
        self.addCleanup(public_zone.delete)
        l3subnet = self.vsd.create_subnet(
            zone=public_zone,
            associated_shared_network_resource_id=shared_l3subnet.id
        )
        self.addCleanup(l3subnet.delete)

        # Get l3 subnet
        subnets = self.NuageNetworksClient.get_vsd_subnets(
            public_zone.id)['vsd_subnets']
        # Check that l3subnet is found
        self.assertNotEmpty(subnets, 'Enterprise should contain l3 subnets')
        self.assertEqual(1, len(subnets),
                         'Exactly one l3 subnet should be found, but '
                         'found: {}'.format(len(subnets)))
        subnet_json = subnets[0]

        # Verify
        self._verify_l3_subnet(subnet_json, vspk_subnet=l3subnet,
                               vspk_backend_subnet=shared_l3subnet,
                               with_enterprise=False)
