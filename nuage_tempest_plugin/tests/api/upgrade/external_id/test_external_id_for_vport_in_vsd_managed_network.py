# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from netaddr import IPNetwork

from tempest.api.network import base as base
from tempest.lib.common.utils import data_utils

import testtools

from .external_id import ExternalId

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.lib.utils import exceptions as n_exceptions
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

LOG = Topology.get_logger(__name__)

extra_dhcp_opts = [
    {'opt_value': '255.255.255.0', 'opt_name': 'netmask'},
    {'opt_value': '200', 'opt_name': 'time-offset'},
    {'opt_value': '11.33.66.3', 'opt_name': 'router'},
    {'opt_value': '11.33.66.4', 'opt_name': 'time-server'},
    {'opt_value': '11.33.66.6', 'opt_name': 'dns-server'},
    {'opt_value': '11.33.66.7', 'opt_name': 'log-server'}
]


class ExternalIdForVPortTest(base.BaseAdminNetworkTest):
    class MatchingVsdVPort(object):
        def __init__(self, outer, port, subnet, vsd_l2domain):
            """Construct a Vsd_port. """
            self.test = outer
            self.port = port
            self.subnet = subnet

            self.vsd_vport = None
            self.vsd_l2domain = vsd_l2domain
            self.vsd_security_policy_group = None

        def get_by_external_id(self):
            vsd_vports = self.test.nuage_client.get_vport(
                parent=n_constants.L2_DOMAIN,
                parent_id=self.vsd_l2domain['ID'],
                filters='externalID',
                filter_value=ExternalId(self.port['id']).at_cms_id())

            # should have exact 1 match
            self.test.assertEqual(len(vsd_vports), 1)
            self.vsd_vport = vsd_vports[0]

            self.test.assertNotEmpty(self.vsd_vport)
            self.test.assertEqual(self.vsd_vport['name'], self.port['id'])
            return self

        def has_dhcp_options(self, with_external_id=None):
            # vsd dhcp_options object has external ID
            vsd_dhcp_options = self.test.nuage_client.get_dhcpoption(
                parent=n_constants.VPORT,
                parent_id=self.vsd_vport['ID'])

            self.test.assertEqual(len(vsd_dhcp_options), len(extra_dhcp_opts),
                                  "dhcp_options not found by VSD parent ID")

            if with_external_id is None:
                self.test.assertIsNone(vsd_dhcp_options[0]['externalID'])
            else:
                vsd_dhcp_options = \
                    self.test.nuage_client.get_child_resource(
                        resource=n_constants.VPORT,
                        resource_id=self.vsd_vport['ID'],
                        child_resource=n_constants.DHCPOPTION,
                        filters='externalID',
                        filter_value=with_external_id)

                self.test.assertEqual(len(vsd_dhcp_options),
                                      len(extra_dhcp_opts),
                                      "dhcp_options not found by ExternalID")
                for vsd_dhcp_option in vsd_dhcp_options:
                    self.test.assertEqual(
                        with_external_id,
                        ExternalId(vsd_dhcp_option['externalID']).at_cms_id())

        def has_default_security_policy_group(self, with_external_id=None):
            # vsd has_default_security_policy_group object has external ID
            # vsd_security_policy_groups = self.test.nuage_client.\
            #                              get_policygroup(
            #     parent=n_constants.POLICYGROUP,
            #     parent_id=self.vsd_vport['parentID'])
            vsd_security_policy_groups = \
                self.test.nuage_client.get_child_resource(
                    resource=n_constants.L2_DOMAIN,
                    resource_id=self.vsd_vport['parentID'],
                    child_resource=n_constants.POLICYGROUP)

            self.test.assertEqual(1, len(vsd_security_policy_groups),
                                  "policy group not found by VSD parent ID")

            self.vsd_security_policy_group = vsd_security_policy_groups[0]

            if with_external_id is None:
                self.test.assertIsNone(
                    vsd_security_policy_groups[0]['externalID'])
            else:
                vsd_security_policy_groups = \
                    self.test.nuage_client.get_child_resource(
                        resource=n_constants.L2_DOMAIN,
                        resource_id=self.vsd_vport['parentID'],
                        child_resource=n_constants.POLICYGROUP,
                        filters='externalID',
                        filter_value=with_external_id)

                self.test.assertEqual(1, len(vsd_security_policy_groups),
                                      "policy group not found by ExternalID")

                self.test.assertEqual(
                    with_external_id,
                    ExternalId(vsd_security_policy_groups[0]['externalID']
                               ).at_cms_id())

        def has_default_ingress_policy_entries(self, with_external_id=None):
            # vsd ingress_acl_template object has external ID
            vsd_ingress_acl_templates =\
                self.test.nuage_client.get_ingressacl_template(
                    parent=n_constants.L2_DOMAIN,
                    parent_id=self.vsd_l2domain['ID'])

            self.test.assertEqual(
                len(vsd_ingress_acl_templates), 1,
                "ingress_acl_template not found by VSD parent ID")

            vsd_ingress_security_policy_entries = \
                self.test.nuage_client.get_child_resource(
                    resource=n_constants.INGRESS_ACL_TEMPLATE,
                    resource_id=vsd_ingress_acl_templates[0]['ID'],
                    child_resource=n_constants.INGRESS_ACL_ENTRY_TEMPLATE,
                    filters='locationID',
                    filter_value=self.vsd_security_policy_group['ID'])

            self.test.assertEqual(
                1, len(vsd_ingress_security_policy_entries),
                "Should find exact 1 match for ingress policy entries")

            if with_external_id is None:
                self.test.assertIsNone(
                    vsd_ingress_security_policy_entries[0]['externalID'])
            else:
                vsd_ingress_security_policy_entries = \
                    self.test.nuage_client.get_child_resource(
                        resource=n_constants.INGRESS_ACL_TEMPLATE,
                        resource_id=vsd_ingress_acl_templates[0]['ID'],
                        child_resource=n_constants.INGRESS_ACL_ENTRY_TEMPLATE,
                        filters='externalID',
                        filter_value=with_external_id)

                self.test.assertEqual(
                    1, len(vsd_ingress_security_policy_entries),
                    "policy group not found by ExternalID")

                self.test.assertEqual(
                    with_external_id,
                    ExternalId(
                        vsd_ingress_security_policy_entries[0]['externalID']
                    ).at_cms_id())

        def has_default_egress_policy_entries(self, with_external_id=None):
            # vsd egress_acl_template object has external ID
            vsd_egress_acl_templates = \
                self.test.nuage_client.get_egressacl_template(
                    parent=n_constants.L2_DOMAIN,
                    parent_id=self.vsd_l2domain['ID'])

            self.test.assertEqual(
                len(vsd_egress_acl_templates), 1,
                "egress_acl_template not found by VSD parent ID")

            vsd_egress_security_policy_entries = \
                self.test.nuage_client.get_child_resource(
                    resource=n_constants.EGRESS_ACL_TEMPLATE,
                    resource_id=vsd_egress_acl_templates[0]['ID'],
                    child_resource=n_constants.EGRESS_ACL_ENTRY_TEMPLATE,
                    filters='locationID',
                    filter_value=self.vsd_security_policy_group['ID'])

            self.test.assertEqual(
                1, len(vsd_egress_security_policy_entries),
                "Should find exact 1 match for egress policy entries")

            if with_external_id is None:
                self.test.assertIsNone(
                    vsd_egress_security_policy_entries[0]['externalID'])
            else:
                vsd_egress_security_policy_entries = \
                    self.test.nuage_client.get_child_resource(
                        resource=n_constants.EGRESS_ACL_TEMPLATE,
                        resource_id=vsd_egress_acl_templates[0]['ID'],
                        child_resource=n_constants.EGRESS_ACL_ENTRY_TEMPLATE,
                        filters='externalID',
                        filter_value=with_external_id)

                self.test.assertEqual(
                    1, len(vsd_egress_security_policy_entries),
                    "policy group not found by ExternalID")

                self.test.assertEqual(
                    with_external_id,
                    ExternalId(
                        vsd_egress_security_policy_entries[0]['externalID']
                    ).at_cms_id())

        def verify_cannot_delete(self):
            # Can't delete vport in VSD
            self.test.assertRaisesRegex(
                n_exceptions.MultipleChoices,
                "Multiple choices",
                self.test.nuage_client.delete_resource,
                n_constants.VPORT,
                self.vsd_vport['ID'])

    @classmethod
    def setUpClass(cls):
        super(ExternalIdForVPortTest, cls).setUpClass()
        cls.test_upgrade = not Topology.within_ext_id_release()

    @classmethod
    def setup_clients(cls):
        super(ExternalIdForVPortTest, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    def create_vsd_dhcpmanaged_l2dom_template(self, **kwargs):
        params = {
            'DHCPManaged': True,
            'address': str(kwargs['cidr'].ip),
            'netmask': str(kwargs['cidr'].netmask),
            'gateway': kwargs['gateway']
        }
        vsd_l2dom_tmplt = self.nuage_client.create_l2domaintemplate(
            kwargs['name'] + '-template', extra_params=params)
        self.addCleanup(self.nuage_client.delete_l2domaintemplate,
                        vsd_l2dom_tmplt[0]['ID'])
        return vsd_l2dom_tmplt

    @testtools.skipUnless(Topology.within_ext_id_release(),
                          'No upgrade testing on vport')
    def test_port_dhcp_options_matches_to_port(self):
        net_name = data_utils.rand_name()
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2domain_templates = self.create_vsd_dhcpmanaged_l2dom_template(
            name=net_name, cidr=cidr, gateway='10.10.100.1')
        self.assertEqual(
            len(vsd_l2domain_templates), 1,
            "Failed to create vsd l2 domain template")

        vsd_l2domain_template = vsd_l2domain_templates[0]
        vsd_l2domains = self.nuage_client.create_l2domain(
            name=net_name, templateId=vsd_l2domain_template['ID'])
        self.assertEqual(
            len(vsd_l2domains), 1, "Failed to create vsd l2 domain")
        vsd_l2domain = vsd_l2domains[0]
        self.addCleanup(
            self.nuage_client.delete_l2domain, vsd_l2domain['ID'])

        body = self.networks_client.create_network(name=net_name)
        network = body['network']
        self.addCleanup(self.networks_client.delete_network, network['id'])
        subnet_kwargs = {
            'name': network['name'],
            'cidr': '10.10.100.0/24',
            'gateway_ip': None,
            'network_id': network['id'],
            'nuagenet': vsd_l2domain['ID'],
            'net_partition': Topology.def_netpartition,
            'enable_dhcp': True,
            'ip_version': 4}

        subnet = self.subnets_client.create_subnet(**subnet_kwargs)
        self.assertIsNotNone(subnet)  # dummy check to use local variable

        name = data_utils.rand_name('extra-dhcp-opt-port-name')
        create_body = self.ports_client.create_port(
            name=name,
            network_id=network['id'],
            extra_dhcp_opts=extra_dhcp_opts)
        port = create_body['port']
        self.addCleanup(self.ports_client.delete_port, port['id'])

        vsd_vport = self.MatchingVsdVPort(
            self, port, subnet, vsd_l2domain).get_by_external_id()
        vsd_vport.has_dhcp_options(
            with_external_id=ExternalId(port['id']).at_cms_id())

        # Delete
        vsd_vport.verify_cannot_delete()
