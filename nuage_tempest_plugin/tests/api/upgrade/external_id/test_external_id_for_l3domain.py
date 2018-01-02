# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_log import log as logging

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.release import Release
from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.lib.utils import exceptions as n_exceptions
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

from external_id import ExternalId
import upgrade_external_id_with_cms_id as upgrade_script

CONF = config.CONF
LOG = logging.getLogger(__name__)


class ExternalIdForL3domainTest(base.BaseAdminNetworkTest):

    def _remove_router_interface_with_subnet_id(self, router_id, subnet_id):
        body = self.routers_client.remove_router_interface(router_id,
                                                           subnet_id=subnet_id)
        self.assertEqual(subnet_id, body['subnet_id'])

    class MatchingVsdl3domain(object):
        def __init__(self, outer, router):
            """Construct a Vsd_l3domain. """
            self.test = outer
            self.router = router
            self.vsd_l3domain = None
            self.vsd_zones = None
            self.vsd_subnets = None

        def get_by_external_id(self):
            vsd_l3domains = self.test.nuage_vsd_client.get_l3domain(
                filters='externalID', filter_value=self.router['id'])

            # should have exact 1 match
            self.test.assertEqual(len(vsd_l3domains), 1)
            self.vsd_l3domain = vsd_l3domains[0]

            self.test.assertNotEmpty(self.vsd_l3domain)
            self.test.assertEqual(self.vsd_l3domain['name'], self.router['id'])
            return self

        def has_zones(self, with_external_id=None):
            self.vsd_zones = self.test.nuage_vsd_client.get_zone(
                parent_id=self.vsd_l3domain['ID'])

            self.test.assertEqual(
                len(self.vsd_zones), 2, "Must find exact 2 zones")

            for zone in self.vsd_zones:
                if with_external_id is None:
                    self.test.assertIsNone(zone['externalID'])
                else:
                    self.test.assertEqual(zone['externalID'], with_external_id)

        def has_subnet(self, with_external_id=None, subnet=None, shared=False):
            self.vsd_subnets = self.test.nuage_vsd_client.get_domain_subnet(
                parent=n_constants.DOMAIN, parent_id=self.vsd_l3domain['ID'])

            found = False
            for l3_subnet in self.vsd_subnets:
                if l3_subnet['name'] == subnet['id']:
                    self.test.assertEqual(
                        shared, self.is_parent_public_zone(l3_subnet))
                    found = True
                if with_external_id is None:
                    self.test.assertIsNone(l3_subnet['externalID'])
                else:
                    self.test.assertEqual(
                        with_external_id, l3_subnet['externalID'])

                    # search globally by external ID
                    vsd_subnets = self.test.nuage_vsd_client.get_domain_subnet(
                        parent=None, parent_id='',
                        filters='externalID', filter_value=with_external_id)
                    self.test.assertEqual(
                        1, len(vsd_subnets), "Subnet not found by ExternalID")
                    self.test.assertEqual(
                        with_external_id, vsd_subnets[0]['externalID'])

            self.test.assertTrue(found, "Subnet not in L3 domain")

        def is_parent_public_zone(self, vsd_subnet):
            for vsd_zone in self.vsd_zones:
                if vsd_zone['ID'] == vsd_subnet['parentID']:
                    return vsd_zone['name'].split('-')[1] == 'pub'
            return False

        def has_permissions(self, with_external_id=None):
            for zone in self.vsd_zones:
                # vsd permissions object has external ID
                vsd_permissions = self.test.nuage_vsd_client.get_permissions(
                    parent=n_constants.ZONE,
                    parent_id=zone['ID'])

                self.test.assertEqual(
                    1, len(vsd_permissions),
                    "VSD Permission not found by parent ID")

                group_external_id = \
                    ExternalId(with_external_id).at_openstack() \
                    if with_external_id else None
                if zone['name'].split('-')[1] == 'pub':
                    self.test.assertEqual(
                        vsd_permissions[0]['permittedEntityName'],
                        "Everybody")
                    self.has_user(group_external_id)
                else:
                    self.test.assertEqual(
                        self.router['tenant_id'],
                        vsd_permissions[0]['permittedEntityName'])
                    self.has_group(group_external_id, for_zone=zone)
                    self.has_user(group_external_id)

                if with_external_id is None:
                    self.test.assertIsNone(vsd_permissions[0]['externalID'])
                else:
                    # permission object has external ID
                    self.test.assertEqual(
                        with_external_id, vsd_permissions[0]['externalID'])

                    # can find vsd permissions by external ID
                    vsd_permissions = \
                        self.test.nuage_vsd_client.get_permissions(
                            parent=n_constants.ZONE,
                            parent_id=zone['ID'],
                            filters='externalID',
                            filter_value=with_external_id)
                    self.test.assertEqual(
                        1, len(vsd_permissions),
                        "VSD Permission not found by ExternalID")

        def has_group(self, with_external_id=None, for_zone=None):
            # vsd permissions object has external ID
            vsd_groups = self.test.nuage_vsd_client.get_usergroup(
                parent=n_constants.ZONE,
                parent_id=for_zone['ID'])

            self.test.assertEqual(
                1, len(vsd_groups), "Group not found by VSD parent ID")

            # matching values
            self.test.assertEqual(
                self.router['tenant_id'], vsd_groups[0]['name'])

            if with_external_id is None:
                self.test.assertIsNone(vsd_groups[0]['externalID'])
            else:
                vsd_groups = self.test.nuage_vsd_client.get_resource(
                    resource=n_constants.GROUP,
                    filters='externalID',
                    filter_value=with_external_id)

                self.test.assertEqual(
                    1, len(vsd_groups), "Group not found by ExternalID")
                self.test.assertEqual(
                    with_external_id, vsd_groups[0]['externalID'])

        def has_user(self, with_external_id=None):
            # vsd user object has external ID
            vsd_users = self.test.nuage_vsd_client.get_user(
                filters='userName',
                filter_value=self.router['tenant_id'])

            self.test.assertEqual(
                1, len(vsd_users), "User not found by VSD parent ID")

            # matching values
            self.test.assertEqual(
                self.router['tenant_id'], vsd_users[0]['userName'])

            if with_external_id is None:
                self.test.assertIsNone(vsd_users[0]['externalID'])
            else:
                vsd_users = self.test.nuage_vsd_client.get_resource(
                    resource=n_constants.USER,
                    filters='externalID',
                    filter_value=with_external_id)

                self.test.assertEqual(
                    1, len(vsd_users), "User not found by ExternalID")
                self.test.assertEqual(
                    with_external_id, vsd_users[0]['externalID'])

        def has_egress_acl_template(self, with_external_id=None):
            # vsd egress_acl_template object has external ID
            vsd_egress_acl_templates = \
                self.test.nuage_vsd_client.get_egressacl_template(
                    parent=n_constants.DOMAIN,
                    parent_id=self.vsd_l3domain['ID'])

            self.test.assertEqual(
                1, len(vsd_egress_acl_templates),
                "egress_acl_template not found by VSD parent ID")

            if with_external_id is None:
                self.test.assertIsNone(
                    vsd_egress_acl_templates[0]['externalID'])
            else:
                vsd_egress_acl_templates = \
                    self.test.nuage_vsd_client.get_child_resource(
                        resource=n_constants.DOMAIN,
                        resource_id=self.vsd_l3domain['ID'],
                        child_resource=n_constants.EGRESS_ACL_TEMPLATE,
                        filters='externalID',
                        filter_value=with_external_id)

                self.test.assertEqual(
                    1, len(vsd_egress_acl_templates),
                    "egress_acl_template not found by ExternalID")
                self.test.assertEqual(
                    with_external_id,
                    vsd_egress_acl_templates[0]['externalID'])

        def has_ingress_acl_template(self, with_external_id=None):
            # vsd ingress_acl_template object has external ID
            vsd_ingress_acl_templates = \
                self.test.nuage_vsd_client.get_ingressacl_template(
                    parent=n_constants.DOMAIN,
                    parent_id=self.vsd_l3domain['ID'])

            self.test.assertEqual(
                1, len(vsd_ingress_acl_templates),
                "ingress_acl_template not found by VSD parent ID")

            if with_external_id is None:
                self.test.assertIsNone(
                    vsd_ingress_acl_templates[0]['externalID'])
            else:
                vsd_ingress_acl_templates = \
                    self.test.nuage_vsd_client.get_child_resource(
                        resource=n_constants.DOMAIN,
                        resource_id=self.vsd_l3domain['ID'],
                        child_resource=n_constants.INGRESS_ACL_TEMPLATE,
                        filters='externalID',
                        filter_value=with_external_id)

                self.test.assertEqual(
                    1, len(vsd_ingress_acl_templates),
                    "ingress_acl_template not found by ExternalID")
                self.test.assertEqual(
                    with_external_id,
                    vsd_ingress_acl_templates[0]['externalID'])

        def has_forwarding_policy_template(self, with_external_id=None):
            # vsd forwarding_policy_template object has external ID
            vsd_forwarding_policy_templates = \
                self.test.nuage_vsd_client.get_child_resource(
                    resource=n_constants.DOMAIN,
                    resource_id=self.vsd_l3domain['ID'],
                    child_resource=n_constants.INGRESS_ADV_FWD_TEMPLATE)

            self.test.assertEqual(
                len(vsd_forwarding_policy_templates), 1,
                "forwarding_policy_template not found by VSD parent ID")

            if with_external_id is None:
                self.test.assertIsNone(
                    vsd_forwarding_policy_templates[0]['externalID'])
            else:
                vsd_forwarding_policy_templates = \
                    self.test.nuage_vsd_client.get_child_resource(
                        resource=n_constants.DOMAIN,
                        resource_id=self.vsd_l3domain['ID'],
                        child_resource=n_constants.INGRESS_ADV_FWD_TEMPLATE,
                        filters='externalID',
                        filter_value=with_external_id)

                self.test.assertEqual(
                    1, len(vsd_forwarding_policy_templates),
                    "forwarding_policy_template not found by ExternalID")
                self.test.assertEqual(
                    with_external_id,
                    vsd_forwarding_policy_templates[0]['externalID'])

        def verify_cannot_delete(self):
            # Can't delete L3 domain in VSD
            self.test.assertRaisesRegex(
                n_exceptions.MultipleChoices,
                "Multiple choices",
                self.test.nuage_vsd_client.delete_domain,
                self.vsd_l3domain['ID'])

        def verify_cannot_delete_subnets(self):
            # Can't delete L3 domain in VSD
            for subnet in self.vsd_subnets:
                self.test.assertRaisesRegex(
                    n_exceptions.MultipleChoices,
                    "Multiple choices",
                    self.test.nuage_vsd_client.delete_domain_subnet,
                    subnet['ID'])

    @classmethod
    def skip_checks(cls):
        super(ExternalIdForL3domainTest, cls).skip_checks()

        external_id_release = Release('4.0R5')
        current_release = Release(Topology.nuage_release)
        cls.test_upgrade = external_id_release > current_release

    @classmethod
    def setup_clients(cls):
        super(ExternalIdForL3domainTest, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()

    @nuage_test.header()
    def test_router_matches_to_l3domain(self):
        # Create a router
        name = data_utils.rand_name('router-')
        create_body = self.routers_client.create_router(
            name=name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=False)
        router = create_body['router']

        self.addCleanup(self.routers_client.delete_router, router['id'])
        self.assertEqual(router['name'], name)

        if self.test_upgrade:
            vsd_l3domain = self.MatchingVsdl3domain(
                self, router).get_by_external_id()
            vsd_l3domain.has_zones(with_external_id=None)
            vsd_l3domain.has_permissions(with_external_id=None)
            vsd_l3domain.has_egress_acl_template(with_external_id=None)
            vsd_l3domain.has_ingress_acl_template(with_external_id=None)
            vsd_l3domain.has_forwarding_policy_template(with_external_id=None)

            upgrade_script.do_run_upgrade_script()

        vsd_l3domain = self.MatchingVsdl3domain(
            self, router).get_by_external_id()
        vsd_l3domain.has_zones(
            with_external_id=ExternalId(router['id']).at_cms_id())
        vsd_l3domain.has_permissions(
            with_external_id=ExternalId(router['tenant_id']).at_cms_id())
        vsd_l3domain.has_egress_acl_template(
            with_external_id=ExternalId(router['id']).at_cms_id())
        vsd_l3domain.has_ingress_acl_template(
            with_external_id=ExternalId(router['id']).at_cms_id())
        vsd_l3domain.has_forwarding_policy_template(
            with_external_id=ExternalId(router['id']).at_cms_id())

        # Delete
        vsd_l3domain.verify_cannot_delete()

    @nuage_test.header()
    def test_subnet_attached_to_router_matches_to_l3domain(self):
        # Create a network
        name = data_utils.rand_name('network-')
        network = self.create_network(network_name=name)

        # Create a subnet
        subnet = self.create_subnet(network)

        # Create a router
        name = data_utils.rand_name('router-')
        create_body = self.routers_client.create_router(
            name=name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=False)
        router = create_body['router']
        self.addCleanup(self.routers_client.delete_router, router['id'])
        self.assertEqual(router['name'], name)

        # Attach subnet to router
        # Add router interface with subnet id
        self.routers_client.add_router_interface(
            router['id'], subnet_id=subnet['id'])
        self.addCleanup(self._remove_router_interface_with_subnet_id,
                        router['id'], subnet['id'])

        if self.test_upgrade:
            vsd_l3domain = self.MatchingVsdl3domain(
                self, router).get_by_external_id()
            vsd_l3domain.has_zones(with_external_id=None)
            vsd_l3domain.has_subnet(
                with_external_id=ExternalId(subnet['id']).at_cms_id(),
                subnet=subnet)

            upgrade_script.do_run_upgrade_script()

        vsd_l3domain = self.MatchingVsdl3domain(
            self, router).get_by_external_id()
        vsd_l3domain.has_zones(
            with_external_id=ExternalId(router['id']).at_cms_id())
        vsd_l3domain.has_subnet(
            with_external_id=ExternalId(subnet['id']).at_cms_id(),
            subnet=subnet)

        # Delete
        vsd_l3domain.verify_cannot_delete()
        vsd_l3domain.verify_cannot_delete_subnets()
