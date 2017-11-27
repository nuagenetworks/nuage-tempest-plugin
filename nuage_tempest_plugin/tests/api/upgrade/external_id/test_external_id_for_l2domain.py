# Copyright 2015 OpenStack Foundation
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

from oslo_log import log as logging

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.nuage_tempest_test_loader import Release
from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.lib.utils import exceptions as n_exceptions
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

from external_id import ExternalId
import upgrade_external_id_with_cms_id as upgrade_script

CONF = config.CONF
LOG = logging.getLogger(__name__)


class ExternalIdForL2domainTest(base.BaseNetworkTest):
    test_upgrade = False
    net_partition_name = CONF.nuage.nuage_default_netpartition

    class MatchingVsdL2domain(object):
        def __init__(self, outer, subnet):
            """Construct a Vsd_l2domain. """
            self.test = outer
            self.subnet = subnet
            self.vsd_l2domain = None
            self.net_partition_name = None

        def get_by_external_id(self, net_partition_name=None):
            self.net_partition_name = net_partition_name
            vsd_l2domains = self.test.nuage_vsd_client.get_l2domain(
                netpart_name=self.net_partition_name,
                filters='externalID', filter_value=self.subnet['id'])

            # should have exact 1 match
            self.test.assertEqual(len(vsd_l2domains), 1)
            self.vsd_l2domain = vsd_l2domains[0]

            self.test.assertNotEmpty(self.vsd_l2domain)
            self.test.assertEqual(self.vsd_l2domain['name'], self.subnet['id'])
            return self

        def has_l2domain_template(self, with_external_id=None):
            # vsd l2domain template object has external ID
            vsd_l2domain_templates = \
                self.test.nuage_vsd_client.get_l2domaintemplate(
                    filters='name', filter_value=self.subnet['id'])
            self.test.assertEqual(
                len(vsd_l2domain_templates), 1,
                "vsd_l2domain_template not found by parent ID")

            if with_external_id is None:
                self.test.assertIsNone(vsd_l2domain_templates[0]['externalID'])
            else:
                # has external ID
                self.test.assertEqual(
                    with_external_id, vsd_l2domain_templates[0]['externalID'])

                # can find vsd permissions by external ID
                vsd_l2domain_templates = \
                    self.test.nuage_vsd_client.get_l2domaintemplate(
                        filters='externalID', filter_value=with_external_id)
                self.test.assertEqual(
                    len(vsd_l2domain_templates), 1,
                    "vsd_l2domain_template not found by ExternalID")

        def has_permissions(self, with_external_id=None):
            # vsd permissions object has external ID
            vsd_permissions = self.test.nuage_vsd_client.get_permissions(
                parent=n_constants.L2_DOMAIN,
                parent_id=self.vsd_l2domain['ID'])

            self.test.assertEqual(
                len(vsd_permissions), 1,
                "VSD Permission not found by parent ID")

            if with_external_id is None:
                self.test.assertIsNone(vsd_permissions[0]['externalID'])
            else:
                # permission object has external ID
                self.test.assertEqual(
                    with_external_id, vsd_permissions[0]['externalID'])

                # can find vsd permissions by external ID
                vsd_permissions = self.test.nuage_vsd_client.get_permissions(
                    parent=n_constants.L2_DOMAIN,
                    parent_id=self.vsd_l2domain['ID'],
                    filters='externalID', filter_value=with_external_id)
                self.test.assertEqual(
                    len(vsd_permissions), 1,
                    "VSD Permission not found by ExternalID")

        def has_group(self, with_external_id=None):
            # vsd group object has external ID
            vsd_groups = self.test.nuage_vsd_client.get_usergroup(
                netpart_name=self.net_partition_name,
                parent=n_constants.L2_DOMAIN,
                parent_id=self.vsd_l2domain['ID'])

            self.test.assertEqual(
                len(vsd_groups), 1, "Group not found by VSD parent ID")

            # matching values
            self.test.assertEqual(
                self.subnet['tenant_id'], vsd_groups[0]['name'])
            self.test.assertEqual("CMS", vsd_groups[0]['managementMode'])

            if with_external_id is None:
                self.test.assertIsNone(vsd_groups[0]['externalID'])
            else:
                vsd_groups = self.test.nuage_vsd_client.get_resource(
                    netpart_name=self.net_partition_name,
                    resource=n_constants.GROUP,
                    filters='externalID',
                    filter_value=with_external_id)

                self.test.assertEqual(
                    len(vsd_groups), 1, "Group not found by ExternalID")
                self.test.assertEqual(
                    with_external_id, vsd_groups[0]['externalID'])

        def has_group_everybody(self):
            # vsd group object has external ID
            vsd_groups = self.test.nuage_vsd_client.get_usergroup(
                parent=n_constants.L2_DOMAIN,
                parent_id=self.vsd_l2domain['ID'])

            self.test.assertEqual(
                len(vsd_groups), 1, "Group not found by VSD parent ID")

            # matching values
            self.test.assertEqual("Everybody", vsd_groups[0]['name'])
            self.test.assertEqual("DEFAULT", vsd_groups[0]['managementMode'])

            self.test.assertIsNone(vsd_groups[0]['externalID'])

        def has_user(self, with_external_id=None):
            # vsd user object has external ID
            vsd_users = self.test.nuage_vsd_client.get_user(
                netpart_name=self.net_partition_name,
                filters='userName',
                filter_value=self.subnet['tenant_id'])

            self.test.assertEqual(
                len(vsd_users), 1, "User not found by VSD parent ID")

            # matching values
            self.test.assertEqual(
                self.subnet['tenant_id'], vsd_users[0]['userName'])
            self.test.assertEqual("CMS", vsd_users[0]['managementMode'])

            if with_external_id is None:
                self.test.assertIsNone(vsd_users[0]['externalID'])
            else:
                vsd_users = self.test.nuage_vsd_client.get_resource(
                    netpart_name=self.net_partition_name,
                    resource=n_constants.USER,
                    filters='externalID',
                    filter_value=with_external_id)

                self.test.assertEqual(
                    len(vsd_users), 1, "User not found by ExternalID")
                self.test.assertEqual(
                    with_external_id, vsd_users[0]['externalID'])

        def has_dhcp_options(self, with_external_id=None, with_dhcp_opts=None):
            # vsd dhcp_options object has external ID
            vsd_dhcp_options = self.test.nuage_vsd_client.get_dhcpoption(
                parent=n_constants.L2_DOMAIN,
                parent_id=self.vsd_l2domain['ID'])

            self.test.assertEqual(len(vsd_dhcp_options), len(with_dhcp_opts),
                                  "dhcp_options not found by VSD parent ID")

            if with_external_id is None:
                self.test.assertIsNone(vsd_dhcp_options[0]['externalID'])
            else:
                vsd_dhcp_options = \
                    self.test.nuage_vsd_client.get_child_resource(
                        resource=n_constants.L2_DOMAIN,
                        resource_id=self.vsd_l2domain['ID'],
                        child_resource=n_constants.DHCPOPTION,
                        filters='externalID',
                        filter_value=with_external_id)

                self.test.assertEqual(
                    len(vsd_dhcp_options), len(with_dhcp_opts),
                    "dhcp_options not found by ExternalID")
                for vsd_dhcp_option in vsd_dhcp_options:
                    self.test.assertEqual(
                        with_external_id, vsd_dhcp_option['externalID'])

        def has_egress_acl_template(self, with_external_id=None):
            # vsd egress_acl_template object has external ID
            vsd_egress_acl_templates = \
                self.test.nuage_vsd_client.get_egressacl_template(
                    parent=n_constants.L2_DOMAIN,
                    parent_id=self.vsd_l2domain['ID'])

            self.test.assertEqual(
                len(vsd_egress_acl_templates), 1,
                "egress_acl_template not found by VSD parent ID")

            if with_external_id is None:
                self.test.assertIsNone(
                    vsd_egress_acl_templates[0]['externalID'])
            else:
                vsd_egress_acl_templates = \
                    self.test.nuage_vsd_client.get_child_resource(
                        resource=n_constants.L2_DOMAIN,
                        resource_id=self.vsd_l2domain['ID'],
                        child_resource=n_constants.EGRESS_ACL_TEMPLATE,
                        filters='externalID',
                        filter_value=with_external_id)

                self.test.assertEqual(
                    len(vsd_egress_acl_templates), 1,
                    "egress_acl_template not found by ExternalID")
                self.test.assertEqual(
                    with_external_id,
                    vsd_egress_acl_templates[0]['externalID'])

        def has_ingress_acl_template(self, with_external_id=None):
            # vsd ingress_acl_template object has external ID
            vsd_ingress_acl_templates = \
                self.test.nuage_vsd_client.get_ingressacl_template(
                    parent=n_constants.L2_DOMAIN,
                    parent_id=self.vsd_l2domain['ID'])

            self.test.assertEqual(
                len(vsd_ingress_acl_templates), 1,
                "ingress_acl_template not found by VSD parent ID")

            if with_external_id is None:
                self.test.assertIsNone(
                    vsd_ingress_acl_templates[0]['externalID'])
            else:
                vsd_ingress_acl_templates = \
                    self.test.nuage_vsd_client.get_child_resource(
                        resource=n_constants.L2_DOMAIN,
                        resource_id=self.vsd_l2domain['ID'],
                        child_resource=n_constants.INGRESS_ACL_TEMPLATE,
                        filters='externalID',
                        filter_value=with_external_id)

                self.test.assertEqual(
                    len(vsd_ingress_acl_templates), 1,
                    "ingress_acl_template not found by ExternalID")
                self.test.assertEqual(
                    with_external_id,
                    vsd_ingress_acl_templates[0]['externalID'])

        def has_forwarding_policy_template(self, with_external_id=None):
            # vsd forwarding_policy_template object has external ID
            vsd_forwarding_policy_templates = \
                self.test.nuage_vsd_client.get_child_resource(
                    resource=n_constants.L2_DOMAIN,
                    resource_id=self.vsd_l2domain['ID'],
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
                        resource=n_constants.L2_DOMAIN,
                        resource_id=self.vsd_l2domain['ID'],
                        child_resource=n_constants.INGRESS_ADV_FWD_TEMPLATE,
                        filters='externalID',
                        filter_value=with_external_id)

                self.test.assertEqual(
                    len(vsd_forwarding_policy_templates), 1,
                    "forwarding_policy_template not found by ExternalID")
                self.test.assertEqual(
                    with_external_id,
                    vsd_forwarding_policy_templates[0]['externalID'])

        def verify_cannot_delete(self):
            # Can't delete l2 domain in VSD
            self.test.assertRaisesRegex(
                n_exceptions.MultipleChoices,
                "Multiple choices",
                self.test.nuage_vsd_client.delete_l2domain,
                self.vsd_l2domain['ID'])

    @classmethod
    def resource_setup(cls):
        super(ExternalIdForL2domainTest, cls).resource_setup()

    @classmethod
    def skip_checks(cls):
        super(ExternalIdForL2domainTest, cls).skip_checks()

        current_release = Release(CONF.nuage_sut.release)
        # if current_release < Release('4.0'):
        #     raise cls.skipException("No external-id testing on release %s"
        #               % current_release)

        external_id_release = Release('4.0R5')
        cls.test_upgrade = external_id_release > current_release

    @classmethod
    def setup_clients(cls):
        super(ExternalIdForL2domainTest, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()
        cls.nuage_network_client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os_primary.default_params)

    def _delete_network(self, network):
        # Deleting network also deletes its subnets if exists
        self.networks_client.delete_network(network['id'])
        if network in self.networks:
            self.networks.remove(network)
        for subnet in self.subnets:
            if subnet['network_id'] == network['id']:
                self.subnets.remove(subnet)

    @nuage_test.header()
    def test_neutron_isolated_subnet_matches_to_l2domain(self):
        # Create a network
        name = data_utils.rand_name('network-')
        network = self.create_network(network_name=name)
        self.addCleanup(self._delete_network, network)
        self.assertEqual('ACTIVE', network['status'])

        # Create a subnet
        # subnet = self.create_subnet(network)
        subnet = self.create_subnet(network)

        dhcp_opts = [
            {'actualType': 3, 'actualValues': subnet['gateway_ip']}
        ]

        if self.test_upgrade:
            vsd_l2domain = self.MatchingVsdL2domain(
                self, subnet).get_by_external_id()
            vsd_l2domain.has_l2domain_template(with_external_id=None)
            vsd_l2domain.has_dhcp_options(
                with_external_id=None, with_dhcp_opts=dhcp_opts)
            vsd_l2domain.has_permissions(with_external_id=None)
            vsd_l2domain.has_group(with_external_id=None)
            vsd_l2domain.has_user(with_external_id=None)
            vsd_l2domain.has_egress_acl_template(with_external_id=None)
            vsd_l2domain.has_ingress_acl_template(with_external_id=None)
            vsd_l2domain.has_forwarding_policy_template(with_external_id=None)

            upgrade_script.do_run_upgrade_script()

        vsd_l2domain = self.MatchingVsdL2domain(
            self, subnet).get_by_external_id()
        vsd_l2domain.has_l2domain_template(
            with_external_id=ExternalId(subnet['id']).at_cms_id())
        vsd_l2domain.has_dhcp_options(
            with_external_id=ExternalId(subnet['id']).at_cms_id(),
            with_dhcp_opts=dhcp_opts)
        vsd_l2domain.has_permissions(
            with_external_id=ExternalId(subnet['tenant_id']).at_cms_id())
        vsd_l2domain.has_group(
            with_external_id=ExternalId(subnet['tenant_id']).at_openstack())
        vsd_l2domain.has_user(
            with_external_id=ExternalId(subnet['tenant_id']).at_openstack())
        vsd_l2domain.has_egress_acl_template(
            with_external_id=ExternalId(subnet['id']).at_cms_id())
        vsd_l2domain.has_ingress_acl_template(
            with_external_id=ExternalId(subnet['id']).at_cms_id())
        vsd_l2domain.has_forwarding_policy_template(
            with_external_id=ExternalId(subnet['id']).at_cms_id())

        # Delete
        vsd_l2domain.verify_cannot_delete()

    @classmethod
    def _create_netpartition(cls):
        name = data_utils.rand_name('netpartition')

        body = cls.nuage_network_client.create_netpartition(name)
        netpartition = body['net_partition']
        return netpartition

    @nuage_test.header()
    # @testtools.skipIf(Release(CONF.nuage_sut.release) < Release('4.0'),
    #    "No external-id testing on this release")
    def test_neutron_isolated_subnet_in_netpartition(self):
        # Create a dedicated netpartition
        netpartition_a = self._create_netpartition()
        self.addCleanup(self.nuage_network_client.delete_netpartition,
                        netpartition_a['id'])

        netpartition_b = self._create_netpartition()
        self.addCleanup(self.nuage_network_client.delete_netpartition,
                        netpartition_b['id'])

        # Create a network 1 in netpartition A
        name = data_utils.rand_name('networkA1')
        network_a1 = self.create_network(network_name=name)
        self.addCleanup(self._delete_network, network_a1)
        subnet_a1 = self.create_subnet(network_a1,
                                       net_partition=netpartition_a['name'])

        # Create a network 2 in netpartition A
        name = data_utils.rand_name('networkA2')
        network_a2 = self.create_network(network_name=name)
        self.addCleanup(self._delete_network, network_a2)
        subnet_a2 = self.create_subnet(network_a2,
                                       net_partition=netpartition_a['name'])
        self.assertIsNotNone(subnet_a2)  # dummy check to use local variable

        # Create a network 1 in netpartition B
        name = data_utils.rand_name('networkB1')
        network_b1 = self.create_network(network_name=name)
        self.addCleanup(self._delete_network, network_b1)
        subnet_b1 = self.create_subnet(network_b1,
                                       net_partition=netpartition_b['name'])

        if self.test_upgrade:
            vsd_l2domain_a1 = self.MatchingVsdL2domain(
                self, subnet_a1).get_by_external_id(
                net_partition_name=netpartition_a['name'])
            vsd_l2domain_a1.has_group(with_external_id=None)
            vsd_l2domain_a1.has_user(with_external_id=None)

            vsd_l2domain_b1 = self.MatchingVsdL2domain(
                self, subnet_b1).get_by_external_id(
                net_partition_name=netpartition_b['name'])
            vsd_l2domain_b1.has_group(with_external_id=None)
            vsd_l2domain_b1.has_user(with_external_id=None)

            upgrade_script.do_run_upgrade_script()

        # has only 1 group and 1 user with same External ID as subnet in
        # netpartition A
        vsd_l2domain_a1 = self.MatchingVsdL2domain(
            self, subnet_a1).get_by_external_id(
            net_partition_name=netpartition_a['name'])
        vsd_l2domain_a1.has_group(
            with_external_id=ExternalId(subnet_a1['tenant_id']).at_openstack())
        vsd_l2domain_a1.has_user(
            with_external_id=ExternalId(subnet_a1['tenant_id']).at_openstack())

        # has group and user with same External ID as subnet in netpartition A
        vsd_l2domain_b1 = self.MatchingVsdL2domain(
            self, subnet_b1).get_by_external_id(
            net_partition_name=netpartition_b['name'])
        vsd_l2domain_b1.has_group(
            with_external_id=ExternalId(subnet_a1['tenant_id']).at_openstack())
        vsd_l2domain_b1.has_user(
            with_external_id=ExternalId(subnet_a1['tenant_id']).at_openstack())

        pass


class ExternalIdForL2domainAdminTest(ExternalIdForL2domainTest):
    @classmethod
    def setup_clients(cls):
        super(ExternalIdForL2domainAdminTest, cls).setup_clients()
        cls.os_admin = cls.get_client_manager(roles=['admin'])
        cls.admin_networks_client = cls.os_admin.networks_client
        cls.admin_routers_client = cls.os_admin.routers_client
        cls.admin_subnets_client = cls.os_admin.subnets_client

    def _delete_network(self, network):
        # Deleting network also deletes its subnets if exists
        self.admin_networks_client.delete_network(network['id'])
        if network in self.networks:
            self.networks.remove(network)
        for subnet in self.subnets:
            if subnet['network_id'] == network['id']:
                self.subnets.remove(subnet)

    @nuage_test.header()
    def test_neutron_isolated_shared_subnet_matches_to_l2domain(self):
        # Create a network
        name = data_utils.rand_name('network-')

        body = self.os_admin.networks_client.create_network(
            name=name, shared=True)
        network = body['network']
        self.addCleanup(self._delete_network, network)
        self.assertEqual('ACTIVE', network['status'])

        # Create a subnet
        subnet = self.create_subnet(network,
                                    client=self.os_admin.subnets_client)

        # Create a second subnet
        subnet_b = self.create_subnet(
            network, client=self.os_admin.subnets_client)

        if self.test_upgrade:
            vsd_l2domain_a = self.MatchingVsdL2domain(
                self, subnet).get_by_external_id()
            vsd_l2domain_a.has_permissions(with_external_id=None)
            vsd_l2domain_a.has_group_everybody()
            vsd_l2domain_a.has_user(with_external_id=None)
            vsd_l2domain_a.has_egress_acl_template(with_external_id=None)
            vsd_l2domain_a.has_ingress_acl_template(with_external_id=None)
            vsd_l2domain_a.has_forwarding_policy_template(
                with_external_id=None)

            vsd_l2domain_b = self.MatchingVsdL2domain(
                self, subnet_b).get_by_external_id()
            vsd_l2domain_b.has_permissions(with_external_id=None)
            vsd_l2domain_b.has_group_everybody()
            vsd_l2domain_b.has_user(with_external_id=None)
            vsd_l2domain_b.has_egress_acl_template(with_external_id=None)
            vsd_l2domain_b.has_ingress_acl_template(with_external_id=None)
            vsd_l2domain_b.has_forwarding_policy_template(
                with_external_id=None)

            upgrade_script.do_run_upgrade_script()

        vsd_l2domain_a = self.MatchingVsdL2domain(
            self, subnet).get_by_external_id()
        vsd_l2domain_a.has_permissions(
            with_external_id=ExternalId(subnet['tenant_id']).at_cms_id())
        vsd_l2domain_a.has_group_everybody()
        vsd_l2domain_a.has_user(
            with_external_id=ExternalId(subnet['tenant_id']).at_openstack())
        vsd_l2domain_a.has_egress_acl_template(
            with_external_id=ExternalId(subnet['id']).at_cms_id())
        vsd_l2domain_a.has_ingress_acl_template(
            with_external_id=ExternalId(subnet['id']).at_cms_id())
        vsd_l2domain_a.has_forwarding_policy_template(
            with_external_id=ExternalId(subnet['id']).at_cms_id())

        vsd_l2domain_b = self.MatchingVsdL2domain(
            self, subnet_b).get_by_external_id()
        vsd_l2domain_b.has_permissions(
            with_external_id=ExternalId(subnet_b['tenant_id']).at_cms_id())
        vsd_l2domain_b.has_group_everybody()
        vsd_l2domain_b.has_user(
            with_external_id=ExternalId(subnet_b['tenant_id']).at_openstack())
        vsd_l2domain_b.has_egress_acl_template(
            with_external_id=ExternalId(subnet_b['id']).at_cms_id())
        vsd_l2domain_b.has_ingress_acl_template(
            with_external_id=ExternalId(subnet_b['id']).at_cms_id())
        vsd_l2domain_b.has_forwarding_policy_template(
            with_external_id=ExternalId(subnet_b['id']).at_cms_id())

        # Delete
        vsd_l2domain_a.verify_cannot_delete()
