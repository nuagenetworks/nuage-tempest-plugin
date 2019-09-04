# Copyright 2017 - Nokia
# All Rights Reserved.

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES
from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as nuage_constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.tests.api.external_id.external_id import ExternalId

net_partition_name = Topology.def_netpartition


class VSDUserGroup(nuage_test.NuageBaseTest):

    @classmethod
    def skip_checks(cls):
        super(VSDUserGroup, cls).skip_checks()
        if not NUAGE_FEATURES.project_name_in_vsd:
            raise cls.skipException('Project name in user group is not'
                                    ' supported in this release')

    @classmethod
    def setup_clients(cls):
        super(VSDUserGroup, cls).setup_clients()
        cls.manager = cls.get_client_manager()
        cls.admin_manager = cls.get_client_manager(credential_type='admin')
        cls.nuage_client = NuageRestClient()

    @classmethod
    def setup_credentials(cls):
        super(VSDUserGroup, cls).setup_credentials()

    def _validate_user_group_description(self, validate_equals, value,
                                         vsd_group):
        self.assertIsNotNone(vsd_group)
        self.assertEqual(1, len(vsd_group))
        if validate_equals:
            self.assertEqual(expected=value,
                             observed=vsd_group[0]['description'],
                             message="project name is not equal to"
                                     " description value")
        else:
            self.assertNotIn('-update',
                             vsd_group[0]['description'],
                             message="project name update in"
                                     " usergroup is fixed"
                                     " without new session")

    def _create_and_validate_os_managed_subnet(self, reload_session=True,
                                               validate_equals=True):
        # Provision OpenStack network
        if reload_session:
            network = self.create_network(client=self.get_client_manager())
            ipv4_subnet = self.create_subnet(network,
                                             client=self.get_client_manager())
            value = self.manager.subnets_client.tenant_name + '-update'
        else:
            network = self.create_network(client=self.manager)
            ipv4_subnet = self.create_subnet(network, client=self.manager)
            value = self.manager.subnets_client.tenant_name
        # When I create an IPv4 subnet
        self.assertIsNotNone(ipv4_subnet)
        # Then a VSD L2 domain is created with type IPv4
        vsd_l2_domain = self.vsd.get_l2domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(ipv4_subnet['id']).at_cms_id()))
        self.assertIsNotNone(vsd_l2_domain)
        vsd_group = self.nuage_client.get_usergroup(
            netpart_name=net_partition_name,
            parent=nuage_constants.L2_DOMAIN,
            parent_id=vsd_l2_domain.id)
        self._validate_user_group_description(validate_equals, value,
                                              vsd_group)

    def _create_and_validate_on_router_create(self, reload_session=True,
                                              validate_equals=True):
        # Provision OpenStack network
        if reload_session:
            value = self.manager.routers_client.tenant_name + '-update'
            router = self.create_router(client=self.get_client_manager())
        else:
            router = self.create_router(client=self.manager)
            value = self.manager.routers_client.tenant_name
        self.assertIsNotNone(router)
        vsd_l3_domain = self.vsd.get_l3domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(router['id']).at_cms_id()))
        self.assertIsNotNone(vsd_l3_domain)
        vsd_l3_domain_zones = self.nuage_client.get_zone(
            parent_id=vsd_l3_domain.id)
        self.assertIsNotNone(vsd_l3_domain_zones)
        for vsd_l3_domain_zone in vsd_l3_domain_zones:
            if '-pub-' not in vsd_l3_domain_zone['name']:
                vsd_group = self.nuage_client.get_usergroup(
                    netpart_name=net_partition_name,
                    parent=nuage_constants.ZONE,
                    parent_id=vsd_l3_domain_zone['ID'])
                self._validate_user_group_description(validate_equals, value,
                                                      vsd_group)

    @nuage_test.skip_because(bug='OPENSTACK-2321')
    def test_os_managed_subnet_create_with_new_session_then_old_session(self):
        self._create_and_validate_os_managed_subnet(reload_session=False,
                                                    validate_equals=True)
        tenant_name = self.manager.subnets_client.tenant_name
        self.admin_manager.projects_client.update_project(
            project_id=self.manager.subnets_client.tenant_id,
            name=tenant_name + '-update')
        self._create_and_validate_os_managed_subnet(reload_session=True,
                                                    validate_equals=True)
        self._create_and_validate_os_managed_subnet(reload_session=False,
                                                    validate_equals=False)

    @nuage_test.skip_because(bug='OPENSTACK-2321')
    def test_os_managed_router_create_with_new_session_then_old_session(self):
        self._create_and_validate_on_router_create(reload_session=False,
                                                   validate_equals=True)
        tenant_name = self.manager.routers_client.tenant_name
        self.admin_manager.projects_client.update_project(
            project_id=self.manager.subnets_client.tenant_id,
            name=tenant_name + '-update')
        self._create_and_validate_on_router_create(reload_session=True,
                                                   validate_equals=True)
        self._create_and_validate_on_router_create(reload_session=False,
                                                   validate_equals=False)
