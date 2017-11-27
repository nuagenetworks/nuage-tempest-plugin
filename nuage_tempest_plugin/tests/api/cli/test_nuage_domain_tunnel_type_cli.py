# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from oslo_log import log as logging

from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.remote_cli.remote_cli_base_testcase \
    import RemoteCliBaseTestCase
from nuage_tempest_plugin.lib.remote_cli.remote_cli_base_testcase import Role
from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.services import nuage_client

CONF = config.CONF


class TestNuageDomainTunnelTypeCli(RemoteCliBaseTestCase):

    # TODO(waelj) don't want to have a dedicated parent class for CLI

    """DomainTunnelType tests using Neutron CLI client.

    """
    LOG = logging.getLogger(__name__)

    @classmethod
    def setup_clients(cls):
        super(TestNuageDomainTunnelTypeCli, cls).setup_clients()
        cls.nuage_vsd_client = nuage_client.NuageRestClient()

    @classmethod
    def skip_checks(cls):
        super(TestNuageDomainTunnelTypeCli, cls).skip_checks()
        if not CONF.service_available.neutron:
            msg = "Skipping all Neutron cli tests because it is not available"
            raise cls.skipException(msg)

        if not utils.is_extension_enabled('nuage-router', 'network'):
            msg = "Extension nuage_floatingip not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(TestNuageDomainTunnelTypeCli, cls).resource_setup()

        cls.ext_net_id = CONF.network.public_network_id
        cls.me = Role.admin

    @classmethod
    def get_data_center_default_domain_tunnel_type(cls):
        system_configurations = cls.nuage_vsd_client.get_system_configuration()
        cls.system_configuration = system_configurations[0]
        return cls.system_configuration['domainTunnelType']

    @classmethod
    def must_have_default_domain_tunnel_type(cls, domain_tunnel_type):
        if not (cls.system_configuration['domainTunnelType'] ==
                domain_tunnel_type):
            cls.system_configuration['domainTunnelType'] = domain_tunnel_type
            configuration_id = cls.system_configuration['ID']
            cls.nuage_vsd_client.update_system_configuration(
                configuration_id, cls.system_configuration)

            updated_system_configurations = \
                cls.nuage_vsd_client.get_system_configuration()
            updated_system_configuration = updated_system_configurations[0]

            cls.system_configuration = updated_system_configuration

    def _do_create_router_with_domain_tunnel_type(self, domain_tunnel_type):
        router_name = data_utils.rand_name('test-router')
        return self.create_router_with_args(
            router_name, "--tunnel-type", domain_tunnel_type)

    def _verify_router_with_domain_tunnel_type_openstack(
            self, the_router, domain_tunnel_type):
        # Then the router has the requested tunnel type
        self.assertEqual(the_router['tunnel_type'], domain_tunnel_type)

        # When I get the router
        show_router = self.show_router(the_router['id'])

        # Then the router has the default tunnel type
        self.assertEqual(show_router['tunnel_type'], domain_tunnel_type)

    @nuage_test.header()
    def test_create_router_with_default_domain_tunnel_type(self):
        get_data_center_default_domain_tunnel_type = \
            self.get_data_center_default_domain_tunnel_type()

        created_router = self.create_router()

        # Then the router has the default tunnel type
        self.assertEqual(
            created_router['tunnel_type'],
            get_data_center_default_domain_tunnel_type)

        # When I get the router
        show_router = self.show_router(created_router['id'])

        # Then the router has the default tunnel type
        self.assertEqual(
            show_router['tunnel_type'],
            get_data_center_default_domain_tunnel_type)

    @nuage_test.header()
    def test_create_update_router_with_tunnel_type_gre(self):
        domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_GRE

        # When I create a router with tunnel type
        created_router = self._do_create_router_with_domain_tunnel_type(
            domain_tunnel_type)

        # Then I have a router in OpenStack with the rqstd domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(
            created_router, domain_tunnel_type)

        domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_VXLAN
        self.update_router_with_args(
            created_router['id'], "--tunnel-type", domain_tunnel_type)

        updated_router = self.show_router(created_router['id'])

        # Then I have a router in OpenStack with the rqstd domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(
            updated_router, domain_tunnel_type)

        # When I update the domain tunnel type to DEFAULT
        get_data_center_default_domain_tunnel_type = \
            self.get_data_center_default_domain_tunnel_type()
        self.update_router_with_args(
            created_router['id'],
            "--tunnel-type", constants.DOMAIN_TUNNEL_TYPE_DEFAULT)

        updated_router = self.show_router(created_router['id'])

        # Then I have a router in OpenStack with the data center default
        # domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(
            updated_router,
            get_data_center_default_domain_tunnel_type)

    @nuage_test.header()
    def test_create_update_router_with_tunnel_type_vxlan(self):
        domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_VXLAN

        # When I create a router with tunnel type
        created_router = self._do_create_router_with_domain_tunnel_type(
            domain_tunnel_type)

        # Then I have a router in OpenStack with the rqstd domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(
            created_router, domain_tunnel_type)

        domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_GRE
        self.update_router_with_args(
            created_router['id'], "--tunnel-type", domain_tunnel_type)

        updated_router = self.show_router(created_router['id'])

        # Then I have a router in OpenStack with the rqstd domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(
            updated_router, domain_tunnel_type)

        # When I update the domain tunnel type to DEFAULT
        get_data_center_default_domain_tunnel_type = \
            self.get_data_center_default_domain_tunnel_type()
        self.update_router_with_args(created_router['id'], "--tunnel-type",
                                     constants.DOMAIN_TUNNEL_TYPE_DEFAULT)

        updated_router = self.show_router(created_router['id'])

        # Then I have a router in OpenStack with the data center default
        # domain tunnel type
        self._verify_router_with_domain_tunnel_type_openstack(
            updated_router,
            get_data_center_default_domain_tunnel_type)


class TestNuageDomainTunnelTypeAsTenantCli(RemoteCliBaseTestCase):

    """DomainTunnelType tests using Neutron CLI client.

    """

    def setUp(self):
        super(TestNuageDomainTunnelTypeAsTenantCli, self).setUp()
        if CONF.nuage_sut.openstack_version >= 'liberty':
            self.CREATE_POLICY_ERROR = "disallowed by policy"
            self.UPDATE_POLICY_ERROR = "disallowed by policy"
        else:
            self.CREATE_POLICY_ERROR = \
                "Policy doesn't allow \(rule:create_router and " \
                "rule:create_router:tunnel_type\) to be performed"
            self.UPDATE_POLICY_ERROR = \
                "Policy doesn't allow \(rule:update_router and " \
                "rule:update_router:tunnel_type\) to be performed"

    @classmethod
    def setup_clients(cls):
        super(TestNuageDomainTunnelTypeAsTenantCli, cls).setup_clients()
        cls.nuage_vsd_client = nuage_client.NuageRestClient()

    @classmethod
    def get_data_center_default_domain_tunnel_type(cls):
        system_configurations = cls.nuage_vsd_client.get_system_configuration()
        cls.system_configuration = system_configurations[0]
        return cls.system_configuration['domainTunnelType']

    @nuage_test.header()
    def test_tenant_shall_not_see_the_router_with_domain_tunnel_type(self):
        def get_attr(a_dict, key):
            return a_dict[key]

        data_center_default_domain_tunnel_type = \
            self.get_data_center_default_domain_tunnel_type()
        router_name = data_utils.rand_name('test-router')

        # tenant can not create a router with domain tunnel type
        self._as_tenant()
        created_router = self.create_router_with_args(router_name)
        self.assertRaises(KeyError, get_attr, created_router, 'tunnel_type')

        # admin can see the router with data center default domain tunnel type
        self._as_admin()
        router_as_admin = self.show_router(created_router['id'])
        self.assertEqual(
            router_as_admin['tunnel_type'],
            data_center_default_domain_tunnel_type)

        # tenant can not see the router domain tunnel type
        self._as_tenant()
        router_as_tenant = self.show_router(created_router['id'])
        self.assertRaises(KeyError, get_attr, router_as_tenant, 'tunnel_type')

        # tenant can not update a router with domain tunnel type
        self._as_tenant()
        new_domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_GRE
        self.assertCommandFailed(self.UPDATE_POLICY_ERROR,
                                 self.update_router_with_args,
                                 created_router['id'],
                                 "--tunnel-type",
                                 new_domain_tunnel_type)

    @nuage_test.header()
    def test_tenant_shall_not_create_router_with_domain_tunnel_type(self):
        router_name = data_utils.rand_name('test-router')
        domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_VXLAN

        # tenant can not create a router with domain tunnel type
        self._as_tenant()
        self.assertCommandFailed(self.CREATE_POLICY_ERROR,
                                 self.create_router_with_args,
                                 router_name,
                                 "--tunnel-type",
                                 domain_tunnel_type)

        # admin can create a router with domain tunnel type
        self._as_admin()
        created_router = self.create_router_with_args(
            router_name, "--tunnel-type", domain_tunnel_type)
        self.assertEqual(created_router['tunnel_type'], domain_tunnel_type)

        # admin can update a router with domain tunnel type
        self._as_admin()
        new_domain_tunnel_type = constants.DOMAIN_TUNNEL_TYPE_GRE
        self.update_router_with_args(
            created_router['id'], "--tunnel-type", new_domain_tunnel_type)
        updated_router = self.show_router(created_router['id'])
        self.assertEqual(
            updated_router['tunnel_type'], new_domain_tunnel_type)
