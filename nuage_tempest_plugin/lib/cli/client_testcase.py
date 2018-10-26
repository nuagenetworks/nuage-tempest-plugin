# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from __future__ import print_function

from enum import Enum
import json
import netaddr
import re
from six import iteritems

from . import client
from . import output_parser as cli_output_parser

from tempest.lib.common import cred_client
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest import test

from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class Role(Enum):
    admin = 1
    tenant = 2
    nonadmin = 3


class CLIClientTestCase(test.BaseTestCase):
    """Base test class for testing the OpenStack client CLI interfaces."""

    credentials = ['primary', 'admin']

    """
    Base class for the Neutron tests that use the remote CLI clients
    """

    force_tenant_isolation = False

    # Default to ipv4.
    _ip_version = 4

    _osc = None

    @classmethod
    def setup_clients(cls):
        super(CLIClientTestCase, cls).setup_clients()

        # This creates a client that abstracts identity v2 and v3 operations
        if CONF.identity.auth_version == 'v2':
            client = cls.os_admin.identity_client
            users_client = cls.os_admin.users_client
            project_client = cls.os_admin.tenants_client
            roles_client = cls.os_admin.roles_client
            domains_client = None
        else:
            client = cls.os_admin.identity_v3_client
            users_client = cls.os_admin.users_v3_client
            project_client = cls.os_admin.projects_client
            roles_client = cls.os_admin.roles_v3_client
            domains_client = cls.os_admin.domains_client

        try:
            domain = client.auth_provider.credentials.project_domain_name
        except AttributeError:
            domain = 'Default'

        cls.creds_client = \
            cred_client.get_creds_client(client,
                                         project_client,
                                         users_client,
                                         roles_client,
                                         domains_client,
                                         project_domain_name=domain)

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(CLIClientTestCase, cls).setup_credentials()

    @classmethod
    def resource_setup(cls):
        super(CLIClientTestCase, cls).resource_setup()

        cls.cli = client.CLIClient(
            username=CONF.auth.admin_username,
            project_name=CONF.auth.admin_project_name,
            password=CONF.auth.admin_password,
            creds_client=cls.creds_client)

        cls.network_cfg = CONF.network
        cls.parser = cli_output_parser
        cls.networks = []
        cls.subnets = []
        cls.ports = []
        cls.routers = []
        cls.floating_ips = []
        cls.security_groups = []
        cls.security_group_rules = []
        cls.vms = []

        cls.ethertype = "IPv" + str(cls._ip_version)

        # tricky stuff to work with 2 OS controllers on Nuage testbed
        # the IP address of osc-2 is always osc-1 + 1
        # work with these 2 uri's
        cls.uri_1 = cls.os_primary.identity_client.base_url
        ip_osc_1 = netaddr.IPAddress(
            re.findall(r'[0-9]+(?:\.[0-9]+){3}', cls.uri_1)[0])
        ip_osc_2 = ip_osc_1 + 1
        cls.uri_2 = re.sub(str(ip_osc_1), str(ip_osc_2), cls.uri_1)

        # make the uri point to the one of osc-1
        cls.uri = cls.uri_1
        cls.admin_cli = client.CLIClient(
            username=CONF.auth.admin_username,
            project_name=CONF.auth.admin_project_name,
            password=CONF.auth.admin_password,
            creds_client=cls.creds_client)
        cls.nonadmin_cli = client.CLIClient(
            username="nonadmin",
            project_name=CONF.auth.admin_project_name,
            password=CONF.auth.admin_password,
            creds_client=cls.creds_client)

        cls.project = cls.creds_client.create_project(
            name=data_utils.rand_name('project-'),
            description="descr")

        cls.user = cls.creds_client.\
            create_user(username=data_utils.rand_name('user-'),
                        password='tigris',
                        project=cls.project,
                        email="email")

        # available_roles = cls.creds_client.roles_client.list_roles()[
        #     'roles']
        roles = cls.creds_client.roles_client.list_user_roles_on_project(
            cls.project['id'], cls.user['id'])['roles']

        if len(roles) == 0:
            # assert len(available_roles) > 0
            # role_name = available_roles[0]['name']
            role_name = CONF.auth.tempest_roles[0]
            cls.creds_client.assign_user_role(
                project=cls.project,
                user=cls.user,
                role_name=role_name)

        cls.tenant_cli = client.CLIClient(
            username=cls.user['name'],
            project_name=cls.project['name'],
            password='tigris',
            creds_client=cls.creds_client)
        cls.me = Role.tenant

    @classmethod
    def resource_cleanup(cls):
        # TODO(team): security groups
        # TODO(team): security group rules

        # Clean up ports
        for port in cls.ports:
            cls._delete_port(port['id'])
        cls.ports = []

        # Clean up routers
        for router in cls.routers:
            cls.delete_router(router)
        cls.routers = []

        # Clean up subnets
        for subnet in cls.subnets:
            cls._delete_subnet(subnet['id'])
        cls.subnets = []

        # Clean up networks
        for network in cls.networks:
            cls._delete_network(network['id'])
        cls.networks = []

        cls.creds_client.delete_user(cls.user['id'])
        cls.creds_client.delete_project(cls.project['id'])

        super(CLIClientTestCase, cls).resource_cleanup()

    @classmethod
    def skip_checks(cls):
        super(CLIClientTestCase, cls).skip_checks()
        if not CONF.service_available.neutron:
            # this check prevents this test to be run in unittests
            raise cls.skipException("Neutron support is required")

    def setUp(self):
        super(CLIClientTestCase, self).setUp()
        self.clients = self._get_clients()
        self.parser = cli_output_parser

    def assertFirstLineStartsWith(self, lines, beginning):
        """assertFirstLineStartsWith

        Verify that the first line starts with a string
        :param lines: strings for each line of output
        :type lines: list
        :param beginning: verify this is at the beginning of the first line
        :type beginning: string
        """
        self.assertTrue(lines[0].startswith(beginning),
                        msg=('Beginning of first line has invalid content: %s'
                             % lines[:3]))

    def assertCommandFailed(self, message, fun, *args, **kwds):
        self.assertRaisesRegex(exceptions.CommandFailed, message,
                               fun, *args, **kwds)

    def _get_clients(self):
        if self.me == Role.admin:
            self.cli = self.admin_cli
        elif self.me == Role.tenant:
            self.cli = self.tenant_cli
        else:
            self.cli = self.nonadmin_cli
        return self.cli

    def _as_admin(self):
        self.me = Role.admin
        self._get_clients()
        return self

    def _as_tenant(self):
        self.me = Role.tenant
        self._get_clients()

    def create_network_with_args(self, *args):
        """Wrapper utility that returns a test network."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('net-create', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Created a new network:')
        network = self.parser.details(response)
        self.networks.append(network)
        return network

    def create_network(self, network_name=None):
        """Wrapper utility that returns a test network."""
        network_name = network_name or data_utils.rand_name('test-network')
        return self.create_network_with_args(network_name)

    def delete_network(self, network_id):
        response = self.cli.neutron('net-delete', params=network_id)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Deleted network')
        self.assertIn(network_id, response)

    def show_network(self, network_id):
        response = self.cli.neutron('net-show', params=network_id)
        network = self.parser.details(response)
        self.assertEqual(network['id'], network_id)
        return network

    def list_networks(self):
        response = self.cli.neutron('net-list')
        return response

    def show_subnet(self, subnet_id):
        response = self.cli.neutron('subnet-show', params=subnet_id)
        subnet = self.parser.details(response)
        self.assertEqual(subnet['id'], subnet_id)
        return subnet

    def delete_subnet(self, subnet_id):
        response = self.cli.neutron('subnet-delete', params=subnet_id)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Deleted subnet')
        self.assertIn(subnet_id, response)

    def list_subnets(self):
        response = self.cli.neutron('subnet-list')
        return response

    def create_subnet_with_args(self, *args):
        """Wrapper utility that returns a test subnet."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('subnet-create', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Created a new subnet:')
        subnet = self.parser.details(response)
        self.subnets.append(subnet)
        return subnet

    def update_subnet_with_args(self, *args):
        """Wrapper utility that updates returns a test subnet."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('subnet-update', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Updated subnet:')

    def create_router_with_args(self, *args):
        """Wrapper utility that returns a test router."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('router-create', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Created a new router:')
        router = self.parser.details(response)
        self.routers.append(router)
        return router

    def create_router(self, router_name=None):
        """Wrapper utility that returns a test router."""
        router_name = router_name or data_utils.rand_name('test-router')
        return self.create_router_with_args(router_name)

    def update_router_with_args(self, *args):
        """Wrapper utility that returns a test router."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('router-update', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Updated router:')
        # router = self.parser.details(response)
        # return router

    def show_router(self, router_id):
        response = self.cli.neutron('router-show', params=router_id)
        router = self.parser.details(response)

        self.assertEqual(router['id'], router_id)
        return router

    def list_routers(self):
        response = self.cli.neutron('router-list')
        return response

    def set_router_gateway_with_args(self, *args):
        """Wrapper utility that sets the router gateway."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('router-gateway-set', params=the_params)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Set gateway for router')

    def add_router_interface_with_args(self, *args):
        """Wrapper utility that sets the router gateway."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('router-interface-add', params=the_params)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Added interface')

    def create_port_with_args(self, *args):
        """Wrapper utility that returns a test port."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg
        if (CONF.network.port_vnic_type == 'direct' and
                'switchdev' in CONF.network.port_profile.get('capabilities',
                                                             [])):
            the_params += ' '
            the_params += '--vnic-type direct'
            the_params += ' '
            the_params += ('--binding:profile type=dict'
                           ' capabilities=[switchdev]')

        response = self.cli.neutron('port-create', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Created a new port:')
        port = self.parser.details(response)
        self.ports.append(port)
        return port

    def create_port(self, network, port_name=None):
        """Wrapper utility that returns a test port."""
        port_name = port_name or data_utils.rand_name('cli-test-port-')
        response = self.create_port_with_args("--name ", port_name,
                                              network['id'])
        return response

    def update_port_with_args(self, port_id, *args):
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg
        response = self.cli.neutron('port-update ',
                                    params=port_id + ' ' + the_params)
        self.assertFirstLineStartsWith(response.split('\n'), 'Updated port:')

    def show_port(self, port_id):
        response = self.cli.neutron('port-show', params=port_id)
        port = self.parser.details(response)
        self.assertEqual(port['id'], port_id)
        return port

    def create_floating_ip_with_args(self, *args):
        """Wrapper utility that returns a test floating_ip."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('floatingip-create',
                                    params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Created a new floatingip:')
        floating_ip = self.parser.details(response)
        self.floating_ips.append(floating_ip)
        return floating_ip

    def update_floating_ip_with_args(self, *args):
        """Wrapper utility that returns a test floating_ip."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('floatingip-update', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Updated floatingip:')

    def create_floating_ip(self, floating_ip_name=None):
        """Wrapper utility that returns a test floating_ip."""
        floating_ip_name = floating_ip_name or data_utils.rand_name(
            'test-floating_ip')
        return self.create_floating_ip_with_args(floating_ip_name)

    def show_floating_ip(self, floating_ip_id):
        response = self.cli.neutron('floatingip-show', params=floating_ip_id)
        floating_ip = self.parser.details(response)
        return floating_ip

    def list_nuage_floating_ip_all(self):
        response = self.cli.neutron('nuage-floatingip-list')
        nuage_floating_ip_list = self.parser.details(response)
        return nuage_floating_ip_list

    def list_nuage_floating_ip_for_subnet(self, subnet_id):
        response = self.cli.neutron('nuage-floatingip-show --subnet ',
                                    params=subnet_id)
        nuage_floating_ip_list = self.parser.details(response)
        return nuage_floating_ip_list

    def list_nuage_floating_ip_for_port(self, port_id):
        response = self.cli.neutron('nuage-floatingip-show --subnet ',
                                    params=port_id)
        nuage_floating_ip_list = self.parser.details(response)
        return nuage_floating_ip_list

    def show_nuage_floating_ip(self, floating_ip_id):
        response = self.cli.neutron('floatingip-show', params=floating_ip_id)
        floating_ip = self.parser.details(response)
        return floating_ip

    def _kwargs_to_cli(self, **kwargs):
        params_str = ''
        if kwargs is not None:
            for key, value in iteritems(kwargs):

                print("%s == %s", (key, value))
                params_str += " --%s %s" % (key, value)

            params_str = params_str.replace("_", "-")
        return params_str

    def associate_floating_ip(self, floating_ip_id, port_id, **kwargs):
        the_params = self._kwargs_to_cli(**kwargs)

        return self.cli.neutron('floatingip-associate',
                                params=floating_ip_id + ' ' +
                                port_id + the_params)

    def disassociate_floating_ip(self, floating_ip_id):
        return self.cli.neutron('floatingip-disassociate',
                                params=floating_ip_id)

    def create_nuage_l2bridge_cli(self, *args):
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        return self.cli.neutron('nuage-l2bridge-create',
                                params=the_params)

    def show_nuage_l2bridge_cli(self, *args):
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        return self.cli.neutron('nuage-l2bridge-show',
                                params=the_params)

    def delete_nuage_l2bridge_cli(self, id, name=None):
        if name:
            return self.cli.neutron('nuage-l2bridge-delete',
                                    params=' ' + name)
        else:
            return self.cli.neutron('nuage-l2bridge-delete',
                                    params=' ' + id)

    def update_nuage_l2bridge_cli(self, *args):
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        return self.cli.neutron('nuage-l2bridge-update',
                                params=the_params)

    def create_security_group_with_args(self, *args):
        """Wrapper utility that returns a test security group."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('security-group-create',
                                    params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Created a new security_group:')
        security_group = self.parser.details(response)
        self.security_groups.append(security_group)
        return security_group

    def update_security_group_with_args(self, *args):
        """Wrapper utility that returns a test security group."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('security-group-update',
                                    params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Updated security_group:')
        security_group = self.parser.details(response)
        return security_group

    def show_security_group(self, sg_id):
        response = self.cli.neutron('security-group-show', params=sg_id)
        security_group = self.parser.details(response)
        self.assertEqual(security_group['id'], sg_id)
        return security_group

    def delete_security_group(self, sg_id):
        response = self.cli.neutron('security-group-delete', params=sg_id)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Deleted security_group(s)')
        self.assertIn(sg_id, response)

    def create_security_group_rule_with_args(self, *args):
        """Wrapper utility that returns a test security group rule."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('security-group-rule-create',
                                    params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Created a new security_group_rule:')
        security_group_rule = self.parser.details(response)
        self.security_group_rules.append(security_group_rule)
        return security_group_rule

    def create_vm_with_args(self, *args):
        """Wrapper utility that returns a test VM."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.nova('boot', params=the_params)

        # self.assertFirstLineStartsWith(response.split('\n'),
        #     'Created a new VM:')
        vm = self.parser.details(response)
        self.vms.append(vm)
        return vm

    @classmethod
    def delete_router(cls, router):

        cls._clear_router_gateway(router['id'])

        interfaces = cls._list_router_ports(router['id'])

        for i in interfaces:
            fixed_ips = i['fixed_ips']
            fixed_ips_dict = json.loads(fixed_ips)
            subnet_id = fixed_ips_dict['subnet_id']
            cls._remove_router_interface_with_subnet_id(router['id'],
                                                        subnet_id)

        cls._delete_router(router['id'])

    @classmethod
    def _delete_network(cls, network_id):
        cls.cli.neutron('net-delete', params=network_id)

    @classmethod
    def _delete_subnet(cls, subnet_id):
        cls.cli.neutron('subnet-delete', params=subnet_id)

    @classmethod
    def _delete_port(cls, port_id):
        cls.cli.neutron('port-delete', params=port_id)

    @classmethod
    def _delete_router(cls, router_id):
        cls.cli.neutron('router-delete', params=router_id)

    @classmethod
    def _delete_floating_ip(cls, floating_ip_id):
        cls.cli.neutron('floatingip-delete', params=floating_ip_id)

    @classmethod
    def _clear_router_gateway(cls, router_id):
        cls.cli.neutron('router-gateway-clear', params=router_id)

    @classmethod
    def _list_router_ports(cls, router_id):
        response = cls.cli.neutron('router-port-list', params=router_id)
        ports = cls.parser.listing(response)
        return ports

    @classmethod
    def _remove_router_interface_with_subnet_id(cls, router_id, subnet_id):
        response = cls.cli.neutron('router-interface-delete',
                                   params=router_id + ' ' + subnet_id)
        return response

    # @classmethod
    def _cli_create_redirect_target_with_args(self, *args):
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('nuage-redirect-target-create',
                                    params=the_params)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Created a new nuage_redirect_target:')
        redirect_target = self.parser.details(response)
        # self.nuage_redirect_targets.append(redirect_target)
        return redirect_target

    def _cli_create_nuage_redirect_target_in_l2_subnet(self, l2subnet,
                                                       name=None):
        if name is None:
            name = data_utils.rand_name('cli-os-l2-rt')
        # parameters for nuage redirection target
        response = self.cli.neutron(
            'nuage-redirect-target-create --insertion-mode VIRTUAL_WIRE '
            '--redundancy-enabled false --subnet',
            params=l2subnet['name'] + ' ' + name)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Created a new nuage_redirect_target:')
        redirect_target = self.parser.details(response)
        # self.nuage_redirect_targets.append(redirect_target)
        return redirect_target

    def _cli_create_nuage_redirect_target_in_l3_subnet(self, l3subnet,
                                                       name=None):
        if name is None:
            name = data_utils.rand_name('cli-os-l3-rt')
        response = self.cli.neutron(
            'nuage-redirect-target-create --insertion-mode L3 '
            '--redundancy-enabled false --subnet',
            params=l3subnet['name'] + ' ' + name)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Created a new nuage_redirect_target:')
        redirect_target = self.parser.details(response)
        # self.nuage_redirect_targets.append(redirect_target)
        return redirect_target

    def delete_redirect_target(self, redirect_target_id):
        self.cli.neutron('nuage-redirect-target-delete',
                         params=redirect_target_id)

    def list_nuage_redirect_target_for_l2_subnet(self, l2subnet):
        response = self.cli.neutron('nuage-redirect-target-list --subnet ',
                                    params=l2subnet['id'])
        rt_list = self.parser.listing(response)
        return rt_list

    def list_nuage_redirect_target_for_port(self, port):
        response = self.cli.neutron('nuage-redirect-target-list --for-port ',
                                    params=port['id'])
        rt_list = self.parser.listing(response)
        return rt_list

    def show_nuage_redirect_target(self, redirect_target_id):
        response = self.cli.neutron('nuage-redirect-target-show',
                                    params=redirect_target_id)
        rt_show = self.parser.details(response)
        return rt_show

    def cli_create_nuage_redirect_target_rule_with_args(self, *args):
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg
        response = self.cli.neutron('nuage-redirect-target-rule-create ',
                                    params=the_params)
        rt_rule = self.parser.details(response)
        return rt_rule

    def list_nuage_policy_group_for_subnet(self, subnet_id):
        response = self.cli.neutron('nuage-policy-group-list --for-subnet ',
                                    params=subnet_id)
        rt_list = self.parser.listing(response)
        return rt_list

    def show_nuage_policy_group(self, policy_group_id):
        response = self.cli.neutron("nuage-policy-group-show",
                                    params=policy_group_id)
        show_pg = self.parser.details(response)
        return show_pg

    def list_nuage_floatingip_by_subnet(self, subnet_id):
        response = self.cli.neutron('nuage-floatingip-list --for-subnet ',
                                    params=subnet_id)
        fp_list = self.parser.listing(response)
        return fp_list

    def list_nuage_floatingip_by_port(self, port_id):
        response = self.cli.neutron('nuage-floatingip-list --for-port ',
                                    params=port_id)
        fp_list = self.parser.listing(response)
        return fp_list

    def show_nuage_floatingip(self, fp_id):
        response = self.cli.neutron('nuage-floatingip-show ', params=fp_id)
        show_fp = self.parser.details(response)
        return show_fp
