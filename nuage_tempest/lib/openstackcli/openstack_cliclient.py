
import logging
import os

from tempest import config

from nuage_tempest.lib.openstackcli import output_parser as cli_output_parser

CONF = config.CONF

LOG = logging.getLogger(__name__)


class CLIClient(object):
    """CLIClient

    Class to use OpenStack official python client CLI's with auth
    :param username: The username to authenticate with
    :type username: string
    :param password: The password to authenticate with
    :type password: string
    :param tenant_name: The name of the tenant to use with the client calls
    :type tenant_name: string
    :param uri: The auth uri for the OpenStack Deployment
    :type uri: string
    :param cli_dir: The path where the python client binaries are installed.
                    defaults to /usr/bin
    :type cli_dir: string
    """

    def __init__(self, username='', password='', tenant_name='', uri='',
                 cli_dir='', osc=None, *args, **kwargs):
        """Initialize a new CLIClient object."""
        super(CLIClient, self).__init__()
        self.username = username
        self.tenant_name = tenant_name
        self.password = password
        self.uri = uri
        self.osc = osc

    def nova(self, action, flags='', params='', fail_ok=False,
             endpoint_type='publicURL', merge_stderr=False, timeout=10):
        """nova

        Executes nova command for the given action.
        :param action: the cli command to run using nova
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        :param merge_stderr: if True the stderr buffer is merged into stdout
        :type merge_stderr: boolean
        """
        flags += ' --endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'nova', action, flags, params, fail_ok, merge_stderr, timeout)

    # TODO(team) - check - kris added cmd arg
    def nova_manage(self, cmd, action, flags='', params='', fail_ok=False,
                    merge_stderr=False, timeout=10):
        """nova_manage

        Executes nova-manage command for the given action.
        :param action: the cli command to run using nova-manage
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param merge_stderr: if True the stderr buffer is merged into stdout
        :type merge_stderr: boolean
        """
        cmd = ' '.join([os.path.join(cmd), flags, action, params])
        LOG.debug("running: '%s'", cmd)
        response = self.osc.cmd(cmd)
        response = response[0]
        resp = ''
        for line in response:
            resp = resp + line + '\n'
        return resp

    def keystone(self, action, flags='', params='', fail_ok=False,
                 merge_stderr=False, timeout=10):
        """keystone

        Executes keystone command for the given action.
        :param action: the cli command to run using keystone
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param merge_stderr: if True the stderr buffer is merged into stdout
        :type merge_stderr: boolean
        """
        return self.cmd_with_auth(
            'keystone', action, flags, params, fail_ok, merge_stderr, timeout)

    def glance(self, action, flags='', params='', fail_ok=False,
               endpoint_type='publicURL', merge_stderr=False, timeout=10):
        """glance

        Executes glance command for the given action.
        :param action: the cli command to run using glance
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        :param merge_stderr: if True the stderr buffer is merged into stdout
        :type merge_stderr: boolean
        """
        flags += ' --os-endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'glance', action, flags, params, fail_ok, merge_stderr, timeout)

    def ceilometer(self, action, flags='', params='',
                   fail_ok=False, endpoint_type='publicURL',
                   merge_stderr=False, timeout=10):
        """ceilometer

        Executes ceilometer command for the given action.
        :param action: the cli command to run using ceilometer
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        :param merge_stderr: if True the stderr buffer is merged into stdout
        :type merge_stderr: boolean
        """
        flags += ' --os-endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'ceilometer', action, flags, params, fail_ok, merge_stderr,
            timeout)

    def heat(self, action, flags='', params='',
             fail_ok=False, endpoint_type='publicURL',
             merge_stderr=False, timeout=10):
        """heat

        Executes heat command for the given action.
        :param action: the cli command to run using heat
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        :param merge_stderr: if True the stderr buffer is merged into stdout
        :type merge_stderr: boolean
        """
        flags += ' --os-endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'heat', action, flags, params, fail_ok, merge_stderr, timeout)

    def cinder(self, action, flags='', params='', fail_ok=False,
               endpoint_type='publicURL', merge_stderr=False, timeout=10):
        """cinder

        Executes cinder command for the given action.
        :param action: the cli command to run using cinder
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        :param merge_stderr: if True the stderr buffer is merged into stdout
        :type merge_stderr: boolean
        """
        flags += ' --endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'cinder', action, flags, params, fail_ok, merge_stderr)

    def swift(self, action, flags='', params='', fail_ok=False,
              endpoint_type='publicURL', merge_stderr=False, timeout=10):
        """swift

        Executes swift command for the given action.
        :param action: the cli command to run using swift
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        :param merge_stderr: if True the stderr buffer is merged into stdout
        :type merge_stderr: boolean
        """
        flags += ' --os-endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'swift', action, flags, params, fail_ok, merge_stderr, timeout)

    def neutron(self, action, flags='', params='', fail_ok=False,
                endpoint_type='publicURL', merge_stderr=False, timeout=20):
        """neutron

        Executes neutron command for the given action.
        :param action: the cli command to run using neutron
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        :param merge_stderr: if True the stderr buffer is merged into stdout
        :type merge_stderr: boolean
        """
        flags += ' --endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'neutron', action, flags, params, fail_ok, merge_stderr, timeout)

    # TODO(team) - check - kris added cmd arg
    def neutron_debug(self, cmd, action, flags='', params='', fail_ok=False,
                      endpoint_type='publicURL', merge_stderr=False,
                      timeout=10):
        """neutron_debug

        Executes neutron-debug command for the given action.
        :param action: the cli command to run using neutron
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        :param merge_stderr: if True the stderr buffer is merged into stdout
        :type merge_stderr: boolean
        """
        cmd = ' '.join([os.path.join(cmd), flags, action, params, timeout])
        LOG.debug("running: '%s'", cmd)
        response = self.osc.cmd(cmd)
        response = response[0]
        resp = ''
        for line in response:
            resp = resp + line + '\n'
        return resp

    def sahara(self, action, flags='', params='',
               fail_ok=False, endpoint_type='publicURL',
               merge_stderr=True, timeout=10):
        """sahara

        Executes sahara command for the given action.
        :param action: the cli command to run using sahara
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param endpoint_type: the type of endpoint for the service
        :type endpoint_type: string
        :param merge_stderr: if True the stderr buffer is merged into stdout
        :type merge_stderr: boolean
        """
        flags += ' --endpoint-type %s' % endpoint_type
        return self.cmd_with_auth(
            'sahara', action, flags, params, fail_ok, merge_stderr, timeout)

    def openstack(self, action, flags='', params='', fail_ok=False,
                  merge_stderr=False, timeout=10):
        """openstack

        Executes openstack command for the given action.
        :param action: the cli command to run using openstack
        :type action: string
        :param flags: any optional cli flags to use
        :type flags: string
        :param params: any optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the
                        cli return code is non-zero
        :type fail_ok: boolean
        :param merge_stderr: if True the stderr buffer is merged into stdout
        :type merge_stderr: boolean
        """
        return self.cmd_with_auth(
            'openstack', action, flags, params, fail_ok, merge_stderr, timeout)

    def cmd_with_auth(self, cmd, action, flags='', params='',
                      fail_ok=False, merge_stderr=False, timeout=10):
        """cmd_with_auth

        Executes given command with auth attributes appended.
        :param cmd: command to be executed
        :type cmd: string
        :param action: command on cli to run
        :type action: string
        :param flags: optional cli flags to use
        :type flags: string
        :param params: optional positional args to use
        :type params: string
        :param fail_ok: if True an exception is not raised when the cli return
                        code is non-zero
        :type fail_ok: boolean
        :param merge_stderr:  if True the stderr buffer is merged into stdout
        :type merge_stderr: boolean
        """
        creds = ('--os-username %s --os-tenant-name %s --os-password %s '
                 '--os-auth-url %s' %
                 (self.username,
                  self.tenant_name,
                  self.password,
                  self.uri))
        flags = creds + ' ' + flags
        cmd = ' '.join([os.path.join(cmd), flags, action, params])
        LOG.debug("running: '%s'", cmd)
        if fail_ok:
            response = self.osc.cmd(cmd, strict=False, timeout=timeout)
            assert response[2] == 1
            return response[1]
        response = self.osc.cmd(cmd, timeout=timeout)
        response = response[0]
        resp = ''
        for line in response:
            resp = resp + line + '\n'
        return resp


class ClientTestBase(object):
    """Base test class for testing the OpenStack client CLI interfaces."""

    def __init__(self, osc):
        self.parser = cli_output_parser
        self.cli = CLIClient(
            username=CONF.auth.admin_username,
            tenant_name=CONF.auth.admin_project_name,
            password=CONF.auth.admin_password,
            uri=CONF.identity.uri, osc=osc)

    def _get_clients(self):
        'TODO: Fix this raise'
        """Abstract method to initialize CLIClient object.
        This method must be overloaded in child test classes. It should be
        used to initialize the CLIClient object with the appropriate
        credentials during the setUp() phase of tests.
        """
        raise NotImplementedError

    def assertTableStruct(self, items, field_names):
        'TODO: fix this assertIn'
        """Verify that all items has keys listed in field_names.
        :param items: items to assert are field names in the output table
        :type items: list
        :param field_names: field names from the output table of the cmd
        :type field_names: list
        """
        for item in items:
            for field in field_names:
                self.assertIn(field, item)

    def assertFirstLineStartsWith(self, lines, beginning):
        """assertFirstLineStartsWith

        Verify that the first line starts with a string
        :param lines: strings for each line of output
        :type lines: list
        :param beginning: verify this is at the beginning of the first line
        :type beginning: string
        """
        msg = 'Beginning of first line has invalid content: ' \
              '{}'.format(lines[:3])
        assert lines[0].startswith(beginning), msg

    def runTest(cls):
        pass
