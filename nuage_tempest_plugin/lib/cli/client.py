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

import os
import shlex
import six
import subprocess

from tempest.lib import exceptions

from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


# TODO(Kris) Refactor me - this for now is copy of execute() method from
# TODO(Kris) tempest/tempest/lib/cli/base.py
# ------------------------- don't change me ----------------------------
def execute(cmd, action, flags='', params='', fail_ok=False,
            merge_stderr=False, cli_dir='/usr/bin', prefix=''):
    """Executes specified command for the given action.

    :param cmd: command to be executed
    :type cmd: string
    :param action: string of the cli command to run
    :type action: string
    :param flags: any optional cli flags to use
    :type flags: string
    :param params: string of any optional positional args to use
    :type params: string
    :param fail_ok: boolean if True an exception is not raised when the
                    cli return code is non-zero
    :type fail_ok: boolean
    :param merge_stderr: boolean if True the stderr buffer is merged into
                         stdout
    :type merge_stderr: boolean
    :param cli_dir: The path where the cmd can be executed
    :type cli_dir: string
    :param prefix: prefix to insert before command
    :type prefix: string
    :param postfix: postfix to insert before command - KRIS ADDED
    :type postfix: string
    """
    cmd = ' '.join([prefix, os.path.join(cli_dir, cmd),
                    flags, action, params])
    cmd = cmd.strip()
    LOG.info("running: '%s'", cmd)
    if six.PY2:
        cmd = cmd.encode('utf-8')
    cmd = shlex.split(cmd)
    result = ''
    result_err = ''
    stdout = subprocess.PIPE
    stderr = subprocess.STDOUT if merge_stderr else subprocess.PIPE
    proc = subprocess.Popen(cmd, stdout=stdout, stderr=stderr)
    result, result_err = proc.communicate()
    if not fail_ok and proc.returncode != 0:
        raise exceptions.CommandFailed(proc.returncode,
                                       cmd,
                                       result,
                                       result_err)
    if six.PY2:
        return result
    else:
        return os.fsdecode(result)
# ------------------------- don't change me ----------------------------


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
    """

    def __init__(self, username='', password='', tenant_name='',
                 cli_dir='', project_name='', creds_client=None):

        """Initialize a new CLIClient object."""
        super(CLIClient, self).__init__()
        self.creds_client = creds_client
        self.username = username
        self.tenant_name = tenant_name
        self.password = password
        self.cli_dir = cli_dir if cli_dir else '/usr/bin'
        self.project_name = project_name

    def nova(self, action, flags='', params='', fail_ok=False,
             endpoint_type='publicURL', merge_stderr=False):
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
            'nova', action, flags, params, fail_ok, merge_stderr)

    def nova_manage(self, action, flags='', params='', fail_ok=False,
                    merge_stderr=False):
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
        return execute(
            'nova-manage',
            action, flags, params, fail_ok, merge_stderr, cli_dir='')

    def keystone(self, action, flags='', params='', fail_ok=False,
                 merge_stderr=False):
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
            'keystone', action, flags, params, fail_ok, merge_stderr)

    def glance(self, action, flags='', params='', fail_ok=False,
               endpoint_type='publicURL', merge_stderr=False):
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
            'glance', action, flags, params, fail_ok, merge_stderr)

    def ceilometer(self, action, flags='', params='',
                   fail_ok=False, endpoint_type='publicURL',
                   merge_stderr=False):
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
            'ceilometer', action, flags, params, fail_ok, merge_stderr)

    def heat(self, action, flags='', params='',
             fail_ok=False, endpoint_type='publicURL', merge_stderr=False):
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
            'heat', action, flags, params, fail_ok, merge_stderr)

    def cinder(self, action, flags='', params='', fail_ok=False,
               endpoint_type='publicURL', merge_stderr=False):
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
              endpoint_type='publicURL', merge_stderr=False):
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
            'swift', action, flags, params, fail_ok, merge_stderr)

    def neutron(self, action, flags='', params='', fail_ok=False,
                endpoint_type='publicURL', merge_stderr=False):
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
            'neutron', action, flags, params, fail_ok, merge_stderr)

    def neutron_debug(self, action, flags='', params='', fail_ok=False,
                      endpoint_type='publicURL', merge_stderr=False):
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

        return execute(
            'neutron-debug',
            action, flags, params, fail_ok, merge_stderr, cli_dir='')

    def sahara(self, action, flags='', params='',
               fail_ok=False, endpoint_type='publicURL', merge_stderr=False):
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
            'sahara', action, flags, params, fail_ok, merge_stderr)

    def openstack(self, action, flags='', params='', fail_ok=False,
                  merge_stderr=False):
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
            'openstack', action, flags, params, fail_ok, merge_stderr)

    def cmd_with_auth(self, cmd, action, flags='', params='',
                      fail_ok=False, merge_stderr=False, timeout=20):
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
        :param merge_stderr: if True the stderr buffer is merged into stdout
        :type merge_stderr: boolean
        """
        creds = self.creds_client.get_credentials(
            {'name': self.username, 'id': None},
            {'name': self.project_name, 'id': None},
            self.password)
        if CONF.identity.auth_version == 'v2':
            cred_flags = ('--os-username {} --os-tenant-name {} --os-password'
                          ' {} --os-auth-url {}').format(
                self.username,
                self.project_name,
                self.password,
                self.creds_client.identity_client.base_url
            )
        else:
            cred_flags = ('--os-username {} --os-project-name {} --os-password'
                          ' {} --os-auth-url {} --os-user-domain-id {}'
                          ' --os-project-domain-id {}').format(
                self.username,
                self.project_name,
                self.password,
                self.creds_client.identity_client.base_url,
                creds.user_domain_id,
                creds.project_domain_id
            )
        flags = cred_flags + ' ' + flags

        return execute(cmd, action,
                       flags, params, fail_ok, merge_stderr, cli_dir='')
