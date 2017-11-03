# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from oslo_log import log as logging
import re

from tempest import config
from tempest import test

from nuage_tempest.lib.nuage_tempest_test_loader import Release
from nuage_tempest.lib.remote_cli import remote_cli_base_testcase
from nuage_tempest.lib.test import nuage_test

CONF = config.CONF

LOG = logging.getLogger(__name__)


class TestNuageNeutronCli(remote_cli_base_testcase.RemoteCliBaseTestCase):
    """Basic, read-only tests for Neutron CLI client.

    Checks return values and output of read-only commands.
    These tests do not presume any content, nor do they create
    their own. They only verify the structure of output if present.
    """
    # cli_client = None

    def __init__(self, *args, **kwargs):
        super(TestNuageNeutronCli, self).__init__(*args, **kwargs)

    @classmethod
    def resource_setup(cls):
        if not CONF.service_available.neutron:
            msg = "Skipping all Neutron cli tests because it is not available"
            raise cls.skipException(msg)
        super(TestNuageNeutronCli, cls).resource_setup()

    @test.attr(type='smoke')
    @nuage_test.header()
    def test_neutron_debug_net_list(self):
        response = self.cli.neutron('net-list', flags='-v')
        items = self.parser.listing(response)
        LOG.debug("List with %d items", items.__len__())
        self.assertNotEmpty(items)

    @test.attr(type='smoke')
    @nuage_test.header()
    def test_neutron_quiet_net_list(self):
        response = self.cli.neutron('net-list', flags='--quiet')
        items = self.parser.listing(response)
        LOG.debug("List with %d items", items.__len__())
        self.assertNotEmpty(items)

    @nuage_test.header()
    def test_neutron_nuage_commands_help(self):
        help_text = self.cli.neutron('help')
        lines = help_text.split('\n')
        self.assertFirstLineStartsWith(lines, 'usage: neutron')

        commands = []
        cmds_start = lines.index('Commands for API v2.0:')
        command_pattern = re.compile('^ {2}([a-z0-9\-_]+)')
        for line in lines[cmds_start:]:
            match = command_pattern.match(line)
            if match:
                commands.append(match.group(1))
        commands = set(commands)

        wanted_commands = {'nuage-netpartition-create'}

        if test.is_extension_enabled('net-partition', 'network'):
            wanted_commands = wanted_commands.union(self._crud_command_list(
                'nuage-netpartition', update=False))

        if test.is_extension_enabled('appdesigner', 'network'):
            wanted_commands = wanted_commands.union(self._crud_command_list(
                'nuage-appdport'))
            wanted_commands = wanted_commands.union(self._crud_command_list(
                'nuage-service'))
            wanted_commands = wanted_commands.union(self._crud_command_list(
                'nuage-tier'))
            wanted_commands = wanted_commands.union(self._crud_command_list(
                'nuage-application'))
            wanted_commands = wanted_commands.union(self._crud_command_list(
                'nuage-applicationdomain'))
            wanted_commands = wanted_commands.union(self._crud_command_list(
                'nuage-flow'))

        if test.is_extension_enabled('nuage-redirect-target', 'network'):
            wanted_commands.add('nuage-redirect-target-vip-create')
            wanted_commands = wanted_commands.union(self._crud_command_list(
                'nuage-redirect-target', update=False))
            wanted_commands = wanted_commands.union(self._crud_command_list(
                'nuage-redirect-target-rule', update=False))

        if Release('4.0') <= Release(CONF.nuage_sut.release):
            wanted_commands.add('nuage-policy-group-list')
            wanted_commands.add('nuage-policy-group-show')
            wanted_commands.add('nuage-floatingip-list')
            wanted_commands.add('nuage-floatingip-show')
            wanted_commands = wanted_commands.union(self._crud_command_list(
                'nuage-external-security-group', update=False))
            wanted_commands = wanted_commands.union(self._crud_command_list(
                'nuage-external-security-group-rule', update=False))

        if test.is_extension_enabled('nuage-gateway', 'network'):
            wanted_commands.add('nuage-gateway-list')
            wanted_commands.add('nuage-gateway-show')
            wanted_commands.add('nuage-gateway-port-list')
            wanted_commands.add('nuage-gateway-port-show')
            wanted_commands.add('nuage-gateway-vlan-assign')
            wanted_commands.add('nuage-gateway-vlan-create')
            wanted_commands.add('nuage-gateway-vlan-list')
            wanted_commands.add('nuage-gateway-vlan-delete')
            wanted_commands.add('nuage-gateway-vlan-show')
            wanted_commands.add('nuage-gateway-vlan-unassign')
            wanted_commands = wanted_commands.union(self._crud_command_list(
                'nuage-gateway-vport', update=False))

        self.assertFalse(wanted_commands - commands)

    def _crud_command_list(self, resource, update=True):
        crud_commands = {'create', 'delete', 'list', 'show'}
        if update:
            crud_commands.add('update')
        crud_commands_list = []
        for crud_operation in crud_commands:
            crud_commands_list.append(resource + "-" + crud_operation)
        return crud_commands_list

    @nuage_test.header()
    def test_crud_list(self):
        the_list = self._crud_command_list("nuage_appdport")
        self.assertNotEmpty(the_list)
        pass
