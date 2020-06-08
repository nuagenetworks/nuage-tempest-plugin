# Copyright 2020 Nokia
# All Rights Reserved.
import json
import testtools

from tempest.common import utils

from nuage_tempest_plugin.lib.cli import client_testcase
from nuage_tempest_plugin.lib.topology import Topology

LOG = Topology.get_logger(__name__)


@testtools.skipIf(Topology.from_openstack('stein'),
                  'Fwaas v1 is removed from stein onwards')
class TestNuageFWaaSCli(client_testcase.CLIClientTestCase):

    @classmethod
    def resource_setup(cls):
        super(TestNuageFWaaSCli, cls).resource_setup()
        if not utils.is_extension_enabled('fwaas', 'network'):
            msg = "FWaaS Extension not enabled."
            raise cls.skipException(msg)

    def test_cli_create_ipv6_icmp_rule(self):
        self._as_admin()
        name = utils.data_utils.rand_name('test-create-firwall-rule-')

        fw_rule = self.create_firewall_rule_cli(
            '--protocol icmp', '--action deny', '--ip-version 6',
            '--name ', name, '-f json', '--insecure')
        self.assertIsNotNone(fw_rule)
        fw_rule = json.loads(fw_rule)
        self.assertEqual(expected=6, observed=fw_rule['ip_version'])
        self.assertEqual(expected='ipv6-icmp', observed=fw_rule['protocol'])
        self.assertEqual(expected='deny', observed=fw_rule['action'])
        self.delete_firewall_rule_cli(name, '--insecure')

    def test_cli_create_ipv4_icmp_rule(self):
        self._as_admin()
        name = utils.data_utils.rand_name('test-create-firwall-rule-')

        fw_rule = self.create_firewall_rule_cli(
            '--protocol icmp', '--action deny', '--name ', name, '-f json',
            '--insecure')
        self.assertIsNotNone(fw_rule)
        fw_rule = json.loads(fw_rule)
        self.assertEqual(expected=4, observed=fw_rule['ip_version'])
        self.assertEqual(expected='icmp', observed=fw_rule['protocol'])
        self.assertEqual(expected='deny', observed=fw_rule['action'])
        self.delete_firewall_rule_cli(name, '--insecure')
