# Copyright 2018 Nokia
# All Rights Reserved.

from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.cli import client_testcase
from nuage_tempest_plugin.lib.topology import Topology

LOG = Topology.get_logger(__name__)


class TestNuageL2BridgeCli(client_testcase.CLIClientTestCase):

    def test_cli_create_delete_l2bridge(self):
        self._as_admin()
        name = data_utils.rand_name('test-create-l2bridge-')
        bridge = self.create_nuage_l2bridge_cli(
            '--physnet ',
            'physnet_name=physnet1,segmentation_id=100,'
            'segmentation_type=vlan ', name)
        self.assertIsNotNone(bridge)
        self.delete_nuage_l2bridge_cli(name)

    def test_cli_create_update_delete_l2bridge(self):
        self._as_admin()
        name = data_utils.rand_name('test-create-l2bridge-')
        bridge = self.create_nuage_l2bridge_cli(name)
        self.assertIsNotNone(bridge)
        self.update_nuage_l2bridge_cli(
            '--physnet ',
            'physnet_name=physnet1,segmentation_id=100,'
            'segmentation_type=vlan ', name)
        bridge = self.show_nuage_l2bridge_cli(name)
        self.assertIsNotNone(bridge)
        self.delete_nuage_l2bridge_cli(name)
