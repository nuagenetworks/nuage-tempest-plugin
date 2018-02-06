# Copyright 2018 NOKIA
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

from netaddr import IPNetwork

from oslo_log import log as logging
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from nuage_tempest_plugin.lib import features
from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.tests.api.cli import base_nuage_networks_cli as base

CONF = config.CONF


class TestStatelessSGCli(base.BaseNuageNetworksCliTestCase):

    """Nuage stateless SGs tests using Neutron CLI client.

    """
    LOG = logging.getLogger(__name__)

    @classmethod
    def setup_clients(cls):
        super(TestStatelessSGCli, cls).setup_clients()

    @classmethod
    def skip_checks(cls):
        super(TestStatelessSGCli, cls).skip_checks()
        if not features.NUAGE_FEATURES.stateless_securitygroups:
            msg = "Stateless SecurityGroups feature is not available"
            raise cls.skipException(msg)

    def _verify_created_sg(self, sg_id, expected):
        sg = self.show_security_group(sg_id)
        self.assertEqual(expected, sg['stateful'])

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_cli_load_extension(self):
        response = self.cli.neutron('security-group-create',
                                    params='-h')
        self.assertIn('--stateful {True,False}', response,
                      message='Expected attribute --stateless not found'
                              ' in output')

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_cli_create_show_security_group_default(self):
        sg_name = data_utils.rand_name('sg')
        created_sg = self.create_security_group_with_args(sg_name)
        self.addCleanup(self.delete_security_group, created_sg['id'])
        # SG must be stateful
        self.assertEqual(created_sg['stateful'], 'True')
        self._verify_created_sg(created_sg['id'], 'True')

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_cli_create_show_security_group_stateless(self):
        sg_name = data_utils.rand_name('sg')
        created_sg = self.create_security_group_with_args(sg_name,
                                                          '--stateful',
                                                          'False')
        self.addCleanup(self.delete_security_group, created_sg['id'])
        # SG must be stateless
        self.assertEqual(created_sg['stateful'], 'False')
        self._verify_created_sg(created_sg['id'], 'False')

    @nuage_test.header()
    @decorators.attr(type=['negative', 'smoke'])
    def test_cli_update_security_group_stateless_fail_in_use(self):
        sg_name = data_utils.rand_name('sg')
        created_sg = self.create_security_group_with_args(sg_name)
        self.addCleanup(self.delete_security_group, created_sg['id'])
        self.assertEqual(created_sg['stateful'], 'True')
        self._verify_created_sg(created_sg['id'], 'True')

        network_name = data_utils.rand_name('net-')
        network = self.create_network_with_args(network_name)
        self.networks.remove(network)
        self.addCleanup(self.delete_network, network['id'])

        subnet_name = data_utils.rand_name('subnet-')
        cidr = IPNetwork('172.31.199.0/24')
        subnet = self.create_subnet_with_args(
            network['name'], str(cidr),
            "--name ", subnet_name)
        self.subnets.remove(subnet)

        port = self.create_port_with_args(network['name'],
                                          '--security-group',
                                          sg_name)
        self.ports.remove(port)
        self.addCleanup(self._delete_port, port['id'])

        self.assertEqual(port['security_groups'], created_sg['id'])
        self.assertCommandFailed("Security Group {} in use"
                                 .format(created_sg['id']),
                                 self.update_security_group_with_args,
                                 created_sg['name'],
                                 '--stateful',
                                 'False')
