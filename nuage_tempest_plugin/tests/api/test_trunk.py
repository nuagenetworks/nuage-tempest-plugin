# Copyright 2016 Hewlett Packard Enterprise Development Company LP
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

import random

from tempest.api.network import base
from tempest.common import utils
from tempest.lib.common.utils import test_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from nuage_tempest_plugin.lib.test.nuage_test import skip_because
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

CONF = Topology.get_conf()


def trunks_cleanup(client, trunks):
    for trunk in trunks:
        subports = test_utils.call_and_ignore_notfound_exc(
            client.get_subports, trunk['id'])
        if subports:
            client.remove_subports(
                trunk['id'], subports['sub_ports'])
        test_utils.call_and_ignore_notfound_exc(
            client.delete_trunk, trunk['id'])


class TrunkTestJSONBase(base.BaseAdminNetworkTest):

    required_extensions = ['trunk']

    def setUp(self):
        self.addCleanup(self.resource_cleanup)
        super(TrunkTestJSONBase, self).setUp()

    @classmethod
    def resource_setup(cls):
        super(TrunkTestJSONBase, cls).resource_setup()
        cls.trunks = []

    @classmethod
    def resource_cleanup(cls):
        trunks_cleanup(cls.client, cls.trunks)
        super(TrunkTestJSONBase, cls).resource_cleanup()

    @classmethod
    def setup_clients(cls):
        super(TrunkTestJSONBase, cls).setup_clients()
        cls.client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)

    def _create_trunk_with_network_and_parent(self, subports,
                                              create_subnet=True, **kwargs):
        network = self.create_network()
        if create_subnet:
            self.create_subnet(network)
        port_data = {}
        parent_port = self.create_port(network, **port_data)
        trunk = self.client.create_trunk(parent_port['id'], subports, **kwargs)
        self.trunks.append(trunk['trunk'])
        return trunk

    @classmethod
    def create_port(cls, network, **kwargs):
        if CONF.network.port_vnic_type and 'binding:vnic_type' not in kwargs:
            kwargs['binding:vnic_type'] = CONF.network.port_vnic_type
        if CONF.network.port_profile and 'binding:profile' not in kwargs:
            kwargs['binding:profile'] = CONF.network.port_profile
        return super(TrunkTestJSONBase, cls).create_port(network,
                                                         **kwargs)

    def _create_port_for_trunk(self):
        network = self.create_network()
        self.create_subnet(network)
        port_data = {}
        port = self.create_port(network, **port_data)
        return port

    def _show_trunk(self, trunk_id):
        return self.client.show_trunk(trunk_id)

    def _list_trunks(self):
        return self.client.list_trunks()


class TrunkTestJSON(TrunkTestJSONBase):

    @decorators.attr(type='smoke')
    def _test_create_trunk(self, subports):
        trunk = self._create_trunk_with_network_and_parent(subports)
        observed_trunk = self._show_trunk(trunk['trunk']['id'])
        self.assertEqual(trunk, observed_trunk)

    @staticmethod
    def _get_random_mac(base_mac):
        mac = [int(base_mac[0], 16), int(base_mac[1], 16),
               int(base_mac[2], 16), random.randint(0x00, 0xff),
               random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
        if base_mac[3] != '00':
            mac[3] = int(base_mac[3], 16)
        return ':'.join(["%02x" % x for x in mac])

    @decorators.attr(type='smoke')
    def test_create_trunk_empty_subports_list(self):
        self._test_create_trunk([])

    def test_create_trunk_subports_not_specified(self):
        self._test_create_trunk(None)

    @decorators.attr(type='smoke')
    def test_create_show_delete_trunk(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        trunk_id = trunk['trunk']['id']
        parent_port_id = trunk['trunk']['port_id']
        res = self._show_trunk(trunk_id)
        self.assertEqual(trunk_id, res['trunk']['id'])
        self.assertEqual(parent_port_id, res['trunk']['port_id'])
        self.client.delete_trunk(trunk_id)
        self.assertRaises(lib_exc.NotFound, self._show_trunk, trunk_id)

    @utils.requires_ext(extension="project-id", service="network")
    def test_show_trunk_has_project_id(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        body = self._show_trunk(trunk['trunk']['id'])
        show_trunk = body['trunk']
        self.assertIn('project_id', show_trunk)
        self.assertIn('tenant_id', show_trunk)
        self.assertEqual(self.client.tenant_id, show_trunk['project_id'])
        self.assertEqual(self.client.tenant_id, show_trunk['tenant_id'])

    @decorators.attr(type='smoke')
    def test_create_update_trunk(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        rev = trunk['trunk']['revision_number']
        trunk_id = trunk['trunk']['id']
        res = self._show_trunk(trunk_id)
        self.assertTrue(res['trunk']['admin_state_up'])
        self.assertEqual(rev, res['trunk']['revision_number'])
        self.assertEqual("", res['trunk']['name'])
        self.assertEqual("", res['trunk']['description'])
        res = self.client.update_trunk(
            trunk_id, name='foo', admin_state_up=False)
        self.assertFalse(res['trunk']['admin_state_up'])
        self.assertEqual("foo", res['trunk']['name'])
        self.assertGreater(res['trunk']['revision_number'], rev)
        # enable the trunk so that it can be managed
        self.client.update_trunk(trunk_id, admin_state_up=True)

    def test_create_update_trunk_with_description(self):
        trunk = self._create_trunk_with_network_and_parent(
            None, description="foo description")
        trunk_id = trunk['trunk']['id']
        self.assertEqual("foo description", trunk['trunk']['description'])
        trunk = self.client.update_trunk(trunk_id, description='')
        self.assertEqual('', trunk['trunk']['description'])

    def test_list_trunks(self):
        trunk1 = self._create_trunk_with_network_and_parent(None)
        trunk2 = self._create_trunk_with_network_and_parent(None)
        expected_trunks = {trunk1['trunk']['id']: trunk1['trunk'],
                           trunk2['trunk']['id']: trunk2['trunk']}
        trunk_list = self._list_trunks()['trunks']
        matched_trunks = [x for x in trunk_list if x['id'] in expected_trunks]
        self.assertEqual(2, len(matched_trunks))
        for trunk in matched_trunks:
            self.assertEqual(expected_trunks[trunk['id']], trunk)

    @decorators.attr(type='smoke')
    def test_add_subport(self):
        trunk = self._create_trunk_with_network_and_parent([])
        port = self._create_port_for_trunk()
        subports = [{'port_id': port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]
        self.client.add_subports(trunk['trunk']['id'], subports)
        trunk = self._show_trunk(trunk['trunk']['id'])
        observed_subports = trunk['trunk']['sub_ports']
        self.assertEqual(1, len(observed_subports))
        created_subport = observed_subports[0]
        self.assertEqual(subports[0], created_subport)

    def test_delete_trunk_with_subport_is_allowed(self):
        port = self._create_port_for_trunk()
        subports = [{'port_id': port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]
        trunk = self._create_trunk_with_network_and_parent(subports)
        self.client.delete_trunk(trunk['trunk']['id'])

    @decorators.attr(type='smoke')
    def test_remove_subport(self):
        subport_parent1 = self._create_port_for_trunk()
        subport_parent2 = self._create_port_for_trunk()
        subports = [{'port_id': subport_parent1['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2},
                    {'port_id': subport_parent2['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 4}]
        trunk = self._create_trunk_with_network_and_parent(subports)
        removed_subport = trunk['trunk']['sub_ports'][0]
        expected_subport = None

        for subport in subports:
            if subport['port_id'] != removed_subport['port_id']:
                expected_subport = subport
                break

        # Remove the subport and validate PUT response
        res = self.client.remove_subports(trunk['trunk']['id'],
                                          [removed_subport])
        self.assertEqual(1, len(res['sub_ports']))
        self.assertEqual(expected_subport, res['sub_ports'][0])

        # Validate the results of a subport list
        trunk = self._show_trunk(trunk['trunk']['id'])
        observed_subports = trunk['trunk']['sub_ports']
        self.assertEqual(1, len(observed_subports))
        self.assertEqual(expected_subport, observed_subports[0])

    def test_get_subports(self):
        port = self._create_port_for_trunk()
        subports = [{'port_id': port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]
        trunk = self._create_trunk_with_network_and_parent(subports)
        trunk = self.client.get_subports(trunk['trunk']['id'])
        observed_subports = trunk['sub_ports']
        self.assertEqual(1, len(observed_subports))

    @skip_because(bug='VSD-27414')
    def test_update_subport(self):
        port = self._create_port_for_trunk()
        subports = [{'port_id': port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]
        trunk = self._create_trunk_with_network_and_parent(subports)
        mac = self._get_random_mac('fa:16:3e:00:00:00'.split(':'))
        update_data = {'mac_address': mac}
        updated_port = self.admin_ports_client.update_port(port['id'],
                                                           **update_data)
        observed_subports = trunk['trunk']['sub_ports']
        self.assertEqual(1, len(observed_subports))
        self.assertEqual(updated_port['port']['mac_address'], mac)


class TrunkTestJSONV6(TrunkTestJSON):
    _ip_version = 6

    @classmethod
    def skip_checks(cls):
        super(TrunkTestJSONV6, cls).skip_checks()
        if not Topology.has_single_stack_v6_support():
            msg = 'There is no single-stack v6 support in current release'
            raise cls.skipException(msg)
