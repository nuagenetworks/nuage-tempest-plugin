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

from oslo_utils import uuidutils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.tests.api import test_trunk


class TrunkTestJSON(test_trunk.TrunkTestJSONBase):

    @decorators.attr(type='negative')
    def test_create_trunk_nonexistent_port_id(self):
        self.assertRaises(lib_exc.NotFound, self.client.create_trunk,
                          uuidutils.generate_uuid(), [])

    @decorators.attr(type='negative')
    def test_create_trunk_nonexistent_subport_port_id(self):
        parent_port = self._create_port_for_trunk()
        self.assertRaises(lib_exc.NotFound, self.client.create_trunk,
                          parent_port['id'],
                          [{'port_id': uuidutils.generate_uuid(),
                            'segmentation_type': 'vlan',
                            'segmentation_id': 2}])

    @decorators.attr(type='negative')
    def test_create_subport_nonexistent_port_id(self):
        trunk = self._create_trunk_with_network_and_parent([])
        self.assertRaises(lib_exc.NotFound, self.client.add_subports,
                          trunk['trunk']['id'],
                          [{'port_id': uuidutils.generate_uuid(),
                            'segmentation_type': 'vlan',
                            'segmentation_id': 2}])

    @decorators.attr(type='negative')
    def test_create_subport_nonexistent_trunk(self):
        parent_port = self._create_port_for_trunk()
        self.assertRaises(lib_exc.NotFound, self.client.add_subports,
                          uuidutils.generate_uuid(),
                          [{'port_id': parent_port['id'],
                            'segmentation_type': 'vlan',
                            'segmentation_id': 2}])

    @decorators.attr(type='negative')
    def test_create_subport_missing_segmentation_id(self):
        trunk = self._create_trunk_with_network_and_parent([])
        parent_port = self._create_port_for_trunk()
        self.assertRaises(lib_exc.BadRequest, self.client.add_subports,
                          trunk['trunk']['id'],
                          [{'port_id': parent_port['id'],
                            'segmentation_type': 'vlan'}])

    @decorators.attr(type='negative')
    def test_create_trunk_with_subport_missing_segmentation_id(self):
        parent_port = self._create_port_for_trunk()
        self.assertRaises(lib_exc.BadRequest, self.client.create_trunk,
                          parent_port['id'],
                          [{'port_id': uuidutils.generate_uuid(),
                            'segmentation_type': 'vlan'}])

    @decorators.attr(type='negative')
    def test_create_trunk_with_subport_missing_segmentation_type(self):
        parent_port = self._create_port_for_trunk()
        self.assertRaises(lib_exc.BadRequest, self.client.create_trunk,
                          parent_port['id'],
                          [{'port_id': uuidutils.generate_uuid(),
                            'segmentation_id': 3}])

    @decorators.attr(type='negative')
    def test_create_trunk_with_subport_missing_port_id(self):
        parent_port = self._create_port_for_trunk()
        self.assertRaises(lib_exc.BadRequest, self.client.create_trunk,
                          parent_port['id'],
                          [{'segmentation_type': 'vlan',
                            'segmentation_id': 3}])

    @decorators.attr(type='negative')
    def test_create_subport_invalid_inherit_network_segmentation_type(self):
        trunk = self._create_trunk_with_network_and_parent([])
        parent_port = self._create_port_for_trunk()
        self.assertRaises(lib_exc.BadRequest, self.client.add_subports,
                          trunk['trunk']['id'],
                          [{'port_id': parent_port['id'],
                            'segmentation_type': 'inherit',
                            'segmentation_id': -1}])

    @decorators.attr(type='negative')
    def test_create_trunk_duplicate_subport_segmentation_ids(self):
        trunk = self._create_trunk_with_network_and_parent([])
        parent_port1 = self._create_port_for_trunk()
        parent_port2 = self._create_port_for_trunk()
        self.assertRaises(lib_exc.BadRequest, self.client.create_trunk,
                          trunk['trunk']['id'],
                          [{'port_id': parent_port1['id'],
                            'segmentation_id': 2,
                            'segmentation_type': 'vlan'},
                           {'port_id': parent_port2['id'],
                            'segmentation_id': 2,
                            'segmentation_type': 'vlan'}])

    @decorators.attr(type='negative')
    def test_add_subport_port_id_uses_trunk_port_id(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        self.assertRaises(lib_exc.Conflict, self.client.add_subports,
                          trunk['trunk']['id'],
                          [{'port_id': trunk['trunk']['port_id'],
                            'segmentation_type': 'vlan',
                            'segmentation_id': 2}])

    @decorators.attr(type='negative')
    def test_add_subport_port_id_disabled_trunk(self):
        trunk = self._create_trunk_with_network_and_parent(
            None, admin_state_up=False)
        self.assertRaises(lib_exc.Conflict,
                          self.client.add_subports,
                          trunk['trunk']['id'],
                          [{'port_id': trunk['trunk']['port_id'],
                            'segmentation_type': 'vlan',
                            'segmentation_id': 2}])
        self.client.update_trunk(
            trunk['trunk']['id'], admin_state_up=True)

    @decorators.attr(type='negative')
    def test_remove_subport_port_id_disabled_trunk(self):
        trunk = self._create_trunk_with_network_and_parent(
            None, admin_state_up=False)
        self.assertRaises(lib_exc.Conflict,
                          self.client.remove_subports,
                          trunk['trunk']['id'],
                          [{'port_id': trunk['trunk']['port_id'],
                            'segmentation_type': 'vlan',
                            'segmentation_id': 2}])
        self.client.update_trunk(
            trunk['trunk']['id'], admin_state_up=True)

    @decorators.attr(type='negative')
    def test_delete_trunk_disabled_trunk(self):
        trunk = self._create_trunk_with_network_and_parent(
            None, admin_state_up=False)
        self.assertRaises(lib_exc.Conflict,
                          self.client.delete_trunk,
                          trunk['trunk']['id'])
        self.client.update_trunk(
            trunk['trunk']['id'], admin_state_up=True)

    @decorators.attr(type='negative')
    def test_add_subport_duplicate_segmentation_details(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        parent_port1 = self._create_port_for_trunk()
        parent_port2 = self._create_port_for_trunk()
        self.client.add_subports(trunk['trunk']['id'],
                                 [{'port_id': parent_port1['id'],
                                   'segmentation_type': 'vlan',
                                   'segmentation_id': 2}])
        self.assertRaises(lib_exc.Conflict, self.client.add_subports,
                          trunk['trunk']['id'],
                          [{'port_id': parent_port2['id'],
                            'segmentation_type': 'vlan',
                            'segmentation_id': 2}])

    @decorators.attr(type='negative')
    def test_add_subport_passing_dict(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        self.assertRaises(lib_exc.BadRequest, self.client.add_subports,
                          trunk['trunk']['id'],
                          {'port_id': trunk['trunk']['port_id'],
                           'segmentation_type': 'vlan',
                           'segmentation_id': 2})

    @decorators.attr(type='negative')
    def test_remove_subport_passing_dict(self):
        parent_port = self._create_port_for_trunk()
        subport_data = {'port_id': parent_port['id'],
                        'segmentation_type': 'vlan',
                        'segmentation_id': 2}
        trunk = self._create_trunk_with_network_and_parent([subport_data])
        self.assertRaises(lib_exc.BadRequest, self.client.remove_subports,
                          trunk['trunk']['id'], subport_data)

    @decorators.attr(type='negative')
    def test_remove_subport_not_found(self):
        parent_port = self._create_port_for_trunk()
        subport_data = {'port_id': parent_port['id'],
                        'segmentation_type': 'vlan',
                        'segmentation_id': 2}
        trunk = self._create_trunk_with_network_and_parent([])
        self.assertRaises(lib_exc.NotFound, self.client.remove_subports,
                          trunk['trunk']['id'], [subport_data])

    @decorators.attr(type='negative')
    def test_delete_port_in_use_by_trunk(self):
        trunk = self._create_trunk_with_network_and_parent(None)
        self.assertRaises(lib_exc.Conflict, self.client.delete_port,
                          trunk['trunk']['port_id'])

    @decorators.attr(type='negative')
    def test_delete_port_in_use_by_subport(self):
        port = self._create_port_for_trunk()
        subports = [{'port_id': port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]
        self._create_trunk_with_network_and_parent(subports)
        self.assertRaises(lib_exc.Conflict, self.client.delete_port,
                          port['id'])

    @decorators.attr(type='negative')
    def test_create_trunk_without_fixed_ip(self):
        self.assertRaises(
            lib_exc.BadRequest,
            self._create_trunk_with_network_and_parent,
            None,
            create_subnet=False)

    @decorators.attr(type='negative')
    def test_add_subport_without_fixed_ip(self):
        trunk = self._create_trunk_with_network_and_parent([])
        network = self.create_network()
        port_data = {}
        port = self.create_port(network, **port_data)
        subports = [{'port_id': port['id'],
                     'segmentation_type': 'vlan',
                     'segmentation_id': 2}]
        self.assertRaises(
            lib_exc.BadRequest,
            self.client.add_subports,
            trunk['trunk']['id'],
            subports)


class TrunkTestJSONV6(TrunkTestJSON):
    _ip_version = 6

    @classmethod
    def skip_checks(cls):
        super(TrunkTestJSONV6, cls).skip_checks()
        if not Topology.has_single_stack_v6_support():
            msg = 'No single-stack v6 support.'
            raise cls.skipException(msg)
