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

from tempest.lib import exceptions

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology

LOG = Topology.get_logger(__name__)


class NuageExtSecGroup(nuage_test.NuageBaseTest):

    if Topology.from_nuage('20.5'):
        expected_exception_from_topology = exceptions.BadRequest
    else:
        expected_exception_from_topology = exceptions.ServerFault

    @classmethod
    def resource_setup(cls):
        super(NuageExtSecGroup, cls).resource_setup()
        cls.network = cls.create_cls_network()
        cls.subnet4 = cls.create_cls_subnet(cls.network, ip_version=4)
        cls.subnet6 = cls.create_cls_subnet(cls.network, ip_version=6)
        cls.router = cls.create_cls_router()
        cls.router_cls_attach(cls.router, cls.subnet4)
        cls.router_cls_attach(cls.router, cls.subnet6)
        cls.domain = cls.vsd.get_l3_domain_by_subnet(cls.subnet4)

    def _create_external_security_group(self, cleanup=True, **kwargs):
        body = self.plugin_network_client.create_nuage_external_security_group(
            **kwargs)
        ext_sg = body['nuage_external_security_group']
        if cleanup:
            self.addCleanup(self._delete_external_security_group,
                            ext_sg['id'])
        return ext_sg

    def _delete_external_security_group(self, esg_id):
        self.plugin_network_client.delete_nuage_external_security_group(esg_id)

    def _create_external_security_group_rule(self, **kwargs):
        body = (self.plugin_network_client.
                create_nuage_external_security_group_rule(**kwargs))
        ext_sg_rule = body['nuage_external_security_group_rule']
        return ext_sg_rule

    def _verify_external_secgroup_properties(self, actual_esg,
                                             vsd_pg):
        self.assertEqual(actual_esg['name'], vsd_pg.name)
        self.assertEqual(actual_esg['extended_community_id'],
                         vsd_pg.evpn_community_tag)
        self.assertEqual(actual_esg['id'], vsd_pg.id)

    def _verify_external_secgroup_rule_properties(self, actual_esgr,
                                                  vsd_pg, origin_sg):
        self.assertEqual(actual_esgr['id'], vsd_pg.id)
        self.assertEqual(actual_esgr['protocol'], vsd_pg.protocol)
        self.assertEqual(actual_esgr['origin_group_id'], origin_sg['id'])

    def _get_nuage_external_acl(self, ext_sg_rule=None):
        if ext_sg_rule:
            template = self.vsd.vspk.NUEgressACLEntryTemplate(
                id=ext_sg_rule['id'])
            template.fetch()
            return template
        else:
            return self.domain.egress_acl_entry_templates.get()

    def test_create_show_list_delete_ext_secgroup(self):
        name = self.get_randomized_name()
        kwargs = {'name': name,
                  'router_id': self.router['id'],
                  'extended_community_id': "1:1"}
        ext_sg = self._create_external_security_group(**kwargs)
        self.assertEqual(ext_sg['name'], name)
        self.assertEqual(ext_sg['extended_community_id'],
                         "1:1")
        # VSD verification of external security group
        ext_pg = self.vsd.vspk.NUPolicyGroup(id=ext_sg['id'])
        ext_pg.fetch()
        show_resp = (self.plugin_network_client.
                     show_nuage_external_security_group(ext_sg['id']))
        self._verify_external_secgroup_properties(
            show_resp['nuage_external_security_group'],
            ext_pg)
        router_ext_id = self.vsd.external_id(self.router['id'])
        self.assertEqual(router_ext_id, ext_pg.external_id)
        # list_external_security_group
        list_resp = (self.plugin_network_client.
                     list_nuage_external_security_group(self.router['id']))
        self._verify_external_secgroup_properties(
            list_resp['nuage_external_security_groups'][0],
            ext_pg)

    def test_create_show_list_delete_ext_secgroup_rule(self):
        sec_group = self.create_security_group()
        name = self.get_randomized_name()
        kwargs = {'name': name,
                  'router_id': self.router['id'],
                  'extended_community_id': "1:1"}
        ext_sg = self._create_external_security_group(**kwargs)
        kwargs = {'protocol': 'tcp',
                  'direction': 'egress',
                  'origin_group_id': sec_group['id'],
                  'remote_external_group_id': ext_sg['id']}
        ext_sg_rule = self._create_external_security_group_rule(**kwargs)
        # Show operation and VSD verification of external security group
        show_resp = (
            self.plugin_network_client.
            show_nuage_external_security_group_rule(ext_sg_rule['id']))
        show_vsd_resp = self._get_nuage_external_acl(ext_sg_rule)
        self._verify_external_secgroup_rule_properties(
            show_resp['nuage_external_security_group_rule'],
            show_vsd_resp, sec_group)

        # Create second rule
        kwargs = {'protocol': 'udp',
                  'port_range_min': 300,
                  'port_range_max': 500,
                  'direction': 'egress',
                  'origin_group_id': sec_group['id'],
                  'remote_external_group_id': ext_sg['id']}
        self._create_external_security_group_rule(**kwargs)

        # Create third rule
        kwargs = {'protocol': 'vrrp',
                  'direction': 'egress',
                  'origin_group_id': sec_group['id'],
                  'remote_external_group_id': ext_sg['id']}
        self._create_external_security_group_rule(**kwargs)

        # List Operation on secgroup rules
        list_resp = (self.plugin_network_client.
                     list_nuage_external_security_group_rule(
                         ext_sg['id'])['nuage_external_security_group_rules'])

        list_vsd_resp = self._get_nuage_external_acl()
        for resp, vsd_resp in zip(list_resp, list_vsd_resp):
            self._verify_external_secgroup_rule_properties(
                resp, vsd_resp, sec_group)
        router_ext_id = self.vsd.external_id(self.router['id'])
        for vsd_resp in list_vsd_resp:
            self.assertEqual(router_ext_id, vsd_resp.external_id)

    def test_create_show_list_delete_ext_secgroup_l2domain(self):
        network = self.create_network()
        esg_subnet = self.create_subnet(network)
        name = self.get_randomized_name()
        kwargs = {'name': name,
                  'subnet_id': esg_subnet['id'],
                  'extended_community_id': "4:4"}
        ext_sg = self._create_external_security_group(**kwargs)
        self.assertEqual(ext_sg['name'], name)
        self.assertEqual(ext_sg['extended_community_id'],
                         "4:4")
        # VSD verification of external security group
        ext_pg = self.vsd.vspk.NUPolicyGroup(id=ext_sg['id'])
        ext_pg.fetch()
        show_resp = (self.plugin_network_client.
                     show_nuage_external_security_group(ext_sg['id']))
        self._verify_external_secgroup_properties(
            show_resp['nuage_external_security_group'],
            ext_pg)
        subnet_ext_id = self.vsd.external_id(esg_subnet['id'])
        self.assertEqual(subnet_ext_id, ext_pg.external_id)

        # list_external_security_group
        list_resp = (
            self.plugin_network_client.
            list_nuage_external_security_group_l2domain(esg_subnet['id']))
        self._verify_external_secgroup_properties(
            list_resp['nuage_external_security_groups'][0],
            ext_pg)

    def test_create_delete_invalid_ext_secgroup(self):
        name = self.get_randomized_name()
        # Missing pararmeter: external_communtiy_tag in input
        kwargs = {'name': name,
                  'router_id': self.router['id']}
        self.assertRaises(
            exceptions.BadRequest,
            self.plugin_network_client.create_nuage_external_security_group,
            **kwargs)
        # Invalid external_communtiy_tag_value
        kwargs = {'name': name,
                  'router_id': self.router['id'],
                  'extended_community_id': "4"}
        self.assertRaises(
            self.expected_exception_from_topology,
            self.plugin_network_client.create_nuage_external_security_group,
            **kwargs)
        # Missing pararmeter: router/subnet ID in input
        kwargs = {'name': name,
                  'router_id': '11111111-1111-1111-1111111111111111',
                  'extended_community_id': "2:2"}
        self.assertRaises(
            exceptions.BadRequest,
            self.plugin_network_client.create_nuage_external_security_group,
            **kwargs)
        # Try deleting invalid external_secgroup
        self.assertRaises(
            exceptions.NotFound,
            self.plugin_network_client.delete_nuage_external_security_group,
            '11111111-1111-1111-1111111111111111')

    def test_create_delete_invalid_ext_secgroup_rule(self):
        sec_group = self.create_security_group()
        name = self.get_randomized_name()
        kwargs = {'name': name,
                  'router_id': self.router['id'],
                  'extended_community_id': "1:1"}
        ext_sg = self._create_external_security_group(**kwargs)
        # Missing mandatory parameter: origin_group_id in input
        kwargs = {'protocol': 'tcp',
                  'direction': 'egress',
                  'remote_external_group_id': ext_sg['id']}
        self.assertRaises(
            self.expected_exception_from_topology,
            self.plugin_network_client.
            create_nuage_external_security_group_rule,
            **kwargs)
        # Invalid remote_group_id value
        kwargs = {'protocol': 'tcp',
                  'direction': 'egress',
                  'origin_group_id': sec_group['id'],
                  'remote_external_group_id':
                  '11111111-1111-1111-1111111111111111'}
        self.assertRaises(
            self.expected_exception_from_topology,
            self.plugin_network_client.
            create_nuage_external_security_group_rule,
            **kwargs)
        # Try deleting invalid external_secgroup_rule
        self.assertRaises(
            exceptions.NotFound,
            self.plugin_network_client.
            delete_nuage_external_security_group_rule,
            '11111111-1111-1111-1111111111111111')
