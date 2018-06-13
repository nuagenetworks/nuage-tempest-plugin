# Copyright 2014 OpenStack Foundation
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

import six

from tempest.api.network import base
from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc
from tempest.test import decorators

from nuage_tempest_plugin.lib.test import vsd_helper
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.fwaas import fwaas_mixins
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

CONF = Topology.get_conf()


class BaseFWaaSTest(fwaas_mixins.FWaaSClientMixin, base.BaseNetworkTest):

    credentials = ['primary', 'admin']

    @classmethod
    def resource_setup(cls):
        cls.nuage_ent_client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)
        super(BaseFWaaSTest, cls).resource_setup()
        cls.def_net_partition = Topology.def_netpartition


class FWaaSExtensionTestJSON(BaseFWaaSTest):

    """Tests the following operations in Neutron API using Neutron REST client

        List firewall rules
        Create firewall rule
        Update firewall rule
        Delete firewall rule
        Show firewall rule
        List firewall policies
        Create firewall policy
        Update firewall policy
        Insert firewall rule to policy
        Remove firewall rule from policy
        Insert firewall rule after/before rule in policy
        Update firewall policy audited attribute
        Delete firewall policy
        Show firewall policy
        List firewall
        Create firewall
        Update firewall
        Delete firewall
        Show firewall
    """

    @classmethod
    def resource_setup(cls):
        super(FWaaSExtensionTestJSON, cls).resource_setup()
        if not utils.is_extension_enabled('fwaas', 'network'):
            msg = "FWaaS Extension not enabled."
            raise cls.skipException(msg)

    def setUp(self):
        super(FWaaSExtensionTestJSON, self).setUp()
        self.fw_rule = self.create_firewall_rule(
            name='fw-rule-1',
            action="allow",
            protocol="tcp",
            source_port=1000,
            destination_port=1000,
            source_ip_address='1.1.1.1/32',
            destination_ip_address='2.2.2.2/32')
        self.fw_policy = self.create_firewall_policy(name='fw-policy-1')

    @classmethod
    def setup_clients(cls):
        super(FWaaSExtensionTestJSON, cls).setup_clients()
        cls.vsd = vsd_helper.VsdHelper()

    def _try_delete_policy(self, policy_id):
        # delete policy, if it exists
        try:
            self.firewall_policies_client.delete_firewall_policy(policy_id)
        # if policy is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def _try_delete_rule(self, rule_id):
        # delete rule, if it exists
        try:
            self.firewall_rules_client.delete_firewall_rule(rule_id)
        # if rule is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

    def _try_delete_firewall(self, fw_id):
        # delete firewall, if it exists
        try:
            self.firewalls_client.delete_firewall(fw_id)
        # if firewall is not found, this means it was deleted in the test
        except lib_exc.NotFound:
            pass

        self.firewalls_client.wait_for_resource_deletion(fw_id)

    def _verify_fw_rule(self, firewall_acl_os, firewall_acl_vsd):

        VSD_TO_OS_ACTION = {
            'allow': "FORWARD",
            'deny': "DROP"
        }

        firewall_acl_vsd = firewall_acl_vsd.to_dict()
        # Protocol and externalID cannot be verified VSD-18219
        self.assertEqual(firewall_acl_os['name'],
                         firewall_acl_vsd['description'])
        if firewall_acl_os['action'] == "allow":
            self.assertEqual(firewall_acl_vsd['stateful'], True)
        else:
            self.assertEqual(firewall_acl_vsd['stateful'], False)
        if firewall_acl_vsd['sourcePort']:
            firewall_acl_vsd['sourcePort'] = \
                firewall_acl_vsd['sourcePort'].replace('-', ':')
        if firewall_acl_vsd['destinationPort']:
            firewall_acl_vsd['destinationPort'] = \
                firewall_acl_vsd['destinationPort'].replace('-', ':')
        self.assertEqual(firewall_acl_os['source_port'],
                         firewall_acl_vsd['sourcePort'])
        self.assertEqual(firewall_acl_os['destination_port'],
                         firewall_acl_vsd['destinationPort'])
        self.assertEqual(firewall_acl_os['source_ip_address'],
                         firewall_acl_vsd['addressOverride'])
        self.assertEqual(firewall_acl_os['destination_ip_address'],
                         firewall_acl_vsd['networkID'])
        self.assertEqual(VSD_TO_OS_ACTION.get(firewall_acl_os['action']),
                         firewall_acl_vsd['action'])
        if firewall_acl_os['firewall_policy_id'] is not None:
            self.assertEqual(firewall_acl_vsd['associatedfirewallACLID'],
                             not None)

    def _wait_until_ready(self, fw_id):
        target_states = ('ACTIVE', 'CREATED')

        def _wait():
            firewall = self.firewalls_client.show_firewall(fw_id)
            firewall = firewall['firewall']
            return firewall['status'] in target_states

        if not test_utils.call_until_true(
                _wait, CONF.network.build_timeout,
                CONF.network.build_interval):
            m = ("Timed out waiting for firewall %s to reach %s state(s)" %
                 (fw_id, target_states))
            raise lib_exc.TimeoutException(m)

    @decorators.idempotent_id('1b84cf01-9c09-4ce7-bc72-b15e39076468')
    def test_list_firewall_rules(self):
        # List firewall rules
        fw_rules = self.firewall_rules_client.list_firewall_rules()
        fw_rules = fw_rules['firewall_rules']
        self.assertIn((self.fw_rule['id'],
                       self.fw_rule['name'],
                       self.fw_rule['action'],
                       self.fw_rule['protocol'],
                       self.fw_rule['ip_version'],
                       self.fw_rule['enabled']),
                      [(m['id'],
                        m['name'],
                        m['action'],
                        m['protocol'],
                        m['ip_version'],
                        m['enabled']) for m in fw_rules])

        vsd_acl = self.vsd.get_firewall_rule(
            by_fw_rule_id=fw_rules[0]['id'])
        self._verify_fw_rule(fw_rules[0], vsd_acl)

    @decorators.idempotent_id('563564f7-7077-4f5e-8cdc-51f37ae5a2b9')
    def test_create_update_delete_firewall_rule(self):
        # Create firewall rule
        body = self.firewall_rules_client.create_firewall_rule(
            name='fw-rule-2',
            action="allow",
            protocol="tcp")
        fw_rule_id = body['firewall_rule']['id']
        vsd_acl = self.vsd.get_firewall_rule(by_fw_rule_id=fw_rule_id)
        self._verify_fw_rule(body['firewall_rule'], vsd_acl)

        # Update firewall rule
        body = self.firewall_rules_admin_client.update_firewall_rule(
            fw_rule_id,
            shared=True,
            source_port=1000,
            destination_port=1000,
            source_ip_address='1.1.1.1/32',
            destination_ip_address='2.2.2.2/32')

        self.assertTrue(body["firewall_rule"]['shared'])

        vsd_acl = self.vsd.get_firewall_rule(by_fw_rule_id=fw_rule_id)
        self._verify_fw_rule(body['firewall_rule'], vsd_acl)

        # Delete firewall rule
        self.firewall_rules_client.delete_firewall_rule(fw_rule_id)
        # Confirm deletion
        fw_rules = self.firewall_rules_client.list_firewall_rules()
        self.assertNotIn(fw_rule_id,
                         [m['id'] for m in fw_rules['firewall_rules']])

    def test_create_update_delete_firewall_rule_all_attributes(self):
        # Create firewall rule
        body = self.firewall_rules_client.create_firewall_rule(
            name='fw-rule-3',
            action="allow",
            protocol="tcp")
        fw_rule_id = body['firewall_rule']['id']
        vsd_acl = self.vsd.get_firewall_rule(by_fw_rule_id=fw_rule_id)
        self._verify_fw_rule(body['firewall_rule'], vsd_acl)

        # Update firewall rule
        updated_dict = {'action': 'deny',
                        'protocol': 'udp',
                        'source_ip_address': '1.1.1.6/32',
                        'destination_ip_address': "2.2.2.6/32",
                        'source_port': "3000:4000",
                        'destination_port': "3000:4000"}
        body = self.firewall_rules_client.update_firewall_rule(fw_rule_id,
                                                               **updated_dict)
        rule = body['firewall_rule']

        vsd_acl = self.vsd.get_firewall_rule(by_fw_rule_id=fw_rule_id)
        self._verify_fw_rule(rule, vsd_acl)

        self.assertEqual((updated_dict['action'],
                          updated_dict['protocol'],
                          updated_dict['source_ip_address'],
                          updated_dict['destination_ip_address'],
                          updated_dict['source_port'],
                          updated_dict['destination_port']),
                         (str(rule['action']),
                          str(rule['protocol']),
                          str(rule['source_ip_address']),
                          str(rule['destination_ip_address']),
                          str(rule['source_port']),
                          str(rule['destination_port'])))

        # Delete firewall rule
        self.firewall_rules_client.delete_firewall_rule(fw_rule_id)
        # Confirm deletion
        fw_rules = self.firewall_rules_client.list_firewall_rules()
        self.assertNotIn(fw_rule_id,
                         [m['id'] for m in fw_rules['firewall_rules']])

    def test_create_invalid_protocol_firewall_rules(self):
        self.assertRaisesRegex(
            lib_exc.BadRequest,
            "port are not allowed when protocol is set to ICMP",
            self.firewall_rules_client.create_firewall_rule,
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol=None,
            source_ip_address="1.1.1.6/32",
            destination_ip_address="2.2.2.6/32",
            source_port="3000:4000",
            destination_port="3000:4000")

    def test_create_invalid_port_firewall_rules(self):
        self.assertRaisesRegex(
            lib_exc.BadRequest,
            "Invalid input for destination_port",
            self.firewall_rules_client.create_firewall_rule,
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol='tcp',
            source_ip_address="1.1.1.6/32",
            destination_ip_address="2.2.2.6/32",
            source_port="3000:4000",
            destination_port="-1:-2")

    def test_create_firewall_rule_different_protocol_types_and_actions(self):
        # Create firewall rule with udp, icmp, any
        all_rules = []
        body = self.firewall_rules_client.create_firewall_rule(
            name='fw-rule-4',
            action="allow",
            protocol=None)
        all_rules.append(body['firewall_rule'])

        body = self.firewall_rules_client.create_firewall_rule(
            name='fw-rule-5',
            action="deny",
            protocol="icmp")
        all_rules.append(body['firewall_rule'])

        body = self.firewall_rules_client.create_firewall_rule(
            name='fw-rule-6',
            action="allow",
            protocol="udp",
            source_ip_address="1.1.1.5/32",
            destination_ip_address="2.2.2.5/32",
            source_port="1000:2000",
            destination_port="1000:2000")
        all_rules.append(body['firewall_rule'])

        body = self.firewall_rules_client.create_firewall_rule(
            name='fw-rule-7',
            action="allow",
            protocol='tcp',
            source_ip_address="1.1.1.6/32",
            destination_ip_address="2.2.2.6/32",
            source_port="3000:4000",
            destination_port="3000:4000")
        all_rules.append(body['firewall_rule'])

        # Verify
        fw_rules = self.firewall_rules_client.list_firewall_rules()
        fw_rules = fw_rules['firewall_rules']

        for rule in all_rules:
            self.assertIn((rule['id'],
                           rule['name'],
                           rule['action'],
                           rule['protocol'],
                           rule['ip_version'],
                           rule['enabled']),
                          [(m['id'],
                            m['name'],
                            m['action'],
                            m['protocol'],
                            m['ip_version'],
                            m['enabled']) for m in fw_rules])

        for rule in all_rules:
            vsd_acl = self.vsd.get_firewall_rule(by_fw_rule_id=rule['id'])
            self._verify_fw_rule(rule, vsd_acl)

        # Delete all rules
        for rule in all_rules:
            self.firewall_rules_client.delete_firewall_rule(rule['id'])

    def test_create_invalid_cidr_firewall_rule(self):
        self.assertRaisesRegex(
            lib_exc.BadRequest,
            "Invalid input for source_ip_address",
            self.firewall_rules_client.create_firewall_rule,
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol='tcp',
            source_ip_address="300.300.300.300/32",
            destination_ip_address="2.2.2.6/32",
            source_port="3000:4000",
            destination_port="3000:4000")

    @decorators.idempotent_id('3ff8c08e-26ff-4034-ae48-810ed213a998')
    def test_show_firewall_rule(self):
        # show a created firewall rule
        fw_rule = self.firewall_rules_client.show_firewall_rule(
            self.fw_rule['id'])
        for key, value in six.iteritems(fw_rule['firewall_rule']):
            self.assertEqual(self.fw_rule[key], value)

    @decorators.idempotent_id('1086dd93-a4c0-4bbb-a1bd-6d4bc62c199f')
    def test_list_firewall_policies(self):
        fw_policies = self.firewall_policies_client.list_firewall_policies()
        fw_policies = fw_policies['firewall_policies']
        self.assertIn((self.fw_policy['id'],
                       self.fw_policy['name'],
                       self.fw_policy['firewall_rules']),
                      [(m['id'],
                        m['name'],
                        m['firewall_rules']) for m in fw_policies])

    @decorators.idempotent_id('bbf37b6c-498c-421e-9c95-45897d3ed775')
    def test_create_update_delete_firewall_policy(self):
        # Create firewall policy
        body = self.firewall_policies_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy_id = body['firewall_policy']['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id)

        # Update firewall policy
        body = self.firewall_policies_admin_client.update_firewall_policy(
            fw_policy_id,
            shared=True,
            name="updated_policy")
        updated_fw_policy = body["firewall_policy"]
        self.assertTrue(updated_fw_policy['shared'])
        self.assertEqual("updated_policy", updated_fw_policy['name'])

        # Delete firewall policy
        self.firewall_policies_client.delete_firewall_policy(fw_policy_id)
        # Confirm deletion
        fw_policies = self.firewall_policies_client.list_firewall_policies()
        fw_policies = fw_policies['firewall_policies']
        self.assertNotIn(fw_policy_id, [m['id'] for m in fw_policies])

    @decorators.idempotent_id('1df59b3a-517e-41d4-96f6-fc31cf4ecff2')
    def test_show_firewall_policy(self):
        # show a created firewall policy
        fw_policy = self.firewall_policies_client.show_firewall_policy(
            self.fw_policy['id'])
        fw_policy = fw_policy['firewall_policy']
        for key, value in six.iteritems(fw_policy):
            self.assertEqual(self.fw_policy[key], value)

    @decorators.idempotent_id('02082a03-3cdd-4789-986a-1327dd80bfb7')
    def test_create_show_delete_firewall(self):
        # Create tenant network resources required for an ACTIVE firewall
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(
            data_utils.rand_name('router-'),
            admin_state_up=True)
        self.routers_client.add_router_interface(router['id'],
                                                 subnet_id=subnet['id'])

        # Create firewall
        body = self.firewalls_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['id'])
        created_firewall = body['firewall']
        firewall_id = created_firewall['id']
        self.addCleanup(self._try_delete_firewall, firewall_id)

        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)

        # show a created firewall
        firewall = self.firewalls_client.show_firewall(firewall_id)
        firewall = firewall['firewall']

        for key, value in six.iteritems(firewall):
            if key == 'status':
                continue
            self.assertEqual(created_firewall[key], value)

        # list firewall
        firewalls = self.firewalls_client.list_firewalls()
        firewalls = firewalls['firewalls']
        self.assertIn((created_firewall['id'],
                       created_firewall['name'],
                       created_firewall['firewall_policy_id']),
                      [(m['id'],
                        m['name'],
                        m['firewall_policy_id']) for m in firewalls])

        # Delete firewall
        self.firewalls_client.delete_firewall(firewall_id)

    @decorators.idempotent_id('1355cf5c-77d4-4bb9-87d7-e50c194d08b5')
    def test_firewall_insertion_mode_add_remove_router(self):
        # Create routers
        router1 = self.create_router(
            data_utils.rand_name('router-'),
            admin_state_up=True)
        router2 = self.create_router(
            data_utils.rand_name('router-'),
            admin_state_up=True)

        # Create firewall on a router1
        body = self.firewalls_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['id'],
            router_ids=[router1['id']])
        created_firewall = body['firewall']
        firewall_id = created_firewall['id']
        self.addCleanup(self._try_delete_firewall, firewall_id)

        self.assertEqual([router1['id']], created_firewall['router_ids'])

        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)

        # Add router2 to the firewall
        body = self.firewalls_client.update_firewall(
            firewall_id, router_ids=[router1['id'], router2['id']])
        updated_firewall = body['firewall']
        self.assertIn(router2['id'], updated_firewall['router_ids'])
        self.assertEqual(2, len(updated_firewall['router_ids']))

        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)

        # Remove router1 from the firewall
        body = self.firewalls_client.update_firewall(
            firewall_id, router_ids=[router2['id']])
        updated_firewall = body['firewall']
        self.assertNotIn(router1['id'], updated_firewall['router_ids'])
        self.assertEqual(1, len(updated_firewall['router_ids']))

    @decorators.idempotent_id('c60ceff5-d51f-451d-b6e6-cb983d16ab6b')
    def test_firewall_insertion_mode_one_firewall_per_router(self):
        # Create router required for an ACTIVE firewall
        router = self.create_router(
            data_utils.rand_name('router1-'),
            admin_state_up=True)

        # Create firewall
        body = self.firewalls_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['id'],
            router_ids=[router['id']])
        created_firewall = body['firewall']
        self.addCleanup(self._try_delete_firewall, created_firewall['id'])

        # Try to create firewall with the same router
        self.assertRaisesRegex(
            lib_exc.Conflict,
            "Conflict with state of target resource",
            self.firewalls_client.create_firewall,
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['id'],
            router_ids=[router['id']])

    def test_firewall_add_remove_add_firewall_one_router(self):
        # Create router required for an ACTIVE firewall
        router = self.create_router(
            data_utils.rand_name('router1-'),
            admin_state_up=True)

        # Create firewall
        body = self.firewalls_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['id'],
            router_ids=[router['id']])
        created_firewall = body['firewall']

        # Dissociate router from Firewall
        update_dict = {'router_ids': []}
        self.firewalls_client.update_firewall(
            created_firewall['id'],
            **update_dict)

        # Verify
        fw = self.firewalls_client.show_firewall(created_firewall['id'])
        self.assertEqual(fw['firewall']['router_ids'], [])

        # Re-associate
        update_dict = {'router_ids': [router['id']]}
        self.firewalls_client.update_firewall(
            created_firewall['id'],
            **update_dict)

        # Verify
        fw = self.firewalls_client.show_firewall(created_firewall['id'])
        self.assertEqual(fw['firewall']['router_ids'], [router['id']])

        self._try_delete_firewall(created_firewall['id'])

    @decorators.attr(type='smoke')
    @decorators.idempotent_id('53305b4b-9897-4e01-87c0-2ae386083180')
    def test_firewall_rule_insertion_position_removal_rule_from_policy(self):
        # Create firewall rule
        body = self.firewall_rules_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="tcp")
        fw_rule_id1 = body['firewall_rule']['id']
        self.addCleanup(self._try_delete_rule, fw_rule_id1)
        # Create firewall policy
        body = self.firewall_policies_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy_id = body['firewall_policy']['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id)

        # Insert rule to firewall policy
        self.firewall_policies_client.insert_firewall_rule_in_policy(
            fw_policy_id, fw_rule_id1, '', '')
        # Verify insertion of rule in policy
        self.assertIn(fw_rule_id1, self._get_list_fw_rule_ids(fw_policy_id))
        # Create another firewall rule
        body = self.firewall_rules_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="icmp")
        fw_rule_id2 = body['firewall_rule']['id']
        self.addCleanup(self._try_delete_rule, fw_rule_id2)

        # Insert rule to firewall policy after the first rule
        self.firewall_policies_client.insert_firewall_rule_in_policy(
            fw_policy_id, fw_rule_id2, fw_rule_id1, '')

        # Verify the position of rule after insertion
        fw_rule = self.firewall_rules_client.show_firewall_rule(
            fw_rule_id1)
        self.assertEqual(int(fw_rule['firewall_rule']['position']), 1)

        fw_rule = self.firewall_rules_client.show_firewall_rule(
            fw_rule_id2)
        self.assertEqual(int(fw_rule['firewall_rule']['position']), 2)

        # Verify Positions on VSD
        # Get rule1 from VSD
        rule1 = self.vsd.get_firewall_rule(by_fw_rule_id=fw_rule_id1)
        self.assertEqual(rule1.priority, 0)
        rule2 = self.vsd.get_firewall_rule(by_fw_rule_id=fw_rule_id2)
        self.assertEqual(rule2.priority, 1)

        # Verify rule association to acl on VSD.
        policy1 = self.vsd.get_firewall_acl(by_fw_policy_id=fw_policy_id)
        self.assertIn(rule1.id, policy1.rule_ids)
        self.assertIn(rule2.id, policy1.rule_ids)

        # Add a rule 3 after rule1 and before rule2
        body = self.firewall_rules_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="udp")
        fw_rule_id3 = body['firewall_rule']['id']
        self.addCleanup(self._try_delete_rule, fw_rule_id3)

        self.firewall_policies_client.insert_firewall_rule_in_policy(
            fw_policy_id, fw_rule_id3, fw_rule_id1, fw_rule_id2)

        # Verify the position of rule after insertion on Openstack
        fw_rule1 = self.firewall_rules_client.show_firewall_rule(
            fw_rule_id1)
        fw_rule2 = self.firewall_rules_client.show_firewall_rule(
            fw_rule_id2)
        fw_rule3 = self.firewall_rules_client.show_firewall_rule(
            fw_rule_id3)
        self.assertEqual(int(fw_rule1['firewall_rule']['position']), 1)
        self.assertEqual(int(fw_rule2['firewall_rule']['position']), 3)
        self.assertEqual(int(fw_rule3['firewall_rule']['position']), 2)

        # Verify Positions on VSD:
        rule1 = self.vsd.get_firewall_rule(by_fw_rule_id=fw_rule_id1)
        self.assertEqual(rule1.priority, 0)
        rule2 = self.vsd.get_firewall_rule(by_fw_rule_id=fw_rule_id2)
        self.assertEqual(rule2.priority, 2)
        rule3 = self.vsd.get_firewall_rule(by_fw_rule_id=fw_rule_id3)
        self.assertEqual(rule3.priority, 1)

        # Verify rule association to acl on VSD.
        policy1 = self.vsd.get_firewall_acl(by_fw_policy_id=fw_policy_id)
        self.assertIn(rule1.id, policy1.rule_ids)
        self.assertIn(rule2.id, policy1.rule_ids)
        self.assertIn(rule3.id, policy1.rule_ids)

        # Remove rule from the firewall policy
        self.firewall_policies_client.remove_firewall_rule_from_policy(
            fw_policy_id, fw_rule_id2)
        # Insert rule to firewall policy before the first rule
        self.firewall_policies_client.insert_firewall_rule_in_policy(
            fw_policy_id, fw_rule_id2, '', fw_rule_id1)
        # Verify the position of rule after insertion
        fw_rule = self.firewall_rules_client.show_firewall_rule(
            fw_rule_id2)
        self.assertEqual(int(fw_rule['firewall_rule']['position']), 1)

        fw_rule = self.firewall_rules_client.show_firewall_rule(
            fw_rule_id1)
        self.assertEqual(int(fw_rule['firewall_rule']['position']), 2)

        # Remove rule from the firewall policy
        self.firewall_policies_client.remove_firewall_rule_from_policy(
            fw_policy_id, fw_rule_id2)
        # Verify removal of rule from firewall policy
        self.assertNotIn(fw_rule_id2, self._get_list_fw_rule_ids(fw_policy_id))

        # Remove rule from the firewall policy
        self.firewall_policies_client.remove_firewall_rule_from_policy(
            fw_policy_id, fw_rule_id1)

        # Verify removal of rule from firewall policy
        self.assertNotIn(fw_rule_id1, self._get_list_fw_rule_ids(fw_policy_id))

        # Remove rule from the firewall policy
        self.firewall_policies_client.remove_firewall_rule_from_policy(
            fw_policy_id, fw_rule_id3)

        # Verify removal of rule from firewall policy
        self.assertNotIn(fw_rule_id3,
                         self._get_list_fw_rule_ids(fw_policy_id))

    def _get_list_fw_rule_ids(self, fw_policy_id):
        fw_policy = self.firewall_policies_client.show_firewall_policy(
            fw_policy_id)
        return [ruleid for ruleid in fw_policy['firewall_policy']
                ['firewall_rules']]

    @decorators.idempotent_id('8515ca8a-0d2f-4298-b5ff-6f924e4587ca')
    def test_update_firewall_policy_audited_attribute(self):
        # Create firewall rule
        body = self.firewall_rules_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="icmp")
        fw_rule_id = body['firewall_rule']['id']
        self.addCleanup(self._try_delete_rule, fw_rule_id)
        # Create firewall policy
        body = self.firewall_policies_client.create_firewall_policy(
            name=data_utils.rand_name('fw-policy'))
        fw_policy_id = body['firewall_policy']['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id)
        self.assertFalse(body['firewall_policy']['audited'])
        # Update firewall policy audited attribute to true
        self.firewall_policies_client.update_firewall_policy(fw_policy_id,
                                                             audited=True)
        # Insert Firewall rule to firewall policy
        self.firewall_policies_client.insert_firewall_rule_in_policy(
            fw_policy_id, fw_rule_id, '', '')
        body = self.firewall_policies_client.show_firewall_policy(
            fw_policy_id)

        policy1 = self.vsd.get_firewall_acl(by_fw_policy_id=fw_policy_id)
        rule1 = self.vsd.get_firewall_rule(by_fw_rule_id=fw_rule_id)
        self.assertIn(rule1.id, policy1.rule_ids)

        self.assertFalse(body['firewall_policy']['audited'])

    def test_invalid_nuage_net_parition_router_firewall_association(self):
        body = self.firewall_policies_client.create_firewall_policy(
            name=data_utils.rand_name('fw-policy'))
        fw_policy_id = body['firewall_policy']['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id)

        body = self.firewalls_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=fw_policy_id)
        created_firewall = body['firewall']
        self.addCleanup(self._try_delete_firewall, created_firewall['id'])

        net_part_name = data_utils.rand_name('fwaas-ent-')
        net_part = self.nuage_ent_client.create_netpartition(
            net_part_name)

        netpart = {'net_partition': net_part_name}

        router = self.create_router(
            data_utils.rand_name('router-'),
            admin_state_up=True, **netpart)

        update_dict = {'router_ids': [router['id']]}

        # This should raise an error.
        self.assertRaisesRegex(
            lib_exc.BadRequest,
            "does not belong to the default netpartition",
            self.firewalls_client.update_firewall,
            created_firewall['id'],
            **update_dict)

        self.delete_router(router)
        # clean up procedure
        body = self.nuage_ent_client.delete_netpartition(
            net_part['net_partition']['id'])
        self.assertEqual('204', body.response['status'])

    def test_create_firewall_rules_in_different_policies(self):
        body = self.firewall_rules_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="tcp")
        fw_rule_id1 = body['firewall_rule']['id']
        self.addCleanup(self._try_delete_rule, fw_rule_id1)
        # Create firewall policy
        body = self.firewall_policies_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy_id1 = body['firewall_policy']['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id1)

        # Insert rule to firewall policy
        self.firewall_policies_client.insert_firewall_rule_in_policy(
            fw_policy_id1, fw_rule_id1, '', '')
        # Verify insertion of rule in policy
        self.assertIn(fw_rule_id1, self._get_list_fw_rule_ids(fw_policy_id1))
        rule1 = self.vsd.get_firewall_rule(by_fw_rule_id=fw_rule_id1)
        policy1 = self.vsd.get_firewall_acl(by_fw_policy_id=fw_policy_id1)
        self.assertIn(rule1.id, policy1.rule_ids)

        body = self.firewall_rules_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="udp")
        fw_rule_id2 = body['firewall_rule']['id']
        self.addCleanup(self._try_delete_rule, fw_rule_id2)
        # Create firewall policy
        body = self.firewall_policies_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy_id2 = body['firewall_policy']['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id2)

        # Insert rule to firewall policy
        self.firewall_policies_client.insert_firewall_rule_in_policy(
            fw_policy_id2, fw_rule_id2, '', '')
        # Verify insertion of rule in policy
        self.assertIn(fw_rule_id2, self._get_list_fw_rule_ids(fw_policy_id2))
        rule2 = self.vsd.get_firewall_rule(by_fw_rule_id=fw_rule_id2)
        policy2 = self.vsd.get_firewall_acl(by_fw_policy_id=fw_policy_id2)
        self.assertIn(rule2.id, policy2.rule_ids)

    def test_create_firewall_rule_and_add_remove_router(self):
        # Create firewall rule
        body = self.firewall_rules_client.create_firewall_rule(
            name=data_utils.rand_name("fw-rule"),
            action="allow",
            protocol="tcp")
        fw_rule_id1 = body['firewall_rule']['id']
        self.addCleanup(self._try_delete_rule, fw_rule_id1)
        # Create firewall policy
        body = self.firewall_policies_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy_id = body['firewall_policy']['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id)

        # Insert rule to firewall policy
        self.firewall_policies_client.insert_firewall_rule_in_policy(
            fw_policy_id, fw_rule_id1, '', '')
        # Verify insertion of rule in policy
        self.assertIn(fw_rule_id1, self._get_list_fw_rule_ids(fw_policy_id))
        # Verify On VSD
        rule1 = self.vsd.get_firewall_rule(by_fw_rule_id=fw_rule_id1)
        policy1 = self.vsd.get_firewall_acl(by_fw_policy_id=fw_policy_id)
        self.assertIn(rule1.id, policy1.rule_ids)

        # Create a router1
        router1 = self.create_router(
            data_utils.rand_name('router-'),
            admin_state_up=True)

        # Create firewall on a router1
        body = self.firewalls_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=fw_policy_id,
            router_ids=[router1['id']])
        created_firewall = body['firewall']
        firewall_id = created_firewall['id']
        self.addCleanup(self._try_delete_firewall, firewall_id)

        self.assertEqual([router1['id']], created_firewall['router_ids'])
        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)
        # Also verify on VSD whether association is created or not
        domains = self.vsd.get_firewall_acl_domains(policy1)
        ext_id = self.vsd.external_id(router1['id'])
        self.assertEqual(domains[0].external_id, ext_id)

        # create a router2
        router2 = self.create_router(
            data_utils.rand_name('router-'),
            admin_state_up=True)

        body = self.firewalls_client.update_firewall(
            firewall_id, router_ids=[router1['id'], router2['id']])
        updated_firewall = body['firewall']
        self.assertIn(router2['id'], updated_firewall['router_ids'])
        self.assertEqual(2, len(updated_firewall['router_ids']))
        self._wait_until_ready(firewall_id)

        # Also verify on VSD whether association is created or not
        domains = self.vsd.get_firewall_acl_domains(policy1)
        ext_id1 = self.vsd.external_id(router1['id'])
        ext_id2 = self.vsd.external_id(router2['id'])
        list_of_ext_ids = [dom.external_id for dom in domains]
        self.assertIn(ext_id1, list_of_ext_ids)
        self.assertIn(ext_id2, list_of_ext_ids)
