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

import random
from six import iteritems

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
LOG = Topology.get_logger(__name__)


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
        self.fw_policy = self.create_firewall_policy(
            name='fw-policy-1', firewall_rules=[self.fw_rule['id']])

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

    def _verify_fw_rule(self, firewall_rule_os, firewall_rule_vsd):

        VSD_TO_OS_ACTION = {
            'allow': "FORWARD",
            'deny': "DROP"
        }

        firewall_rule_vsd = firewall_rule_vsd.to_dict()
        # Protocol and externalID cannot be verified VSD-18219
        self.assertEqual(firewall_rule_os['name'],
                         firewall_rule_vsd['description'])
        if firewall_rule_os['action'] == "allow":
            self.assertEqual(firewall_rule_vsd['stateful'], True)
        else:
            self.assertEqual(firewall_rule_vsd['stateful'], False)
        if firewall_rule_vsd['sourcePort']:
            firewall_rule_vsd['sourcePort'] = \
                firewall_rule_vsd['sourcePort'].replace('-', ':')
        if firewall_rule_vsd['destinationPort']:
            firewall_rule_vsd['destinationPort'] = \
                firewall_rule_vsd['destinationPort'].replace('-', ':')
        self.assertEqual(firewall_rule_os['source_port'],
                         firewall_rule_vsd['sourcePort'])
        self.assertEqual(firewall_rule_os['destination_port'],
                         firewall_rule_vsd['destinationPort'])

        ip_version = firewall_rule_os.get('ip_version')
        self.assertIn(needle=ip_version, haystack=[4, 6])
        vsd_source_ip_field_name = (
            'addressOverride' if ip_version == 4 or Topology.is_v5
            else 'IPv6AddressOverride')
        self.assertEqual(firewall_rule_os['source_ip_address'],
                         firewall_rule_vsd[vsd_source_ip_field_name])

        self.assertEqual(firewall_rule_os['destination_ip_address'],
                         firewall_rule_vsd['networkID'])
        self.assertEqual(VSD_TO_OS_ACTION.get(firewall_rule_os['action']),
                         firewall_rule_vsd['action'])
        if firewall_rule_os['firewall_policy_id'] is not None:
            self.assertIsNotNone(firewall_rule_vsd['associatedfirewallACLID'])

    def _verify_block_all_acl(self, firewall, router=None,
                              should_have_router=True):
        acls_on_vsd = self.vsd.get_firewall_acls()
        nr_acls_for_router = 0
        nr_drop_acls = 0
        for acl in acls_on_vsd:
            acl.domains.fetch()
            domain_external_ids = [d.external_id for d in acl.domains]
            router_external_id = (self.vsd.external_id(router['id'])
                                  if router else None)

            if acl.name == "DROP_ALL_ACL_{}".format(firewall['id']):
                nr_drop_acls += 1
                if (router and router_external_id in domain_external_ids
                        and not should_have_router):
                    self.fail("DROP_ALL_ACL has router {}, while it "
                              "should not".format(router['id']))
            if router:
                if router_external_id in domain_external_ids:
                    # Verify that router is not attached to another ACL
                    self.assertEqual("DROP_ALL_ACL_{}".format(firewall['id']),
                                     acl.name)
                    nr_acls_for_router += 1
        self.assertEqual(1, nr_drop_acls,
                         "Expected 1 drop ACL for FW "
                         "on VSD but got {}".format(nr_drop_acls))
        if router and should_have_router:
            self.assertEqual(1, nr_acls_for_router,
                             "Expected 1 ACL for router "
                             "on VSD but got {}".format(nr_acls_for_router))
        else:
            self.assertEqual(0, nr_acls_for_router,
                             "Expected 0 ACL for router "
                             "on VSD but got {}".format(nr_acls_for_router))

        # Verify that firewall ACL is not deleted from VSD
        if firewall.get('firewall_policy_id'):
            acl = self.vsd.get_firewall_acl(
                by_fw_policy_id=firewall['firewall_policy_id'])
            self.assertIsNotNone(acl,
                                 "Firewall ACL {} not found on "
                                 "VSD".format(firewall['firewall_policy_id']))

    def verify_firewall_VSD(self, firewall, fw_policy, router=None,
                            should_have_router=True):
        # Get ACL from VSD
        policy_acl = self.vsd.get_firewall_acl(
            by_fw_policy_id=fw_policy['id'])
        self.assertIsNotNone(policy_acl, "Could not find ACL for fw_policy.")
        # Make sure all rules are present
        rules = policy_acl.firewall_rules.get()
        self.assertEqual(len(fw_policy['firewall_rules']),
                         len(rules), "Amount of rules ({}) associated to "
                                     "firewall_policy {} does not correspond "
                                     "to amount of rules ({}) associated to "
                                     "ACL {} on VSD".format(
            len(fw_policy['firewall_rules']), fw_policy['id'],
            len(rules), policy_acl.id))
        # TODO(TEAM) More extensive test based on ext_id in VSPK
        # Verify that there are no other policies applied and that there is no
        # block ACL for this firewall.
        acls_on_vsd = self.vsd.get_firewall_acls()
        nr_acls_for_router = 0
        for acl in acls_on_vsd:
            acl.domains.fetch()
            self.assertNotEqual("DROP_ALL_ACL_{}".format(firewall['id']),
                                acl.name)
            if router:
                domain_external_ids = [d.external_id for d in acl.domains]
                router_external_id = self.vsd.external_id(router['id'])
                if router_external_id in domain_external_ids:
                    if should_have_router:
                        self.assertEqual(policy_acl.id,
                                         acl.id)
                    nr_acls_for_router += 1
        if should_have_router:
            self.assertEqual(1, nr_acls_for_router,
                             "Expected 1 acl on VSD for "
                             "router but got "
                             "{}".format(nr_acls_for_router))
        else:
            self.assertEqual(0, nr_acls_for_router,
                             "Expected 0 acl on VSD for "
                             "router but got {}".format(nr_acls_for_router))

    def verify_after_delete_firewall(self, firewall, router):
        acls_on_vsd = self.vsd.get_firewall_acls()
        for acl in acls_on_vsd:
            self.assertNotEqual("DROP_ALL_ACL_{}".format(firewall['id']),
                                acl.name, "Drop all ACL still present in VSD.")
        policy_acl = self.vsd.get_firewall_acl(
            by_fw_policy_id=self.fw_policy['id'])
        policy_acl.domains.fetch()
        domain_external_ids = [d.external_id for d in acl.domains]
        router_external_id = self.vsd.external_id(router['id'])
        self.assertNotIn(router_external_id, domain_external_ids,
                         "Router still attached to ACL after firewall delete")

    def _wait_until_ready(self, fw_id):
        target_states = ('ACTIVE', 'INACTIVE', 'DOWN')

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

    def test_create_update_delete_firewall_rule_ipv4(self):
        self._create_update_delete_firewall_rule_impl(
            ip_version=4, source_ip_address='1.1.1.1/32',
            destination_ip_address='2.2.2.2/32')

    def test_create_update_delete_firewall_rule_ipv6(self):
        self._create_update_delete_firewall_rule_impl(
            ip_version=6, source_ip_address='cafe:babe::1/128',
            destination_ip_address='b16b:b5::2/128')

    def _create_update_delete_firewall_rule_impl(self, ip_version,
                                                 source_ip_address,
                                                 destination_ip_address):
        # Create firewall rule
        body = self.firewall_rules_client.create_firewall_rule(
            name='fw-rule-2',
            action="allow",
            protocol="tcp",
            ip_version=ip_version)
        fw_rule_id = body['firewall_rule']['id']
        vsd_acl = self.vsd.get_firewall_rule(by_fw_rule_id=fw_rule_id)
        self._verify_fw_rule(body['firewall_rule'], vsd_acl)

        # Update firewall rule
        body = self.firewall_rules_admin_client.update_firewall_rule(
            fw_rule_id,
            shared=True,
            source_port=1000,
            destination_port=1000,
            source_ip_address=source_ip_address,
            destination_ip_address=destination_ip_address)

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

    def test_show_firewall_rule(self):
        # show a created firewall rule
        fw_rule = self.firewall_rules_client.show_firewall_rule(
            self.fw_rule['id'])
        for key, value in iteritems(fw_rule['firewall_rule']):
            if key == 'position' or key == 'firewall_policy_id':
                continue
                # Could have changed inbetween creation and show
            self.assertEqual(self.fw_rule[key], value)

    def test_list_firewall_policies(self):
        fw_policies = self.firewall_policies_client.list_firewall_policies()
        fw_policies = fw_policies['firewall_policies']
        self.assertIn((self.fw_policy['id'],
                       self.fw_policy['name'],
                       self.fw_policy['firewall_rules']),
                      [(m['id'],
                        m['name'],
                        m['firewall_rules']) for m in fw_policies])

    def create_update_validate_firewall_policy_with_n_rules(
            self, total_amount_of_rules, policy_amount_of_rules):
        # can't have more rules in policy than total amount
        assert 0 < policy_amount_of_rules <= total_amount_of_rules

        # create firewall rules
        firewall_ids = [self.create_firewall_rule(
            action=random.choice(['allow', 'deny']),
            protocol=random.choice(['icmp', 'udp', 'tcp']))['id']
            for _ in range(total_amount_of_rules)]

        # create firewall policy with specified set of rules
        rule_selection = random.sample(firewall_ids, policy_amount_of_rules)
        fw_policy_id = self.create_firewall_policy(
            firewall_rules=rule_selection)['id']
        self.check_firewallacl_on_vsd(policy_amount_of_rules,
                                      fw_policy_id, rule_selection)

        # update firewall policy by removing a rule
        self.firewall_policies_client.update_firewall_policy(
            fw_policy_id, firewall_rules=rule_selection[:-1])
        self.check_firewallacl_on_vsd(policy_amount_of_rules - 1,
                                      fw_policy_id, rule_selection[:-1])

    def check_firewallacl_on_vsd(self, n, fw_policy_id, os_rule_ids):
        # TODO(vandewat) Speed up if get_firewall_acl returns externalIDs
        self.assertEqual(len(os_rule_ids), n)
        fw_acl = self.vsd.get_firewall_acl(by_fw_policy_id=fw_policy_id)
        self.assertIsNotNone(fw_acl)
        self.assertEqual(len(fw_acl.rule_ids), n)
        vsd_rule_ids = [self.vsd.get_firewall_rule(by_fw_rule_id=rule_id).id
                        for rule_id in os_rule_ids]
        # list compare since order of firewall rules is important
        self.assertListEqual(fw_acl.rule_ids, vsd_rule_ids)

    def test_create_update_delete_firewall_policy_with_0_rules(self):
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

    def test_create_update_firewall_policy_with_1_rule(self):
        self.create_update_validate_firewall_policy_with_n_rules(2, 1)

    def test_create_firewall_policy_with_81_rules(self):
        # tests the boundary of the X-Nuage-Filter chunk, this is an
        # implementation detail, a unit test would be better
        self.create_update_validate_firewall_policy_with_n_rules(82, 81)

    def test_show_firewall_policy(self):
        # show a created firewall policy
        fw_policy = self.firewall_policies_client.show_firewall_policy(
            self.fw_policy['id'])
        fw_policy = fw_policy['firewall_policy']
        for key, value in iteritems(fw_policy):
            self.assertEqual(self.fw_policy[key], value)

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
            firewall_policy_id=self.fw_policy['id'],
            router_ids=[router['id']]
        )
        created_firewall = body['firewall']

        self.assertEqual('ACTIVE', created_firewall['status'])
        firewall_id = created_firewall['id']
        self.addCleanup(self._try_delete_firewall, firewall_id)

        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)

        # show a created firewall
        firewall = self.firewalls_client.show_firewall(firewall_id)
        firewall = firewall['firewall']

        for key, value in iteritems(firewall):
            self.assertEqual(created_firewall[key], value)

        self.verify_firewall_VSD(firewall, self.fw_policy, router)

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

        self.verify_after_delete_firewall(firewall, router)

    def test_create_show_update_delete_firewall_admin_down(self):
        """test_create_show_update_delete_firewall_admin_down

        Create firewall with a router, admin state down
        update firewall to be admin state up
        update firewall to be admin state down
        delete firewall
        """
        # Create tenant network resources required for an ACTIVE firewall
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(
            data_utils.rand_name('router-'),
            admin_state_up=True)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_router, router)
        self.routers_client.add_router_interface(router['id'],
                                                 subnet_id=subnet['id'])

        # Create firewall
        body = self.firewalls_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['id'],
            router_ids=[router['id']],
            admin_state_up=False)
        created_firewall = body['firewall']

        self.assertEqual('DOWN', created_firewall['status'])
        firewall_id = created_firewall['id']
        # Cleanup fallback
        self.addCleanup(self._try_delete_firewall, firewall_id)

        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)

        # show a created firewall
        firewall = self.firewalls_client.show_firewall(firewall_id)
        firewall = firewall['firewall']

        for key, value in iteritems(firewall):
            self.assertEqual(created_firewall[key], value)

        # Check block rules on VSD and only block rules
        self._verify_block_all_acl(firewall, router)

        # Update firewall to be admin state up
        updated_fw = self.firewalls_client.update_firewall(
            firewall['id'], admin_state_up=True)['firewall']
        self.assertEqual('ACTIVE', updated_fw['status'])

        # Check no block rules and policy is correctly applied
        self.verify_firewall_VSD(updated_fw, self.fw_policy, router)

        # Update firewall to be admin state down
        updated_fw = self.firewalls_client.update_firewall(
            firewall['id'], admin_state_up=False)['firewall']
        self.assertEqual('DOWN', updated_fw['status'])

        # Check no block rules and policy is correctly applied
        self._verify_block_all_acl(firewall, router)

        # Delete firewall
        self.firewalls_client.delete_firewall(firewall_id)

        # Verify no block all ACL, ACL not connected to domain
        self.verify_after_delete_firewall(firewall, router)

    def test_create_show_update_delete_firewall_admin_down_no_router(self):
        """test_create_show_update_delete_firewall_admin_down

        Create firewall with a router, admin state down
        update firewall to be admin state up
        update firewall to be admin state down
        delete firewall
        """

        # Create firewall
        body = self.firewalls_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=self.fw_policy['id'],
            router_ids=[],
            admin_state_up=False)
        created_firewall = body['firewall']

        self.assertEqual('INACTIVE', created_firewall['status'])
        firewall_id = created_firewall['id']
        # Cleanup fallback
        self.addCleanup(self._try_delete_firewall, firewall_id)

        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)

        # show a created firewall
        firewall = self.firewalls_client.show_firewall(firewall_id)
        firewall = firewall['firewall']

        for key, value in iteritems(firewall):
            self.assertEqual(created_firewall[key], value)

        # Check block rules on VSD and only block rules
        self._verify_block_all_acl(firewall, None)

        # Update firewall to be admin state up
        updated_fw = self.firewalls_client.update_firewall(
            firewall['id'], admin_state_up=True)['firewall']
        self.assertEqual('INACTIVE', updated_fw['status'])

        # Check no block rules and policy is correctly applied
        self.verify_firewall_VSD(updated_fw, self.fw_policy, None,
                                 should_have_router=False)

        # Update firewall to be admin state down
        updated_fw = self.firewalls_client.update_firewall(
            firewall['id'], admin_state_up=False)['firewall']
        self.assertEqual('INACTIVE', updated_fw['status'])

        # Check no block rules and policy is correctly applied
        self._verify_block_all_acl(firewall, None)

        # Update a down router to have a router
        router = self.create_router(
            data_utils.rand_name('router-'),
            admin_state_up=True)
        updated_fw = self.firewalls_client.update_firewall(
            firewall['id'], router_ids=[router['id']])['firewall']
        self.assertEqual('DOWN', updated_fw['status'])
        self._verify_block_all_acl(firewall, router)

        # Update a down router to not have a router anymore
        router = self.create_router(
            data_utils.rand_name('router-'),
            admin_state_up=True)
        updated_fw = self.firewalls_client.update_firewall(
            firewall['id'], router_ids=[router['id']])['firewall']
        self.assertEqual('DOWN', updated_fw['status'])
        self._verify_block_all_acl(firewall, router)

        # Delete firewall
        self.firewalls_client.delete_firewall(firewall_id)

        # Verify no block all ACL, ACL not connected to domain
        self.verify_after_delete_firewall(firewall, router)

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
        self.assertEqual('ACTIVE', created_firewall['status'])
        firewall_id = created_firewall['id']
        self.addCleanup(self._try_delete_firewall, firewall_id)

        self.verify_firewall_VSD(created_firewall, self.fw_policy, router1)

        self.assertEqual([router1['id']], created_firewall['router_ids'])

        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)

        # Add router2 to the firewall
        body = self.firewalls_client.update_firewall(
            firewall_id, router_ids=[router1['id'], router2['id']])
        updated_firewall = body['firewall']
        self.assertEqual('ACTIVE', updated_firewall['status'])
        self.assertIn(router2['id'], updated_firewall['router_ids'])
        self.assertEqual(2, len(updated_firewall['router_ids']))

        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)

        # Remove router1 from the firewall
        body = self.firewalls_client.update_firewall(
            firewall_id, router_ids=[router2['id']])
        updated_firewall = body['firewall']
        self.assertEqual('ACTIVE', updated_firewall['status'])
        self.assertNotIn(router1['id'], updated_firewall['router_ids'])
        self.assertEqual(1, len(updated_firewall['router_ids']))
        self.verify_firewall_VSD(updated_firewall, self.fw_policy, router2)

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
        self.assertEqual('ACTIVE', created_firewall['status'])
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
        self.assertEqual('ACTIVE', created_firewall['status'])
        self.verify_firewall_VSD(created_firewall, self.fw_policy, router)

        # Dissociate router from Firewall
        update_dict = {'router_ids': []}
        self.firewalls_client.update_firewall(
            created_firewall['id'],
            **update_dict)

        # Verify
        fw = self.firewalls_client.show_firewall(created_firewall['id'])
        self.assertEqual(fw['firewall']['router_ids'], [])
        self.assertEqual('INACTIVE', fw['firewall']['status'])
        self.verify_firewall_VSD(created_firewall, self.fw_policy, router,
                                 should_have_router=False)

        # Re-associate
        update_dict = {'router_ids': [router['id']]}
        self.firewalls_client.update_firewall(
            created_firewall['id'],
            **update_dict)

        # Verify
        fw = self.firewalls_client.show_firewall(created_firewall['id'])
        self.assertEqual(fw['firewall']['router_ids'], [router['id']])
        self.assertEqual('ACTIVE', fw['firewall']['status'])
        self.verify_firewall_VSD(created_firewall, self.fw_policy, router)

        self._try_delete_firewall(created_firewall['id'])
        self.verify_after_delete_firewall(created_firewall, router)

    @decorators.attr(type='smoke')
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
            router_ids=[],
            firewall_policy_id=fw_policy_id)
        created_firewall = body['firewall']
        self.assertEqual('INACTIVE', created_firewall['status'])

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
        self.assertEqual('ACTIVE', created_firewall['status'])
        firewall_id = created_firewall['id']
        self.addCleanup(self._try_delete_firewall, firewall_id)

        self.assertEqual([router1['id']], created_firewall['router_ids'])
        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)
        # Also verify on VSD whether association is created or not
        fw_policy = self.firewall_policies_client.show_firewall_policy(
            fw_policy_id)['firewall_policy']
        self.verify_firewall_VSD(created_firewall, fw_policy, router1)

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
        self.verify_firewall_VSD(created_firewall, fw_policy, router1)
        self.verify_firewall_VSD(created_firewall, fw_policy, router2)

    def test_create_firewall_delete_in_admin_down_state(self):
        # Create firewall policy
        body = self.firewall_policies_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy = body['firewall_policy']
        fw_policy_id = fw_policy['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id)
        policy1 = self.vsd.get_firewall_acl(by_fw_policy_id=fw_policy_id)
        self.assertEmpty(policy1.rule_ids)

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

        self.assertEqual([router1['id']], created_firewall['router_ids'])
        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)
        self.assertEqual('ACTIVE', created_firewall['status'])
        self.verify_firewall_VSD(created_firewall, fw_policy, router=router1)

        # create a router2
        router2 = self.create_router(
            data_utils.rand_name('router-'),
            admin_state_up=True)

        body = self.firewalls_client.update_firewall(
            firewall_id, router_ids=[router1['id'], router2['id']],
            admin_state_up=False)
        updated_firewall = body['firewall']
        self.assertEqual(2, len(updated_firewall['router_ids']))
        self.assertEqual('DOWN', updated_firewall['status'])
        self._verify_block_all_acl(updated_firewall, router1)
        self._verify_block_all_acl(updated_firewall, router2)
        block_all = self.vsd.get_firewall_acl(by_fw_policy_id=firewall_id)
        domains = self.vsd.get_firewall_acl_domains(block_all)
        list_of_ext_ids = [dom.external_id for dom in domains]
        self.assertEqual(2, len(list_of_ext_ids),
                         message="Expected number of domains in policy"
                                 " do not match expected")

        self.firewalls_client.delete_firewall(firewall_id)
        # check if BLOCK_ALL_ACL was deleted
        self.verify_after_delete_firewall(created_firewall, router1)
        self.verify_after_delete_firewall(created_firewall, router2)

        # check if policy mapped FirewallACL is not deleted
        self.assertIsNotNone(
            self.vsd.get_firewall_acl(by_fw_policy_id=fw_policy_id))

    def test_create_update_firewall_in_admin_down_state(self):
        # Create firewall policy
        body = self.firewall_policies_client.create_firewall_policy(
            name=data_utils.rand_name("fw-policy"))
        fw_policy = body['firewall_policy']
        fw_policy_id = fw_policy['id']
        self.addCleanup(self._try_delete_policy, fw_policy_id)
        policy1 = self.vsd.get_firewall_acl(by_fw_policy_id=fw_policy_id)
        self.assertEmpty(policy1.rule_ids)

        # Create a router1
        router1 = self.create_router(
            data_utils.rand_name('router-'),
            admin_state_up=True)

        # Create firewall on a router1
        body = self.firewalls_client.create_firewall(
            name=data_utils.rand_name("firewall"),
            firewall_policy_id=fw_policy_id,
            router_ids=[router1['id']],
            admin_state_up=False)
        created_firewall = body['firewall']
        firewall_id = created_firewall['id']

        self.assertEqual([router1['id']], created_firewall['router_ids'])
        # Wait for the firewall resource to become ready
        self._wait_until_ready(firewall_id)
        self.assertEqual('DOWN', created_firewall['status'])

        # Also verify on VSD whether association is created or not
        self._verify_block_all_acl(created_firewall, router1)

        # create a router2
        router2 = self.create_router(
            data_utils.rand_name('router-'),
            admin_state_up=True)

        body = self.firewalls_client.update_firewall(
            firewall_id, router_ids=[router1['id'], router2['id']],
            admin_state_up=False)
        updated_firewall = body['firewall']
        self.assertIn(router1['id'], updated_firewall['router_ids'])
        self.assertIn(router2['id'], updated_firewall['router_ids'])
        self.assertEqual(2, len(updated_firewall['router_ids']))
        self.assertEqual('DOWN', created_firewall['status'])

        # Verify on VSD whether association is accurate
        self._verify_block_all_acl(created_firewall, router1)
        self._verify_block_all_acl(created_firewall, router2)

        block_all = self.vsd.get_firewall_acl(by_fw_policy_id=firewall_id)
        domains = self.vsd.get_firewall_acl_domains(block_all)
        list_of_ext_ids = [dom.external_id for dom in domains]
        self.assertEqual(2, len(list_of_ext_ids),
                         message="Expected number of domains in policy"
                                 " do not match expected")

        # update to only one router in firewall
        body = self.firewalls_client.update_firewall(
            firewall_id, router_ids=[router2['id']])
        updated_firewall = body['firewall']
        self.assertIn(router2['id'], updated_firewall['router_ids'])
        self.assertEqual(1, len(updated_firewall['router_ids']))
        self.assertEqual('DOWN', updated_firewall['status'])

        # Verify on VSD whether association is accurate
        self._verify_block_all_acl(created_firewall, router2)

        block_all = self.vsd.get_firewall_acl(by_fw_policy_id=firewall_id)
        domains = self.vsd.get_firewall_acl_domains(block_all)
        list_of_ext_ids = [dom.external_id for dom in domains]
        self.assertEqual(1, len(list_of_ext_ids),
                         message="Expected number of domains in policy"
                                 " do not match expected")
        self.assertNotIn(self.vsd.external_id(router1['id']), list_of_ext_ids)

        # Change to admin state up to clean up correctly
        updated_firewall = self.firewalls_client.update_firewall(
            firewall_id, router_ids=[router1['id'], router2['id']],
            admin_state_up=True)['firewall']
        # check if BLOCK_ALL_ACL was deleted
        self.assertEqual('ACTIVE', updated_firewall['status'])

        # verify on VSD whether association is accurate
        self.verify_firewall_VSD(updated_firewall, fw_policy, router1)
        self.verify_firewall_VSD(updated_firewall, fw_policy, router2)
        domains = self.vsd.get_firewall_acl_domains(policy1)
        list_of_ext_ids = [dom.external_id for dom in domains]
        self.assertEqual(2, len(list_of_ext_ids),
                         message="Expected number of domains in policy"
                                 " do not match expected")

        self.firewalls_client.delete_firewall(firewall_id)
        # check if policy mapped FirewallACL is not deleted
        self.verify_after_delete_firewall(updated_firewall, router1)
        self.verify_after_delete_firewall(updated_firewall, router2)
