# Copyright 2012 OpenStack Foundation
# Copyright 2013 Hewlett-Packard Development Company, L.P.
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

import collections

from tempest.lib import exceptions as lib_exc
from tempest.scenario import manager

from nuage_tempest_plugin.lib.topology import Topology

LOG = Topology.get_logger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


# NOTE(KRIS) : This class is used in particular testing - leave it in for now
class NuageNetworkScenarioTest(manager.NetworkScenarioTest):

    default_prepare_for_connectivity = True

    def _create_loginable_secgroup_rule(self, security_group_rules_client=None,
                                        secgroup=None,
                                        security_groups_client=None):
        """_create_loginable_secgroup_rule

        On queens-em and rocky-em tempest, the create_loginable_secgroup_rule
        is called _create_loginable_secgroup_rule. To support both master
        branch of tempest and queens/rocky-em branch of tempest we refer both
        to the same implementation.

        """
        self.create_loginable_secgroup_rule(
            security_group_rules_client, secgroup, security_groups_client)

    def create_loginable_secgroup_rule(self, security_group_rules_client=None,
                                       secgroup=None,
                                       security_groups_client=None):
        """Create loginable security group rule

        These rules are intended to permit inbound ssh and icmp
        traffic from all sources, so no group_id is provided.
        Setting a group_id would only permit traffic from ports
        belonging to the same security group.
        """

        if security_group_rules_client is None:
            security_group_rules_client = self.security_group_rules_client
        if security_groups_client is None:
            security_groups_client = self.security_groups_client
        rules = []
        rulesets = [
            dict(
                # ssh
                protocol='tcp',
                port_range_min=22,
                port_range_max=22,
            ),
            dict(
                # ping
                protocol='icmp',
            )
        ]
        sec_group_rules_client = security_group_rules_client
        for ruleset in rulesets:
            for r_direction in ['ingress', 'egress']:
                ruleset['direction'] = r_direction
                try:
                    try:
                        sg_rule = self.create_security_group_rule(
                            sec_group_rules_client=sec_group_rules_client,
                            secgroup=secgroup,
                            security_groups_client=security_groups_client,
                            **ruleset)
                    except AttributeError:
                        # In queens/rocky-em this function is defined as
                        # self._create_security_group_rule
                        sg_rule = self._create_security_group_rule(
                            sec_group_rules_client=sec_group_rules_client,
                            secgroup=secgroup,
                            security_groups_client=security_groups_client,
                            **ruleset)
                except lib_exc.Conflict as ex:
                    # if rule already exist - skip rule and continue
                    msg = 'Security group rule already exists'
                    if msg not in ex._error_string:
                        raise ex
                else:
                    self.assertEqual(r_direction, sg_rule['direction'])
                    rules.append(sg_rule)

        return rules
