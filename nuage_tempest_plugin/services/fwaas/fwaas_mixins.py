# Copyright (c) 2015 Midokura SARL
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

import time

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.fwaas import fwaas_client as client

CONF = Topology.get_conf()

PENDING_CREATE = "PENDING_CREATE"
PENDING_UPDATE = "PENDING_UPDATE"
PENDING_DELETE = "PENDING_DELETE"


class FWaaSClientMixin(object):

    @classmethod
    def resource_setup(cls):
        super(FWaaSClientMixin, cls).resource_setup()
        manager = cls.os_primary
        cls.firewalls_client = client.FirewallsClient(
            manager.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **manager.default_params)
        cls.firewall_policies_client = client.FirewallPoliciesClient(
            manager.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **manager.default_params)
        cls.firewall_rules_client = client.FirewallRulesClient(
            manager.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **manager.default_params)
        cls.firewall_policies_admin_client = client.FirewallPoliciesClient(
            cls.os_admin.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os_admin.default_params)
        cls.firewall_rules_admin_client = client.FirewallRulesClient(
            cls.os_admin.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os_admin.default_params)

    def create_firewall_rule(self, name=None, **kwargs):
        if not name:
            name = data_utils.rand_name("fw-rule")
        body = self.firewall_rules_client.create_firewall_rule(
            name=name, **kwargs)
        fw_rule = body['firewall_rule']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.firewall_rules_client.delete_firewall_rule,
                        fw_rule['id'])
        return fw_rule

    def create_firewall_policy(self, name=None, **kwargs):
        if not name:
            name = data_utils.rand_name("fw-policy")
        body = self.firewall_policies_client.create_firewall_policy(
            name=name, **kwargs)
        fw_policy = body['firewall_policy']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.firewall_policies_client.delete_firewall_policy,
                        fw_policy['id'])
        return fw_policy

    def create_firewall(self, name=None, **kwargs):
        if not name:
            name = data_utils.rand_name("fw")
        body = self.firewalls_client.create_firewall(
            name=name, **kwargs)
        fw = body['firewall']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.delete_firewall_and_wait,
                        fw['id'])
        return fw

    def delete_firewall_and_wait(self, firewall_id):
        self.firewalls_client.delete_firewall(firewall_id)
        self._wait_firewall_while(firewall_id, [PENDING_DELETE],
                                  not_found_ok=True)

    def _wait_firewall_ready(self, firewall_id):
        self._wait_firewall_while(firewall_id,
                                  [PENDING_CREATE,
                                   PENDING_UPDATE])

    def _wait_firewall_while(self, firewall_id, statuses, not_found_ok=False):
        start = int(time.time())
        if not_found_ok:
            expected_exceptions = (lib_exc.NotFound)
        else:
            expected_exceptions = ()
        while True:
            try:
                fw = self.firewalls_client.show_firewall(firewall_id)
            except expected_exceptions:
                break
            status = fw['firewall']['status']
            if status not in statuses:
                break
            if int(time.time()) - start >= self.firewalls_client.build_timeout:
                msg = ("Firewall %(firewall)s failed to reach "
                       "non PENDING status (current %(status)s)") % {
                    "firewall": firewall_id,
                    "status": status,
                }
                raise lib_exc.TimeoutException(msg)
            time.sleep(1)
