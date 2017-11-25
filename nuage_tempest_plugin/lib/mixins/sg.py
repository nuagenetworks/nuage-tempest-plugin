# Copyright 2017 NOKIA
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

import contextlib

from tempest.common.utils import data_utils
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.mixins import base


class SGMixin(base.BaseMixin):

    @classmethod
    def setup_clients(cls):
        super(SGMixin, cls).setup_clients()
        if cls.has_primary:
            cls.sg_client = cls.os_primary.security_groups_client
            cls.sg_rules_client = cls.os_primary.security_group_rules_client
        if cls.has_admin:
            cls.sg_client_admin = cls.os_admin.security_groups_client
            cls.sg_rules_client = cls.os_admin.security_group_rules_client

    # ---------- SG ----------
    def sg_client(self, as_admin=False):
        if as_admin or not self.has_primary:
            return self.sg_client_admin
        return self.sg_client

    @contextlib.contextmanager
    def security_group(self, as_admin=False, **kwargs):
        sg = self.create_security_group(cleanup=False, as_admin=as_admin,
                                        **kwargs)
        try:
            yield sg
        finally:
            self.delete_security_group(sg['id'], as_admin=as_admin)

    def get_security_group(self, sg_id, as_admin=False):
        client = self.sg_client(as_admin)
        return client.show_security_group(sg_id)['security_group']

    def show_security_group(self, sg_id, as_admin=False):
        return self.get_security_group(sg_id, as_admin=as_admin)

    def get_security_groups(self, as_admin=False, **kwargs):
        client = self.sg_client(as_admin)
        return client.list_security_groups(**kwargs)['security_groups']

    def list_security_groups(self, as_admin=False, **kwargs):
        return self.get_security_groups(as_admin=as_admin, **kwargs)

    def create_security_group(self, as_admin=False, cleanup=True, **kwargs):
        client = self.sg_client(as_admin)
        sg = {'name': data_utils.rand_name('security-group')}
        sg.update(kwargs)
        sg = client.create_security_group(**sg)['security_group']
        if cleanup:
            self.addCleanup(self.delete_security_group, sg['id'],
                            as_admin=as_admin)
        return sg

    def update_security_group(self, sg_id, as_admin=False, **kwargs):
        client = self.sg_client(as_admin)
        return client.update_security_group(sg_id, **kwargs)['security_group']

    def delete_security_group(self, sg_id,
                              as_admin=False, ignore_not_found=True):
        client = self.sg_client(as_admin)
        try:
            client.delete_security_group(sg_id)
        except exceptions.NotFound:
            if not ignore_not_found:
                raise

    # ---------- SG rules ----------

    def sg_rules_client(self, as_admin=False):
        if as_admin or not self.has_primary:
            return self.sg_rules_client_admin
        return self.sg_rules_client

    @contextlib.contextmanager
    def security_group_rule(self, sg_id, as_admin=False, **kwargs):
        sg_rule = self.create_security_group_rule(sg_id, cleanup=False,
                                                  as_admin=as_admin, **kwargs)
        try:
            yield sg_rule
        finally:
            self.delete_security_group_rule(sg_rule['id'])

    def get_security_group_rule(self, rule_id, as_admin=False):
        client = self.sg_rules_client(as_admin=as_admin)
        return client.show_security_group_rule(rule_id)['security_group_rule']

    def show_security_group_rule(self, rule_id, as_admin=False):
        return self.get_security_group_rule(rule_id, as_admin=as_admin)

    def get_security_group_rules(self, as_admin=False, **kwargs):
        client = self.sg_rules_client(as_admin=as_admin)
        return client.list_security_group_rules(
            **kwargs)['security_group_rules']

    def list_security_group_rules(self, as_admin=False, **kwargs):
        return self.get_security_group_rules(as_admin=as_admin, **kwargs)

    def create_security_group_rule(self, sg_id, cleanup=True,
                                   as_admin=False, **kwargs):
        client = self.sg_rules_client(as_admin=as_admin)
        sg_rule = {'security_group_id': sg_id}
        sg_rule.update(kwargs)
        sg_rule = client.create_port(**sg_rule)['security_group_rule']
        if cleanup:
            self.addCleanup(self.delete_security_group_rule, sg_rule['id'])
        return sg_rule

    def delete_security_group_rule(self, rule_id,
                                   as_admin=False, ignore_not_found=True):
        client = self.sg_rules_client(as_admin=as_admin)
        try:
            client.delete_security_group_rule(rule_id)
        except exceptions.NotFound:
            if not ignore_not_found:
                raise
