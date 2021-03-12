# Copyright 2015 Alcatel-Lucent USA Inc.
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

from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.mixins import base
from nuage_tempest_plugin.services.bgpvpn import bgpvpn_client


class BGPVPNMixin(base.BaseMixin):

    @classmethod
    def setup_clients(cls):
        super(BGPVPNMixin, cls).setup_clients()
        cls.bgpvpn_client = bgpvpn_client.BGPVPNClient(
            cls.os_primary.auth_provider)
        cls.bgpvpn_client_admin = bgpvpn_client.BGPVPNClient(
            cls.os_admin.auth_provider)
        cls.net_assoc_client = bgpvpn_client.BGPVPNNetworkAssociationClient(
            cls.os_primary.auth_provider)
        cls.net_assoc_client_admin = bgpvpn_client.\
            BGPVPNNetworkAssociationClient(cls.os_admin.auth_provider)
        cls.rtr_assoc_client = bgpvpn_client.BGPVPNRouterAssociationClient(
            cls.os_primary.auth_provider)
        cls.rtr_assoc_client_admin = bgpvpn_client.\
            BGPVPNRouterAssociationClient(cls.os_admin.auth_provider)

    @contextlib.contextmanager
    def bgpvpn(self, do_delete=True, as_admin=True, **kwargs):
        client = self.bgpvpn_client_admin if as_admin else self.bgpvpn_client
        bgpvpn = {'name': data_utils.rand_name('bgpvpn')}
        bgpvpn.update(kwargs)
        bgpvpn = client.create_bgpvpn(**bgpvpn)
        try:
            yield bgpvpn
        finally:
            if do_delete:
                client.delete_bgpvpn(bgpvpn['id'])

    @contextlib.contextmanager
    def router_association(self, router_id, bgpvpn_id, do_delete=True,
                           as_admin=False, **kwargs):
        client = (self.rtr_assoc_client_admin if as_admin
                  else self.rtr_assoc_client)
        rtr_assoc = {'router_id': router_id}
        rtr_assoc.update(kwargs)
        rtr_assoc = client.create_router_association(bgpvpn_id, **rtr_assoc)
        try:
            yield rtr_assoc
        finally:
            if do_delete:
                client.delete_router_association(rtr_assoc['id'], bgpvpn_id)

    @contextlib.contextmanager
    def network_association(self, network_id, bgpvpn_id, do_delete=True,
                            as_admin=False, **kwargs):
        client = (self.net_assoc_client_admin if as_admin
                  else self.net_assoc_client)
        net_assoc = {'network_id': network_id}
        net_assoc.update(kwargs)
        net_assoc = client.create_network_association(bgpvpn_id, **net_assoc)
        try:
            yield net_assoc
        finally:
            if do_delete:
                client.delete_network_association(net_assoc['id'], bgpvpn_id)
