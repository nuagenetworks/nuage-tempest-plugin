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

from nuage_tempest_plugin.lib.mixins import base
from nuage_tempest_plugin.services.net_topology import net_topology_client


class NetTopologyMixin(base.BaseMixin):

    @classmethod
    def setup_clients(cls):
        super(NetTopologyMixin, cls).setup_clients()

        cls.switchport_mapping_client_admin = net_topology_client.\
            SwitchportMappingClient(cls.os_admin.auth_provider)
        cls.switchport_binding_client_admin = net_topology_client.\
            SwitchportBindingClient(cls.os_admin.auth_provider)

    @contextlib.contextmanager
    def switchport_mapping(self, do_delete=True, **kwargs):
        client = self.switchport_mapping_client_admin
        mapping = {}
        mapping.update(kwargs)
        mapping = client.create_switchport_mapping(**mapping)
        try:
            yield mapping
        finally:
            if do_delete:
                client.delete_switchport_mapping(mapping['id'])
