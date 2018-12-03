# Copyright 2018 NOKIA
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

from nuage_tempest_lib.tests.nuage_test import NuageBaseTest
from nuage_tempest_lib.vsdclient.nuage_network_client \
    import NuageNetworkClientJSON


class BaseNuageL2Bridge(NuageBaseTest):
    @classmethod
    def setup_clients(cls):
        super(BaseNuageL2Bridge, cls).setup_clients()
        cls.NuageNetworksClient = NuageNetworkClientJSON(
            cls.os_admin.auth_provider,
            **cls.os_admin.default_params)
        cls.NuageNetworksClientNonAdmin = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)

    def create_l2bridge(self, name, physnets, is_admin=True, cleanup=True):
        if is_admin:
            body = self.NuageNetworksClient.create_nuage_l2bridge(
                name, physnets=physnets)
        else:
            body = self.NuageNetworksClientNonAdmin.create_nuage_l2bridge(
                name, physnets=physnets)
        bridge = body['nuage_l2bridge']
        if cleanup:
            self.addCleanup(self.delete_l2bridge, bridge['id'])
        return bridge

    def get_l2bridge(self, l2bridge_id):
        body = self.NuageNetworksClient.get_nuage_l2bridge(l2bridge_id)
        return body['nuage_l2bridge']

    def update_l2bridge(self, l2bridge_id, name=None, physnets=None,
                        is_admin=True):
        if is_admin:
            if name and physnets:
                body = self.NuageNetworksClient.update_nuage_l2bridge(
                    l2bridge_id,
                    name=name, physnets=physnets)
            elif name:
                body = self.NuageNetworksClient.update_nuage_l2bridge(
                    l2bridge_id,
                    name=name)
            elif physnets:
                body = self.NuageNetworksClient.update_nuage_l2bridge(
                    l2bridge_id,
                    physnets=physnets)
        else:
            if name and physnets:
                body = self.NuageNetworksClientNonAdmin.update_nuage_l2bridge(
                    l2bridge_id,
                    name=name, physnets=physnets)
            elif name and not physnets:
                body = self.NuageNetworksClientNonAdmin.update_nuage_l2bridge(
                    l2bridge_id,
                    name=name)
            elif physnets and not name:
                body = self.NuageNetworksClientNonAdmin.update_nuage_l2bridge(
                    l2bridge_id,
                    physnets=physnets)
        return body['nuage_l2bridge']

    def delete_l2bridge(self, l2bridge_id):
        self.NuageNetworksClient.delete_nuage_l2bridge(l2bridge_id)
