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


class L3Mixin(base.BaseMixin):

    @classmethod
    def setup_clients(cls):
        super(L3Mixin, cls).setup_clients()
        if cls.has_primary:
            cls.routers_client = cls.os_primary.routers_client
            cls.floating_ips_client = cls.os_primary.floating_ips_client
        if cls.has_admin:
            cls.routers_client_admin = cls.os_admin.routers_client
            cls.floating_ips_client_admin = cls.os_admin.floating_ips_client

    # ---------- Routers ----------

    def router_client(self, as_admin=False):
        if as_admin or not self.has_primary:
            return self.routers_client_admin
        return self.routers_client

    @contextlib.contextmanager
    def router(self, attached_subnets=[], attached_ports=[], as_admin=False,
               **kwargs):
        router = self.create_router(as_admin=as_admin, **kwargs)
        try:
            for subnet_id in attached_subnets:
                self.add_router_interface(router['id'], subnet_id=subnet_id,
                                          as_admin=as_admin)
            for port_id in attached_ports:
                self.add_router_interface(router['id'], port_id=port_id,
                                          as_admin=as_admin)
            yield router
        finally:
            for subnet_id in attached_subnets:
                self.remove_router_interface(router['id'], subnet_id=subnet_id)
            for port_id in attached_ports:
                self.remove_router_interface(router['id'], port_id=port_id)
            self.delete_router(router['id'])

    def get_router(self, router_id, as_admin=False):
        client = self.router_client(as_admin=as_admin)
        return client.show_router(router_id)['router']

    def show_router(self, router_id, as_admin=False):
        return self.get_router(router_id, as_admin=as_admin)

    def get_routers(self, as_admin=False, **kwargs):
        client = self.router_client(as_admin=as_admin)
        return client.list_routers(**kwargs)['routers']

    def list_routers(self, as_admin=False, **kwargs):
        return self.get_routers(as_admin=as_admin, **kwargs)

    def create_router(self, cleanup=True, as_admin=False, **kwargs):
        client = self.router_client(as_admin=as_admin)
        router = {'name': data_utils.rand_name('router')}
        router.update(kwargs)
        router = client.create_router(**router)['router']
        if cleanup:
            self.addCleanup(self.delete_router, router['id'])
        return router

    def update_router(self, router_id, as_admin=False, **kwargs):
        client = self.router_client(as_admin=as_admin)
        return client.update_router(router_id, **kwargs)['router']

    def delete_router(self, router_id, as_admin=False, ignore_not_found=True):
        client = self.router_client(as_admin=as_admin)
        try:
            client.delete_router(router_id)
        except exceptions.NotFound:
            if not ignore_not_found:
                raise

    def add_router_interface(self, router_id, subnet_id=None, port_id=None,
                             as_admin=False):
        if subnet_id and port_id:
            raise Exception("subnet_id and port_id are mutually exclusive.")
        if subnet_id is None and port_id is None:
            raise Exception("One of [subnet_id|port_id] should not be None.")
        client = self.router_client(as_admin=as_admin)
        if subnet_id is not None:
            interface = client.add_router_interface(router_id,
                                                    subnet_id=subnet_id)
        else:
            interface = client.add_router_interface(router_id,
                                                    port_id=port_id)
        self.addCleanup(self.remove_router_interface,
                        router_id, subnet_id=subnet_id, port_id=port_id,
                        ignore_not_found=True, as_admin=as_admin)
        return interface

    def remove_router_interface(self, router_id, subnet_id=None, port_id=None,
                                ignore_not_found=False, as_admin=False):
        if subnet_id and port_id:
            raise Exception("subnet_id and port_id are mutually exclusive.")
        if subnet_id is None and port_id is None:
            raise Exception("One of [subnet_id|port_id] should not be None.")
        client = self.router_client(as_admin=as_admin)
        try:
            if subnet_id is not None:
                client.remove_router_interface(router_id, subnet_id=subnet_id)
            if port_id is not None:
                client.remove_router_interface(router_id, port_id=port_id)
        except exceptions.NotFound:
            if not ignore_not_found:
                raise

    # ---------- Floatingips ----------

    def floatingip_client(self, as_admin=False):
        if as_admin or not self.has_primary:
            return self.floating_ips_client_admin
        return self.floating_ips_client

    @contextlib.contextmanager
    def floatingip(self, network_id, as_admin=False, **kwargs):
        fip = self.create_floatingip(network_id, as_admin=as_admin, **kwargs)
        try:
            yield fip
        finally:
            self.delete_floatingip(fip['id'])

    def get_floatingip(self, floatingip_id, as_admin=False):
        client = self.floatingip_client(as_admin=as_admin)
        return client.show_floatingip(floatingip_id)['floatingip']

    def show_floatingip(self, floatingip_id, as_admin=False):
        return self.get_floatingip(floatingip_id, as_admin=as_admin)

    def get_floatingips(self, as_admin=False, **kwargs):
        client = self.floatingip_client(as_admin=as_admin)
        return client.list_floatingips(**kwargs)['floatingips']

    def list_floatingips(self, as_admin=False, **kwargs):
        return self.get_floatingips(as_admin=as_admin, **kwargs)

    def create_floatingip(self, network_id, cleanup=False, as_admin=False,
                          **kwargs):
        client = self.floatingip_client(as_admin=as_admin)
        floatingip = {'name': data_utils.rand_name('floatingip'),
                      'floating_network_id': network_id}
        floatingip.update(kwargs)
        floatingip = client.create_floatingip(**floatingip)['floatingip']
        if cleanup:
            self.addCleanup(self.delete_floatingip, floatingip['id'])
        return floatingip

    def update_floatingip(self, floatingip_id, as_admin=False, **kwargs):
        client = self.floatingip_client(as_admin=as_admin)
        return client.update_floatingip(floatingip_id, **kwargs)['floatingip']

    def delete_floatingip(self, floatingip_id, as_admin=False,
                          ignore_not_found=True):
        client = self.floatingip_client(as_admin=as_admin)
        try:
            client.delete_floatingip(floatingip_id)
        except exceptions.NotFound:
            if not ignore_not_found:
                raise
