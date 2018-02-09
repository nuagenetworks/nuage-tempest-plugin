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
import netaddr

from tempest.common.utils import data_utils
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.mixins import base
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON


class NetworkMixin(base.BaseMixin):

    @classmethod
    def setup_clients(cls):
        super(NetworkMixin, cls).setup_clients()
        if cls.has_primary:
            cls.networks_client = cls.os_primary.networks_client
            cls.subnets_client = cls.os_primary.subnets_client
            cls.ports_client = cls.os_primary.ports_client
            cls.plugin_network_client = NuageNetworkClientJSON(
                cls.os_primary.auth_provider,
                **cls.os_primary.default_params)

        if cls.has_admin:
            cls.networks_client_admin = cls.os_admin.networks_client
            cls.subnets_client_admin = cls.os_admin.subnets_client
            cls.ports_client_admin = cls.os_admin.ports_client
            cls.plugin_network_client_admin = NuageNetworkClientJSON(
                cls.os_admin.auth_provider,
                **cls.os_admin.default_params)

    # ---------- Networks ----------

    def net_client(self, as_admin=False):
        if as_admin or not self.has_primary:
            return self.networks_client_admin
        return self.networks_client

    @contextlib.contextmanager
    def network(self, as_admin=False, **kwargs):
        network = self.create_network(cleanup=False, as_admin=as_admin,
                                      **kwargs)
        try:
            yield network
        finally:
            self.delete_network(network['id'], as_admin=as_admin)

    def get_network(self, network_id, as_admin=False):
        client = self.net_client(as_admin)
        return client.show_network(network_id)['network']

    def show_network(self, network_id, as_admin=False):
        return self.get_network(network_id, as_admin=as_admin)

    def get_networks(self, as_admin=False, **kwargs):
        client = self.net_client(as_admin)
        return client.list_networks(**kwargs)['networks']

    def list_networks(self, as_admin=False, **kwargs):
        return self.get_networks(as_admin=as_admin, **kwargs)

    def create_network(self, as_admin=False, cleanup=True, **kwargs):
        client = self.net_client(as_admin)
        network = {'name': data_utils.rand_name('network')}
        network.update(kwargs)
        network = client.create_network(**network)['network']
        if cleanup:
            self.addCleanup(self.delete_network, network['id'],
                            as_admin=as_admin)
        return network

    def update_network(self, network_id, as_admin=False, **kwargs):
        client = self.net_client(as_admin)
        return client.update_network(network_id, **kwargs)['network']

    def delete_network(self, network_id,
                       as_admin=False, ignore_not_found=True):
        client = self.net_client(as_admin)
        try:
            client.delete_network(network_id)
        except exceptions.NotFound:
            if not ignore_not_found:
                raise

    # ---------- Subnets ----------

    def subnet_client(self, as_admin=False):
        if as_admin or not self.has_primary:
            return self.subnets_client_admin
        return self.subnets_client

    @contextlib.contextmanager
    def subnet(self, cidr, network_id, as_admin=False, **kwargs):
        subnet = self.create_subnet(cidr, network_id, cleanup=False,
                                    as_admin=as_admin, **kwargs)
        try:
            yield subnet
        finally:
            self.delete_subnet(subnet['id'])

    def get_subnet(self, subnet_id, as_admin=False):
        client = self.subnet_client(as_admin=as_admin)
        return client.show_subnet(subnet_id)['subnet']

    def show_subnet(self, subnet_id, as_admin=False):
        return self.get_subnet(subnet_id, as_admin=as_admin)

    def get_subnets(self, as_admin=False, **kwargs):
        client = self.subnet_client(as_admin=as_admin)
        return client.list_subnets(**kwargs)['subnets']

    def list_subnets(self, as_admin=False, **kwargs):
        return self.get_subnets(as_admin=as_admin, **kwargs)

    def create_subnet(self, cidr, network_id,
                      as_admin=False, cleanup=True, **kwargs):
        client = self.subnet_client(as_admin=as_admin)
        subnet = {'name': data_utils.rand_name('subnet'),
                  'cidr': cidr,
                  'network_id': network_id,
                  'ip_version': netaddr.IPNetwork(cidr).version}
        subnet.update(kwargs)
        subnet = client.create_subnet(**subnet)['subnet']
        if cleanup:
            self.addCleanup(self.delete_subnet, subnet['id'],
                            as_admin=as_admin)
        return subnet

    def update_subnet(self, subnet_id, as_admin=False, **kwargs):
        client = self.subnet_client(as_admin=as_admin)
        return client.update_subnet(subnet_id, **kwargs)['subnet']

    def delete_subnet(self, subnet_id, as_admin=False, ignore_not_found=True):
        client = self.subnet_client(as_admin=as_admin)
        try:
            client.delete_subnet(subnet_id)
        except exceptions.NotFound:
            if not ignore_not_found:
                raise

    # ---------- Ports ----------

    def port_client(self, as_admin=False):
        if as_admin or not self.has_primary:
            return self.ports_client_admin
        return self.ports_client

    @contextlib.contextmanager
    def port(self, network_id, as_admin=False, **kwargs):
        port = self.create_port(network_id, cleanup=False, as_admin=as_admin,
                                **kwargs)
        try:
            yield port
        finally:
            self.delete_port(port['id'])

    def get_port(self, port_id, as_admin=False):
        client = self.port_client(as_admin=as_admin)
        return client.show_port(port_id)['port']

    def show_port(self, port_id, as_admin=False):
        return self.get_port(port_id, as_admin=as_admin)

    def get_ports(self, as_admin=False, **kwargs):
        client = self.port_client(as_admin=as_admin)
        return client.list_ports(**kwargs)['ports']

    def list_ports(self, as_admin=False, **kwargs):
        return self.get_ports(as_admin=as_admin, **kwargs)

    def create_port(self, network_id, cleanup=True, as_admin=False, **kwargs):
        client = self.port_client(as_admin=as_admin)
        port = {'name': data_utils.rand_name('port'),
                'network_id': network_id}
        port.update(kwargs)
        port = client.create_port(**port)['port']
        if cleanup:
            self.addCleanup(self.delete_port, port['id'])
        return port

    def update_port(self, port_id, as_admin=False, **kwargs):
        client = self.port_client(as_admin=as_admin)
        return client.update_port(port_id, **kwargs)['port']

    def delete_port(self, port_id, as_admin=False, ignore_not_found=True):
        client = self.port_client(as_admin=as_admin)
        try:
            client.delete_port(port_id)
        except exceptions.NotFound:
            if not ignore_not_found:
                raise

    # ---------- Trunks ----------
    def trunk_client(self, as_admin=False):
        if as_admin or not self.has_primary:
            return self.plugin_network_client_admin
        return self.plugin_network_client

    @contextlib.contextmanager
    def trunk(self, parent_port_id, subports=None,
              as_admin=False, **kwargs):
        client = self.trunk_client(as_admin=as_admin)
        trunk = client.create_trunk(parent_port_id=parent_port_id,
                                    subports=subports,
                                    as_admin=as_admin,
                                    **kwargs)
        try:
            yield trunk
        finally:
            self.remove_subports(trunk['id'], subports)
            self.delete_trunk(trunk['id'])

    def get_trunk(self, trunk_id, as_admin=False):
        client = self.trunk_client(as_admin=as_admin)
        return client.show_trunk(trunk_id)['trunk']

    def show_trunk(self, trunk_id, as_admin=False):
        return self.get_trunk(trunk_id, as_admin=as_admin)

    def get_trunks(self, as_admin=False, **kwargs):
        client = self.trunk_client(as_admin=as_admin)
        return client.list_trunks(**kwargs)['trunks']

    def list_trunks(self, as_admin=False, **kwargs):
        return self.get_trunks(as_admin=as_admin, **kwargs)

    def create_trunk(self, parent_port_id, subports,
                     cleanup=True, as_admin=False, **kwargs):
        client = self.trunk_client(as_admin=as_admin)
        trunk = {'name': data_utils.rand_name('trunk')}
        trunk.update(kwargs)
        trunk = client.create_trunk(parent_port_id,
                                    subports, **trunk)['trunk']
        if cleanup:
            self.addCleanup(self.delete_trunk, trunk['id'])
            if subports:
                self.addCleanup(self.remove_subports, trunk['id'], subports,
                                ignore_not_found=True, as_admin=as_admin)
        return trunk

    def update_trunk(self, trunk_id, as_admin=False, **kwargs):
        client = self.trunk_client(as_admin=as_admin)
        return client.update_trunk(trunk_id, **kwargs)['trunk']

    def delete_trunk(self, trunk_id, as_admin=False, ignore_not_found=True):
        client = self.trunk_client(as_admin=as_admin)
        try:
            client.delete_trunk(trunk_id)
        except exceptions.NotFound:
            if not ignore_not_found:
                raise

    def add_subports(self, trunk_id, subports, as_admin=False):
        client = self.trunk_client(as_admin=as_admin)
        sub_ports = client.add_subports(trunk_id, subports)['sub_ports']
        self.addCleanup(self.remove_subports, trunk_id, sub_ports,
                        ignore_not_found=True, as_admin=as_admin)
        return sub_ports

    def remove_subports(self, trunk_id, subports,
                        ignore_not_found=False, as_admin=False):
        client = self.trunk_client(as_admin=as_admin)
        try:
            return client.remove_subports(trunk_id, subports)['sub_ports']
        except exceptions.NotFound:
            if not ignore_not_found:
                raise

    def get_subports(self, trunk_id, as_admin=False):
        client = self.trunk_client(as_admin=as_admin)
        return client.get_subports(trunk_id)['sub_ports']

    # ---------- Agents ----------

    dhcp_agent_present = None

    def is_dhcp_agent_present(self):
        if self.dhcp_agent_present is None:
            agents = self.os_admin.network_agents_client.list_agents() \
                .get('agents')
            if agents:
                self.dhcp_agent_present = any(
                    agent for agent in agents if agent['alive'] and
                    agent['binary'] == 'neutron-dhcp-agent')
            else:
                self.dhcp_agent_present = False

        return self.dhcp_agent_present
