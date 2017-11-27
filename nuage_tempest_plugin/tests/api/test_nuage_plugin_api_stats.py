# Copyright 2017 Nokia
# All Rights Reserved.
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

from oslo_log import log as logging

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.test import decorators

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

CONF = config.CONF
LOG = logging.getLogger(__name__)


class NuagePluginApiStats(base.BaseAdminNetworkTest):
    _interface = 'json'

    os_version = Topology.openstack_version
    api_workers = Topology.api_workers
    api_count = 0
    api_discrepancies = []

    #
    # Expected API calls, 5.0 onwards ...
    #
    expected_api_calls = {
        'newton':
            {'create_network': 0,
             'create_subnet': 12,
             'create_security_group': 0,
             'create_port': 22,
             'create_subsequent_port': 6,
             'create_router': 12,
             'create_router_interface': 15,
             'remove_router_interface': 21,
             'delete_router': 3,
             'delete_port': 6,
             'delete_last_port': 5,
             'delete_security_group': 2,
             'delete_subnet': 6,
             'delete_network': 0
             },

        'ocata':
            {'create_network': 0,
             'create_subnet': 12,
             'create_security_group': 0,
             'create_port': 22,
             'create_subsequent_port': 6,
             'create_router': 12,
             'create_router_interface': 15,
             'remove_router_interface': 21,
             'delete_router': 3,
             'delete_port': 6,
             'delete_last_port': 5,
             'delete_security_group': 2,
             'delete_subnet': 6,
             'delete_network': 0
             },

        'pike':
            {'create_network': 0,
             'create_subnet': 12,
             'create_security_group': 0,
             'create_port': 21,
             'create_subsequent_port': 12,
             'create_router': 12,
             'create_router_interface': 15,
             'remove_router_interface': 21,
             'delete_router': 3,
             'delete_port': 6,
             'delete_last_port': 5,
             'delete_security_group': 2,
             'delete_subnet': 6,
             'delete_network': 0
             },

        'master':
            {'create_network': 0,
             'create_subnet': 12,
             'create_security_group': 0,
             'create_port': 21,
             'create_subsequent_port': 12,
             'create_router': 12,
             'create_router_interface': 15,
             'remove_router_interface': 21,
             'delete_router': 3,
             'delete_port': 6,
             'delete_last_port': 5,
             'delete_security_group': 2,
             'delete_subnet': 6,
             'delete_network': 0
             }
    }

    @classmethod
    def setup_clients(cls):
        super(NuagePluginApiStats, cls).setup_clients()
        cls.client = NuageNetworkClientJSON(
            cls.os_admin.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os_admin.default_params)

    @classmethod
    def skip_checks(cls):
        super(NuagePluginApiStats, cls).skip_checks()
        if cls.api_workers != 1:
            msg = ('Test requires neutron to be set up with '
                   'single api worker.')
            raise cls.skipException(msg)

    def _reset_api_calls(self):
        self.api_count = self.client.get_nuage_api_count()
        self.api_discrepancies = []

    def _actual_api_calls(self):
        new_api_count = self.client.get_nuage_api_count()
        actual_api_calls = new_api_count - self.api_count
        self.api_count = new_api_count
        return actual_api_calls

    def _validate_api_calls(self, operation):
        actual_cnt = self._actual_api_calls()
        expected_cnt = self.expected_api_calls[self.os_version][operation]
        if actual_cnt != expected_cnt:
            api_discrepancy = '{:s} expected {:d} api calls, got {:d}'.format(
                operation, expected_cnt, actual_cnt)
            self.api_discrepancies.append(api_discrepancy)
            LOG.error(api_discrepancy)

    def create_security_group(self):
        return self.security_groups_client.create_security_group(
            name=data_utils.rand_name('secgroup-'))['security_group']

    def fail_test(self, reason, skip_instead_of_fail=True):
        if skip_instead_of_fail:  # Leave room for analysis
            self.skipTest(reason)
        else:
            self.fail(reason)

    @decorators.attr(type='smoke')
    def test_api_counts_for_virtio(self):

        self._reset_api_calls()

        # create network
        network = self.create_network()
        self._validate_api_calls('create_network')

        # create subnet
        subnet = self.create_subnet(network)
        self._validate_api_calls('create_subnet')

        # create security group
        sg = self.create_security_group()
        self._validate_api_calls('create_security_group')

        # create port
        port = self.create_port(network, security_groups=[sg['id']])
        self._validate_api_calls('create_port')

        # create subsequent port
        port2 = self.create_port(network, security_groups=[sg['id']])
        self._validate_api_calls('create_subsequent_port')

        # create router
        router = self.create_router()
        self._validate_api_calls('create_router')

        # router subnet-attach
        self.create_router_interface(router['id'], subnet['id'])
        self._validate_api_calls('create_router_interface')

        # router subnet-detach
        self.routers_client.remove_router_interface(
            router['id'], subnet_id=subnet['id'])
        self._validate_api_calls('remove_router_interface')

        # delete router
        self.delete_router(router)
        self._validate_api_calls('delete_router')

        # delete port
        self.ports_client.delete_port(port2['id'])
        self._validate_api_calls('delete_port')

        # delete last port
        self.ports_client.delete_port(port['id'])
        self._validate_api_calls('delete_last_port')

        # delete security group
        self.security_groups_client.delete_security_group(sg['id'])
        self._validate_api_calls('delete_security_group')

        # delete subnet
        self.subnets_client.delete_subnet(subnet['id'])
        self._validate_api_calls('delete_subnet')

        # delete network
        self.networks_client.delete_network(network['id'])
        self._validate_api_calls('delete_network')

        # consolidate
        if self.api_discrepancies:
            self.fail_test('{:d} api call discrepancies observed:\n'.
                           format(len(self.api_discrepancies)) +
                           '\n'.join(self.api_discrepancies))
