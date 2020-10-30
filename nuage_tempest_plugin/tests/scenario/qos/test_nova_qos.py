# Copyright 2016 Red Hat, Inc., 2020 NOKIA
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

from oslo_log import log
from tempest.common import waiters
from tempest.lib.services.compute import base_compute_client
import testtools

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils
from nuage_tempest_plugin.tests.scenario.qos import base_nuage_qos

LOG = log.getLogger(__name__)

CONF = Topology.get_conf()


class NuageNovaQosTest(base_nuage_qos.NuageQosTestmixin,
                       nuage_test.NuageBaseTest):

    def _create_nova_qos_flavor(self, bw_limit):
        # Create a flavor with rate limiting
        flavors_client = self.admin_manager.flavors_client
        default_flavor = flavors_client.show_flavor(
            CONF.compute.flavor_ref)
        default_flavor = default_flavor['flavor']
        body = flavors_client.create_flavor(
            name='Nova RateLimit',
            disk=default_flavor['disk'],
            ram=default_flavor['ram'],
            vcpus=default_flavor['vcpus']
        )
        flavor = body['flavor']
        self.addCleanup(flavors_client.delete_flavor, flavor['id'])
        default_extra_specs = flavors_client.list_flavor_extra_specs(
            default_flavor['id'])['extra_specs']
        extra_specs = {'quota:vif_outbound_average': str(bw_limit),
                       'quota:vif_inbound_peak': str(bw_limit),
                       'quota:vif_outbound_peak': str(bw_limit),
                       'quota:vif_inbound_average': str(bw_limit)}
        extra_specs.update(default_extra_specs)
        flavors_client.set_flavor_extra_spec(
            flavor['id'], **extra_specs)
        return flavor

    @testtools.skipUnless(CONF.compute.min_compute_nodes > 1,
                          'Less than 2 compute nodes, skipping multinode '
                          'tests.')
    def test_nova_qos_migration(self):
        """Test migration QOS when using NOVA flavor

        """
        BW_LIMIT_NOVA = 1000
        BW_LIMIT_NOVA_FLAVOR = BW_LIMIT_NOVA // 8

        network = self.create_network()
        subnet4 = self.create_subnet(network=network)
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.router_attach(router, subnet4)

        # Ensure TCP traffic is allowed
        security_group = self.create_open_ssh_security_group()
        self.create_traffic_sg_rule(security_group,
                                    direction='ingress',
                                    ip_version=4,
                                    dest_port=self.DEST_PORT)

        # Create NOVA QOS flavor
        flavor = self._create_nova_qos_flavor(BW_LIMIT_NOVA_FLAVOR)

        server = self.create_tenant_server(
            networks=[network], security_groups=[security_group],
            flavor=flavor['id'], prepare_for_connectivity=True)

        # Check bw limited
        data_utils.wait_until_true(
            lambda: self._check_bw(
                server, port=self.DEST_PORT, configured_bw_kbps=BW_LIMIT_NOVA,
                direction='egress'),
            timeout=120,
            exception=data_utils.WaitTimeout(
                "Timed out waiting for traffic to be limited in egress "
                "direction before migration"))
        data_utils.wait_until_true(
            lambda: self._check_bw(
                server, port=self.DEST_PORT, configured_bw_kbps=BW_LIMIT_NOVA,
                direction='ingress'),
            timeout=120,
            exception=data_utils.WaitTimeout(
                "Timed out waiting for traffic to be limited in ingress "
                "direction before migration"))

        # Migrate
        server_show = server.get_server_details()
        original_host = server_show['hostId']
        # Set Nova API to latest for better api support
        base_compute_client.COMPUTE_MICROVERSION = 'latest'
        self.admin_manager.servers_client.live_migrate_server(
            server_show['id'], block_migration='auto', host=None)
        base_compute_client.COMPUTE_MICROVERSION = None
        server.wait_for_cloudinit_to_complete()
        waiters.wait_for_server_status(self.manager.servers_client,
                                       server_show['id'], 'ACTIVE')
        server.server_details = None
        server_show = server.get_server_details()
        self.assertNotEqual(original_host, server_show['hostId'],
                            "Migration did not happen")
        # Check bw limited
        data_utils.wait_until_true(
            lambda: self._check_bw(
                server, port=self.DEST_PORT, configured_bw_kbps=BW_LIMIT_NOVA,
                direction='egress'),
            timeout=120,
            exception=data_utils.WaitTimeout(
                "Timed out waiting for traffic to be limited in egress "
                "direction after migration"))
        data_utils.wait_until_true(
            lambda: self._check_bw(
                server, port=self.DEST_PORT, configured_bw_kbps=BW_LIMIT_NOVA,
                direction='ingress'),
            timeout=120,
            exception=data_utils.WaitTimeout(
                "Timed out waiting for traffic to be limited in ingress "
                "direction after migration"))

    def test_nova_qos_fip_rate_limiting(self):
        """Test QOS when using NOVA flavor, with nuage fip rate limiting

        """
        BW_LIMIT_NOVA = 1000
        BW_LIMIT_NOVA_FLAVOR = BW_LIMIT_NOVA // 8
        BW_LIMIT_FIP_EGRESS = 500
        BW_LIMIT_FIP_INGRESS = 250

        network = self.create_network()
        subnet4 = self.create_subnet(network=network)
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.router_attach(router, subnet4)

        # Ensure TCP traffic is allowed
        security_group = self.create_open_ssh_security_group()
        self.create_traffic_sg_rule(security_group,
                                    direction='ingress',
                                    ip_version=4,
                                    dest_port=self.DEST_PORT)

        # Create NOVA QOS flavor
        flavor = self._create_nova_qos_flavor(BW_LIMIT_NOVA_FLAVOR)

        server = self.create_tenant_server(
            networks=[network], security_groups=[security_group],
            flavor=flavor['id'], prepare_for_connectivity=True)

        # Check bw limited
        data_utils.wait_until_true(
            lambda: self._check_bw(
                server, port=self.DEST_PORT, configured_bw_kbps=BW_LIMIT_NOVA,
                direction='egress'),
            timeout=120,
            exception=data_utils.WaitTimeout(
                "Timed out waiting for traffic to be limited in egress "
                "direction"))
        data_utils.wait_until_true(
            lambda: self._check_bw(
                server, port=self.DEST_PORT, configured_bw_kbps=BW_LIMIT_NOVA,
                direction='ingress'),
            timeout=120,
            exception=data_utils.WaitTimeout(
                "Timed out waiting for traffic to be limited in ingress "
                "direction"))

        # Set ingress & egress fip rate limiting
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=BW_LIMIT_FIP_EGRESS,
            nuage_ingress_fip_rate_kbps=BW_LIMIT_FIP_INGRESS)
        # Check bw limited
        data_utils.wait_until_true(
            lambda: self._check_bw(
                server, port=self.DEST_PORT,
                configured_bw_kbps=BW_LIMIT_FIP_EGRESS, direction='egress'),
            timeout=120,
            exception=data_utils.WaitTimeout(
                "Timed out waiting for traffic to be limited in egress "
                "direction"))
        # VRS-47436: No OS ingress RL, no VSD egress fip rate limiting
        # data_utils.wait_until_true(
        #     lambda: self._check_bw(
        #         server, port=self.DEST_PORT,
        #         configured_bw_kbps=BW_LIMIT_FIP_INGRESS,
        #         direction='ingress'),
        #     timeout=120,
        #     exception=data_utils.WaitTimeout(
        #         "Timed out waiting for traffic to be limited in ingress "
        #         "direction"))

        # Remove fip rate limit
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=-1,
            nuage_ingress_fip_rate_kbps=-1)

        # Check bw limited again to original nova qos
        # TODO(Tom) create ticket for this when executing nova qos testplan
        # data_utils.wait_until_true(
        #     lambda: self._check_bw(
        #         server, port=self.DEST_PORT,
        #         configured_bw_kbps=BW_LIMIT_NOVA,
        #         direction='egress'),
        #     timeout=120,
        #     exception=data_utils.WaitTimeout(
        #         "Timed out waiting for traffic to be limited in egress "
        #         "direction"))
        # data_utils.wait_until_true(
        #     lambda: self._check_bw(
        #         server, port=self.DEST_PORT,
        #         configured_bw_kbps=BW_LIMIT_NOVA,
        #         direction='ingress'),
        #     timeout=120,
        #     exception=data_utils.WaitTimeout(
        #         "Timed out waiting for traffic to be limited in ingress "
        #         "direction"))
