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
from tempest.lib import exceptions
from tempest.lib.services.compute import base_compute_client
from tempest.test import decorators
import testtools

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils
from nuage_tempest_plugin.tests.scenario.qos import base_nuage_qos

LOG = log.getLogger(__name__)

CONF = Topology.get_conf()


class NuageNovaQosTest(base_nuage_qos.NuageQosTestmixin,
                       nuage_test.NuageBaseTest):
    # NOVA QOS is average based so download duration needs to be longer
    DOWNLOAD_DURATION = 30

    @classmethod
    def skip_checks(cls):
        super(NuageNovaQosTest, cls).skip_checks()
        if not CONF.nuage_feature_enabled.nova_qos:
            raise cls.skipException('Nova/libvirt Qos support required')

    def _create_nova_qos_flavor(self, bw_limit):
        # Create a flavor with rate limiting
        flavors_client = self.admin_manager.flavors_client
        default_flavor = flavors_client.show_flavor(
            CONF.compute.flavor_ref)
        default_flavor = default_flavor['flavor']
        flavor_name = self.get_randomized_name()
        body = flavors_client.create_flavor(
            name=flavor_name,
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
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_NOVA,
                             ingress_bw=BW_LIMIT_NOVA,
                             test_msg='Nova QOS before migration.')

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
                            'Migration did not happen')
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_NOVA,
                             ingress_bw=BW_LIMIT_NOVA,
                             test_msg='Nova QOS after migration.')

    @testtools.skipUnless(CONF.compute.min_compute_nodes > 1,
                          'Less than 2 compute nodes, skipping multinode '
                          'tests.')
    @testtools.skipIf(
        not CONF.nuage_feature_enabled.proprietary_fip_rate_limiting,
        'Support for fip rate limiting required')
    def test_nova_qos_fip_rate_limit_migration(self):
        """test_nova_qos_fip_rate_limit_migration

        Test migration QOS when using NOVA flavor and fip rate limiting

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
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        # Set ingress & egress fip rate limiting
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=BW_LIMIT_FIP_EGRESS,
            nuage_ingress_fip_rate_kbps=BW_LIMIT_FIP_INGRESS)

        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP_EGRESS,
                             ingress_bw=BW_LIMIT_FIP_INGRESS,
                             test_msg='FIP QOS before migration.')

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
                            'Migration did not happen')
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP_EGRESS,
                             ingress_bw=BW_LIMIT_FIP_INGRESS,
                             test_msg='FIP QOS after migration.')

    @testtools.skipUnless(CONF.compute.min_compute_nodes > 1,
                          'Less than 2 compute nodes, skipping multinode '
                          'tests.')
    def test_nova_qos_migration_update_flavor(self):
        """test_nova_qos_migration_update_flavor

        Test migration using Nova QOS:
        - Deploy with Flavor
        - Update Flavor after deploy, no datapath impact expected
        - Migrate VM, check original Nova QOS is active
        """
        BW_LIMIT_NOVA = 1000
        BW_LIMIT_NOVA_FLAVOR = BW_LIMIT_NOVA // 8
        BW_LIMIT_NOVA_UPDATE = 500
        BW_LIMIT_NOVA_UPDATE_FLAVOR = BW_LIMIT_NOVA_UPDATE // 8

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
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        flavors_client = self.admin_manager.flavors_client
        existing_extra_specs = flavors_client.list_flavor_extra_specs(
            flavor['id'])['extra_specs']
        extra_specs = {'quota:vif_outbound_average':
                       str(BW_LIMIT_NOVA_UPDATE_FLAVOR),
                       'quota:vif_inbound_peak':
                       str(BW_LIMIT_NOVA_UPDATE_FLAVOR),
                       'quota:vif_outbound_peak':
                       str(BW_LIMIT_NOVA_UPDATE_FLAVOR),
                       'quota:vif_inbound_average':
                       str(BW_LIMIT_NOVA_UPDATE_FLAVOR)}
        extra_specs.update(existing_extra_specs)
        flavors_client.set_flavor_extra_spec(
            flavor['id'], **extra_specs)

        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_NOVA,
                             ingress_bw=BW_LIMIT_NOVA,
                             test_msg='Nova QOS before migration.')

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
                            'Migration did not happen')
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_NOVA,
                             ingress_bw=BW_LIMIT_NOVA,
                             test_msg='Nova QOS after migration.')

    @testtools.skipUnless(CONF.compute.min_compute_nodes > 1,
                          'Less than 2 compute nodes, skipping multinode '
                          'tests.')
    @testtools.skipIf(
        not CONF.nuage_feature_enabled.proprietary_fip_rate_limiting,
        'Support for fip rate limiting required')
    def test_nova_qos_fip_rate_limit_update_flavor_migration(self):
        """test_nova_qos_fip_rate_limit_update_flavor_migration

        Test migration using Nova QOS:
        - Deploy with Flavor
        - Attach floating ip with rate limit
        - Update Flavor after deploy, no datapath impact expected
        - Migrate VM, check FIP rate limit is still active

        """
        BW_LIMIT_NOVA = 1000
        BW_LIMIT_NOVA_FLAVOR = BW_LIMIT_NOVA // 8
        BW_LIMIT_NOVA_UPDATE = 200
        BW_LIMIT_NOVA_UPDATE_FLAVOR = BW_LIMIT_NOVA_UPDATE // 8
        BW_LIMIT_FIP_EGRESS = 1500
        BW_LIMIT_FIP_INGRESS = 1250

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
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        # Set ingress & egress fip rate limiting
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=BW_LIMIT_FIP_EGRESS,
            nuage_ingress_fip_rate_kbps=BW_LIMIT_FIP_INGRESS)

        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP_EGRESS,
                             ingress_bw=BW_LIMIT_FIP_INGRESS,
                             test_msg='FIP QOS before migration.')

        # Update flavor
        flavors_client = self.admin_manager.flavors_client
        existing_extra_specs = flavors_client.list_flavor_extra_specs(
            flavor['id'])['extra_specs']
        extra_specs = {'quota:vif_outbound_average':
                       str(BW_LIMIT_NOVA_UPDATE_FLAVOR),
                       'quota:vif_inbound_peak':
                       str(BW_LIMIT_NOVA_UPDATE_FLAVOR),
                       'quota:vif_outbound_peak':
                       str(BW_LIMIT_NOVA_UPDATE_FLAVOR),
                       'quota:vif_inbound_average':
                       str(BW_LIMIT_NOVA_UPDATE_FLAVOR)}
        extra_specs.update(existing_extra_specs)
        flavors_client.set_flavor_extra_spec(
            flavor['id'], **extra_specs)

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
                            'Migration did not happen')
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP_EGRESS,
                             ingress_bw=BW_LIMIT_FIP_INGRESS,
                             test_msg='FIP QOS after migration.')

    @testtools.skipIf(
        not CONF.nuage_feature_enabled.proprietary_fip_rate_limiting,
        'Support for fip rate limiting required')
    @decorators.attr(type='smoke')
    def test_nova_qos_fip_rate_limiting(self):
        """test_nova_qos_fip_rate_limiting

        Test NOVA QOS with fip rate limiting interaction

        """
        BW_LIMIT_NOVA = 1000
        BW_LIMIT_NOVA_FLAVOR = BW_LIMIT_NOVA // 8
        BW_LIMIT_FIP_EGRESS = 500
        BW_LIMIT_FIP_INGRESS = 250
        BW_LIMIT_FIP_EGRESS_UPDATE = 200
        BW_LIMIT_FIP_INGRESS_UPDATE = 100

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
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_NOVA,
                             ingress_bw=BW_LIMIT_NOVA,
                             test_msg='Nova Qos only.')

        # Set ingress & egress fip rate limiting
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=BW_LIMIT_FIP_EGRESS,
            nuage_ingress_fip_rate_kbps=BW_LIMIT_FIP_INGRESS)
        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP_EGRESS,
                             ingress_bw=BW_LIMIT_FIP_INGRESS,
                             test_msg='Nova Qos + FIP.')

        # update ingress & egress fip rate limiting
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=BW_LIMIT_FIP_EGRESS_UPDATE,
            nuage_ingress_fip_rate_kbps=BW_LIMIT_FIP_INGRESS_UPDATE)
        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP_EGRESS_UPDATE,
                             ingress_bw=BW_LIMIT_FIP_INGRESS_UPDATE,
                             test_msg='Nova Qos + FIP updated.')

        # Remove fip rate limit
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=-1,
            nuage_ingress_fip_rate_kbps=-1)

        # Check bw limited again to original nova qos
        # VRS-48228: Fip rate limit clear does not restore Nova QOS
        # self._test_bandwidth(server, egress_bw=BW_LIMIT_NOVA,
        #                      ingress_bw=BW_LIMIT_NOVA,
        #                      test_msg='Nova Qos After Fip RL delete.')

    @testtools.skipIf(
        not CONF.nuage_feature_enabled.proprietary_fip_rate_limiting,
        'Support for fip rate limiting required')
    def test_nova_qos_fip_rate_limiting_reboot_vm(self):
        """Test QOS when using NOVA flavor, with nuage fip rate limiting

        """
        BW_LIMIT_NOVA = 1000
        BW_LIMIT_NOVA_FLAVOR = BW_LIMIT_NOVA // 8
        BW_LIMIT_FIP_EGRESS = 500
        BW_LIMIT_FIP_INGRESS = 250
        BW_LIMIT_FIP_EGRESS_UPDATE = 200
        BW_LIMIT_FIP_INGRESS_UPDATE = 100

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
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_NOVA,
                             ingress_bw=BW_LIMIT_NOVA,
                             test_msg='Nova Qos only.')

        # Reboot server
        self.manager.servers_client.reboot_server(server.id, type='HARD')
        waiters.wait_for_server_status(self.manager.servers_client, server.id,
                                       'ACTIVE')
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        self._test_bandwidth(server, egress_bw=BW_LIMIT_NOVA,
                             ingress_bw=BW_LIMIT_NOVA,
                             test_msg='Nova Qos only after reboot.')
        if not CONF.nuage_feature_enabled.proprietary_fip_rate_limiting:
            # no further testing possible, as fip rate limit is not supported.
            return

        # Set ingress & egress fip rate limiting
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=BW_LIMIT_FIP_EGRESS,
            nuage_ingress_fip_rate_kbps=BW_LIMIT_FIP_INGRESS)
        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP_EGRESS,
                             ingress_bw=BW_LIMIT_FIP_INGRESS,
                             test_msg='Nova Qos + FIP RL.')

        # Reboot server
        self.manager.servers_client.reboot_server(server.id, type='HARD')
        waiters.wait_for_server_status(self.manager.servers_client, server.id,
                                       'ACTIVE')
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP_EGRESS,
                             ingress_bw=BW_LIMIT_FIP_INGRESS,
                             test_msg='Nova Qos + FIP RL after reboot.')

        # update ingress & egress fip rate limiting
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=BW_LIMIT_FIP_EGRESS_UPDATE,
            nuage_ingress_fip_rate_kbps=BW_LIMIT_FIP_INGRESS_UPDATE)
        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP_EGRESS_UPDATE,
                             ingress_bw=BW_LIMIT_FIP_INGRESS_UPDATE,
                             test_msg='Nova Qos + FIP RL Updated.')

        # Reboot server
        self.manager.servers_client.reboot_server(server.id, type='HARD')
        waiters.wait_for_server_status(self.manager.servers_client, server.id,
                                       'ACTIVE')
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP_EGRESS_UPDATE,
                             ingress_bw=BW_LIMIT_FIP_INGRESS_UPDATE,
                             test_msg='Nova Qos + FIP RL updated '
                                      'after reboot.')

        # Remove fip rate limit
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=-1,
            nuage_ingress_fip_rate_kbps=-1)
        # Reboot server
        self.manager.servers_client.reboot_server(server.id, type='HARD')
        waiters.wait_for_server_status(self.manager.servers_client, server.id,
                                       'ACTIVE')
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        self._test_bandwidth(server, egress_bw=BW_LIMIT_NOVA,
                             ingress_bw=BW_LIMIT_NOVA,
                             test_msg='Nova Qos + deleted Fip RL '
                                      'after reboot.')

    @testtools.skipIf(
        not CONF.nuage_feature_enabled.proprietary_fip_rate_limiting,
        'Support for fip rate limiting required')
    def test_nova_qos_fip_rate_limit_disassociate(self):
        """test_nova_qos_fip_rate_limit_disassociate

        Test NOVA QOS with fip rate limiting when changing the
        associated fip.

        """
        BW_LIMIT_NOVA = 1000
        BW_LIMIT_NOVA_FLAVOR = BW_LIMIT_NOVA // 8
        BW_LIMIT_FIP_EGRESS = 500
        BW_LIMIT_FIP_INGRESS = 250
        BW_LIMIT_FIP_EGRESS_UPDATE = 200
        BW_LIMIT_FIP_INGRESS_UPDATE = 100

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
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        # update ingress & egress fip rate limiting
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=BW_LIMIT_FIP_EGRESS,
            nuage_ingress_fip_rate_kbps=BW_LIMIT_FIP_INGRESS)

        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP_EGRESS,
                             ingress_bw=BW_LIMIT_FIP_INGRESS,
                             test_msg='First associated floating ip.')

        # Disassociate current FIP & Associate new FIP
        self.update_floatingip(server.associated_fip, port_id=None)
        server.associated_fip = None
        port = server.get_server_port_in_network(network)
        self.create_fip_to_server(server, port=port)
        server.init_console()

        # update ingress & egress fip rate limiting
        self.update_floatingip(
            server.associated_fip,
            nuage_egress_fip_rate_kbps=BW_LIMIT_FIP_EGRESS_UPDATE,
            nuage_ingress_fip_rate_kbps=BW_LIMIT_FIP_INGRESS_UPDATE)

        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP_EGRESS_UPDATE,
                             ingress_bw=BW_LIMIT_FIP_INGRESS_UPDATE,
                             test_msg='Second associated floating ip.')

    @testtools.skipIf(
        not CONF.nuage_feature_enabled.proprietary_fip_rate_limiting,
        'Support for fip rate limiting required')
    def test_nova_qos_multinic(self):
        """test_nova_qos_multinic

        Test NOVA QOS with fip rate limiting when changing the
        associated fip.

        """
        BW_LIMIT_NOVA = 1000
        BW_LIMIT_NOVA_FLAVOR = BW_LIMIT_NOVA // 8
        BW_LIMIT_FIP_EGRESS1 = 500
        BW_LIMIT_FIP_INGRESS1 = 250
        BW_LIMIT_FIP_EGRESS2 = 200
        BW_LIMIT_FIP_INGRESS2 = 100

        network1 = self.create_network()
        cidr1 = data_utils.gimme_a_cidr()
        subnet41 = self.create_subnet(network=network1, cidr=cidr1)
        network2 = self.create_network()
        cidr2 = data_utils.gimme_a_cidr()
        subnet42 = self.create_subnet(network=network2, cidr=cidr2)
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.router_attach(router, subnet41)
        self.router_attach(router, subnet42)

        # Ensure TCP traffic is allowed
        security_group = self.create_open_ssh_security_group()
        self.create_traffic_sg_rule(security_group,
                                    direction='ingress',
                                    ip_version=4,
                                    dest_port=self.DEST_PORT)

        # Create NOVA QOS flavor
        flavor = self._create_nova_qos_flavor(BW_LIMIT_NOVA_FLAVOR)

        port1 = self.create_port(
            network=network1,
            security_groups=[security_group['id']])
        # router option = 0 to prevent default route being installed.
        port2 = self.create_port(
            network=network2,
            security_groups=[security_group['id']],
            extra_dhcp_opts=[{'opt_name': 'router', 'opt_value': '0'}])

        server = self.create_tenant_server(
            ports=[port1, port2],
            flavor=flavor['id'], prepare_for_connectivity=True)
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth0 mtu {}'.format(
            base_nuage_qos.QOS_MTU))
        # VRS-35132: Ethernet fragmentation causes QOS to drop packets.
        server.send('sudo ip link set dev eth1 mtu {}'.format(
            base_nuage_qos.QOS_MTU))

        # Associate a second IP to the second interface
        floatingip1 = server.associated_fip
        # Flip floating ip of server
        # First delete wrong default route, set timeout shorter because the
        # request will time out as return traffic does not have a route.
        original_timeout = server.console().ssh_client.timeout
        server.console().ssh_client.timeout = 10
        try:
            server.console().exec_command(
                'sudo ip r del default; '
                'sudo ip r add default via {}'.format(
                    subnet42['gateway_ip']))
        except exceptions.TimeoutException:
            pass
        server.console().ssh_client.timeout = original_timeout

        server.associated_fip = None
        self.create_fip_to_server(server, port=port2)
        server.init_console()
        floatingip2 = server.associated_fip
        # Test both FIPS throughput with only NOVA QOS active
        self._test_bandwidth(server, egress_bw=BW_LIMIT_NOVA,
                             ingress_bw=BW_LIMIT_NOVA,
                             test_msg='FIP2 with Nova QOS only.')
        # Flip floating ip of server
        # First delete wrong default route, set timeout shorter because the
        # request will time out as return traffic does not have a route.
        original_timeout = server.console().ssh_client.timeout
        server.console().ssh_client.timeout = 10
        try:
            server.console().exec_command(
                'sudo ip r del default; '
                'sudo ip r add default via {}'.format(
                    subnet41['gateway_ip']))
        except exceptions.TimeoutException:
            pass
        server.console().ssh_client.timeout = original_timeout
        server.associated_fip = floatingip1
        server.init_console()
        self._test_bandwidth(server, egress_bw=BW_LIMIT_NOVA,
                             ingress_bw=BW_LIMIT_NOVA,
                             test_msg='FIP1 with Nova Qos Only.')

        # update ingress & egress fip rate limiting
        self.update_floatingip(
            floatingip1,
            nuage_egress_fip_rate_kbps=BW_LIMIT_FIP_EGRESS1,
            nuage_ingress_fip_rate_kbps=BW_LIMIT_FIP_INGRESS1)
        self.update_floatingip(
            floatingip2,
            nuage_egress_fip_rate_kbps=BW_LIMIT_FIP_EGRESS2,
            nuage_ingress_fip_rate_kbps=BW_LIMIT_FIP_INGRESS2)

        # Check bw limited
        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP_EGRESS1,
                             ingress_bw=BW_LIMIT_FIP_INGRESS1,
                             test_msg='Fip1 with Fip RL active.')
        # Flip floating ip of server, change default route
        server.console().ssh_client.timeout = 10
        try:
            server.console().exec_command(
                'sudo ip r del default; '
                'sudo ip r add default via {}'.format(
                    subnet42['gateway_ip']))
        except exceptions.TimeoutException:
            pass
        server.console().ssh_client.timeout = original_timeout
        server.associated_fip = floatingip2
        server.init_console()
        self._test_bandwidth(server, egress_bw=BW_LIMIT_FIP_EGRESS2,
                             ingress_bw=BW_LIMIT_FIP_INGRESS2,
                             test_msg='Fip2 with Fip RL active.')
