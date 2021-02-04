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
import socket
import time

import openstack
from openstack.exceptions import SDKException
from tempest.common import waiters
from tempest.lib.services.compute import base_compute_client

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology

LOG = Topology.get_logger(__name__)
CONF = Topology.get_conf()


class NovaEvacuateTest(nuage_test.NuageBaseTest):

    @classmethod
    def skip_checks(cls):
        super(NovaEvacuateTest, cls).skip_checks()
        if Topology.tempest_concurrency > 1:
            raise cls.skipException('Skip Nova evacuate tests when multiple '
                                    'tempest workers are present')

    def test_nova_evacuate_reboot_hv(self):
        """test_nova_evacuate_reboot_hv

        Spin a VM on a hypervisor
        Bring down hypervisor
        Nova evacuate VM
        Bring up hypervisor
        Make sure connectivity remains
        """
        network = self.create_network()
        subnet = self.create_subnet(
            network, ip_version=4, mask_bits=24,
            enable_dhcp=True)
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.router_attach(router, subnet)
        security_group = self.create_open_ssh_security_group()
        server1 = self.create_tenant_server(
            networks=[network],
            security_groups=[security_group],
            prepare_for_connectivity=True)
        server2 = self.create_tenant_server(
            networks=[network],
            security_groups=[security_group],
            prepare_for_connectivity=True,
            scheduler_hints={'different_host': server1.id}
        )

        # Find the server that is running on the local compute
        if server1.get_hypervisor_hostname() == socket.gethostname():
            local_server = server1
            remote_server = server2
        else:
            local_server = server2
            remote_server = server1

        self.assert_ping(local_server, remote_server, network=network,
                         ip_version=4)

        remote_host = remote_server.get_hypervisor_hostname()
        # strip out novalocal if necessary
        remote_host.replace('.novalocal', '')

        # connect to undercloud / controller of hypervisor
        # Requirement: clouds.yaml with undercloud defined
        connection = openstack.connect(cloud=CONF.nuage_sut.undercloud_name)
        # Find remote host, a hv in the undercloud
        remote_host_hv = connection.compute.find_server(remote_host)
        connection.compute.stop_server(remote_host_hv)

        def cleanup_stopped_remote_hv_server(hv_server):
            # Assure remote hypervisor is booted at end of test even when
            # there is a failure.
            try:
                connection.compute.start_server(hv_server)
            except SDKException:
                # Already started VM
                pass

        self.addCleanup(cleanup_stopped_remote_hv_server, remote_host_hv)
        connection.compute.wait_for_server(remote_host_hv, status='SHUTOFF')

        # Nova evacuate
        # Wait for compute service to notice outage.
        time.sleep(60)
        base_compute_client.COMPUTE_MICROVERSION = 'latest'
        enable_instance_password = (
            self.admin_manager.servers_client.enable_instance_password)
        self.admin_manager.servers_client.enable_instance_password = False
        self.admin_manager.servers_client.evacuate_server(
            remote_server.id)
        self.admin_manager.servers_client.enable_instance_password = (
            enable_instance_password)
        base_compute_client.COMPUTE_MICROVERSION = None
        waiters.wait_for_server_status(self.manager.servers_client,
                                       remote_server.id, 'ACTIVE')
        remote_server.waiting_for_cloudinit_completion = False
        remote_server.cloudinit_complete = False
        remote_server.wait_for_cloudinit_to_complete()

        # Assert traffic is restored
        self.assert_ping(local_server, remote_server, network=network,
                         ip_version=4)

        # Boot remote hv
        connection.compute.start_server(remote_host_hv)
        connection.compute.wait_for_server(remote_host_hv, status='ACTIVE')

        # Wait 60s for boot process to finish
        time.sleep(60)

        # Assert traffic is not aborted by remote hv booting
        self.assert_ping(local_server, remote_server, network=network,
                         ip_version=4)
