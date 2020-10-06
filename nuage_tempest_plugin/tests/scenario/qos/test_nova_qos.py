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

from neutron_tempest_plugin.common import utils as common_utils
from neutron_tempest_plugin import config
from neutron_tempest_plugin.scenario import base as neutron_base
from oslo_log import log
from tempest.lib.common.utils import data_utils
from tempest.lib.services.compute import base_compute_client
import testtools

from nuage_tempest_plugin.tests.scenario.qos import base_nuage_qos

LOG = log.getLogger(__name__)

CONF = config.CONF


class NuageNovaQosTest(base_nuage_qos.NuageQoSTestMixin,
                       neutron_base.BaseTempestTestCase):

    credentials = ['primary', 'admin']

    LIMIT_KBPS = 120

    def setup_network_and_server(self, router=None, server_name=None,
                                 network=None, **kwargs):
        """Create network resources and a server.

        Creating a network, subnet, router, keypair, security group
        and a server.
        """
        self.network = network or self.create_network()
        LOG.debug("Created network %s", self.network['name'])
        self.subnet = self.create_subnet(self.network)
        LOG.debug("Created subnet %s", self.subnet['id'])

        secgroup = self.os_primary.network_client.create_security_group(
            name=data_utils.rand_name('secgroup'))
        LOG.debug("Created security group %s",
                  secgroup['security_group']['name'])
        self.security_groups.append(secgroup['security_group'])
        if not router:
            router = self.create_router_by_client(**kwargs)
        self.create_router_interface(router['id'], self.subnet['id'])
        self.keypair = self.create_keypair()
        self.create_loginable_secgroup_rule(
            secgroup_id=secgroup['security_group']['id'])

        # Create a flavor with rate limiting
        flavors_client = self.os_admin.compute.FlavorsClient()
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
        extra_specs = {'quota:vif_outbound_average': str(self.LIMIT_KBPS),
                       'quota:vif_inbound_peak': str(self.LIMIT_KBPS),
                       'quota:vif_outbound_peak': str(self.LIMIT_KBPS),
                       'quota:vif_inbound_average': str(self.LIMIT_KBPS)}
        extra_specs.update(default_extra_specs)
        flavors_client.set_flavor_extra_spec(
            flavor['id'], **extra_specs)

        server_kwargs = {
            'flavor_ref': flavor['id'],
            'image_ref': CONF.compute.image_ref,
            'key_name': self.keypair['name'],
            'networks': [{'uuid': self.network['id']}],
            'security_groups': [{'name': secgroup['security_group']['name']}],
        }
        if server_name is not None:
            server_kwargs['name'] = server_name

        self.server = self.create_server(**server_kwargs)
        self.wait_for_server_active(self.server['server'])
        self.port = self.client.list_ports(network_id=self.network['id'],
                                           device_id=self.server[
                                               'server']['id'])['ports'][0]
        self.fip = self.create_floatingip(port=self.port)

    @testtools.skipUnless(CONF.compute.min_compute_nodes > 1,
                          'Less than 2 compute nodes, skipping multinode '
                          'tests.')
    def test_nova_qos(self):
        """Test QOS when using NOVA flavor

        """
        self._test_basic_resources()
        ssh_client = self._create_ssh_client()
        if hasattr(self, 'FILE_SIZE'):
            # Queens & Rocky: create file
            self._create_file_for_bw_tests(ssh_client)

        limit_bytes_sec = self.LIMIT_KBPS * 1024 * self.TOLERANCE_FACTOR
        # Check bw limited
        common_utils.wait_until_true(
            lambda: self._check_bw(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT,
                expected_bw=limit_bytes_sec),
            timeout=200,
            sleep=1)
        common_utils.wait_until_true(
            lambda: self._check_bw_ingress(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT + 1,
                expected_bw=limit_bytes_sec),
            timeout=200,
            sleep=1)
        # Migrate
        original_host = self.os_primary.servers_client.show_server(
            self.server['server']['id'])['server']['hostId']
        # Set Nova API to latest for better api support
        base_compute_client.COMPUTE_MICROVERSION = 'latest'
        self.os_admin.servers_client.live_migrate_server(
            self.server['server']['id'], block_migration='auto', host=None)
        base_compute_client.COMPUTE_MICROVERSION = None
        self.wait_for_server_active(self.server['server'])
        new_host = self.os_primary.servers_client.show_server(
            self.server['server']['id'])['server']['hostId']
        self.assertNotEqual(original_host, new_host,
                            "Migration did not happen")
        # Check bw limited
        common_utils.wait_until_true(
            lambda: self._check_bw(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT,
                expected_bw=limit_bytes_sec),
            timeout=200,
            sleep=1)
        common_utils.wait_until_true(
            lambda: self._check_bw_ingress(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT + 1,
                expected_bw=limit_bytes_sec),
            timeout=200,
            sleep=1)

    @testtools.skip('Nova QOS testplan under development')
    def test_nova_qos_fip_rate_limiting(self):
        """Test QOS when using NOVA flavor, with nuage fip rate limiting

        """
        self._test_basic_resources()
        ssh_client = self._create_ssh_client()
        if hasattr(self, 'FILE_SIZE'):
            # Queens & Rocky: create file
            self._create_file_for_bw_tests(ssh_client)

        limit_bytes_sec = self.LIMIT_KBPS * 1024 * self.TOLERANCE_FACTOR
        # Check bw limited
        common_utils.wait_until_true(
            lambda: self._check_bw(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT,
                expected_bw=limit_bytes_sec),
            timeout=200,
            sleep=1)
        common_utils.wait_until_true(
            lambda: self._check_bw_ingress(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT + 1,
                expected_bw=limit_bytes_sec),
            timeout=200,
            sleep=1)

        # Set ingress & egress fip rate limiting
        self.client.update_floatingip(
            self.fip['id'],
            nuage_egress_fip_rate_kbps=400,
            nuage_ingress_fip_rate_kbps=200)
        # Check bw limited
        expected_egress_bw = 200 * 1024 * self.TOLERANCE_FACTOR / 8.0
        expected_ingress_bw = 400 * 1024 * self.TOLERANCE_FACTOR / 8.0
        common_utils.wait_until_true(
            lambda: self._check_bw(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT,
                expected_bw=expected_egress_bw),
            timeout=200,
            sleep=1)
        common_utils.wait_until_true(
            lambda: self._check_bw_ingress(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT + 1,
                expected_bw=expected_ingress_bw),
            timeout=200,
            sleep=1)

        # Remove fip rate limit
        self.client.update_floatingip(
            self.fip['id'],
            nuage_egress_fip_rate_kbps=-1,
            nuage_ingress_fip_rate_kbps=-1)

        # Check bw limited again to original nova qos
        limit_bytes_sec = self.LIMIT_KBPS * 1024 * 1.5
        # Check bw limited
        common_utils.wait_until_true(
            lambda: self._check_bw(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT,
                expected_bw=limit_bytes_sec),
            timeout=200,
            sleep=1)
        common_utils.wait_until_true(
            lambda: self._check_bw_ingress(
                ssh_client,
                self.fip['floating_ip_address'],
                port=self.NC_PORT + 1,
                expected_bw=limit_bytes_sec),
            timeout=200,
            sleep=1)
