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

import testtools

from tempest.common import utils as tutils
from tempest.lib import decorators

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils as utils


LOG = Topology.get_logger(__name__)
CONF = Topology.get_conf()

CONFIGURE_VLAN_INTERFACE_COMMANDS = (
    'sudo ip l a link %(itf)s name %(itf)s.%(tag)d type vlan id %(tag)d &&'
    'sudo ip l s up dev %(itf)s.%(tag)d && '
    'ps -ef | grep -q "udhcpc .*%(itf)s.%(tag)d" || '
    'sudo udhcpc -i %(itf)s.%(tag)d -s /sbin/cirros-dhcpc;')


class TrunkTest(NuageBaseTest):
    force_tenant_isolation = False

    @classmethod
    @tutils.requires_ext(extension="trunk", service="network")
    def resource_setup(cls):
        super(TrunkTest, cls).resource_setup()

    def _create_server_with_trunk_port(self):
        port = self.create_port(self.network, security_groups=[
            self.secgroup['id']])
        trunk = self.create_trunk(port)
        server, fip = self._create_server_with_fip(port)
        return {'port': port, 'trunk': trunk, 'fip': fip,
                'server': server}

    def _create_server_with_fip(self, port, **server_kwargs):
        server = self.create_tenant_server(
            ports=[port],
            make_reachable=True)
        return (server, server.associated_fip)

    def _is_port_down(self, port_id):
        p = self.plugin_network_client.show_port(port_id)['port']
        return p['status'] == 'DOWN'

    def _is_port_active(self, port_id):
        p = self.plugin_network_client.show_port(port_id)['port']
        return p['status'] == 'ACTIVE'

    def _is_trunk_active(self, trunk_id):
        t = self.plugin_network_client.show_trunk(trunk_id)['trunk']
        return t['status'] == 'ACTIVE'

    def _create_server_with_port_and_subport(self, subport_network, vlan_tag):
        parent_port = self.create_port(self.network, security_groups=[
            self.secgroup['id']])
        port_for_subport = self.create_port(
            subport_network,
            security_groups=[self.secgroup['id']],
            mac_address=parent_port['mac_address'])
        subport = {
            'port_id': port_for_subport['id'],
            'segmentation_type': 'vlan',
            'segmentation_id': vlan_tag}
        self.create_trunk(parent_port, [subport])

        server, fip = self._create_server_with_fip(parent_port)

        return {
            'server': server,
            'fip': fip,
            'subport': port_for_subport,
        }

    def _setup_resources(self):
        # setup basic topology for servers we can log into
        self.network = self.create_network()
        self.subnet = self.create_subnet(self.network)
        router = self.create_public_router()
        self.router_attach(router, self.subnet)
        self.keypair = self.create_keypair()
        self.secgroup = self._create_empty_security_group()
        self.create_security_group_rule(
            security_group=self.secgroup,
            direction='ingress', ethertype='IPv4', protocol='tcp')

    @decorators.attr(type='smoke')
    def test_trunk_subport_lifecycle(self):
        """Test trunk creation and subport transition to ACTIVE status.

        This is a basic test for the trunk extension to ensure that we
        can create a trunk, attach it to a server, add/remove subports,
        while ensuring the status transitions as appropriate.

        This test does not assert any dataplane behavior for the subports.
        It's just a high-level check to ensure the agents claim to have
        wired the port correctly and that the trunk port itself maintains
        connectivity.
        """
        self._setup_resources()

        # create a few more networks and ports for subports first
        # to allow for proper cleanup
        max_vlan = 5
        allowed_vlans = range(3, max_vlan)
        nets = [self.create_network() for seg_id in allowed_vlans]
        [self.create_subnet(net, gateway=None) for net in nets]
        subports = [{'port_id': self.create_port(net)['id'],
                     'segmentation_type': 'vlan', 'segmentation_id': seg_id}
                    for seg_id, net in zip(allowed_vlans, nets)]

        server1 = self._create_server_with_trunk_port()
        server2 = self._create_server_with_trunk_port()

        trunk1_id, trunk2_id = server1['trunk']['id'], server2['trunk']['id']
        # trunks should transition to ACTIVE without any subports
        utils.wait_until_true(
            lambda: self._is_trunk_active(trunk1_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk1_id))
        utils.wait_until_true(
            lambda: self._is_trunk_active(trunk2_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk2_id))

        # add all subports to server1
        self.plugin_network_client.add_subports(trunk1_id, subports)
        # ensure trunk transitions to ACTIVE
        utils.wait_until_true(
            lambda: self._is_trunk_active(trunk1_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk1_id))
        # ensure all underlying subports transitioned to ACTIVE
        for s in subports:
            utils.wait_until_true(lambda: self._is_port_active(s['port_id']))
        # ensure main dataplane wasn't interrupted
        server1['server'].check_connectivity()

        # move subports over to other server
        self.plugin_network_client.remove_subports(trunk1_id, subports)
        # ensure all subports go down
        for s in subports:
            utils.wait_until_true(
                lambda: self._is_port_down(s['port_id']),
                exception=RuntimeError("Timed out waiting for subport %s to "
                                       "transition to DOWN." % s['port_id']))
        self.plugin_network_client.add_subports(trunk2_id, subports)
        # wait for both trunks to go back to ACTIVE
        utils.wait_until_true(
            lambda: self._is_trunk_active(trunk1_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk1_id))
        utils.wait_until_true(
            lambda: self._is_trunk_active(trunk2_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk2_id))
        # ensure subports come up on other trunk
        for s in subports:
            utils.wait_until_true(
                lambda: self._is_port_active(s['port_id']),
                exception=RuntimeError("Timed out waiting for subport %s to "
                                       "transition to ACTIVE." % s['port_id']))
        # final connectivity check
        server1['server'].vm_console.validate_authentication()
        server2['server'].vm_console.validate_authentication()

    @testtools.skipUnless(
        CONF.nuage_sut.image_is_advanced,
        "Advanced image is required to run this test.")
    def test_subport_connectivity(self):
        self._setup_resources()
        vlan_tag = 10

        subport_network = self.create_network()
        self.create_subnet(subport_network, cidr=utils.gimme_a_cidr(),
                           gateway=None)

        servers = [
            self._create_server_with_port_and_subport(
                subport_network, vlan_tag)
            for i in range(2)]

        for server in servers:
            # Configure VLAN interfaces on server
            command = CONFIGURE_VLAN_INTERFACE_COMMANDS % {'itf': 'eth0',
                                                           'tag': vlan_tag}
            server['server'].send(command)
            out = server['server'].send(
                'ip addr list')
            LOG.debug("Interfaces on server %s: %s", server, out)

        # Ping from server1 to server2 via VLAN interface should fail because
        # we haven't allowed ICMP
        self.assert_ping(
            servers[0]['server'],
            servers[1]['server'],
            subport_network,
            address=servers[1]['subport']['fixed_ips'][0]['ip_address'],
            should_pass=False)

        # allow intra-securitygroup traffic
        self.create_security_group_rule(
            security_group=self.secgroup,
            direction='ingress', ethertype='IPv4', protocol='icmp',
            remote_group_id=self.secgroup['id'])

        self.assert_ping(
            servers[0]['server'],
            servers[1]['server'],
            subport_network,
            address=servers[1]['subport']['fixed_ips'][0]['ip_address'])
