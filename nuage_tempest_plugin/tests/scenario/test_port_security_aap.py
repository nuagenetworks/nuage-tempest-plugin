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

from netaddr import IPNetwork

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils

LOG = Topology.get_logger(__name__)
CONF = Topology.get_conf()


CONFIGURE_SECONDARY_IP_CMD = (
    'sudo ip address add %(ip)s/%(len)d dev %(dev)s'
)

CONFIGURE_MAC_CMD = (
    'sudo ip link set %(dev)s down;'
    'sudo ip link set dev %(dev)s address %(mac)s;'
    'sudo ip link set %(dev)s up'
)


class PortSecAAPTest(NuageBaseTest):

    default_prepare_for_connectivity = True
    force_tenant_isolation = False

    def _create_server_with_ports(self, is_l2=False):
        ports = []
        port = self.create_port(self.network, security_groups=[
            self.secgroup['id']])
        ports.append(port)
        if is_l2:
            test_port = self.create_port(self.test_network, security_groups=[
                self.secgroup['id']])
            ports.append(test_port)
        else:
            test_port = port
        server = self.create_tenant_server(
            ports=ports,
            prepare_for_connectivity=True)
        return {'port': port, 'test_port': test_port, 'server': server}

    def _setup_resources(self, is_l2=False):
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
        self.create_security_group_rule(
            security_group=self.secgroup,
            direction='ingress', ethertype='IPv4', protocol='icmp')
        # create additional network for L2
        if is_l2:
            self.test_network = self.create_network()
            self.test_subnet = self.create_subnet(
                self.test_network,
                cidr=data_utils.gimme_a_cidr(),
                gateway=None)
        else:
            self.test_network = self.network
            self.test_subnet = self.subnet

    def _test_port_security_aap(self, is_l2=False):
        """Test port security enforces address spoofing.

        This is a basic test for the address spoofing functionality in VSP
        to ensure that tenant traffic is dropped when originating from IP/MAC
        different from one of the corresponding neutron port unless it is
        configured as AAP on that port.
        """
        self._setup_resources(is_l2=is_l2)

        net = IPNetwork(self.test_subnet['cidr'])

        # create port to reserve ip/mac for AAP
        port_for_aap = self.create_port(
            self.test_network)

        servers = [
            self._create_server_with_ports(is_l2=is_l2)
            for _ in range(2)]

        # Configure secondary ip (and mac in case of L2) on servers[0]
        dev = servers[0]['server'].console().get_nic_name_by_mac(
            servers[0]['test_port']['mac_address']
        )
        self.assertIsNotNone(
            dev,
            message="Could not compute device name for secondary ip")

        command = CONFIGURE_SECONDARY_IP_CMD % {
            'ip': port_for_aap['fixed_ips'][0]['ip_address'],
            'len': net.prefixlen,
            'dev': dev
        }
        servers[0]['server'].send(command)
        if is_l2:
            command = CONFIGURE_MAC_CMD % {
                'dev': dev,
                'mac': port_for_aap['mac_address']
            }
            servers[0]['server'].send(command)

        # Ping from server1 to server2 via secondary ip should fail because
        # we don't have AAP on port
        self.assert_ping(
            servers[0]['server'],
            servers[1]['server'],
            self.network,
            interface=port_for_aap['fixed_ips'][0]['ip_address'],
            address=servers[1]['test_port']['fixed_ips'][0]['ip_address'],
            should_pass=False)

        # Configure AAP on servers[0] port
        # Note(gridinv): in VSP we implement this as VIP for L3
        # and enable address spoofing on L2, so that though
        # AAP did not include mac, traffic will still be allowed in L2
        body = {'allowed_address_pairs': [{
            'ip_address': port_for_aap['fixed_ips'][0]['ip_address']}]}
        self.update_port(servers[0]['test_port'], **body)

        # Ping should succeed with AAP on source port
        self.assert_ping(
            servers[0]['server'],
            servers[1]['server'],
            self.network,
            interface=port_for_aap['fixed_ips'][0]['ip_address'],
            address=servers[1]['test_port']['fixed_ips'][0]['ip_address'])

    def test_port_security_aap_l3(self):
        self._test_port_security_aap()

    def test_port_security_aap_l2(self):
        self._test_port_security_aap(is_l2=True)
