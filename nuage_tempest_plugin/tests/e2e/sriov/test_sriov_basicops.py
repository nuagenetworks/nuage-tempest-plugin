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
import testtools

from tempest.common import utils as utils
from tempest.lib.common.utils import data_utils as tempest_data_utils

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils

LOG = Topology.get_logger(__name__)
CONF = Topology.get_conf()

NETWORK_ARGS = {
    'segments': [
        {
            'provider:network_type': 'vxlan'
        },
        {
            'provider:network_type': 'vlan',
            'provider:segmentation_id': 123,
            'provider:physical_network': 'physnet1'
        }
    ]
}

VIRTIO_ARGS = {'binding:vnic_type': 'normal'}

CONFIGURE_VLAN_INTERFACE_COMMANDS = (
    'sudo ip link add link %(itf)s name %(itf)s.%(tag)d type vlan id %(tag)d;'
    'sudo ip link set up dev %(itf)s.%(tag)d;'
    'sudo ip link set %(itf)s.%(tag)d address %(mac)s;'
    'sudo ip address add %(ip)s/%(len)d dev %(itf)s.%(tag)d'
)


class SriovBasicOpsTest(NuageBaseTest):
    force_tenant_isolation = False

    ip_types = {(4,): 'IPV4', (6,): 'IPV6', (4, 6): 'DUALSTACK'}

    @classmethod
    def resource_setup(cls):
        super(SriovBasicOpsTest, cls).resource_setup()
        cls.aggregates = cls.admin_manager.aggregates_client.list_aggregates()

        cls.hosts_vrs = [aggregate['hosts'] for aggregate in
                         cls.aggregates['aggregates']
                         if aggregate['metadata']['flavor'] == 'vrs'][0]

        cls.hosts_sriov = [aggregate['hosts'] for aggregate in
                           cls.aggregates['aggregates']
                           if aggregate['metadata']['flavor'] == 'sriov'][0]

        cls.availability_zones_vrs = ['nova:' + host for host
                                      in cls.hosts_vrs]
        cls.availability_zones_sriov = ['nova:' + host for host
                                        in cls.hosts_sriov]

    @classmethod
    def skip_checks(cls):
        super(SriovBasicOpsTest, cls).skip_checks()

        if CONF.network.port_vnic_type not in ['direct']:
            msg = 'Test requires port_vnic_type "direct"'
            raise cls.skipException(msg)
        if Topology.has_default_switchdev_port_profile():
            raise cls.skipException('Test requires switchdev offloading '
                                    'to be disabled')

    def _check_connectivity(self, ip_version=4):
        connectivity_check_pairs = []

        sriov_compute = self.availability_zones_sriov[0]
        server_to = self._create_server_with_direct_port(
            availability_zone=sriov_compute)

        vrs_computes = [sriov_compute]
        if any(self.availability_zones_vrs):
            vrs_computes.append(self.availability_zones_vrs[0])
        for availability_zone in vrs_computes:
            server_from = self._create_server_with_virtio_port(
                availability_zone=availability_zone)
            connectivity_check_pairs.append((server_from, server_to))

        for server_from, server_to in connectivity_check_pairs:
            self.assert_ping(
                server_from['server'],
                ip_version=ip_version,
                address=server_to['port']['fixed_ips'][0]['ip_address'])

    def _create_server_with_virtio_port(self, availability_zone):
        port = self.create_port(self.network, security_groups=[
            self.secgroup['id']],
            manager=self.admin_manager,
            **VIRTIO_ARGS)
        server = self.create_tenant_server(
            availability_zone=availability_zone,
            ports=[port],
            prepare_for_connectivity=True,
            manager=self.admin_manager)
        return {'port': port, 'server': server}

    def _create_server_with_direct_port(self, availability_zone):
        kwargs = {'config_drive': True}
        port = self.create_port(self.network,
                                port_security_enabled=False,
                                manager=self.admin_manager)
        server = self.create_tenant_server(
            availability_zone=availability_zone,
            ports=[port],
            prepare_for_connectivity=False,  # explicit, as must be
            manager=self.admin_manager,
            **kwargs)
        return {'port': port, 'server': server}

    def _create_vsd_domain(self, is_l3=True, ip_version=(4,)):
        cidr4 = None
        cidr6 = None
        enable_dhcpv4 = enable_dhcpv6 = Topology.before_nuage('6.0')
        gateway4 = None
        gateway6 = None

        for ip_type in ip_version:
            if ip_type == 4:
                cidr4 = data_utils.gimme_a_cidr(ip_type)
                gateway4 = str(cidr4[1]) if is_l3 else None
            elif ip_type == 6:
                cidr6 = data_utils.gimme_a_cidr(ip_type)
                gateway6 = str(cidr6[1]) if is_l3 else None

        kwargs = {}
        if CONF.nuage_sut.gateway_type == 'cisco':
            kwargs['ingress_replication_enabled'] = True

        if is_l3:
            l3template = self.vsd_create_l3domain_template()
            self.domain = self.vsd_create_l3domain(template_id=l3template.id)
            zone = self.vsd_create_zone(domain=self.domain)

            self.l3subnet = self.create_vsd_subnet(
                zone=zone,
                cidr4=cidr4,
                cidr6=cidr6,
                enable_dhcpv4=enable_dhcpv4,
                enable_dhcpv6=enable_dhcpv6,
                gateway4=gateway4,
                gateway6=gateway6,
                ip_type=self.ip_types[ip_version],
                **kwargs
            )
        else:
            l2template = self.vsd_create_l2domain_template(
                cidr4=cidr4,
                cidr6=cidr6,
                enable_dhcpv4=enable_dhcpv4,
                enable_dhcpv6=enable_dhcpv6,
                ip_type=self.ip_types[ip_version],
            )

            self.l2domain = self.vsd_create_l2domain(template=l2template,
                                                     **kwargs)

    def _setup_resources_vsd_mgd(self, is_l3=True, ip_version=(4,)):
        self._create_vsd_domain(is_l3=is_l3, ip_version=ip_version)
        domain = self.domain if is_l3 else self.l2domain
        pg_name = tempest_data_utils.rand_name('pg-')
        self.vsd.create_policy_group(domain, name=pg_name)
        allow_ipv4 = 4 in ip_version
        allow_ipv6 = 6 in ip_version
        self.vsd.define_any_to_any_acl(domain, allow_ipv4=allow_ipv4,
                                       allow_ipv6=allow_ipv6, stateful=True)

        self.network = self.create_network(
            manager=self.admin_manager,
            tenant_id=self.manager.networks_client.tenant_id,
            **NETWORK_ARGS)

        if is_l3:
            vsd_subnet = self.l3subnet
            create_vsd_managed_subnet = self.create_l3_vsd_managed_subnet
        else:
            vsd_subnet = self.l2domain
            create_vsd_managed_subnet = self.create_l2_vsd_managed_subnet

        self.subnet = []
        for ip_type in ip_version:
            self.subnet.append(create_vsd_managed_subnet(
                self.network, vsd_subnet, ip_version=ip_type,
                manager=self.admin_manager,
                dhcp_managed=Topology.before_nuage('6.0')))

        self.secgroup = self.create_open_ssh_security_group(
            manager=self.admin_manager)

    def _setup_resources(self, is_l3=True, ip_version=(4,)):
        # setup basic topology for servers we can log into
        self.network = self.create_network(
            manager=self.admin_manager,
            tenant_id=self.manager.networks_client.tenant_id,
            **NETWORK_ARGS)

        self.subnet = []
        for ip_type in ip_version:
            self.subnet.append(self.create_subnet(self.network,
                                                  ip_version=ip_type,
                                                  manager=self.admin_manager,
                                                  enable_dhcp=False))

        if is_l3:
            router = self.create_public_router(manager=self.admin_manager)
            for subnet in self.subnet:
                self.router_attach(router, subnet,
                                   manager=self.admin_manager)

        self.secgroup = self.create_open_ssh_security_group(
            manager=self.admin_manager)

    def test_server_connectivity_l3(self):
        self._setup_resources()
        self._check_connectivity()

    def test_server_connectivity_l2(self):
        self._setup_resources(is_l3=False)
        self._check_connectivity()

    @testtools.skipIf(Topology.before_nuage('6.0'), 'Unsupported pre-6.0')
    def test_server_connectivity_l3_ipv6(self):
        self._setup_resources(ip_version=(6,))
        self._check_connectivity(ip_version=6)

    @testtools.skipIf(Topology.before_nuage('6.0'), 'Unsupported pre-6.0')
    def test_server_connectivity_l2_ipv6(self):
        self._setup_resources(is_l3=False, ip_version=(6,))
        self._check_connectivity(ip_version=6)

    def test_server_connectivity_l3_dual(self):
        self._setup_resources(ip_version=(4, 6))
        self._check_connectivity()

    def test_server_connectivity_l2_dual(self):
        self._setup_resources(is_l3=False, ip_version=(4, 6))
        self._check_connectivity()

    def test_server_connectivity_l3_vsd_mgd(self):
        self._setup_resources_vsd_mgd()
        self._check_connectivity()

    def test_server_connectivity_l2_vsd_mgd(self):
        self._setup_resources_vsd_mgd(is_l3=False)
        self._check_connectivity()

    @testtools.skipIf(Topology.before_nuage('6.0'), 'Unsupported pre-6.0')
    def test_server_connectivity_l3_ipv6_vsd_mgd(self):
        self._setup_resources_vsd_mgd(ip_version=(6,))
        self._check_connectivity(ip_version=6)

    @testtools.skipIf(Topology.before_nuage('6.0'), 'Unsupported pre-6.0')
    def test_server_connectivity_l2_ipv6_vsd_mgd(self):
        self._setup_resources_vsd_mgd(is_l3=False, ip_version=(6,))
        self._check_connectivity(ip_version=6)

    def test_server_connectivity_l3_dual_vsd_mgd(self):
        self._setup_resources_vsd_mgd(ip_version=(4, 6))
        self._check_connectivity()

    def test_server_connectivity_l2_dual_vsd_mgd(self):
        self._setup_resources_vsd_mgd(is_l3=False, ip_version=(4, 6))
        self._check_connectivity()


class SriovTrunkTest(NuageBaseTest):
    force_tenant_isolation = False

    @classmethod
    @utils.requires_ext(extension="trunk", service="network")
    def resource_setup(cls):
        super(SriovTrunkTest, cls).resource_setup()

    @classmethod
    def skip_checks(cls):
        super(SriovTrunkTest, cls).skip_checks()

        if CONF.network.port_vnic_type not in ['direct']:
            msg = 'Test requires port_vnic_type "direct"'
            raise cls.skipException(msg)
        if Topology.has_default_switchdev_port_profile():
            raise cls.skipException('Test requires switchdev offloading '
                                    'to be disabled')

    def _create_network(self, segmentation_id=0):
        network_type = 'vlan' if segmentation_id else 'flat'
        kwargs = {
            'segments': [
                {
                    "provider:network_type": "vxlan"
                },
                {
                    "provider:network_type": network_type,
                    "provider:physical_network": 'physnet1',
                    "provider:segmentation_id": segmentation_id
                }
            ]
        }
        return self.create_network(
            manager=self.admin_manager,
            tenant_id=self.manager.networks_client.tenant_id,
            **kwargs)

    def _setup_resources(self, is_l3=True, ip_version=4):
        # setup basic topology for servers we can log into
        self.network = self._create_network()
        self.subnet = self.create_subnet(self.network,
                                         ip_version=ip_version)
        if is_l3:
            router = self.create_public_router()
            self.router_attach(router, self.subnet)
        self.keypair = self.create_keypair()
        self.secgroup = self._create_empty_security_group()
        self.create_security_group_rule(
            security_group=self.secgroup,
            direction='ingress', ethertype='IPv4', protocol='tcp')

    def _is_port_down(self, port_id):
        p = self.plugin_network_client.show_port(port_id)['port']
        return p['status'] == 'DOWN'

    def _is_port_active(self, port_id):
        p = self.plugin_network_client.show_port(port_id)['port']
        return p['status'] == 'ACTIVE'

    def _is_trunk_active(self, trunk_id):
        t = self.plugin_network_client.show_trunk(trunk_id)['trunk']
        return t['status'] == 'ACTIVE'

    def _create_server_with_direct_trunk_port(self):
        kwargs = {'config_drive': True}
        port = self.create_port(self.network,
                                port_security_enabled=False)
        trunk = self.create_trunk(port)
        server = self.create_tenant_server(
            ports=[port],
            **kwargs)
        return {'port': port, 'trunk': trunk, 'server': server}

    def _create_server_with_port_and_subport(self, access_network,
                                             subport_network, vlan_tag):
        access_port = self.create_port(access_network, security_groups=[
            self.secgroup['id']],
            **VIRTIO_ARGS)
        parent_port = self.create_port(self.network,
                                       port_security_enabled=False)
        port_for_subport = self.create_port(
            subport_network,
            port_security_enabled=False)

        subport = {
            'port_id': port_for_subport['id'],
            'segmentation_type': 'vlan',
            'segmentation_id': vlan_tag}
        self.create_trunk(parent_port, [subport])

        kwargs = {'config_drive': True,
                  'user_data': '/sbin/ip route del default via {}\n'.format(
                      self.subnet['gateway_ip'])}
        server = self.create_tenant_server(
            ports=[access_port, parent_port],
            prepare_for_connectivity=True,
            **kwargs)

        return {
            'server': server,
            'trunkport': parent_port,
            'subport': port_for_subport,
        }

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
        nets = [self._create_network(seg_id) for seg_id in allowed_vlans]
        [self.create_subnet(net, gateway=None) for net in nets]
        subports = [{'port_id': self.create_port(net)['id'],
                     'segmentation_type': 'vlan', 'segmentation_id': seg_id}
                    for seg_id, net in zip(allowed_vlans, nets)]

        server1 = self._create_server_with_direct_trunk_port()
        server2 = self._create_server_with_direct_trunk_port()

        trunk1_id, trunk2_id = server1['trunk']['id'], server2['trunk']['id']
        # trunks should transition to ACTIVE without any subports
        data_utils.wait_until_true(
            lambda: self._is_trunk_active(trunk1_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk1_id))
        data_utils.wait_until_true(
            lambda: self._is_trunk_active(trunk2_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk2_id))

        # add all subports to server1
        self.plugin_network_client.add_subports(trunk1_id, subports)
        # ensure trunk transitions to ACTIVE
        data_utils.wait_until_true(
            lambda: self._is_trunk_active(trunk1_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk1_id))
        # ensure all underlying subports transitioned to ACTIVE
        for s in subports:
            data_utils.wait_until_true(
                lambda: self._is_port_active(s['port_id']))

        # move subports over to other server
        self.plugin_network_client.remove_subports(trunk1_id, subports)
        # ensure all subports go down
        for s in subports:
            data_utils.wait_until_true(
                lambda: self._is_port_down(s['port_id']),
                exception=RuntimeError("Timed out waiting for subport %s to "
                                       "transition to DOWN." % s['port_id']))
        self.plugin_network_client.add_subports(trunk2_id, subports)
        # wait for both trunks to go back to ACTIVE
        data_utils.wait_until_true(
            lambda: self._is_trunk_active(trunk1_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk1_id))
        data_utils.wait_until_true(
            lambda: self._is_trunk_active(trunk2_id),
            exception=RuntimeError("Timed out waiting for trunk %s to "
                                   "transition to ACTIVE." % trunk2_id))
        # ensure subports come up on other trunk
        for s in subports:
            data_utils.wait_until_true(
                lambda: self._is_port_active(s['port_id']),
                exception=RuntimeError("Timed out waiting for subport %s to "
                                       "transition to ACTIVE." % s['port_id']))

    @testtools.skipUnless(
        CONF.nuage_sut.image_is_advanced,
        "Advanced image is required to run this test.")
    def test_subport_connectivity(self):
        self._setup_resources()
        vlan_tag = 10

        # create resources for access to vms
        access_router = self.create_public_router()
        access_network = self.create_network()
        access_subnet = self.create_subnet(access_network,
                                           cidr=data_utils.gimme_a_cidr())
        self.router_attach(access_router, access_subnet)

        subport_network = self._create_network(vlan_tag)
        subport_subnet = self.create_subnet(subport_network,
                                            cidr=data_utils.gimme_a_cidr(),
                                            gateway=None)
        net = IPNetwork(subport_subnet['cidr'])
        servers = [
            self._create_server_with_port_and_subport(
                access_network, subport_network, vlan_tag)
            for _ in range(2)]

        # Compute/configure dot1q interfaces
        for server in servers:
            dev = server['server'].console().get_nic_name_by_mac(
                server['trunkport']['mac_address']
            )
            self.assertIsNotNone(
                dev,
                message="Could not compute device name for interface")

            # Configure VLAN interfaces on server
            command = CONFIGURE_VLAN_INTERFACE_COMMANDS % {
                'itf': dev,
                'tag': vlan_tag,
                'mac': server['trunkport']['mac_address'],
                'ip': server['subport']['fixed_ips'][0]['ip_address'],
                'len': net.prefixlen,
            }
            server['server'].send(command)

            out = server['server'].send(
                'ip addr list')
            LOG.debug("Interfaces on server %s: %s", server, out)

        self.assert_ping(
            servers[0]['server'],
            servers[1]['server'],
            address=servers[1]['subport']['fixed_ips'][0]['ip_address'])
