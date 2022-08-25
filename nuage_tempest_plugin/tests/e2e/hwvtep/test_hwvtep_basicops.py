# Nokia 2020
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
from collections import namedtuple
from netaddr import IPNetwork

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils

CONF = Topology.get_conf()

CONFIGURE_VLAN_INTERFACE_COMMANDS = (
    '{pre} link add link {dev} name {dev}.{tag} type vlan id {tag}\n'
    '{pre} link set up dev {dev}.{tag}\n'
    '{pre} link set {dev}.{tag} address {mac}\n'
    '{pre} address add {ip}/{len} dev {dev}.{tag}\n'
)
CONFIGURE_SECOND_IP = (
    '{pre} address add {ip}/{len} dev {dev}.{tag}\n'
)
ServerPorts = namedtuple('ServerPorts', 'server port subports')


class HwvtepBasicOpsTest(NuageBaseTest):

    is_trunk = False
    ip_types = {(4,): 'IPV4', (6,): 'IPV6', (4, 6): 'DUALSTACK'}

    netmask_ipv4 = 28
    netmask_ipv6 = 64

    @classmethod
    def resource_setup(cls):
        super(HwvtepBasicOpsTest, cls).resource_setup()
        cls.aggregates = cls.admin_manager.aggregates_client.list_aggregates()
        cls.hosts_ovs = next((aggregate['hosts'] for aggregate in
                              cls.aggregates['aggregates']
                              if aggregate['metadata']['flavor'] == 'hwvtep'),
                             [])
        if not len(cls.hosts_ovs):
            raise cls.skipException('Not enough hwvtep hosts available')

        cls.availability_zones_ovs = ['nova:' + host for host
                                      in cls.hosts_ovs]

    def _create_server_hwvtep(self, prepare_for_connectivity,
                              availability_zone):
        port = self.create_port(self.network,
                                manager=self.admin_manager)
        server = self.create_tenant_server(
            availability_zone=availability_zone,
            ports=[port],
            prepare_for_connectivity=prepare_for_connectivity,
            manager=self.admin_manager,
            config_drive=True,
            no_net_partition=True,
            flavor=CONF.compute.flavor_ref_alt
            if 'hwvtepdpdk' in availability_zone else None)
        return ServerPorts(server, port, [])

    def _check_connectivity(self, ip_version=(4,)):
        servers_to = []

        for availability_zone in self.availability_zones_ovs:
            server_to = self._create_server_hwvtep(
                prepare_for_connectivity=False,
                availability_zone=availability_zone)
            servers_to.append(server_to)

        for availability_zone in self.availability_zones_ovs:
            server_from = self._create_server_hwvtep(
                prepare_for_connectivity=True,
                availability_zone=availability_zone)

            for dest in servers_to:
                for i, ip_type in enumerate(ip_version):
                    self.assert_ping(
                        server_from.server,
                        ip_version=ip_type,
                        address=dest.port['fixed_ips'][i]['ip_address'])
                    if self.is_trunk:
                        # Ping 802.1Q interfaces
                        for subport in dest.subports:
                            self.assert_ping(
                                server_from.server,
                                ip_version=ip_type,
                                address=subport['fixed_ips'][i]['ip_address'])

    def _create_vsd_domain(self, is_l3=False, ip_version=(4,)):
        cidr4 = None
        cidr6 = None
        enable_dhcpv4 = False
        enable_dhcpv6 = False
        gateway4 = None
        gateway6 = None

        for ip_type in ip_version:
            if ip_type == 4:
                cidr4 = data_utils.gimme_a_cidr(ip_type, self.netmask_ipv4)
                gateway4 = str(cidr4[1]) if is_l3 else None
            elif ip_type == 6:
                cidr6 = data_utils.gimme_a_cidr(ip_type, self.netmask_ipv6)
                gateway6 = str(cidr6[1]) if is_l3 else None

        if is_l3:
            l3template = self.vsd_create_l3domain_template()
            self.domain = self.vsd_create_l3domain(template_id=l3template.id)
            self.zone = self.vsd_create_zone(domain=self.domain)

            self.l3subnet = self.create_vsd_subnet(
                zone=self.zone,
                cidr4=cidr4,
                cidr6=cidr6,
                enable_dhcpv4=enable_dhcpv4,
                enable_dhcpv6=enable_dhcpv6,
                gateway4=gateway4,
                gateway6=gateway6,
                ip_type=self.ip_types[ip_version]
            )
        else:
            l2template = self.vsd_create_l2domain_template(
                cidr4=cidr4,
                cidr6=cidr6,
                enable_dhcpv4=enable_dhcpv4,
                enable_dhcpv6=enable_dhcpv6,
                ip_type=self.ip_types[ip_version],
            )

            self.l2domain = self.vsd_create_l2domain(template=l2template)

    def _setup_resources(self, ip_version=(4,), is_flat=False,
                         is_l3=False, is_vsd_mgd=False):

        kwargs = {
            'provider:network_type': 'flat' if is_flat else 'vlan',
            'provider:physical_network': 'physnet1'
        }
        self.network = self.create_network(
            manager=self.admin_manager,
            tenant_id=self.manager.networks_client.tenant_id,
            **kwargs)

        if is_vsd_mgd:
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
                    dhcp_managed=False))
        else:
            self.subnet = []
            for ip_type in ip_version:
                netmask = (self.netmask_ipv4 if ip_type == 4
                           else self.netmask_ipv6)
                self.subnet.append(self.create_subnet(
                    self.network, ip_version=ip_type,
                    cidr=data_utils.gimme_a_cidr(ip_type, netmask),
                    manager=self.admin_manager,
                    enable_dhcp=False))

        if self.is_trunk:
            self._create_trunk_subports_resources(ip_version, is_vsd_mgd,
                                                  is_l3)

    def _create_trunk_subports_resources(self, ip_version, is_vsd_mgd, is_l3):
        pass

    def test_server_connectivity_l2(self):
        self._setup_resources()
        self._check_connectivity()

    def test_server_connectivity_l2_ipv6(self):
        self._setup_resources(ip_version=(6,))
        self._check_connectivity(ip_version=(6,))

    def test_server_connectivity_l2_dual(self):
        self._setup_resources(ip_version=(4, 6))
        self._check_connectivity((4, 6))

    def test_server_connectivity_l2_flat(self):
        if not self.is_trunk:
            self.skipTest("Flat network tested in vlan aware tests")
        self._setup_resources(is_flat=True)
        self._check_connectivity()

    def test_server_connectivity_l2_ipv6_flat(self):
        if not self.is_trunk:
            self.skipTest("Flat network tested in vlan aware tests")
        self._setup_resources(ip_version=(6,), is_flat=True)
        self._check_connectivity(ip_version=(6,))

    def test_server_connectivity_l2_dual_flat(self):
        if not self.is_trunk:
            self.skipTest("Flat network tested in vlan aware tests")
        self._setup_resources(ip_version=(4, 6), is_flat=True)
        self._check_connectivity((4, 6))

    def test_server_connectivity_l2_vsd(self):
        self._create_vsd_domain()
        self._setup_resources(is_vsd_mgd=True)
        self._check_connectivity()

    def test_server_connectivity_l2_ipv6_vsd(self):
        self._create_vsd_domain(ip_version=(6,))
        self._setup_resources(ip_version=(6,), is_vsd_mgd=True)
        self._check_connectivity(ip_version=(6,))

    def test_server_connectivity_l2_dual_vsd(self):
        self._create_vsd_domain(ip_version=(4, 6))
        self._setup_resources(ip_version=(4, 6), is_vsd_mgd=True)
        self._check_connectivity((4, 6))

    def test_server_connectivity_l2_flat_vsd(self):
        if not self.is_trunk:
            self.skipTest("Flat network tested in vlan aware tests")
        self._create_vsd_domain()
        self._setup_resources(is_flat=True, is_vsd_mgd=True)
        self._check_connectivity()

    def test_server_connectivity_l2_ipv6_flat_vsd(self):
        if not self.is_trunk:
            self.skipTest("Flat network tested in vlan aware tests")
        self._create_vsd_domain(ip_version=(6,))
        self._setup_resources(ip_version=(6,), is_flat=True, is_vsd_mgd=True)
        self._check_connectivity(ip_version=(6,))

    def test_server_connectivity_l2_dual_flat_vsd(self):
        if not self.is_trunk:
            self.skipTest("Flat network tested in vlan aware tests")
        self._create_vsd_domain(ip_version=(4, 6))
        self._setup_resources(ip_version=(4, 6), is_flat=True, is_vsd_mgd=True)
        self._check_connectivity((4, 6))

    def test_server_connectivity_l3_vsd(self):
        self._create_vsd_domain(is_l3=True)
        self._setup_resources(is_vsd_mgd=True, is_l3=True)
        self._check_connectivity()

    def test_server_connectivity_l3_ipv6_vsd(self):
        self._create_vsd_domain(ip_version=(6,), is_l3=True)
        self._setup_resources(ip_version=(6,), is_vsd_mgd=True, is_l3=True)
        self._check_connectivity(ip_version=(6,))

    def test_server_connectivity_l3_dual_vsd(self):
        self._create_vsd_domain(ip_version=(4, 6), is_l3=True)
        self._setup_resources(ip_version=(4, 6), is_vsd_mgd=True, is_l3=True)
        self._check_connectivity((4, 6))

    def test_server_connectivity_l3_flat_vsd(self):
        if not self.is_trunk:
            self.skipTest("Flat network tested in vlan aware tests")
        self._create_vsd_domain(is_l3=True)
        self._setup_resources(is_flat=True, is_vsd_mgd=True, is_l3=True)
        self._check_connectivity()

    def test_server_connectivity_l3_ipv6_flat_vsd(self):
        if not self.is_trunk:
            self.skipTest("Flat network tested in vlan aware tests")
        self._create_vsd_domain(ip_version=(6,), is_l3=True)
        self._setup_resources(ip_version=(6,), is_flat=True,
                              is_vsd_mgd=True, is_l3=True)
        self._check_connectivity(ip_version=(6,))

    def test_server_connectivity_l3_dual_flat_vsd(self):
        if not self.is_trunk:
            self.skipTest("Flat network tested in vlan aware tests")
        self._create_vsd_domain(ip_version=(4, 6), is_l3=True)
        self._setup_resources(ip_version=(4, 6), is_flat=True,
                              is_vsd_mgd=True, is_l3=True)
        self._check_connectivity((4, 6))


class HwvtepVlanAwareOpsTest(HwvtepBasicOpsTest):

    is_trunk = True
    num_subports = 2
    segment_ids = range(100, 100 + num_subports)
    subports = dict()

    def _create_trunk_subports_resources(self, ip_version, is_vsd_mgd, is_l3):
        kwargs = {'provider:network_type': 'vlan',
                  'provider:physical_network': 'physnet1'}
        self.subports['networks'] = [self.create_network(
            manager=self.admin_manager, **kwargs)
            for _ in range(self.num_subports)]

        if is_vsd_mgd:
            self._create_subports_vsd_resources(ip_version, is_l3)
            if is_l3:
                vsd_subnets = self.subports['l3subnets']
                create_vsd_managed_subnet = self.create_l3_vsd_managed_subnet
            else:
                vsd_subnets = self.subports['l2domains']
                create_vsd_managed_subnet = self.create_l2_vsd_managed_subnet

            for ip_type in ip_version:
                for network, vsd_subnet in zip(self.subports['networks'],
                                               vsd_subnets):
                    create_vsd_managed_subnet(
                        network, vsd_subnet, ip_version=ip_type,
                        manager=self.admin_manager, dhcp_managed=False)
        else:
            for ip_type in ip_version:
                netmask = (self.netmask_ipv4 if ip_type == 4
                           else self.netmask_ipv6)
                for network in self.subports['networks']:
                    self.create_subnet(
                        network, enable_dhcp=False,
                        cidr=data_utils.gimme_a_cidr(ip_type, netmask),
                        ip_version=ip_type, manager=self.admin_manager)

    def _create_subports_vsd_resources(self, ip_version, is_l3):
        enable_dhcpv4 = False
        enable_dhcpv6 = False

        is_ipv4 = 4 in ip_version
        is_ipv6 = 6 in ip_version

        if is_l3:
            self.subports['l3subnets'] = []
            for _ in range(self.num_subports):
                cidr4 = (data_utils.gimme_a_cidr(4, self.netmask_ipv4)
                         if is_ipv4 else None)
                cidr6 = (data_utils.gimme_a_cidr(6, self.netmask_ipv6)
                         if is_ipv6 else None)
                self.subports['l3subnets'].append(self.create_vsd_subnet(
                    zone=self.zone,
                    cidr4=cidr4,
                    cidr6=cidr6,
                    enable_dhcpv4=enable_dhcpv4,
                    enable_dhcpv6=enable_dhcpv6,
                    gateway4=str(cidr4[1]) if is_ipv4 else None,
                    gateway6=str(cidr6[1]) if is_ipv6 else None,
                    ip_type=self.ip_types[ip_version])
                )
        else:
            l2templates = [self.vsd_create_l2domain_template(
                cidr4=(data_utils.gimme_a_cidr(4, self.netmask_ipv4)
                       if is_ipv4 else None),
                cidr6=(data_utils.gimme_a_cidr(6, self.netmask_ipv6)
                       if is_ipv6 else None),
                enable_dhcpv4=enable_dhcpv4,
                enable_dhcpv6=enable_dhcpv6,
                ip_type=self.ip_types[ip_version],
            ) for _ in range(self.num_subports)]

            self.subports['l2domains'] = [
                self.vsd_create_l2domain(template=l2template)
                for l2template in l2templates]

    def _create_server_hwvtep(self, prepare_for_connectivity,
                              availability_zone):
        parent_port = self.create_port(self.network,
                                       manager=self.admin_manager)

        tagged_subports = self._add_subports(parent_port)

        kwargs = dict()
        if not prepare_for_connectivity:
            # Configure 802.1Q interfaces using user_data
            # eth0 hard coded - Rhel image
            user_data = self._create_commands_string(tagged_subports, 'eth0',
                                                     is_user_data=True)
            kwargs['user_data'] = user_data
        else:
            # In case of connectivity, delete default route of parent subnet
            kwargs = {
                'user_data': '/sbin/ip route del default via {}\n'.format(
                    self.subnet[0]['gateway_ip'])}

        server = self.create_tenant_server(
            availability_zone=availability_zone,
            ports=[parent_port],
            prepare_for_connectivity=prepare_for_connectivity,
            manager=self.admin_manager,
            config_drive=True,
            no_net_partition=True,
            flavor=CONF.compute.flavor_ref_alt
            if 'hwvtepdpdk' in availability_zone else None,
            **kwargs)
        if prepare_for_connectivity:
            # Configure 802.1Q interfaces by sending commands to server
            # Cannot use user_data because the allocation of ports is not fixed
            dev = server.console().get_nic_name_by_mac(
                parent_port['mac_address'])
            self.assertIsNotNone(
                dev,
                message="Could not compute device name for interface")
            cmd = self._create_commands_string(tagged_subports, dev,
                                               is_user_data=False)
            server.send(cmd)
        return ServerPorts(server, parent_port, tagged_subports)

    def _add_subports(self, port):
        trunk = self.create_trunk(port,
                                  client=self.plugin_network_client_admin)
        tagged_ports = [self.create_port(network,
                                         mac_address=port['mac_address'],
                                         manager=self.admin_manager)
                        for network in self.subports['networks']]
        subports = [{
            'port_id': tagged_ports[i]['id'],
            'segmentation_type': 'vlan',
            'segmentation_id': segment_id}
            for i, segment_id in enumerate(self.segment_ids)]
        self.add_trunk_subports(subports, trunk['id'],
                                client=self.plugin_network_client_admin)
        return tagged_ports

    def _create_commands_string(self, tagged_ports, dev, is_user_data):
        cmd = ''
        pre = '/sbin/ip' if is_user_data else 'sudo ip'
        for i, segment_id in enumerate(self.segment_ids):
            commands = CONFIGURE_VLAN_INTERFACE_COMMANDS.format(
                pre=pre,
                dev=dev,
                tag=segment_id,
                mac=tagged_ports[i]['mac_address'],
                ip=tagged_ports[i]['fixed_ips'][0]['ip_address'],
                len=IPNetwork(self.subnet[0]['cidr']).prefixlen,
            )
            if len(tagged_ports[i]['fixed_ips']) == 2:
                commands = commands + CONFIGURE_SECOND_IP.format(
                    pre=pre,
                    dev=dev,
                    tag=segment_id,
                    ip=tagged_ports[i]['fixed_ips'][1]['ip_address'],
                    len=IPNetwork(self.subnet[1]['cidr']).prefixlen,
                )
            cmd += commands
        if not is_user_data:
            cmd = cmd.replace('\n', ';')
        return cmd
