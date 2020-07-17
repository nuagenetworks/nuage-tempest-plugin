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

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils

CONF = Topology.get_conf()


class HwvtepBasicOpsTest(NuageBaseTest):

    ip_types = {(4,): 'IPV4', (6,): 'IPV6', (4, 6): 'DUALSTACK'}

    @classmethod
    def resource_setup(cls):
        super(HwvtepBasicOpsTest, cls).resource_setup()
        cls.aggregates = cls.admin_manager.aggregates_client.list_aggregates()
        cls.hosts_ovs = [aggregate['hosts'] for aggregate in
                         cls.aggregates['aggregates']
                         if aggregate['metadata']['flavor'] == 'hwvtep'][0]

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
        return {'port': port, 'server': server}

    def _check_connectivity(self, ip_version=4):
        servers_to = []

        for availability_zone in self.availability_zones_ovs:
            server_to = self._create_server_hwvtep(
                prepare_for_connectivity=False,
                availability_zone=availability_zone)
            servers_to.append(server_to)

        for availability_zone in self.availability_zones_ovs:
            # TODO(Marcelo) - Find a way to ssh the floating ip
            #  in the dpdk compute. Only ping works.
            if 'hwvtepdpdk' not in availability_zone:
                server_from = self._create_server_hwvtep(
                    prepare_for_connectivity=True,
                    availability_zone=availability_zone)

                for dest in servers_to:
                    self.assert_ping(
                        server_from['server'],
                        ip_version=ip_version,
                        address=dest['port']['fixed_ips'][0]['ip_address'])

    def _create_vsd_domain(self, is_l3=False, ip_version=(4,)):
        cidr4 = None
        cidr6 = None
        enable_dhcpv4 = False
        enable_dhcpv6 = False

        for ip_type in ip_version:
            if ip_type == 4:
                cidr4 = data_utils.gimme_a_cidr(ip_type)
            elif ip_type == 6:
                cidr6 = data_utils.gimme_a_cidr(ip_type)

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
                self.subnet.append(self.create_subnet(
                    self.network, ip_version=ip_type,
                    manager=self.admin_manager,
                    enable_dhcp=False))

    def test_server_connectivity_l2(self):
        self._setup_resources()
        self._check_connectivity()

    def test_server_connectivity_l2_ipv6(self):
        self._setup_resources(ip_version=(6,))
        self._check_connectivity(ip_version=6)

    def test_server_connectivity_l2_dual(self):
        self._setup_resources(ip_version=(4, 6))
        self._check_connectivity()

    def test_server_connectivity_l2_flat(self):
        self._setup_resources(is_flat=True)
        self._check_connectivity()

    def test_server_connectivity_l2_ipv6_flat(self):
        self._setup_resources(ip_version=(6,), is_flat=True)
        self._check_connectivity(ip_version=6)

    def test_server_connectivity_l2_dual_flat(self):
        self._setup_resources(ip_version=(4, 6), is_flat=True)
        self._check_connectivity()

    def test_server_connectivity_l2_vsd(self):
        self._create_vsd_domain()
        self._setup_resources(is_vsd_mgd=True)
        self._check_connectivity()

    def test_server_connectivity_l2_ipv6_vsd(self):
        self._create_vsd_domain(ip_version=(6,))
        self._setup_resources(ip_version=(6,), is_vsd_mgd=True)
        self._check_connectivity(ip_version=6)

    def test_server_connectivity_l2_dual_vsd(self):
        self._create_vsd_domain(ip_version=(4, 6))
        self._setup_resources(ip_version=(4, 6), is_vsd_mgd=True)
        self._check_connectivity()

    def test_server_connectivity_l2_flat_vsd(self):
        self._create_vsd_domain()
        self._setup_resources(is_flat=True, is_vsd_mgd=True)
        self._check_connectivity()

    def test_server_connectivity_l2_ipv6_flat_vsd(self):
        self._create_vsd_domain(ip_version=(6,))
        self._setup_resources(ip_version=(6,), is_flat=True, is_vsd_mgd=True)
        self._check_connectivity(ip_version=6)

    def test_server_connectivity_l2_dual_flat_vsd(self):
        self._create_vsd_domain(ip_version=(4, 6))
        self._setup_resources(ip_version=(4, 6), is_flat=True, is_vsd_mgd=True)
        self._check_connectivity()

    def test_server_connectivity_l3_vsd(self):
        self._create_vsd_domain(is_l3=True)
        self._setup_resources(is_vsd_mgd=True, is_l3=True)
        self._check_connectivity()

    def test_server_connectivity_l3_ipv6_vsd(self):
        self._create_vsd_domain(ip_version=(6,), is_l3=True)
        self._setup_resources(ip_version=(6,), is_vsd_mgd=True, is_l3=True)
        self._check_connectivity(ip_version=6)

    def test_server_connectivity_l3_dual_vsd(self):
        self._create_vsd_domain(ip_version=(4, 6), is_l3=True)
        self._setup_resources(ip_version=(4, 6), is_vsd_mgd=True, is_l3=True)
        self._check_connectivity()

    def test_server_connectivity_l3_flat_vsd(self):
        self._create_vsd_domain(is_l3=True)
        self._setup_resources(is_flat=True, is_vsd_mgd=True, is_l3=True)
        self._check_connectivity()

    def test_server_connectivity_l3_ipv6_flat_vsd(self):
        self._create_vsd_domain(ip_version=(6,), is_l3=True)
        self._setup_resources(ip_version=(6,), is_flat=True,
                              is_vsd_mgd=True, is_l3=True)
        self._check_connectivity(ip_version=6)

    def test_server_connectivity_l3_dual_flat_vsd(self):
        self._create_vsd_domain(ip_version=(4, 6), is_l3=True)
        self._setup_resources(ip_version=(4, 6), is_flat=True,
                              is_vsd_mgd=True, is_l3=True)
        self._check_connectivity()
