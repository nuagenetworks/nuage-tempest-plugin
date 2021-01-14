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

import random

from tempest.lib.common.utils import data_utils as tempest_data_utils

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils

LOG = Topology.get_logger(__name__)
CONF = Topology.get_conf()

NETWORK_ARGS = {
    'segments': [
        {
            'provider:network_type': 'vlan',
            'provider:segmentation_id': 123,
            'provider:physical_network': 'physnet1'
        },
        {
            'provider:network_type': 'vxlan'
        }
    ]
}

OVS_ARGS = {'binding:vnic_type': 'normal'}


class HwvtepSriovBasicOpsTest(NuageBaseTest):
    force_tenant_isolation = False

    ip_types = {(4,): 'IPV4', (6,): 'IPV6', (4, 6): 'DUALSTACK'}

    @classmethod
    def resource_setup(cls):
        super(HwvtepSriovBasicOpsTest, cls).resource_setup()
        cls.aggregates = cls.admin_manager.aggregates_client.list_aggregates()

        cls.hosts_ovs = [aggregate['hosts'] for aggregate in
                         cls.aggregates['aggregates']
                         if aggregate['metadata']['flavor'] == 'hwvtep'][0]

        cls.hosts_sriov = [aggregate['hosts'] for aggregate in
                           cls.aggregates['aggregates']
                           if aggregate['metadata']['flavor'] == 'sriov'][0]

        cls.availability_zones_ovs = ['nova:' + host for host
                                      in cls.hosts_ovs]
        cls.availability_zones_sriov = ['nova:' + host for host
                                        in cls.hosts_sriov]

    @classmethod
    def skip_checks(cls):
        super(HwvtepSriovBasicOpsTest, cls).skip_checks()

        if CONF.network.port_vnic_type not in ['direct']:
            msg = 'Test requires port_vnic_type "direct"'
            raise cls.skipException(msg)
        if Topology.has_default_switchdev_port_profile():
            raise cls.skipException('Test requires switchdev offloading '
                                    'to be disabled')

    def _check_connectivity(self, ip_version=4):

        sriov_compute = self.availability_zones_sriov[0]
        server_to = self._create_server_with_direct_port(
            availability_zone=sriov_compute)

        ovs_compute_from = random.choice(self.availability_zones_ovs)
        server_from = self._create_server_hwvtep(
            availability_zone=ovs_compute_from)

        self.assert_ping(server_from, server_to, network=self.network,
                         ip_version=ip_version)

    def _create_server_hwvtep(self, availability_zone):
        port = self.create_port(self.network,
                                manager=self.admin_manager,
                                **OVS_ARGS)
        return self.create_tenant_server(
            availability_zone=availability_zone,
            ports=[port],
            prepare_for_connectivity=True,
            manager=self.admin_manager,
            config_drive=True,
            no_net_partition=True)

    def _create_server_with_direct_port(self, availability_zone):
        kwargs = {'config_drive': True}
        port = self.create_port(self.network,
                                port_security_enabled=False,
                                manager=self.admin_manager)
        return self.create_tenant_server(
            availability_zone=availability_zone,
            ports=[port],
            prepare_for_connectivity=False,
            manager=self.admin_manager,
            **kwargs)

    def _create_vsd_domain(self, is_l3=True, ip_version=(4,)):
        cidr4 = None
        cidr6 = None
        enable_dhcpv4 = False
        enable_dhcpv6 = False

        for ip_type in ip_version:
            if ip_type == 4:
                cidr4 = data_utils.gimme_a_cidr(ip_type)
            elif ip_type == 6:
                cidr6 = data_utils.gimme_a_cidr(ip_type)

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
                manager=self.admin_manager, dhcp_managed=False))

        self.secgroup = self.create_open_ssh_security_group(
            manager=self.admin_manager)

    def _setup_resources(self, ip_version=(4,)):
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

        self.secgroup = self.create_open_ssh_security_group(
            manager=self.admin_manager)

    def test_server_connectivity_l2(self):
        self._setup_resources()
        self._check_connectivity()

    def test_server_connectivity_l2_ipv6(self):
        self._setup_resources(ip_version=(6,))
        self._check_connectivity(ip_version=6)

    def test_server_connectivity_l2_dual(self):
        self._setup_resources(ip_version=(4, 6))
        self._check_connectivity()

    def test_server_connectivity_l3_vsd_mgd(self):
        self._setup_resources_vsd_mgd()
        self._check_connectivity()

    def test_server_connectivity_l2_vsd_mgd(self):
        self._setup_resources_vsd_mgd(is_l3=False)
        self._check_connectivity()

    def test_server_connectivity_l3_ipv6_vsd_mgd(self):
        self._setup_resources_vsd_mgd(ip_version=(6,))
        self._check_connectivity(ip_version=6)

    def test_server_connectivity_l2_ipv6_vsd_mgd(self):
        self._setup_resources_vsd_mgd(is_l3=False, ip_version=(6,))
        self._check_connectivity(ip_version=6)

    def test_server_connectivity_l3_dual_vsd_mgd(self):
        self._setup_resources_vsd_mgd(ip_version=(4, 6))
        self._check_connectivity()

    def test_server_connectivity_l2_dual_vsd_mgd(self):
        self._setup_resources_vsd_mgd(is_l3=False, ip_version=(4, 6))
        self._check_connectivity()
