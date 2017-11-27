# Copyright 2015 OpenStack Foundation
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

from netaddr import IPAddress
from netaddr import IPNetwork
from oslo_log import log as logging

from tempest import config
from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.tests.api.vsd_managed \
    import base_vsd_managed_port_attributes

CONF = config.CONF
LOG = logging.getLogger(__name__)


class BaseVSDManagedSRIOV(
        base_vsd_managed_port_attributes.BaseVSDManagedPortAttributes):

    @classmethod
    def setup_clients(cls):
        super(BaseVSDManagedSRIOV, cls).setup_clients()
        # cls.nuageclient = NuageRestClient()

    # TODO(team) shd below methods be class methods ? then replace self by cls

    @classmethod
    def _create_vsd_l2_managed_subnet_withoptions(self, net_name_prefix, cidr,
                                                  gateway):
        kwargs = {
            'name': data_utils.rand_name(net_name_prefix),
            'cidr': cidr,
            'gateway': gateway,
        }
        l2dom_template = self.create_vsd_dhcpmanaged_l2dom_template(**kwargs)
        vsd_l2_subnet = self.create_vsd_l2domain(tid=l2dom_template[0]['ID'])
        return vsd_l2_subnet, l2dom_template

    @classmethod
    def _create_vsd_l3_managed_subnet_withoptions(
            self, cidr, net_name_prefix="l3dom_template"):
        # create template
        kwargs = {
            'name': data_utils.rand_name("l3dom_template"),
        }
        l3dom_template = self.create_vsd_l3dom_template(**kwargs)
        # create domain
        vsd_l3_domain = self.create_vsd_l3domain(tid=l3dom_template[0]['ID'])
        # create zone om domain
        zone = self.create_vsd_zone(name='l3-zone',
                                    domain_id=vsd_l3_domain[0]['ID'])
        # create subnet in zone
        kwargs = {
            'name': data_utils.rand_name("vsd-l3-mgd-subnet"),
            'zone_id': zone[0]['ID'],
            'cidr': cidr,
            'gateway': str(IPAddress(cidr.first + 1)),
            'extra_params': ""
        }
        vsd_l3_subnet = self.create_vsd_l3domain_managed_subnet(**kwargs)
        return vsd_l3_subnet, vsd_l3_domain

    @classmethod
    def _create_os_vsd_managed_subnet_withoptions(self, network,
                                                  vsd_subnet, cidr):
        kwargs = {
            'network': network,
            'cidr': cidr,
            'mask_bits': cidr.prefixlen,
            'net_partition': CONF.nuage.nuage_default_netpartition,
            'nuagenet': vsd_subnet[0]['ID']
            # 'tenant_id': None
        }
        subnet = self._create_subnet(**kwargs)
        return subnet

    @classmethod
    def create_sriov_dummy_network_multisegment(
            self, name="dummy-1", physnet_name="physnet1"):
        segments_req = [{"provider:network_type": "flat",
                         "provider:physical_network": physnet_name},
                        {"provider:physical_network": "",
                         "provider:network_type": "vxlan"}]
        network_name = data_utils.rand_name(name)
        kwargs = {'description': 'sriov parent dummy network',
                  'segments': segments_req}
        body = self.admin_networks_client.create_network(
            name=network_name, **kwargs)
        network = body['network']
        self.networks.append(network)
        return network

    @classmethod
    def create_sriov_overlay_network_multisegment(
            self, segmentation, name="overlay-1", physnet_name="physnet1"):
        segments_req = [{"provider:network_type": "vlan",
                         "provider:physical_network": physnet_name,
                         "provider:segmentation_id": segmentation},
                        {"provider:physical_network": "",
                         "provider:network_type": "vxlan"}]
        network_name = data_utils.rand_name(name)
        kwargs = {'description': 'sriov overlay vlan network',
                  'segments': segments_req}
        body = self.networks_client.create_network(
            name=network_name, **kwargs)
        network = body['network']
        self.networks.append(network)
        return network

    def sriov_port_create(
            self, network, port_name="direct-port", vnic_type="direct"):
        kwargs = {
            'name': port_name,
            'binding:vnic_type': vnic_type
        }
        port1 = self.create_port(network, **kwargs)
        return port1

    @classmethod
    def setup_sriov_networks(self):
        dummy_network_ip = IPNetwork('99.0.0.0/8')
        dummy_network_ip_gw = "99.0.0.1"
        net_vlan_12_ip = IPNetwork('12.0.0.0/8')
        net_vlan_12_ip_gw = "12.0.0.1"
        net_vlan_33_ip = IPNetwork('33.0.0.0/8')
        net_vlan_33_ip_gw = "33.0.0.1"
        net_vlan_20_ip = IPNetwork('20.0.0.0/8')
        net_vlan_20_ip_gw = "20.0.0.1"
        net_vlan_22_ip = IPNetwork('22.0.0.0/8')
        net_vlan_34_ip = IPNetwork('34.0.0.0/8')
        net_vlan_35_ip = IPNetwork('35.0.0.0/8')

        # create dummy network
        vsd_l2_subnet, l2_domtmpl = \
            self._create_vsd_l2_managed_subnet_withoptions(
                "dummy_net_physnet2",
                dummy_network_ip, dummy_network_ip_gw)
        network = self.create_sriov_dummy_network_multisegment(
            "dummy_net_physnet2",
            "physnet2")
        self._create_os_vsd_managed_subnet_withoptions(
            network, vsd_l2_subnet, dummy_network_ip)

        # create l2 overlay network
        vsd_l2_subnet_1, l2_domtmpl_1 = \
            self._create_vsd_l2_managed_subnet_withoptions(
                "net_vlan_33", net_vlan_33_ip, net_vlan_33_ip_gw)
        network_33 = self.create_sriov_overlay_network_multisegment(
            "33", "net_vlan_33", "physnet2")
        self._create_os_vsd_managed_subnet_withoptions(
            network_33, vsd_l2_subnet_1, net_vlan_33_ip)

        # create l2 overlay network
        vsd_l2_subnet_2, l2_domtmpl_2 = \
            self._create_vsd_l2_managed_subnet_withoptions(
                "net_vlan_20", net_vlan_20_ip, net_vlan_20_ip_gw)
        network_20 = self.create_sriov_overlay_network_multisegment(
            "20", "net_vlan_20", "physnet2")
        self._create_os_vsd_managed_subnet_withoptions(
            network_20, vsd_l2_subnet_2, net_vlan_20_ip)

        # create l2 overlay network
        vsd_l2_subnet_3, l2_domtmpl_3 = \
            self._create_vsd_l2_managed_subnet_withoptions(
                "net_vlan_12", net_vlan_12_ip, net_vlan_12_ip_gw)
        network_12 = self.create_sriov_overlay_network_multisegment(
            "12", "net_vlan_12", "physnet2")
        self._create_os_vsd_managed_subnet_withoptions(
            network_12, vsd_l2_subnet_3, net_vlan_12_ip)

        # create l3 overlay network
        vsd_l3_subnet_34, vsd_l3_domain_1 = \
            self._create_vsd_l3_managed_subnet_withoptions(
                net_vlan_34_ip, "net_vlan_34")
        network_34 = self.create_sriov_overlay_network_multisegment(
            "34", "net_vlan_34", "physnet2")
        self._create_os_vsd_managed_subnet_withoptions(
            network_34, vsd_l3_subnet_34, net_vlan_34_ip)

        # create l3 overlay network
        vsd_l3_subnet_2, vsd_l3_domain_2 = \
            self._create_vsd_l3_managed_subnet_withoptions(
                net_vlan_35_ip, "net_vlan_35")
        network_35 = self.create_sriov_overlay_network_multisegment(
            "35", "net_vlan_35", "physnet2")
        self._create_os_vsd_managed_subnet_withoptions(
            network_35, vsd_l3_subnet_2, net_vlan_35_ip)

        # create l3 overlay network
        vsd_l3_subnet_3, vsd_l3_domain_3 = \
            self._create_vsd_l3_managed_subnet_withoptions(
                net_vlan_22_ip, "net_vlan_22")
        network_22 = self.create_sriov_overlay_network_multisegment(
            "22", "net_vlan_22", "physnet2")
        self._create_os_vsd_managed_subnet_withoptions(
            network_22, vsd_l3_subnet_3, net_vlan_22_ip)

        return network, vsd_l2_subnet, network_12, vsd_l2_subnet_3,\
            network_34, vsd_l3_subnet_34

    def _create_server_sriov_port(self, port, name="vm1", flavor="2",
                                  image=CONF.compute.image_ref,
                                  config_drive="true"):
        kwargs = {'networks': [{'port': port['id']}],
                  'config_drive': config_drive}
        return self.create_server(name, image, flavor, **kwargs)
