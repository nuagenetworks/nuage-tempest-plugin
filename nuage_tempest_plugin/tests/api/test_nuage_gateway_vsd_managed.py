# Copyright 2015 Alcatel-Lucent USA Inc.
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
#

from . import base_nuage_gateway as base

from netaddr import IPNetwork
from nuage_tempest_plugin.tests.api.vsd_managed \
    import base_vsd_managed_networks as base_vsdman

from tempest.lib.common.utils import data_utils
from tempest.test import decorators

from nuage_tempest_plugin.lib.topology import Topology

LOG = Topology.get_logger(__name__)


class NuageGatewayTestVSDManaged(base.BaseNuageGatewayTest,
                                 base_vsdman.BaseVSDManagedNetwork):

    @classmethod
    def resource_setup(cls):
        super(NuageGatewayTestVSDManaged, cls).resource_setup()
        # create test topology
        cls.create_test_gateway_topology()

    @decorators.attr(type='smoke')
    def test_vport_l3(self):
        name = data_utils.rand_name('l3domain-')
        vsd_l3dom_tmplt = self.create_vsd_l3dom_template(
            name=name)
        vsd_l3dom = self.create_vsd_l3domain(name=name,
                                             tid=vsd_l3dom_tmplt[0]['ID'])
        zonename = data_utils.rand_name('l3dom-zone-')
        vsd_zone = self.create_vsd_zone(name=zonename,
                                        domain_id=vsd_l3dom[0]['ID'])
        subname = data_utils.rand_name('l3dom-sub-')
        cidr = IPNetwork('10.10.100.0/24')
        extra_params = {}
        vsd_subnet = self.create_vsd_l3domain_subnet(
            name=subname,
            zone_id=vsd_zone[0]['ID'],
            cidr=cidr,
            gateway='10.10.100.1',
            extra_params=extra_params)
        net_name = data_utils.rand_name('network-vsd-managed-')
        net = self.create_network(network_name=net_name)
        np = Topology.def_netpartition
        subnet = self.create_subnet(net,
                                    cidr=cidr,
                                    mask_bits=24,
                                    nuagenet=vsd_subnet[0]['ID'],
                                    net_partition=np)

        post_body = {"network_id": net['id'],
                     "device_owner": 'compute:ironic'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Create host vport
        kwargs = {
            'gatewayvlan': self.gatewayvlans[2][0]['ID'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.client.tenant_id
        }

        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport, "vport is not created")
        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], subnet['id'])
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport, "show host vport failed")
        self.verify_vport_properties(gw_vport[0], vport,
                                     post_body['network_id'])

        # Create Bridge vport
        kwargs = {
            'gatewayvlan': self.gatewayvlans[4][0]['ID'],
            'port': None,
            'subnet': subnet['id'],
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport, "vport is not created")
        self.gatewayvports.append(vport)

        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport,
                                     post_body['network_id'])
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], subnet['id'])
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport, "show Bridge Vport failed")
        self.verify_vport_properties(gw_vport[0], vport,
                                     post_body['network_id'])

    @decorators.attr(type='smoke')
    def test_vport_managed_l2(self):
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name, cidr=cidr, gateway='10.10.100.1')
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        net = self.create_network(network_name=net_name)
        subnet = self.create_subnet(
            net, gateway=None,
            cidr=cidr, mask_bits=24, nuagenet=vsd_l2dom[0]['ID'],
            net_partition=Topology.def_netpartition,
            enable_dhcp=True)
        post_body = {"network_id": net['id'],
                     "device_owner": 'compute:ironic'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Create host vport
        kwargs = {
            'gatewayvlan': self.gatewayvlans[2][0]['ID'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.client.tenant_id
        }

        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport, "vport is not created")
        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], subnet['id'])
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone("show Host Vport failed")
        self.verify_vport_properties(gw_vport[0], vport,
                                     post_body['network_id'])

        # Create Bridge vport
        kwargs = {
            'gatewayvlan': self.gatewayvlans[1][0]['ID'],
            'port': None,
            'subnet': subnet['id'],
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport, "vport is not created")
        self.gatewayvports.append(vport)

        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport,
                                     post_body['network_id'])
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], subnet['id'])
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport, "show Bridge Vport failed")
        self.verify_vport_properties(gw_vport[0], vport,
                                     post_body['network_id'])

    @decorators.attr(type='smoke')
    def test_vport_managed_l2_dhcp_disabled(self):
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name, cidr=cidr, enableDHCPv4=False)
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l2dom[0]['name'], name)
        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        net = self.create_network(network_name=net_name)
        subnet = self.create_subnet(
            net,
            cidr=cidr,
            mask_bits=24, nuagenet=vsd_l2dom[0]['ID'],
            net_partition=Topology.def_netpartition,
            enable_dhcp=False)
        post_body = {"network_id": net['id'],
                     "device_owner": 'compute:ironic'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Create host vport
        kwargs = {
            'gatewayvlan': self.gatewayvlans[2][0]['ID'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.client.tenant_id
        }

        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport, "vport is not created")
        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], subnet['id'])
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport, "show Host Vport failed")
        self.verify_vport_properties(gw_vport[0], vport,
                                     post_body['network_id'])
