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

from netaddr import IPNetwork

from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils.data_utils import rand_name
from tempest.test import decorators

from . import base_nuage_gateway as base

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.lib.utils import exceptions
from nuage_tempest_plugin.tests.api.vsd_managed \
    import base_vsd_managed_networks as base_vsdman

LOG = Topology.get_logger(__name__)


class NuageGatewayTestRedundancy(base.BaseNuageGatewayTest,
                                 base_vsdman.BaseVSDManagedNetwork):

    @classmethod
    def resource_setup(cls):
        super(NuageGatewayTestRedundancy, cls).resource_setup()
        cls.gatewaygroups = []
        cls.redundant_gateways = []
        cls.redundant_ports = []
        cls.group_ports = []
        cls.group_vlans = []
        cls.group_vports = []

        cls.create_redundant_gateway_topology()

    @classmethod
    def resource_cleanup(cls):
        has_exception = False

        for vport in cls.group_vports:
            try:
                if vport['type'] == n_constants.HOST_VPORT:
                    cls.nuage_client.delete_host_interface(
                        vport['interface'])
                elif vport['type'] == n_constants.BRIDGE_VPORT:
                    cls.nuage_client.delete_bridge_interface(
                        vport['interface'])
                cls.nuage_client.delete_host_vport(vport['id'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for vlan in cls.group_vlans:
            try:
                if 'id' in vlan:
                    vlan_id = vlan['id']
                else:
                    vlan_id = vlan[0]['ID']
                cls.nuage_client.delete_vlan_permission(vlan_id)
                cls.nuage_client.delete_gateway_vlan(vlan_id)
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for grp in cls.gatewaygroups:
            try:
                cls.nuage_client.delete_gateway_redundancy_group(
                    grp[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for port in cls.redundant_ports:
            try:
                cls.nuage_client.delete_gateway_port(port[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for gateway in cls.redundant_gateways:
            try:
                cls.nuage_client.delete_gateway(gateway[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        super(NuageGatewayTestRedundancy, cls).resource_cleanup()
        if has_exception:
            raise exceptions.TearDownException()

    @classmethod
    def create_gateway_group(cls, gw1_id, gw2_id):
        name = rand_name('tempest-gw-grp')
        grp = cls.nuage_client.create_gateway_redundancy_group(
            name, gw1_id, gw2_id, None)
        return grp

    @classmethod
    def create_redundant_gateway_topology(cls):
        for personality in n_constants.GW_TYPES_UNDER_TEST:
            gw1 = cls.create_gateway(personality)
            cls.redundant_gateways.append(gw1)
            gw2 = cls.create_gateway(personality)
            cls.redundant_gateways.append(gw2)
            port_name = rand_name('tempest-redcy-port')
            p1 = cls.create_gateway_port(gw1, port_name)
            cls.redundant_ports.append(p1)
            p2 = cls.create_gateway_port(gw2, port_name)
            cls.redundant_ports.append(p2)
            gw_grp = cls.create_gateway_group(
                gw1[0]['ID'], gw2[0]['ID'])
            cls.gatewaygroups.append(gw_grp)
            if cls.is_hw_gateway_personality(personality):
                cls.nuage_client.create_vsg_redundant_port(
                    port_name,
                    'test',
                    'ACCESS',
                    gw_grp[0]['ID'])
            group_ports = cls.nuage_client.list_ports_by_redundancy_group(
                gw_grp[0]['ID'], personality)
            for port in group_ports:
                cls.group_ports.append(port)
                for i in range(n_constants.NUMBER_OF_VLANS_PER_PORT):
                    gw_vlan = (cls.nuage_client.
                               create_gateway_vlan_redundant_port(
                                   port['ID'],
                                   "test-vlan",
                                   str(n_constants.START_VLAN_VALUE + i),
                                   personality))
                    cls.group_vlans.append(gw_vlan)

    @staticmethod
    def get_item_by_id(id, item_list):
        return next((elem for elem in item_list if elem['id'] == id), None)

    @decorators.attr(type='smoke')
    def test_list_gateway_redundant(self):
        body = self.admin_client.list_gateways()
        gateways = body['nuage_gateways']
        for gw in self.gatewaygroups:
            gateway = self.get_item_by_id(gw[0]['ID'], gateways)
            self.assertIsNotNone(gateway,
                                 "Gateway %s not found" % gw[0]['name'])
            self.verify_gateway_properties(gw[0], gateway)

    @decorators.attr(type='smoke')
    def test_show_gateway_redundant(self):
        for gw in self.gatewaygroups:
            body = self.admin_client.show_gateway(gw[0]['ID'])
            gateway = body['nuage_gateway']
            self.verify_gateway_properties(gw[0], gateway)

    @decorators.attr(type='smoke')
    def test_list_redundant_port(self):
        for gw in self.gatewaygroups:
            body = self.admin_client.list_gateway_ports(gw[0]['ID'])
            gateway_ports = body['nuage_gateway_ports']
            for gw_port in self.group_ports:
                if gw_port['parentID'] == gw[0]['ID']:
                    gateway_port = self.get_item_by_id(gw_port['ID'],
                                                       gateway_ports)
                    self.assertIsNotNone(
                        gateway_port,
                        "Gateway Port %s not found" % gw_port['ID'])
                    self.verify_gateway_port_properties(
                        gw_port,
                        gateway_port)

    @decorators.attr(type='smoke')
    def test_list_redundant_port_by_gateway_name(self):
        for gw in self.gatewaygroups:
            body = self.admin_client.list_gateway_ports_by_gateway_name(
                gw[0]['name'])
            gateway_ports = body['nuage_gateway_ports']
            for gw_port in self.group_ports:
                if gw_port['parentID'] == gw[0]['ID']:
                    gateway_port = self.get_item_by_id(gw_port['ID'],
                                                       gateway_ports)
                    self.assertIsNotNone(
                        gateway_port,
                        "Gateway Port %s not found" % gw_port['ID'])
                    self.verify_gateway_port_properties(
                        gw_port,
                        gateway_port)

    @decorators.attr(type='smoke')
    def test_show_redundant_port(self):
        for gw_port in self.group_ports:
            body = self.admin_client.show_gateway_port(gw_port['ID'])
            gateway_port = body['nuage_gateway_port']
            self.verify_gateway_port_properties(gw_port, gateway_port)

    @decorators.attr(type='smoke')
    def test_create_vlan_redundant(self):
        gw_port = self.group_ports[0]
        kwargs = {
            'gatewayport': gw_port['ID'],
            'value': '900'
        }
        body = self.admin_client.create_gateway_vlan(**kwargs)
        vlan = body['nuage_gateway_vlan']

        # Get the vlan
        gw_vlan = self.nuage_client.get_gateway_vlan(
            n_constants.GATEWAY_PORT, gw_port['ID'], filters='value',
            filter_value=900)
        self.group_vlans.append(gw_vlan)

        vlan = body['nuage_gateway_vlan']
        self.verify_vlan_properties(gw_vlan[0], vlan)

    @decorators.attr(type='smoke')
    def test_delete_vlan_redundant(self):
        gw_port = self.group_ports[0]
        kwargs = {
            'gatewayport': gw_port['ID'],
            'value': '211'
        }
        body = self.admin_client.create_gateway_vlan(**kwargs)
        vlan = body['nuage_gateway_vlan']

        # Get the vlan
        gw_vlan = self.nuage_client.get_gateway_vlan(
            n_constants.GATEWAY_PORT, gw_port['ID'], filters='value',
            filter_value=211)

        self.group_vlans.append(gw_vlan)
        self.verify_vlan_properties(gw_vlan[0], vlan)

        # Delete the vlan
        self.client.delete_gateway_vlan(vlan['id'])

        # Verify in VSD
        gw_vlan = self.nuage_client.get_gateway_vlan(
            n_constants.GATEWAY_PORT, gw_port['ID'], filters='value',
            filter_value=211)

        self.assertEmpty(gw_vlan)

        # Since the vlan is deleted successfully, remove it from
        # self.group_vlans
        for gw_vlan in self.group_vlans:
            if 'id' in gw_vlan:
                vlan_id = gw_vlan['id']
            else:
                vlan_id = gw_vlan[0]['ID']

            if vlan_id == vlan['id']:
                self.group_vlans.remove(gw_vlan)

    @decorators.attr(type='smoke')
    def test_assign_unassign_vlan_redundant(self):
        gw_port = self.group_ports[0]
        kwargs = {
            'gatewayport': gw_port['ID'],
            'value': '210'
        }
        body = self.admin_client.create_gateway_vlan(**kwargs)
        vlan = body['nuage_gateway_vlan']
        # Get the vlan
        gw_vlan = self.nuage_client.get_gateway_vlan(
            n_constants.GATEWAY_PORT, gw_port['ID'], filters='value',
            filter_value=210)

        self.verify_vlan_properties(gw_vlan[0], vlan)

        self.group_vlans.append(gw_vlan)
        kwargs = {
            'action': 'assign',
            'tenant': self.client.tenant_id
        }

        body = self.admin_client.assign_gateway_vlan(
            vlan['id'], **kwargs)
        vlan_ent_permission = self.nuage_client.get_vlan_permission(
            n_constants.VLAN, vlan['id'], n_constants.ENTERPRISE_PERMS)
        self.assertEqual(vlan_ent_permission[0]['permittedEntityName'],
                         Topology.def_netpartition)

        vlan_permission = self.nuage_client.get_vlan_permission(
            n_constants.VLAN, vlan['id'], n_constants.PERMIT_ACTION)
        self.assertEqual(vlan_permission[0]['permittedEntityName'],
                         self.client.tenant_id)

        kwargs = {
            'action': 'unassign',
            'tenant': self.client.tenant_id
        }

        body = self.admin_client.assign_gateway_vlan(
            vlan['id'], **kwargs)
        vlan_ent_permission = self.nuage_client.get_vlan_permission(
            n_constants.VLAN, vlan['id'], n_constants.ENTERPRISE_PERMS)
        self.assertEmpty(vlan_ent_permission)

        vlan_permission = self.nuage_client.get_vlan_permission(
            n_constants.VLAN, vlan['id'], n_constants.PERMIT_ACTION)
        self.assertEmpty(vlan_permission)

    @decorators.attr(type='smoke')
    def test_nuage_vport_redundant_os_managed(self):
        # Create a host vport
        # Create a neutron port
        post_body = {"network_id": self.network['id'],
                     "device_owner": 'compute:ironic'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Create host vport
        kwargs = {
            'gatewayvlan': self.group_vlans[0][0]['ID'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.client.tenant_id
        }

        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport)
        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport)
        # tests vport-list
        body = self.admin_client.list_gateway_vport(self.subnet['id'])
        vports = body['nuage_gateway_vports']
        vport = self.get_item_by_id(gw_vport[0]['ID'], vports)
        self.assertIsNotNone(vport)
        self.verify_vport_properties(gw_vport[0], vport)

        # tests vport-show
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], self.subnet['id'])
        self.assertIsNotNone(body)
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport,
                             "Host Vport not found in gateway-vport-show")
        self.verify_vport_properties(gw_vport[0], vport)

        # Create Bridge vport
        kwargs = {
            'gatewayvlan': self.group_vlans[1][0]['ID'],
            'port': None,
            'subnet': self.subnet['id'],
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.group_vports.append(vport)

        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport)
        # tests vport-list
        body = self.admin_client.list_gateway_vport(self.subnet['id'])
        vports = body['nuage_gateway_vports']
        vport = self.get_item_by_id(gw_vport[0]['ID'], vports)
        self.assertIsNotNone(vport,
                             "Bridge Vport not found in gateway-vport-list")
        self.verify_vport_properties(gw_vport[0], vport)

        # tests vport-show
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], self.subnet['id'])
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport,
                             "Bridge Vport not found in gateway-vport-show")
        self.verify_vport_properties(gw_vport[0], vport)

    @decorators.attr(type='smoke')
    def test_nuage_vport_redundant_os_managed_nondef_netpart(self):
        # Create a host vport
        # Create a neutron port
        post_body = {"network_id": self.nondef_network['id'],
                     "device_owner": 'compute:ironic'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Create host vport
        kwargs = {
            'gatewayvlan': self.group_vlans[6][0]['ID'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.client.tenant_id
        }

        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport)
        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport)
        # tests vport-list
        body = self.admin_client.list_gateway_vport(self.nondef_subnet['id'])
        vports = body['nuage_gateway_vports']
        vport = self.get_item_by_id(gw_vport[0]['ID'], vports)
        self.assertIsNotNone(vport)
        self.verify_vport_properties(gw_vport[0], vport)

        # tests vport-show
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], self.nondef_subnet['id'])
        self.assertIsNotNone(body)
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport,
                             "Host Vport not found in gateway-vport-show")
        self.verify_vport_properties(gw_vport[0], vport)

        # Create Bridge vport
        kwargs = {
            'gatewayvlan': self.group_vlans[7][0]['ID'],
            'port': None,
            'subnet': self.nondef_subnet['id'],
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.group_vports.append(vport)

        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport)
        # tests vport-list
        body = self.admin_client.list_gateway_vport(self.nondef_subnet['id'])
        vports = body['nuage_gateway_vports']
        vport = self.get_item_by_id(gw_vport[0]['ID'], vports)
        self.assertIsNotNone(vport,
                             "Bridge Vport not found in gateway-vport-list")
        self.verify_vport_properties(gw_vport[0], vport)

        # tests vport-show
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], self.nondef_subnet['id'])
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport,
                             "Bridge Vport not found in gateway-vport-show")
        self.verify_vport_properties(gw_vport[0], vport)

    @decorators.attr(type='smoke')
    def test_vport_l3_vsd_managed(self):
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
            'gatewayvlan': self.group_vlans[2][0]['ID'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.client.tenant_id
        }

        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], subnet['id'])
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport, "Host Vport not found")
        self.verify_vport_properties(gw_vport[0], vport)

        # Create Bridge vport
        kwargs = {
            'gatewayvlan': self.group_vlans[3][0]['ID'],
            'port': None,
            'subnet': subnet['id'],
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.group_vports.append(vport)

        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport)
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], subnet['id'])
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport, "Bridge Vport not found")
        self.verify_vport_properties(gw_vport[0], vport)

    @decorators.attr(type='smoke')
    def test_vport_managed_l2_vsd_managed(self):
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
            'gatewayvlan': self.group_vlans[2][0]['ID'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], subnet['id'])
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport, "Host Vport not found")
        self.verify_vport_properties(gw_vport[0], vport)

        # Create Bridge vport
        kwargs = {
            'gatewayvlan': self.group_vlans[0][0]['ID'],
            'port': None,
            'subnet': subnet['id'],
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.group_vports.append(vport)

        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport)
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], subnet['id'])
        vport = body['nuage_gateway_vport']
        self.assertIsNotNone(vport, "Bridge Vport not found")
        self.verify_vport_properties(gw_vport[0], vport)
