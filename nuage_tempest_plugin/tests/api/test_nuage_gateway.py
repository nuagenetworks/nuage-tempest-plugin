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

import uuid

from testtools.matchers import ContainsDict
from testtools.matchers import Equals

from tempest.lib import exceptions as lib_exec
from tempest.test import decorators

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.tests.api.upgrade.external_id.external_id \
    import ExternalId

from . import base_nuage_gateway as base

LOG = Topology.get_logger(__name__)


class NuageGatewayTestJSON(base.BaseNuageGatewayTest):

    @classmethod
    def resource_setup(cls):
        super(NuageGatewayTestJSON, cls).resource_setup()
        # create test topology
        cls.create_test_gateway_topology()

    @classmethod
    def resource_cleanup(cls):
        super(NuageGatewayTestJSON, cls).resource_cleanup()

    @decorators.attr(type='smoke')
    def test_list_gateway(self):
        body = self.admin_client.list_gateways()
        gateways = body['nuage_gateways']

        for gw in self.gateways:
            found_gateway = False
            for gateway in gateways:
                if gw[0]['name'] == gateway['name']:
                    found_gateway = True
                    self.verify_gateway_properties(gw[0], gateway)

            if not found_gateway:
                assert False, "Gateway not found"

    @decorators.attr(type='smoke')
    def test_show_gateway(self):
        for gw in self.gateways:
            body = self.admin_client.show_gateway(gw[0]['ID'])
            gateway = body['nuage_gateway']
            self.verify_gateway_properties(gw[0], gateway)

    @decorators.attr(type='smoke')
    def test_list_gateway_port(self):
        for gw in self.gateways:
            body = self.admin_client.list_gateway_ports(gw[0]['ID'])
            gateway_ports = body['nuage_gateway_ports']
            for gateway_port in gateway_ports:
                found_port = False
                for gw_port in self.gatewayports:
                    if gw_port[0]['ID'] == gateway_port['id']:
                        found_port = True
                        self.verify_gateway_port_properties(
                            gw_port[0],
                            gateway_port)
                if not found_port:
                    assert False, "Gateway Port not found"

    @decorators.attr(type='smoke')
    def test_list_gateway_port_by_gateway_name(self):
        for gw in self.gateways:
            body = self.admin_client.list_gateway_ports_by_gateway_name(
                gw[0]['name'])
            gateway_ports = body['nuage_gateway_ports']
            for gateway_port in gateway_ports:
                found_port = False
                for gw_port in self.gatewayports:
                    if gw_port[0]['ID'] == gateway_port['id']:
                        found_port = True
                        self.verify_gateway_port_properties(
                            gw_port[0],
                            gateway_port)
                if not found_port:
                    assert False, "Gateway Port not found"

    @decorators.attr(type='smoke')
    def test_show_gateway_port(self):
        for gw_port in self.gatewayports:
            body = self.admin_client.show_gateway_port(gw_port[0]['ID'])
            gateway_port = body['nuage_gateway_port']
            self.verify_gateway_port_properties(gw_port[0], gateway_port)

    @decorators.attr(type='smoke')
    def test_show_gateway_port_by_gateway_name(self):
        for gw_port in self.gatewayports:
            gateway = self.nuage_client.get_global_gateways(
                filters='ID', filter_value=gw_port[0]['parentID'])
            body = self.admin_client.show_gateway_ports_by_gateway_name(
                gw_port[0]['name'], gateway[0]['name'])
            gateway_port = body['nuage_gateway_port']
            self.verify_gateway_port_properties(gw_port[0], gateway_port)

    @decorators.attr(type='smoke')
    def test_create_vlan(self):
        gw_port = self.gatewayports[0]
        kwargs = {
            'gatewayport': gw_port[0]['ID'],
            'value': '900'
        }
        body = self.admin_client.create_gateway_vlan(**kwargs)
        vlan = body['nuage_gateway_vlan']

        # Get the vlan
        gw_vlan = self.nuage_client.get_gateway_vlan(
            n_constants.GATEWAY_PORT, gw_port[0]['ID'], filters='value',
            filter_value=900)
        self.gatewayvlans.append(gw_vlan)

        vlan = body['nuage_gateway_vlan']
        self.verify_vlan_properties(gw_vlan[0], vlan)

    @decorators.attr(type='smoke')
    def test_delete_vlan(self):
        gw_port = self.gatewayports[0]
        kwargs = {
            'gatewayport': gw_port[0]['ID'],
            'value': '211'
        }
        body = self.admin_client.create_gateway_vlan(**kwargs)
        vlan = body['nuage_gateway_vlan']

        # Get the vlan
        gw_vlan = self.nuage_client.get_gateway_vlan(
            n_constants.GATEWAY_PORT, gw_port[0]['ID'], filters='value',
            filter_value=211)

        self.gatewayvlans.append(gw_vlan)
        self.verify_vlan_properties(gw_vlan[0], vlan)

        # Delete the vlan
        self.client.delete_gateway_vlan(vlan['id'])

        # Verify in VSD
        gw_vlan = self.nuage_client.get_gateway_vlan(
            n_constants.GATEWAY_PORT, gw_port[0]['ID'], filters='value',
            filter_value=211)

        self.assertEmpty(gw_vlan)

        # Since the vlan is deleted successfully, remove it from
        # self.gatewayvlans
        for gw_vlan in self.gatewayvlans:
            if 'id' in gw_vlan:
                vlan_id = gw_vlan['id']
            else:
                vlan_id = gw_vlan[0]['ID']

            if vlan_id == vlan['id']:
                self.gatewayvlans.remove(gw_vlan)

    @decorators.attr(type='smoke')
    def test_show_vlan_by_admin_tenant(self):
        gw_vlan = self.gatewayvlans[0]
        # Get the vlan
        body = (self.admin_client.show_gateway_vlan(gw_vlan[0]['ID']))

        vlan = body['nuage_gateway_vlan']
        self.verify_vlan_properties(gw_vlan[0], vlan, False)

    @decorators.attr(type='smoke')
    def test_show_vlan_by_admin_tenant_by_name(self):
        gw_vlan = self.gatewayvlans[0]
        gateway = self.nuage_client.get_global_gateways(
            filters='ID',
            filter_value=gw_vlan[0]['gatewayID'])
        # Get the vlan
        body = (self.admin_client.show_gateway_vlan_by_name(
            gw_vlan[0]['value'],
            self.gatewayports[0][0]['name'],
            gateway[0]['name']))

        vlan = body['nuage_gateway_vlan']
        self.verify_vlan_properties(gw_vlan[0], vlan, False)

    @decorators.attr(type='smoke')
    def test_list_vlan_by_admin_tenant(self):
        gw_port = self.gatewayports[0]
        body = self.admin_client.list_gateway_vlans(gw_port[0]['ID'])
        vlans = body['nuage_gateway_vlans']

        for vlan in vlans:
            found_vlan = False
            for gw_vlan in self.gatewayvlans:
                if gw_vlan[0]['ID'] == vlan['id']:
                    found_vlan = True
                    self.verify_vlan_properties(gw_vlan[0], vlan, False)
            if not found_vlan:
                assert False, "Vlan not found"

    @decorators.attr(type='smoke')
    def test_list_vlan_by_admin_tenant_by_name(self):
        gw_port = self.gatewayports[0]
        gateway = self.nuage_client.get_global_gateways(
            filters='ID', filter_value=gw_port[0]['parentID'])
        gatway_port = gw_port[0]['name']
        body = self.admin_client.list_gateway_vlans_by_name(
            gatway_port, gateway[0]['name'])
        vlans = body['nuage_gateway_vlans']

        for vlan in vlans:
            found_vlan = False
            for gw_vlan in self.gatewayvlans:
                if gw_vlan[0]['ID'] == vlan['id']:
                    found_vlan = True
                    self.verify_vlan_properties(gw_vlan[0], vlan, False)
            if not found_vlan:
                assert False, "Vlan not found"

    @decorators.attr(type=['negative', 'smoke'])
    def test_create_invalid_vlan(self):
        gw_port = self.gatewayports[0]
        kwargs = {
            'gatewayport': gw_port[0]['ID'],
            'value': '11111111111111111111111111111111'
        }

        self.assertRaises(lib_exec.BadRequest,
                          self.admin_client.create_gateway_vlan,
                          **kwargs)

    @decorators.attr(type=['negative', 'smoke'])
    def test_delete_invalid_vlan(self):
        self.assertRaises(lib_exec.NotFound,
                          self.admin_client.delete_gateway_vlan,
                          '11111111111111111111111111111111')

    @decorators.attr(type=['negative', 'smoke'])
    def test_show_invalid_vlan(self):
        self.assertRaises(lib_exec.NotFound,
                          self.admin_client.show_gateway_vlan,
                          '11111111111111111111111111111111')

    @decorators.attr(type='smoke')
    def test_assign_unassign_vlan(self):
        gw_port = self.gatewayports[0]
        kwargs = {
            'gatewayport': gw_port[0]['ID'],
            'value': '210'
        }
        body = self.admin_client.create_gateway_vlan(**kwargs)
        vlan = body['nuage_gateway_vlan']
        # Get the vlan
        gw_vlan = self.nuage_client.get_gateway_vlan(
            n_constants.GATEWAY_PORT, gw_port[0]['ID'], filters='value',
            filter_value=210)

        self.verify_vlan_properties(gw_vlan[0], vlan)

        self.gatewayvlans.append(gw_vlan)
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

        self.admin_client.assign_gateway_vlan(
            vlan['id'], **kwargs)
        vlan_ent_permission = self.nuage_client.get_vlan_permission(
            n_constants.VLAN, vlan['id'], n_constants.ENTERPRISE_PERMS)
        self.assertEmpty(vlan_ent_permission)

        vlan_permission = self.nuage_client.get_vlan_permission(
            n_constants.VLAN, vlan['id'], n_constants.PERMIT_ACTION)
        self.assertEmpty(vlan_permission)

    @decorators.attr(type='smoke')
    def test_port_fip_assoc(self):
        # Verify port creation
        post_body = {"network_id": self.network['id'],
                     "device_owner": 'compute:ironic'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Associate a fip to the vport
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=port['id'],
            fixed_ip_address=port['fixed_ips'][0]['ip_address'])
        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['id'])
        self.assertEqual(created_floating_ip['fixed_ip_address'],
                         port['fixed_ips'][0]['ip_address'])

    @decorators.attr(type='smoke')
    def test_port_fip_assoc_nondef_netpart(self):
        # Verify port creation
        post_body = {"network_id": self.nondef_network['id'],
                     "device_owner": 'compute:ironic'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Associate a fip to the vport
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=port['id'],
            fixed_ip_address=port['fixed_ips'][0]['ip_address'])
        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['id'])
        self.assertEqual(created_floating_ip['fixed_ip_address'],
                         port['fixed_ips'][0]['ip_address'])

    @decorators.attr(type='smoke')
    def test_host_port_fip_assoc(self):
        # Verify port creation
        post_body = {"network_id": self.network['id'],
                     "device_owner": 'compute:ironic'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])

        # Associate a fip to the vport
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=port['id'],
            fixed_ip_address=port['fixed_ips'][0]['ip_address'])
        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['id'])
        self.assertEqual(created_floating_ip['fixed_ip_address'],
                         port['fixed_ips'][0]['ip_address'])

        # Create a vlan
        gw_port = self.gatewayports[0]
        kwargs = {
            'gatewayport': gw_port[0]['ID'],
            'value': '3000'
        }
        body = self.admin_client.create_gateway_vlan(**kwargs)
        vlan = body['nuage_gateway_vlan']

        # Get the vlan
        gw_vlan = self.nuage_client.get_gateway_vlan(
            n_constants.GATEWAY_PORT, gw_port[0]['ID'], filters='value',
            filter_value=3000)

        self.gatewayvlans.append(gw_vlan)
        self.verify_vlan_properties(gw_vlan[0], vlan)

        # Create a vport
        kwargs = {
            'gatewayvlan': vlan['id'],
            'port': port['id'],
            'subnet': None,
            'tenant': str(uuid.uuid4()).replace('-', '')
        }

        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']

        # Verify fip is associated in VSD
        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        network_id = self.network['id']
        self.verify_vport_properties(gw_vport[0], vport, network_id)
        self.assertIsNotNone(gw_vport[0]['associatedFloatingIPID'])

    @decorators.attr(type='smoke')
    def test_list_nuage_vport(self):
        # Create a host vport
        # Create a neutron port
        post_body = {"network_id": self.network['id'],
                     "device_owner": 'compute:ironic'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Create host vport
        kwargs = {
            'gatewayvlan': self.gatewayvlans[0][0]['ID'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.client.tenant_id
        }

        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']

        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        network_id = self.network['id']
        self.verify_vport_properties(gw_vport[0], vport, network_id)
        body = self.admin_client.list_gateway_vport(self.subnet['id'])
        vports = body['nuage_gateway_vports']
        found_vport = False
        for vport in vports:
            if vport['name'] == gw_vport[0]['name']:
                found_vport = True
                self.verify_vport_properties(gw_vport[0], vport, network_id)

        if not found_vport:
            assert False, "Host Vport not found"

        # Create Bridge vport
        kwargs = {
            'gatewayvlan': self.gatewayvlans[1][0]['ID'],
            'port': None,
            'subnet': self.subnet['id'],
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.gatewayvports.append(vport)

        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport, network_id)
        body = self.admin_client.list_gateway_vport(self.subnet['id'])
        vports = body['nuage_gateway_vports']
        found_vport = False
        for vport in vports:
            if vport['name'] == gw_vport[0]['name']:
                found_vport = True
                self.verify_vport_properties(gw_vport[0], vport, network_id)

        if not found_vport:
            assert False, "Bridge Vport not found"

    @decorators.attr(type='smoke')
    def test_list_nuage_vport_nondef_netpart(self):
        # Create a host vport
        # Create a neutron port
        post_body = {"network_id": self.nondef_network['id'],
                     "device_owner": 'compute:ironic'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Create host vport
        kwargs = {
            'gatewayvlan': self.gatewayvlans[11][0]['ID'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.client.tenant_id
        }

        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']

        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport,
                                     self.nondef_network['id'])
        body = self.admin_client.list_gateway_vport(self.nondef_subnet['id'])
        vports = body['nuage_gateway_vports']
        found_vport = False
        for vport in vports:
            if vport['name'] == gw_vport[0]['name']:
                found_vport = True
                self.verify_vport_properties(gw_vport[0], vport,
                                             self.nondef_network['id'])

        if not found_vport:
            assert False, "Host Vport not found"

        # Create Bridge vport
        kwargs = {
            'gatewayvlan': self.gatewayvlans[8][0]['ID'],
            'port': None,
            'subnet': self.nondef_subnet['id'],
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.gatewayvports.append(vport)
        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport,
                                     self.nondef_network['id'])
        body = self.admin_client.list_gateway_vport(self.nondef_subnet['id'])
        vports = body['nuage_gateway_vports']
        found_vport = False
        for vport in vports:
            if vport['name'] == gw_vport[0]['name']:
                found_vport = True
                self.verify_vport_properties(gw_vport[0], vport,
                                             self.nondef_network['id'])

        if not found_vport:
            assert False, "Bridge Vport not found"

    @decorators.attr(type='smoke')
    def test_show_nuage_vport(self):
        post_body = {"network_id": self.network['id'],
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
        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], self.subnet['id'])
        vport = body['nuage_gateway_vport']
        if vport is None:
            assert False, "Host Vport not found"
        self.verify_vport_properties(gw_vport[0], vport, self.network['id'])

    @decorators.attr(type='smoke')
    def test_show_nuage_vport_nondef_netpart(self):
        post_body = {"network_id": self.nondef_network['id'],
                     "device_owner": 'compute:ironic'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Create host vport
        kwargs = {
            'gatewayvlan': self.gatewayvlans[9][0]['ID'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.client.tenant_id
        }

        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], self.nondef_subnet['id'])
        vport = body['nuage_gateway_vport']
        if vport is None:
            assert False, "Host Vport not found"
        self.verify_vport_properties(gw_vport[0], vport, self.network['id'])

    # @decorators.attr(type='smoke')
    def test_default_security_group_host_port(self):
        post_body = {"network_id": self.network['id'],
                     "device_owner": 'nuage:vip'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Create host vport
        kwargs = {
            'gatewayvlan': self.gatewayvlans[3][0]['ID'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], self.subnet['id'])
        vport = body['nuage_gateway_vport']
        if vport is None:
            assert False, "Host Vport not found"
        self.verify_vport_properties(gw_vport[0], vport, self.network['id'])
        l3domain = self.nuage_client.get_l3domain(
            filters='externalID',
            filter_value=self.router['id'])
        default_pg = self.nuage_client.get_policygroup(
            n_constants.DOMAIN, l3domain[0]['ID'])
        if default_pg[0]['name'] == n_constants.NUAGE_PLCY_GRP_ALLOW_ALL:
            pg_num = 0
        else:
            pg_num = 1
        self.assertEqual(n_constants.NUAGE_PLCY_GRP_ALLOW_ALL,
                         default_pg[pg_num]['name'])
        vport_from_pg = self.nuage_client.get_vport(
            n_constants.POLICYGROUP,
            default_pg[pg_num]['ID'])
        if len(vport_from_pg) == 1:
            self.assertEqual(vport_from_pg[0]['name'], vport['name'])
        elif len(vport_from_pg) == 2:
            # One bridge vport is created by another test or neutron dhcp
            # agent is enabled.
            self.assertEqual(vport_from_pg[1]['name'], vport['name'])
        else:
            # One bridge vport is created by another test and neutron dhcp
            # agent is enabled.
            self.assertEqual(vport_from_pg[2]['name'], vport['name'])
        nuage_eacl_template = self.nuage_client.get_egressacl_template(
            n_constants.DOMAIN,
            l3domain[0]['ID'])
        nuage_eacl_entrytemplate = \
            self.nuage_client.get_egressacl_entrytemplate(
                n_constants.EGRESS_ACL_TEMPLATE,
                nuage_eacl_template[0]['ID'])
        vport_tp_pg_mapping = False
        for nuage_eacl_entry in nuage_eacl_entrytemplate:
            if nuage_eacl_entry['locationID'] == default_pg[pg_num]['ID']:
                self.assertEqual(
                    nuage_eacl_entry['networkType'],
                    'ANY')
                self.assertEqual(
                    nuage_eacl_entry['locationType'],
                    'POLICYGROUP')
                vport_tp_pg_mapping = True

        if vport_tp_pg_mapping is False:
            assert False, "Host Vport not found in default PG"

    # @decorators.attr(type='smoke')
    def test_default_security_group_bridge_port(self):
        kwargs = {
            'gatewayvlan': self.gatewayvlans[4][0]['ID'],
            'port': None,
            'subnet': self.subnet['id'],
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport1 = body['nuage_gateway_vport']
        self.gatewayvports.append(vport1)

        gw_vport = self.nuage_client.get_host_vport(vport1['id'])
        self.verify_vport_properties(gw_vport[0], vport1, self.network['id'])
        body = self.admin_client.list_gateway_vport(self.subnet['id'])
        vports = body['nuage_gateway_vports']
        found_vport = False
        vport = None
        for vport in vports:
            if vport['name'] == gw_vport[0]['name']:
                found_vport = True
                self.verify_vport_properties(gw_vport[0], vport,
                                             self.network['id'])
                # TODO(Kris noticed) - shld there be break here?

        if not found_vport:
            assert False, "Bridge Vport not found"
        l3domain = self.nuage_client.get_l3domain(
            filters='externalID',
            filter_value=self.router['id'])
        default_pg = self.nuage_client.get_policygroup(
            n_constants.DOMAIN, l3domain[0]['ID'])
        self.assertEqual(n_constants.NUAGE_PLCY_GRP_ALLOW_ALL,
                         default_pg[0]['name'])

        if Topology.within_ext_id_release():
            self.assertThat(default_pg[0],
                            ContainsDict(
                                {'externalID':
                                 Equals(ExternalId(
                                     n_constants.NUAGE_PLCY_GRP_ALLOW_ALL
                                 ).at_cms_id())}))
        else:
            self.assertThat(default_pg[0],
                            ContainsDict({'externalID': Equals(None)}))

        vports_from_pg = self.nuage_client.get_vport(
            n_constants.POLICYGROUP,
            default_pg[0]['ID'])
        for vport_from_pg in vports_from_pg:
            if vport_from_pg['name'] == vport['name']:
                break
        else:
            self.fail("Can't find Vport {} under the policy group {}".format(
                vport['name'], default_pg[0]['name']))

        # Egress ACL
        nuage_eacl_template = self.nuage_client.get_egressacl_template(
            n_constants.DOMAIN,
            l3domain[0]['ID'])

        if Topology.within_ext_id_release():
            # must have external ID as router_id @ cms_id
            self.assertThat(nuage_eacl_template[0],
                            ContainsDict({'externalID':
                                         Equals(ExternalId(
                                             self.router['id']
                                         ).at_cms_id())}))
        else:
            self.assertThat(nuage_eacl_template[0],
                            ContainsDict({'externalID': Equals(None)}))

        nuage_eacl_entrytemplate = \
            self.nuage_client.get_egressacl_entrytemplate(
                n_constants.EGRESS_ACL_TEMPLATE,
                nuage_eacl_template[0]['ID'])

        if Topology.within_ext_id_release():
            self.assertThat(nuage_eacl_entrytemplate[0],
                            ContainsDict({'externalID': Equals(
                                ExternalId(
                                    n_constants.NUAGE_PLCY_GRP_ALLOW_ALL
                                ).at_cms_id())}))
        else:
            self.assertThat(nuage_eacl_entrytemplate[0],
                            ContainsDict({'externalID': Equals(None)}))

        vport_tp_pg_mapping = False
        for nuage_eacl_entry in nuage_eacl_entrytemplate:
            if nuage_eacl_entry['locationID'] == default_pg[0]['ID']:
                if Topology.within_ext_id_release():
                    self.assertThat(
                        nuage_eacl_entry,
                        ContainsDict({'externalID': Equals(ExternalId(
                            n_constants.NUAGE_PLCY_GRP_ALLOW_ALL
                        ).at_cms_id())}))
                else:
                    self.assertThat(nuage_eacl_entry,
                                    ContainsDict({'externalID': Equals(None)}))

                self.assertEqual(
                    nuage_eacl_entry['networkType'],
                    'ANY')
                self.assertEqual(
                    nuage_eacl_entry['locationType'],
                    'POLICYGROUP')
                vport_tp_pg_mapping = True

        if vport_tp_pg_mapping is False:
            assert False, "Bridge Vport not found in default PG"

        # Ingress ACL
        nuage_iacl_template = self.nuage_client.get_ingressacl_template(
            n_constants.DOMAIN,
            l3domain[0]['ID'])

        if Topology.within_ext_id_release():
            # must have external ID as router_id @ cms_id
            self.assertThat(nuage_iacl_template[0],
                            ContainsDict({'externalID':
                                         Equals(ExternalId(
                                             self.router['id']
                                         ).at_cms_id())}))
        else:
            self.assertThat(nuage_iacl_template[0],
                            ContainsDict({'externalID': Equals(None)}))

        nuage_iacl_entrytemplate = \
            self.nuage_client.get_ingressacl_entrytemplate(
                n_constants.INGRESS_ACL_TEMPLATE,
                nuage_iacl_template[0]['ID'])

        if Topology.within_ext_id_release():
            self.assertThat(nuage_iacl_entrytemplate[0],
                            ContainsDict({'externalID': Equals(
                                ExternalId(
                                    n_constants.NUAGE_PLCY_GRP_ALLOW_ALL,
                                ).at_cms_id())}))
        else:
            self.assertThat(nuage_iacl_entrytemplate[0],
                            ContainsDict({'externalID': Equals(None)}))

        vport_tp_pg_mapping = False
        for nuage_iacl_entry in nuage_iacl_entrytemplate:
            if nuage_iacl_entry['locationID'] == default_pg[0]['ID']:
                if Topology.within_ext_id_release():
                    self.assertThat(
                        nuage_iacl_entry,
                        ContainsDict({'externalID': Equals(ExternalId(
                            n_constants.NUAGE_PLCY_GRP_ALLOW_ALL
                        ).at_cms_id())}))
                else:
                    self.assertThat(nuage_iacl_entry,
                                    ContainsDict({'externalID': Equals(None)}))

                self.assertEqual(
                    nuage_iacl_entry['networkType'],
                    'ANY')
                self.assertEqual(
                    nuage_iacl_entry['locationType'],
                    'POLICYGROUP')
                vport_tp_pg_mapping = True

        if vport_tp_pg_mapping is False:
            assert False, "Bridge Vport not found in default PG"

    # @decorators.attr(type='smoke')
    def test_default_security_group_host_port_nondef_netpart(self):
        post_body = {"network_id": self.nondef_network['id'],
                     "device_owner": 'nuage:vip'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Create host vport
        kwargs = {
            'gatewayvlan': self.gatewayvlans[5][0]['ID'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], self.nondef_subnet['id'])
        vport = body['nuage_gateway_vport']
        if vport is None:
            assert False, "Host Vport not found"
        self.verify_vport_properties(gw_vport[0], vport, self.network['id'])
        l3domain = self.nuage_client.get_l3domain(
            filters='externalID',
            filter_value=self.nondef_router['id'],
            netpart_name=self.nondef_netpart['name'])
        default_pg = self.nuage_client.get_policygroup(
            n_constants.DOMAIN, l3domain[0]['ID'])
        if default_pg[0]['name'] == n_constants.NUAGE_PLCY_GRP_ALLOW_ALL:
            pg_num = 0
        else:
            pg_num = 1

        self.assertEqual(n_constants.NUAGE_PLCY_GRP_ALLOW_ALL,
                         default_pg[pg_num]['name'])
        vport_from_pg = self.nuage_client.get_vport(
            n_constants.POLICYGROUP,
            default_pg[pg_num]['ID'])
        if len(vport_from_pg) == 1:
            self.assertEqual(vport_from_pg[0]['name'], vport['name'])
        elif len(vport_from_pg) == 2:
            # One bridge vport is created by another test or neutron dhcp
            # agent is enabled.
            self.assertEqual(vport_from_pg[1]['name'], vport['name'])
        else:
            # One bridge vport is created by another test and neutron dhcp
            # agent is enabled.
            self.assertEqual(vport_from_pg[2]['name'], vport['name'])
        nuage_eacl_template = self.nuage_client.get_egressacl_template(
            n_constants.DOMAIN,
            l3domain[0]['ID'])
        nuage_eacl_entrytemplate = \
            self.nuage_client.get_egressacl_entrytemplate(
                n_constants.EGRESS_ACL_TEMPLATE,
                nuage_eacl_template[0]['ID'])
        vport_tp_pg_mapping = False
        for nuage_eacl_entry in nuage_eacl_entrytemplate:
            if nuage_eacl_entry['locationID'] == default_pg[pg_num]['ID']:
                self.assertEqual(
                    nuage_eacl_entry['networkType'],
                    'ANY')
                self.assertEqual(
                    nuage_eacl_entry['locationType'],
                    'POLICYGROUP')
                vport_tp_pg_mapping = True

        if vport_tp_pg_mapping is False:
            assert False, "Host Vport not found in default PG"

    # @decorators.attr(type='smoke')
    def test_default_security_group_bridge_port_nondef_netpart(self):
        kwargs = {
            'gatewayvlan': self.gatewayvlans[6][0]['ID'],
            'port': None,
            'subnet': self.nondef_subnet['id'],
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.gatewayvports.append(vport)

        gw_vport = self.nuage_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport,
                                     self.nondef_network['id'])
        body = self.admin_client.list_gateway_vport(self.nondef_subnet['id'])
        vports = body['nuage_gateway_vports']
        found_vport = False
        for vport in vports:
            if vport['name'] == gw_vport[0]['name']:
                found_vport = True
                self.verify_vport_properties(gw_vport[0], vport,
                                             self.nondef_network['id'])

        if not found_vport:
            assert False, "Bridge Vport not found"
        l3domain = self.nuage_client.get_l3domain(
            filters='externalID',
            filter_value=self.nondef_router['id'],
            netpart_name=self.nondef_netpart['name'])
        default_pg = self.nuage_client.get_policygroup(
            n_constants.DOMAIN, l3domain[0]['ID'])
        self.assertEqual(n_constants.NUAGE_PLCY_GRP_ALLOW_ALL,
                         default_pg[0]['name'])
        vports_from_pg = self.nuage_client.get_vport(
            n_constants.POLICYGROUP,
            default_pg[0]['ID'])
        for vport_from_pg in vports_from_pg:
            if vport_from_pg['name'] == vport['name']:
                break
        else:
            self.fail("Can't find Vport {} under the policy group {}".format(
                vport['name'], default_pg[0]['name']))
        nuage_eacl_template = self.nuage_client.get_egressacl_template(
            n_constants.DOMAIN,
            l3domain[0]['ID'])
        nuage_eacl_entrytemplate = \
            self.nuage_client.get_egressacl_entrytemplate(
                n_constants.EGRESS_ACL_TEMPLATE,
                nuage_eacl_template[0]['ID'])
        vport_tp_pg_mapping = False
        for nuage_eacl_entry in nuage_eacl_entrytemplate:
            if nuage_eacl_entry['locationID'] == default_pg[0]['ID']:
                self.assertEqual(
                    nuage_eacl_entry['networkType'],
                    'ANY')
                self.assertEqual(
                    nuage_eacl_entry['locationType'],
                    'POLICYGROUP')
                vport_tp_pg_mapping = True

        if vport_tp_pg_mapping is False:
            assert False, "Bridge Vport not found in default PG"
