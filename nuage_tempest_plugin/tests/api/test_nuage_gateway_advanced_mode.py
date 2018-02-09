# Copyright 2015 Alcatel-Lucent USA Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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
import uuid

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.lib.utils import exceptions
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON
from nuage_tempest_plugin.tests.api.vsd_managed \
    import base_vsd_managed_network as base_vsdman

from tempest.api.network import base
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils.data_utils import rand_name
from tempest.lib import exceptions as lib_exec
from tempest.test import decorators

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class NuageGatewayTestJSON(base.BaseAdminNetworkTest,
                           base_vsdman.BaseVSDManagedNetworksTest):
    _interface = 'json'

    @classmethod
    def create_gateway(cls, personality):
        name = rand_name('tempest-gw')
        gw = cls.nuage_vsd_client.create_gateway(
            name, str(uuid.uuid4()), personality, None)
        return gw

    @classmethod
    def create_gateway_port(cls, gw):
        name = rand_name('tempest-gw-port')
        gw_port = cls.nuage_vsd_client.create_gateway_port(
            name, 'test', 'ACCESS', gw[0]['ID'])
        return gw_port

    @classmethod
    def create_gateway_vlan(cls, gw_port, value):
        gw_port = cls.nuage_vsd_client.create_gateway_vlan(
            gw_port[0]['ID'], 'test', value)
        return gw_port

    @classmethod
    def create_redundancy_group(cls, gw1, gw2):
        rdn_grp_name = rand_name('rd-grp')
        rdn_grp = cls.nuage_vsd_client.create_redundancy_group(
            rdn_grp_name, gw1[0]['ID'], gw2[0]['ID'])
        return rdn_grp

    @classmethod
    def create_vrsg_redundancy_ports(cls, rd_grp):
        name = rand_name('tempest-gw-vrsg-rd-port')
        gw_port = cls.nuage_vsd_client.create_vrsg_redundancy_ports(
            name, 'test', 'ACCESS', rd_grp[0]['ID'])
        return gw_port

    @classmethod
    def create_vsg_redundancy_ports(cls, gw_1_port, gw_2_port, rdn_grp):
        name = rand_name('tempest-gw-vsg-rd-port')
        gw_port = cls.nuage_vsd_client.create_vsg_redundancy_ports(
            name, 'test', 'ACCESS',
            gw_1_port[0]['ID'],
            gw_2_port[0]['ID'], rdn_grp)
        return gw_port

    @classmethod
    def create_vsg_redundancy_vlans(cls, rd_port, value):
        gw_vlan = cls.nuage_vsd_client.create_vsg_redundancy_vlans(
            rd_port[0]['ID'], 'test', value)
        return gw_vlan

    @classmethod
    def create_test_gateway_topology(cls):
        for personality in n_constants.PERSONALITY_LIST:
            gw = cls.create_gateway(personality)
            cls.gateways.append(gw)

        for gateway in cls.gateways:
            for i in range(n_constants.NUMBER_OF_PORTS_PER_GATEWAY):
                gw_port = cls.create_gateway_port(gateway)
                cls.gatewayports.append(gw_port)

        for gw_port in cls.gatewayports:
            for i in range(n_constants.NUMBER_OF_VLANS_PER_PORT):
                gw_vlan = cls.create_gateway_vlan(
                    gw_port, str(
                        n_constants.START_VLAN_VALUE + i))
                cls.gatewayvlans.append(gw_vlan)

    @classmethod
    def create_test_gateway_redundancy_topology(cls):
        gw_1_port = []
        gw_2_port = []
        for personality in n_constants.PERSONALITY_LIST:
            gw1 = cls.create_gateway(personality)
            gw2 = cls.create_gateway(personality)
            cls.rdn_gateways.append(gw1)
            cls.rdn_gateways.append(gw2)

            if personality == 'VSG':
                name = 'rd-gw-port-vsg'
                gw_1_port = cls.nuage_vsd_client.create_gateway_port(
                    name, 'test', 'ACCESS', gw1[0]['ID'])
                gw_2_port = cls.nuage_vsd_client.create_gateway_port(
                    name, 'test', 'ACCESS', gw2[0]['ID'])
                cls.rdn_gw_ports_vsg.append(gw_1_port)
                cls.rdn_gw_ports_vsg.append(gw_2_port)

            rdn_grp = cls.create_redundancy_group(gw1, gw2)
            cls.rdn_groups.append(rdn_grp)

            if personality == 'VRSG':
                gw_port = cls.create_vrsg_redundancy_ports(rdn_grp)
                cls.rdn_gw_ports_vrsg.append(gw_port)
                gw_vlan = cls.create_gateway_vlan(
                    gw_port, n_constants.START_VLAN_VALUE)
                cls.gatewayvlans.append(gw_vlan)

            if personality == 'VSG':
                name = 'rd-gw-port-vsg'
                gw_port = cls.nuage_vsd_client.create_vsg_redundancy_ports(
                    name, 'test', 'ACCESS',
                    gw_1_port[0]['ID'],
                    gw_2_port[0]['ID'], rdn_grp)
                cls.rdn_gw_ports_vsg_combn.append(gw_port)
                gw_vlan = cls.create_vsg_redundancy_vlans(
                    gw_port, n_constants.START_VLAN_VALUE)
                cls.gatewayvlans.append(gw_vlan)

    @classmethod
    def delete_test_gateway_redundancy_topology(cls):
        has_exception = False

        for port in cls.rdn_gw_ports_vrsg:
            try:
                cls.nuage_vsd_client.delete_gateway_port(port[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        if has_exception:
            raise exceptions.TearDownException()

        for port in cls.rdn_gw_ports_vsg_combn:
            try:
                cls.nuage_vsd_client.delete_vsg_redundancy_ports(port[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        if has_exception:
            raise exceptions.TearDownException()

        for port in cls.rdn_gw_ports_vsg:
            try:
                cls.nuage_vsd_client.delete_gateway_port(port[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        if has_exception:
            raise exceptions.TearDownException()

        for grp in cls.rdn_groups:
            try:
                cls.nuage_vsd_client.delete_redundancy_group(grp[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        if has_exception:
            raise exceptions.TearDownException()

        for gateway in cls.rdn_gateways:
            try:
                cls.nuage_vsd_client.delete_gateway(gateway[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        if has_exception:
            raise exceptions.TearDownException()

    @classmethod
    def setup_clients(cls):
        super(NuageGatewayTestJSON, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()
        # Overriding cls.client with Nuage network client
        cls.client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)
        # initialize admin client
        cls.admin_client = NuageNetworkClientJSON(
            cls.os_admin.auth_provider,
            **cls.os_admin.default_params)

    @classmethod
    def setUpClass(cls):
        super(NuageGatewayTestJSON, cls).setUpClass()

        cls.gateways = []
        cls.gatewayports = []
        cls.gatewayvlans = []
        cls.gatewayvports = []
        cls.rdn_gateways = []
        cls.rdn_groups = []
        cls.rdn_gw_ports_vsg = []
        cls.rdn_gw_ports_vrsg = []
        cls.rdn_gw_ports_vsg_combn = []

        cls.ext_net_id = CONF.network.public_network_id
        cls.network = cls.create_network()

        name = data_utils.rand_name('l3domain-')
        cls.vsd_l3dom_tmplt = cls.create_vsd_l3dom_template(name=name)
        l3dom_extra_params = {'tunnelType': 'VXLAN'}
        cls.vsd_l3dom = cls.create_vsd_l3domain(
            name=name,
            tid=cls.vsd_l3dom_tmplt[0]['ID'],
            extra_params=l3dom_extra_params)

        zonename = data_utils.rand_name('l3dom-zone-')
        vsd_zone = cls.create_vsd_zone(name=zonename,
                                       domain_id=cls.vsd_l3dom[0]['ID'])
        subname = data_utils.rand_name('l3dom-sub-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_domain_subnet = cls.create_vsd_l3domain_subnet(
            name=subname,
            zone_id=vsd_zone[0]['ID'],
            cidr=cidr,
            gateway='10.10.100.1')
        cls.subnet = cls.create_subnet(
            cls.network,
            cidr=cidr, mask_bits=24, nuagenet=vsd_domain_subnet[0]['ID'],
            net_partition=Topology.def_netpartition)

        # Create resources in non-default net-partition
        netpart_body = cls.client.create_netpartition(
            data_utils.rand_name('Enterprise-'))
        cls.nondef_netpart = netpart_body['net_partition']
        cls.nondef_network = cls.create_network()
        name = data_utils.rand_name('l3domain-')
        cls.nondef_vsd_l3dom_tmplt = cls.nuageclient.create_l3domaintemplate(
            name=name, netpart_name=cls.nondef_netpart['name'])

        l3dom_extra_params = {'tunnelType': 'VXLAN'}
        cls.nondef_vsd_l3dom = cls.nuageclient.create_domain(
            name,
            cls.nondef_vsd_l3dom_tmplt[0]['ID'],
            netpart_name=cls.nondef_netpart['name'],
            extra_params=l3dom_extra_params)
        cls.vsd_l3domain.append(cls.nondef_vsd_l3dom)

        zonename = data_utils.rand_name('l3dom-zone-')
        vsd_zone = cls.create_vsd_zone(name=zonename,
                                       domain_id=cls.nondef_vsd_l3dom[0]['ID'])
        subname = data_utils.rand_name('l3dom-sub-')
        l2domain_extra_params = {'net_partition': cls.nondef_netpart['name']}
        vsd_domain_subnet = cls.nuageclient.create_domain_subnet(
            name=subname,
            parent_id=vsd_zone[0]['ID'],
            net_address='20.20.200.0',
            netmask='255.255.255.0',
            gateway='20.20.200.1',
            extra_params=l2domain_extra_params)
        cls.nondef_subnet = cls.create_subnet(
            cls.nondef_network,
            cidr=IPNetwork('20.20.200.0/24'),
            mask_bits=24, nuagenet=vsd_domain_subnet[0]['ID'],
            net_partition=cls.nondef_netpart['name'])

        # Create test gateway
        cls.create_test_gateway_topology()
        cls.create_test_gateway_redundancy_topology()

    @classmethod
    def resource_cleanup(cls):
        has_exception = False

        for vport in cls.gatewayvports:
            try:
                if vport['type'] == n_constants.HOST_VPORT:
                    cls.nuage_vsd_client.delete_host_interface(
                        vport['interface'])
                elif vport['type'] == n_constants.BRIDGE_VPORT:
                    cls.nuage_vsd_client.delete_bridge_interface(
                        vport['interface'])
                cls.nuage_vsd_client.delete_host_vport(vport['id'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        if has_exception:
            raise exceptions.TearDownException()

        for vlan in cls.gatewayvlans:
            try:
                if 'id' in vlan:
                    vlan_id = vlan['id']
                else:
                    vlan_id = vlan[0]['ID']
                cls.nuage_vsd_client.delete_vlan_permission(vlan_id)
                cls.nuage_vsd_client.delete_gateway_vlan(vlan_id)
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        if has_exception:
            raise exceptions.TearDownException()

        for port in cls.gatewayports:
            try:
                cls.nuage_vsd_client.delete_gateway_port(port[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        if has_exception:
            raise exceptions.TearDownException()

        for gateway in cls.gateways:
            try:
                cls.nuage_vsd_client.delete_gateway(gateway[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        if has_exception:
            raise exceptions.TearDownException()

        cls.delete_test_gateway_redundancy_topology()

        super(NuageGatewayTestJSON, cls).resource_cleanup()
        cls.client.delete_netpartition(cls.nondef_netpart['id'])

    def verify_gateway_properties(self, actual_gw, expected_gw):
        self.assertEqual(actual_gw['ID'], expected_gw['id'])
        self.assertEqual(actual_gw['name'], expected_gw['name'])
        self.assertEqual(actual_gw['personality'], expected_gw['type'])

    def verify_gateway_port_properties(self, actual_port, expected_port):
        self.assertEqual(actual_port['name'], expected_port['name'])
        self.assertEqual(actual_port['ID'], expected_port['id'])

    def verify_vlan_properties(self, actual_vlan, expected_vlan,
                               verify_ext=True):
        self.assertEqual(actual_vlan['ID'], expected_vlan['id'])
        self.assertEqual(actual_vlan['userMnemonic'],
                         expected_vlan['usermnemonic'])
        self.assertEqual(actual_vlan['value'], expected_vlan['value'])
        if Topology.within_ext_id_release() and verify_ext:
            external_id = (expected_vlan['gatewayport'] + "." +
                           str(expected_vlan['value']))
            self.assertEqual(actual_vlan['externalID'],
                             self.nuage_vsd_client.get_vsd_external_id(
                                 external_id))

    def verify_vport_properties(self, actual_vport, expected_vport):
        self.assertEqual(actual_vport['ID'], expected_vport['id'])
        self.assertEqual(actual_vport['type'], expected_vport['type'])
        self.assertEqual(actual_vport['name'], expected_vport['name'])
        if Topology.within_ext_id_release():
            if expected_vport['type'] == n_constants.BRIDGE_VPORT:
                self.assertEqual(actual_vport['externalID'],
                                 self.nuage_vsd_client.get_vsd_external_id(
                                     expected_vport['subnet']))
            else:
                self.assertEqual(actual_vport['externalID'],
                                 self.nuage_vsd_client.get_vsd_external_id(
                                     expected_vport['port']))

    @decorators.attr(type='smoke')
    def test_list_gateway(self):
        # List both single and redundant gateways
        body = self.admin_client.list_gateways()
        gateways = body['nuage_gateways']

        for gw in self.gateways and self.rdn_groups:
            found_gateway = False
            for gateway in gateways:
                if gw[0]['name'] == gateway['name']:
                    found_gateway = True
                    self.verify_gateway_properties(gw[0], gateway)

            if not found_gateway:
                assert False, "Gateway/Redundancy Group not found"

    @decorators.attr(type='smoke')
    def test_show_gateway(self):
        # Show both single and redundant gateways
        for gw in self.gateways and self.rdn_groups:
            body = self.admin_client.show_gateway(gw[0]['ID'])
            gateway = body['nuage_gateway']
            self.verify_gateway_properties(gw[0], gateway)

    @decorators.attr(type='smoke')
    def test_list_gateway_port(self):
        found_port = False
        # List ports of both single and redundant gateways
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

        for gw in self.rdn_groups:
            body = self.admin_client.list_gateway_ports(gw[0]['ID'])
            gateway_ports = body['nuage_gateway_ports']
            for gateway_port in gateway_ports:
                found_port = False
                for gw_port in self.rdn_gw_ports_vsg_combn:
                    if gw_port[0]['ID'] == gateway_port['id']:
                        found_port = True
                        self.verify_gateway_port_properties(
                            gw_port[0],
                            gateway_port)

        if not found_port:
            assert False, "Redundant Gateway Port not found"

    @decorators.attr(type='smoke')
    def test_list_gateway_port_by_gateway_name(self):
        found_port = False
        # List ports of both single and redundant gateways
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

        for gw in self.rdn_groups:
            body = self.admin_client.list_gateway_ports_by_gateway_name(
                gw[0]['name'])
            gateway_ports = body['nuage_gateway_ports']
            for gateway_port in gateway_ports:
                found_port = False
                for gw_port in self.rdn_gw_ports_vsg_combn:
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
            gateway = self.nuage_vsd_client.get_global_gateways(
                filters='ID', filter_value=gw_port[0]['parentID'])
            body = self.admin_client.show_gateway_ports_by_gateway_name(
                gw_port[0]['name'], gateway[0]['name'])
            gateway_port = body['nuage_gateway_port']
            self.verify_gateway_port_properties(gw_port[0], gateway_port)

    def _create_gateway_vlan(self, gw_type, gw_port):
        kwargs = {
            'gatewayport': gw_port[0]['ID'],
            'value': '900'
        }
        body = self.admin_client.create_gateway_vlan(**kwargs)
        vlan = body['nuage_gateway_vlan']
        self.assertIsNotNone(vlan)

        if gw_type == 'non-redundant':
            gw_vlan = self.nuage_vsd_client.get_gateway_vlan(
                n_constants.GATEWAY_PORT, gw_port[0]['ID'],
                filters='value',
                filter_value=900)
        else:
            gw_vlan = self.nuage_vsd_client.get_gateway_vlan(
                n_constants.VSG_REDUNDANT_PORTS, gw_port[0]['ID'],
                filters='value',
                filter_value=900)
        self.gatewayvlans.append(gw_vlan)

        vlan = body['nuage_gateway_vlan']
        self.verify_vlan_properties(gw_vlan[0], vlan)

    @decorators.attr(type='smoke')
    def test_create_vlan(self):
        self._create_gateway_vlan('non-redundant', self.gatewayports[0])

    @decorators.attr(type='smoke')
    def test_create_vlan_redundant_vsg(self):
        self._create_gateway_vlan('redundant', self.rdn_gw_ports_vsg_combn[0])

    @decorators.attr(type='smoke')
    def test_create_vlan_redundant_vrsg(self):
        self._create_gateway_vlan('non-redundant', self.rdn_gw_ports_vrsg[0])

    def _delete_gateway_vlan(self, gw_type, gw_port):
        # gw_port = self.gatewayports[0]
        kwargs = {
            'gatewayport': gw_port[0]['ID'],
            'value': '211'
        }
        body = self.admin_client.create_gateway_vlan(**kwargs)
        vlan = body['nuage_gateway_vlan']

        # Get the vlan
        if gw_type == 'non-redundant':
            gw_vlan = self.nuage_vsd_client.get_gateway_vlan(
                n_constants.GATEWAY_PORT, gw_port[0]['ID'],
                filters='value',
                filter_value=211)
        else:
            gw_vlan = self.nuage_vsd_client.get_gateway_vlan(
                n_constants.VSG_REDUNDANT_PORTS, gw_port[0]['ID'],
                filters='value',
                filter_value=211)

        self.gatewayvlans.append(gw_vlan)
        self.verify_vlan_properties(gw_vlan[0], vlan)

        # Delete the vlan
        self.client.delete_gateway_vlan(vlan['id'])

        # Verify in VSD
        # Get the vlan
        if gw_type == 'non-redundant':
            gw_vlan = self.nuage_vsd_client.get_gateway_vlan(
                n_constants.GATEWAY_PORT, gw_port[0]['ID'],
                filters='value',
                filter_value=211)
        else:
            gw_vlan = self.nuage_vsd_client.get_gateway_vlan(
                n_constants.VSG_REDUNDANT_PORTS, gw_port[0]['ID'],
                filters='value',
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
    def test_delete_vlan(self):
        self._delete_gateway_vlan('non-redundant', self.gatewayports[0])

    @decorators.attr(type='smoke')
    def test_delete_vlan_redundant_vsg(self):
        self._delete_gateway_vlan('redundant', self.rdn_gw_ports_vsg_combn[0])

    @decorators.attr(type='smoke')
    def test_delete_vlan_redundant_vrsg(self):
        self._delete_gateway_vlan('non-redundant', self.rdn_gw_ports_vrsg[0])

    def _show_verify_gateway_vlan(self, gw_vlan):
        # Get the vlan
        body = (self.admin_client.show_gateway_vlan(gw_vlan[0]['ID']))

        vlan = body['nuage_gateway_vlan']
        self.verify_vlan_properties(gw_vlan[0], vlan, verify_ext=False)

    @decorators.attr(type='smoke')
    def test_show_vlan_by_admin_tenant(self):
        self._show_verify_gateway_vlan(self.gatewayvlans[0])

    @decorators.attr(type='smoke')
    def test_show_vlan_by_admin_tenant_rdn_gateway(self):
        self._show_verify_gateway_vlan(self.gatewayvlans[9])

    @decorators.attr(type='smoke')
    def test_show_vlan_by_admin_tenant_by_name(self):
        gw_vlan = self.gatewayvlans[0]
        gw_port = self.gatewayports[0]
        self.assertIsNotNone(gw_port)
        gateway = self.nuage_vsd_client.get_global_gateways(
            filters='ID',
            filter_value=gw_vlan[0]['gatewayID'])
        # Get the vlan
        body = (self.admin_client.show_gateway_vlan_by_name(
            gw_vlan[0]['value'],
            self.gatewayports[0][0]['name'],
            gateway[0]['name']))

        vlan = body['nuage_gateway_vlan']
        self.verify_vlan_properties(gw_vlan[0], vlan, verify_ext=False)

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
                    self.verify_vlan_properties(gw_vlan[0], vlan,
                                                verify_ext=False)
            if not found_vlan:
                assert False, "Vlan not found"

    @decorators.attr(type='smoke')
    def test_list_vlan_by_admin_tenant_by_name(self):
        gw_port = self.gatewayports[0]
        gateway = self.nuage_vsd_client.get_global_gateways(
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
                    self.verify_vlan_properties(gw_vlan[0], vlan,
                                                verify_ext=False)
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
    def test_create_invalid_vlan_rdn_gateway(self):
        gw_port = self.rdn_gw_ports_vsg_combn[0]
        kwargs = {
            'gatewayport': gw_port[0]['ID'],
            'value': '11111111111111111111111111111111'
        }

        self.assertRaises(lib_exec.BadRequest,
                          self.admin_client.create_gateway_vlan,
                          **kwargs)

    @decorators.attr(type=['negative', 'smoke'])
    def test_delete_invalid_vlan(self):
        non_exist_id = data_utils.rand_uuid()
        self.assertRaises(lib_exec.NotFound,
                          self.admin_client.delete_gateway_vlan,
                          non_exist_id)

    @decorators.attr(type=['negative', 'smoke'])
    def test_show_invalid_vlan(self):
        non_exist_id = data_utils.rand_uuid()
        self.assertRaises(lib_exec.NotFound,
                          self.admin_client.show_gateway_vlan,
                          non_exist_id)

    def _assign_unassign_vlan(self, gw_type, gw_port):
        kwargs = {
            'gatewayport': gw_port[0]['ID'],
            'value': '210'
        }
        body = self.admin_client.create_gateway_vlan(**kwargs)
        vlan = body['nuage_gateway_vlan']
        # Get the vlan

        if gw_type == 'non-redundant':
            gw_vlan = self.nuage_vsd_client.get_gateway_vlan(
                n_constants.GATEWAY_PORT, gw_port[0]['ID'],
                filters='value',
                filter_value=210)
        else:
            gw_vlan = self.nuage_vsd_client.get_gateway_vlan(
                n_constants.VSG_REDUNDANT_PORTS, gw_port[0]['ID'],
                filters='value',
                filter_value=210)

        self.verify_vlan_properties(gw_vlan[0], vlan)

        self.gatewayvlans.append(gw_vlan)
        kwargs = {
            'action': 'assign',
            'tenant': self.client.tenant_id
        }

        body = self.admin_client.assign_gateway_vlan(
            vlan['id'], **kwargs)
        self.assertIsNotNone(body)
        vlan_ent_permission = self.nuage_vsd_client.get_vlan_permission(
            n_constants.VLAN, vlan['id'], n_constants.ENTERPRISE_PERMS)
        self.assertEqual(vlan_ent_permission[0]['permittedEntityName'],
                         Topology.def_netpartition)

        vlan_permission = self.nuage_vsd_client.get_vlan_permission(
            n_constants.VLAN, vlan['id'], n_constants.PERMIT_ACTION)
        self.assertEqual(vlan_permission[0]['permittedEntityName'],
                         self.client.tenant_id)

        kwargs = {
            'action': 'unassign',
            'tenant': self.client.tenant_id
        }

        body = self.admin_client.assign_gateway_vlan(
            vlan['id'], **kwargs)
        self.assertIsNotNone(body)
        vlan_ent_permission = self.nuage_vsd_client.get_vlan_permission(
            n_constants.VLAN, vlan['id'], n_constants.ENTERPRISE_PERMS)
        self.assertEmpty(vlan_ent_permission)

        vlan_permission = self.nuage_vsd_client.get_vlan_permission(
            n_constants.VLAN, vlan['id'], n_constants.PERMIT_ACTION)
        self.assertEmpty(vlan_permission)

    @decorators.attr(type='smoke')
    def test_assign_unassign_vlan(self):
        self._assign_unassign_vlan('non-redundant', self.gatewayports[0])

    @decorators.attr(type='smoke')
    def test_assign_unassign_vlan_redundant_vsg(self):
        self._assign_unassign_vlan('redundant', self.rdn_gw_ports_vsg_combn[0])

    @decorators.attr(type='smoke')
    def test_assign_unassign_vlan_redundant_vrsg(self):
        self._delete_gateway_vlan('non-redundant', self.rdn_gw_ports_vrsg[0])

    def _create_list_nuage_vport(self, gw_vlan1, gw_vlan2,
                                 nondef_netpart=False):
        # Create a host vport
        # Create a neutron port
        if nondef_netpart:
            post_body = {"network_id": self.nondef_network['id'],
                         "device_owner": 'compute:ironic'}
        else:
            post_body = {"network_id": self.network['id'],
                         "device_owner": 'compute:ironic'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Create host vport
        kwargs = {
            'gatewayvlan': gw_vlan1[0]['ID'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.client.tenant_id
        }

        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']

        gw_vport = self.nuage_vsd_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport)
        if nondef_netpart:
            body = self.admin_client.list_gateway_vport(
                self.nondef_subnet['id'])
        else:
            body = self.admin_client.list_gateway_vport(self.subnet['id'])
        vports = body['nuage_gateway_vports']
        found_vport = False
        for vport in vports:
            if vport['name'] == gw_vport[0]['name']:
                found_vport = True
                self.verify_vport_properties(gw_vport[0], vport)

        if not found_vport:
            assert False, "Host Vport not found"

        # Create Bridge vport
        if nondef_netpart:
            kwargs = {
                'gatewayvlan': gw_vlan2[0]['ID'],
                'port': None,
                'subnet': self.nondef_subnet['id'],
                'tenant': self.client.tenant_id
            }
        else:
            kwargs = {
                'gatewayvlan': gw_vlan2[0]['ID'],
                'port': None,
                'subnet': self.subnet['id'],
                'tenant': self.client.tenant_id
            }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.gatewayvports.append(vport)

        gw_vport = self.nuage_vsd_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport)
        if nondef_netpart:
            body = self.admin_client.list_gateway_vport(
                self.nondef_subnet['id'])
        else:
            body = self.admin_client.list_gateway_vport(self.subnet['id'])
        vports = body['nuage_gateway_vports']
        found_vport = False
        for vport in vports:
            if vport['name'] == gw_vport[0]['name']:
                found_vport = True
                self.verify_vport_properties(gw_vport[0], vport)

        if not found_vport:
            assert False, "Bridge Vport not found"

    @decorators.attr(type='smoke')
    def test_list_nuage_vport(self):
        self._create_list_nuage_vport(self.gatewayvlans[0],
                                      self.gatewayvlans[1])

    @decorators.attr(type='smoke')
    def test_list_nuage_vport_nondef_netpart(self):
        self._create_list_nuage_vport(self.gatewayvlans[12],
                                      self.gatewayvlans[13],
                                      nondef_netpart=True)

    @decorators.attr(type='smoke')
    def test_list_nuage_vport_from_rdn_gateways(self):
        self._create_list_nuage_vport(self.gatewayvlans[8],
                                      self.gatewayvlans[9])

    @decorators.attr(type='smoke')
    def test_list_nuage_vport_from_rdn_gateways_nondef_netpart(self):
        self._create_list_nuage_vport(self.gatewayvlans[10],
                                      self.gatewayvlans[11],
                                      nondef_netpart=True)

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
        gw_vport = self.nuage_vsd_client.get_host_vport(vport['id'])
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], self.subnet['id'])
        vport = body['nuage_gateway_vport']
        if vport is None:
            assert False, "Host Vport not found"
        self.verify_vport_properties(gw_vport[0], vport)

    @decorators.attr(type='smoke')
    def test_show_nuage_vport_nondef_netpart(self):
        post_body = {"network_id": self.nondef_network['id'],
                     "device_owner": 'compute:ironic'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Create host vport
        kwargs = {
            'gatewayvlan': self.gatewayvlans[6][0]['ID'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.client.tenant_id
        }

        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        gw_vport = self.nuage_vsd_client.get_host_vport(vport['id'])
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], self.nondef_subnet['id'])
        vport = body['nuage_gateway_vport']
        if vport is None:
            assert False, "Host Vport not found"
        self.verify_vport_properties(gw_vport[0], vport)

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
        gw_vport = self.nuage_vsd_client.get_host_vport(vport['id'])
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], self.subnet['id'])
        vport = body['nuage_gateway_vport']
        if vport is None:
            assert False, "Host Vport not found"

    @decorators.attr(type='smoke')
    def test_default_security_group_host_port_nondef_netpart(self):
        post_body = {"network_id": self.nondef_network['id'],
                     "device_owner": 'nuage:vip'}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Create host vport
        kwargs = {
            'gatewayvlan': self.gatewayvlans[7][0]['ID'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        gw_vport = self.nuage_vsd_client.get_host_vport(vport['id'])
        body = self.admin_client.show_gateway_vport(
            gw_vport[0]['ID'], self.nondef_subnet['id'])
        vport = body['nuage_gateway_vport']
        if vport is None:
            assert False, "Host Vport not found"

    @decorators.attr(type='smoke')
    def test_default_security_group_bridge_port(self):
        kwargs = {
            'gatewayvlan': self.gatewayvlans[4][0]['ID'],
            'port': None,
            'subnet': self.subnet['id'],
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.gatewayvports.append(vport)

        gw_vport = self.nuage_vsd_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport)
        body = self.admin_client.list_gateway_vport(self.subnet['id'])
        vports = body['nuage_gateway_vports']
        found_vport = False
        for vport in vports:
            if vport['name'] == gw_vport[0]['name']:
                found_vport = True
                self.verify_vport_properties(gw_vport[0], vport)

        if not found_vport:
            assert False, "Bridge Vport not found"

    @decorators.attr(type='smoke')
    def test_default_security_group_bridge_port_nondef_netpart(self):
        kwargs = {
            'gatewayvlan': self.gatewayvlans[5][0]['ID'],
            'port': None,
            'subnet': self.nondef_subnet['id'],
            'tenant': self.client.tenant_id
        }
        body = self.client.create_gateway_vport(**kwargs)
        vport = body['nuage_gateway_vport']
        self.gatewayvports.append(vport)

        gw_vport = self.nuage_vsd_client.get_host_vport(vport['id'])
        self.verify_vport_properties(gw_vport[0], vport)
        body = self.admin_client.list_gateway_vport(self.nondef_subnet['id'])
        vports = body['nuage_gateway_vports']
        found_vport = False
        for vport in vports:
            if vport['name'] == gw_vport[0]['name']:
                found_vport = True
                self.verify_vport_properties(gw_vport[0], vport)

        if not found_vport:
            assert False, "Bridge Vport not found"
