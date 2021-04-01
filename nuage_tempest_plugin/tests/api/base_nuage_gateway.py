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
import random
import time
import uuid

from nuage_tempest_plugin.lib.test.nuage_test import NuageAdminNetworksTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.lib.utils import exceptions
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

from tempest.api.network import base
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils.data_utils import rand_name
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class BaseNuageGatewayTest(NuageAdminNetworksTest):
    _interface = 'json'

    @staticmethod
    def is_hw_gateway_personality(personality):
        return personality not in n_constants.SW_GW_TYPES

    @classmethod
    def create_gnmi_profile(cls):
        name = rand_name('tempest-gnmi')
        gnmi_profile = cls.nuage_client.create_gnmi_profile(name)[0]
        cls.addClassResourceCleanup(cls.nuage_client.delete_gnmi_profile,
                                    gnmi_profile['ID'])
        return gnmi_profile

    @classmethod
    def create_gateway_template(cls, personality):
        name = rand_name('tempest-gw-templ')
        gw_template = cls.nuage_client.create_gateway_template(
            name, personality)[0]
        cls.addClassResourceCleanup(cls.nuage_client.delete_gateway_template,
                                    gw_template['ID'])
        return gw_template

    @classmethod
    def create_gateway(cls, personality, **extra_params):
        name = rand_name('tempest-gw')
        gw = cls.nuage_client.create_gateway(
            name, str(uuid.uuid4()), personality, np_id=None,
            extra_params=extra_params)
        return gw

    @classmethod
    def create_gateway_group(cls, gw1_id, gw2_id):
        name = rand_name('tempest-gw-grp')
        grp = cls.nuage_client.create_gateway_redundancy_group(
            name, gw1_id, gw2_id, None)
        return grp

    @classmethod
    def create_gateway_port(cls, gw, name=None):
        if not name:
            name = rand_name('tempest-gw-port')
        gw_port = cls.nuage_client.create_gateway_port(
            name, 'test', 'ACCESS', gw[0]['ID'])
        return gw_port

    @classmethod
    def create_gateway_vlan(cls, gw_port, value):
        gw_port = cls.nuage_client.create_gateway_vlan(
            gw_port[0]['ID'], 'test', value)
        return gw_port

    @classmethod
    def create_test_gateway_topology(cls):
        if Topology.has_srl_support:
            gw_types = (n_constants.GW_TYPES_UNDER_TEST +
                        [n_constants.SRL_GW_TYPE])
        else:
            gw_types = n_constants.GW_TYPES_UNDER_TEST

        for personality in gw_types:
            if personality == n_constants.SRL_GW_TYPE:
                # First create a dummy gNMI profile
                gnmi_profile = cls.create_gnmi_profile()
                # Create template
                gw_template = cls.create_gateway_template(personality)
                ip_address = '{}.{}.{}.{}'.format(random.randint(10, 20),
                                                  random.randint(3, 254),
                                                  random.randint(3, 254),
                                                  random.randint(3, 254))
                gw = cls.create_gateway(
                    personality, associatedGNMIProfileID=gnmi_profile['ID'],
                    templateID=gw_template['ID'], managementID=ip_address)
            else:
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
    def setup_clients(cls):
        super(BaseNuageGatewayTest, cls).setup_clients()
        cls.nuage_client = NuageRestClient()
        cls.client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)
        # initialize admin client
        cls.admin_client = NuageNetworkClientJSON(
            cls.os_admin.auth_provider,
            **cls.os_admin.default_params)

    # TODO(TEAM) - THIS IS A COPY OF UPSTREAM CODE BUT NOW USING ADMIN CLIENT
    # WE SHOULD PUT COMMIT UPSTREAM WHICH MAKES CLIENT CONFIGURABLE
    # ------------------------- START OF COPY -------------------------
    @classmethod
    def create_router(cls, router_name=None, admin_state_up=False,
                      external_network_id=None, enable_snat=None,
                      **kwargs):
        router_name = router_name or data_utils.rand_name(
            cls.__name__ + "-router")

        ext_gw_info = {}
        if external_network_id:
            ext_gw_info['network_id'] = external_network_id
        if enable_snat is not None:
            ext_gw_info['enable_snat'] = enable_snat
        body = cls.admin_routers_client.create_router(
            name=router_name, external_gateway_info=ext_gw_info,
            admin_state_up=admin_state_up, **kwargs)
        router = body['router']
        cls.addClassResourceCleanup(test_utils.call_and_ignore_notfound_exc,
                                    cls.delete_router, router)
        return router

    @classmethod
    def create_router_interface(cls, router_id, subnet_id):
        """Wrapper utility that returns a router interface."""
        interface = cls.admin_routers_client.add_router_interface(
            router_id, subnet_id=subnet_id)
        return interface

    @classmethod
    def delete_router(cls, router):
        body = cls.admin_ports_client.list_ports(device_id=router['id'])
        interfaces = body['ports']
        for i in interfaces:
            if i['device_owner'] == 'network:router_interface':
                test_utils.call_and_ignore_notfound_exc(
                    cls.admin_routers_client.remove_router_interface,
                    router['id'],
                    subnet_id=i['fixed_ips'][0]['subnet_id'])
        cls.admin_routers_client.delete_router(router['id'])
    # ------------------------- END OF COPY -------------------------

    @classmethod
    def resource_setup(cls):
        super(BaseNuageGatewayTest, cls).resource_setup()

        cls.gateways = []
        cls.gatewayports = []
        cls.gatewayvlans = []
        cls.gatewayvports = []
        cls.router_interfaces = []

        cls.network = cls.create_network()

        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(
            data_utils.rand_name('router-'),
            external_network_id=cls.ext_net_id,
            tunnel_type="VXLAN")

        cls.create_router_interface(
            cls.router['id'], cls.subnet['id'])

        # Resource for non-default net-partition
        netpart_body = cls.client.create_netpartition(
            data_utils.rand_name('Enterprise-'))
        cls.nondef_netpart = netpart_body['net_partition']
        cls.nondef_network = cls.create_network()
        cls.nondef_subnet = cls.create_subnet(
            cls.nondef_network,
            net_partition=cls.nondef_netpart['id'])
        cls.nondef_router = cls.create_router(
            data_utils.rand_name('router-'),
            external_network_id=cls.ext_net_id,
            tunnel_type='VXLAN',
            net_partition=cls.nondef_netpart['id'])
        cls.create_router_interface(
            cls.nondef_router['id'],
            cls.nondef_subnet['id'])

    @classmethod
    def resource_cleanup(cls):
        has_exception = False

        for vport in cls.gatewayvports:
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

        for vlan in cls.gatewayvlans:
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

        for port in cls.gatewayports:
            try:
                cls.nuage_client.delete_gateway_port(port[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        for gateway in cls.gateways:
            try:
                cls.nuage_client.delete_gateway(gateway[0]['ID'])
            except Exception as exc:
                LOG.exception(exc)
                has_exception = True

        super(BaseNuageGatewayTest, cls).resource_cleanup()

        try:
            cls.client.delete_netpartition(cls.nondef_netpart['id'])
        except Exception as exc:
            LOG.exception(exc)
            has_exception = True

        if has_exception:
            raise exceptions.TearDownException()

    @classmethod
    def create_subnet(cls, network, gateway='', cidr=None, mask_bits=None,
                      ip_version=None, client=None, **kwargs):
        subnet = super(base.BaseAdminNetworkTest, cls).create_subnet(
            network, gateway, cidr, mask_bits, ip_version, client, **kwargs)
        dhcp_enabled = subnet['enable_dhcp']
        current_time = time.time()
        if cls.is_dhcp_agent_present() and dhcp_enabled:
            LOG.info("Waiting for dhcp port resolution")
            dhcp_subnets = []
            while subnet['id'] not in dhcp_subnets:
                if time.time() - current_time > 30:
                    raise lib_exc.NotFound("DHCP port not resolved within"
                                           " allocated time.")
                time.sleep(0.5)
                filters = {
                    'device_owner': 'network:dhcp',
                    'network_id': subnet['network_id']
                }
                dhcp_ports = cls.ports_client.list_ports(**filters)['ports']
                if not dhcp_ports:
                    time.sleep(0.5)
                    continue
                dhcp_port = dhcp_ports[0]
                dhcp_subnets = [x['subnet_id'] for x in dhcp_port['fixed_ips']]
            LOG.info("DHCP port resolved")
        return subnet

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
        if verify_ext:
            external_id = (expected_vlan['gatewayport'] + "." +
                           str(expected_vlan['value']))
            self.assertEqual(actual_vlan['externalID'],
                             self.nuage_client.get_vsd_external_id(
                                 external_id))

    def verify_vport_properties(self, actual_vport, expected_vport,
                                network_id):
        self.assertEqual(actual_vport['ID'], expected_vport['id'])
        self.assertEqual(actual_vport['type'], expected_vport['type'])
        self.assertEqual(actual_vport['name'], expected_vport['name'])
        if expected_vport['type'] == n_constants.BRIDGE_VPORT:
            self.assertEqual(actual_vport['externalID'],
                             self.nuage_client.get_vsd_external_id(
                                 expected_vport['subnet'] if Topology.is_v5
                                 else network_id))
        else:
            self.assertEqual(actual_vport['externalID'],
                             self.nuage_client.get_vsd_external_id(
                                 expected_vport['port']))
