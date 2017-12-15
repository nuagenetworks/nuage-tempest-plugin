# Copyright 2017 NOKIA
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
import testtools
from testtools import matchers

from tempest import config
from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.mixins import l3
from nuage_tempest_plugin.lib.mixins import net_topology as topology_mixin
from nuage_tempest_plugin.lib.mixins import network as network_mixin
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

CONF = config.CONF


class Topology(object):
    def __init__(self, vsd_client, network, subnet, router, port, subnetv6):
        super(Topology, self).__init__()
        self.vsd_client = vsd_client
        self.network = network
        self.subnet = subnet
        self.router = router
        self.normal_port = port
        self.direct_port = None
        self.subnetv6 = subnetv6

    @property
    def vsd_vport_parent(self):
        if not getattr(self, '_vsd_vport_parent', False):
            self._vsd_vport_parent = self.vsd_client.get_global_resource(
                self.vsd_vport_parent_resource,
                filters='externalID',
                filter_value=self.subnet['id'])[0]
        return self._vsd_vport_parent

    @property
    def vsd_vport_parent_resource(self):
        if not getattr(self, '_vsd_vport_parent_resource', False):
            if self.router:
                self._vsd_vport_parent_resource = constants.SUBNETWORK
            else:
                self._vsd_vport_parent_resource = constants.L2_DOMAIN
        return self._vsd_vport_parent_resource

    @property
    def vsd_direct_vport(self):
        if not getattr(self, '_vsd_direct_vport', False):
            vsd_vports = self.vsd_client.get_vport(
                self.vsd_vport_parent_resource,
                self.vsd_vport_parent['ID'],
                filters='externalID',
                filter_value=self.subnet['id'])
            self._vsd_direct_vport = vsd_vports[0]
        return self._vsd_direct_vport

    @property
    def vsd_domain(self):
        if not getattr(self, '_vsd_domain', False):
            if self.router:
                zone = self.vsd_client.get_global_resource(
                    constants.ZONE + '/' +
                    self.vsd_vport_parent['parentID'])[0]
                self._vsd_domain = self.vsd_client.get_global_resource(
                    constants.DOMAIN + '/' + zone['parentID'])[0]
            else:
                self._vsd_domain = self.vsd_vport_parent
        return self._vsd_domain

    @property
    def vsd_domain_resource(self):
        if not getattr(self, '_vsd_domain_resource', False):
            if self.router:
                self._vsd_domain_resource = constants.DOMAIN
            else:
                self._vsd_domain_resource = constants.L2_DOMAIN
        return self._vsd_domain_resource

    @property
    def vsd_policygroups(self):
        if not getattr(self, '_vsd_policygroups', False):
            self._vsd_policygroups = self.vsd_client.get_policygroup(
                self.vsd_domain_resource,
                self.vsd_domain['ID'])
        return self._vsd_policygroups

    @property
    def vsd_direct_interface_resource(self):
        if not getattr(self, '_vsd_direct_interface_resource', False):
            self._vsd_direct_interface_resource = constants.BRIDGE_IFACE
        return self._vsd_direct_interface_resource

    @property
    def vsd_direct_interface(self):
        if not getattr(self, '_vsd_direct_interface', False):
            self._vsd_direct_interface = self.vsd_client.get_child_resource(
                constants.VPORT,
                self.vsd_direct_vport['ID'],
                self.vsd_direct_interface_resource)[0]
        return self._vsd_direct_interface

    @property
    def vsd_egress_acl_template(self):
        if not getattr(self, '_vsd_egress_acl_templates', False):
            self._vsd_egress_acl_templates = \
                self.vsd_client.get_egressacl_template(
                    self.vsd_domain_resource,
                    self.vsd_domain['ID'])[0]
        return self._vsd_egress_acl_templates

    @property
    def vsd_egress_acl_entries(self):
        if not getattr(self, '_vsd_egress_acl_entries', False):
            self._vsd_egress_acl_entries = \
                self.vsd_client.get_egressacl_entytemplate(
                    constants.EGRESS_ACL_TEMPLATE,
                    self.vsd_egress_acl_template['ID'])
        return self._vsd_egress_acl_entries

    @property
    def vsd_direct_dhcp_opts(self):
        if not getattr(self, '_vsd_direct_dhcp_opts', False):
            self._vsd_direct_dhcp_opts = self.vsd_client.get_dhcpoption(
                self.vsd_direct_interface_resource,
                self.vsd_direct_interface['ID'])
        return self._vsd_direct_dhcp_opts


class PortsDirectTest(network_mixin.NetworkMixin,
                      l3.L3Mixin,
                      topology_mixin.NetTopologyMixin):

    credentials = ['admin']

    @classmethod
    def setUpClass(cls):
        super(PortsDirectTest, cls).setUpClass()
        cls.expected_vport_type = constants.VPORT_TYPE_BRIDGE
        cls.expected_vlan = 123

    @classmethod
    def setup_clients(cls):
        super(PortsDirectTest, cls).setup_clients()
        cls.vsd_client = NuageRestClient()

    @classmethod
    def skip_checks(cls):
        super(PortsDirectTest, cls).skip_checks()
        if CONF.network.port_vnic_type not in ['direct', 'macvtap']:
            msg = ("Test requires nuage_test_sriov mech driver "
                   "and port_vnic_type=='direct'")
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(PortsDirectTest, cls).resource_setup()
        # Only gateway here, to support parallel testing each tests makes its
        # own gateway port so no VLAN overlap should occur.
        cls.gateway = cls.vsd_client.create_gateway(
            data_utils.rand_name(name='vsg'),
            data_utils.rand_name(name='sys_id'), 'VSG')[0]

    @classmethod
    def resource_cleanup(cls):
        super(PortsDirectTest, cls).resource_cleanup()
        cls.vsd_client.delete_gateway(cls.gateway['ID'])

    def setUp(self):
        super(PortsDirectTest, self).setUp()
        gw_port_name = data_utils.rand_name(name='gw-port')
        self.gw_port = self.vsd_client.create_gateway_port(
            gw_port_name, gw_port_name, 'ACCESS', self.gateway['ID'],
            extra_params={'VLANRange': '0-4095'})[0]
        self.binding_data = {
            'binding:vnic_type': 'direct',
            'binding:host_id': 'host-hierarchical', 'binding:profile': {
                "pci_slot": "0000:03:10.6",
                "physical_network": "physnet1",
                "pci_vendor_info": "8086:10ed"
            }}

    def test_direct_port_l3_create(self):
        topology = self._create_topology(with_router=True)
        self._test_direct_port(topology, update=False)

    def test_direct_port_l3_update(self):
        topology = self._create_topology(with_router=True)
        self._test_direct_port(topology, update=True)

    def test_direct_port_l3_ipv6_create(self):
        topology = self._create_topology(with_router=True, dualstack=True)
        self._test_direct_port(topology, update=False)

    def test_direct_port_l3_ipv6_update(self):
        topology = self._create_topology(with_router=True, dualstack=True)
        self._test_direct_port(topology, update=True)

    def test_direct_port_l2_create(self):
        topology = self._create_topology(with_router=False)
        self._test_direct_port(topology, update=False)

    def test_direct_port_l2_update(self):
        topology = self._create_topology(with_router=False)
        self._test_direct_port(topology, update=True)

    def test_direct_port_l2_ipv6_create(self):
        topology = self._create_topology(with_router=False, dualstack=True)
        self._test_direct_port(topology, update=False)

    def test_direct_port_l2_ipv6_update(self):
        topology = self._create_topology(with_router=False, dualstack=True)
        self._test_direct_port(topology, update=True)

    @testtools.skip("Currently unknown how to trigger vport resolution")
    def test_router_attach(self):
        topology = self._create_topology(with_router=False)
        port = self.create_port(topology.network['id'], **self.binding_data)
        topology.direct_port = port
        with self.router(attached_subnets=[topology.subnet['id']]) as router:
            topology.router = router
            self._validate_vsd(topology)

    def test_bind_dead_agent(self):
        topology = self._create_topology(with_router=False)
        create_data = {
            'binding:vnic_type': 'direct',
            'security_groups': [],
            'binding:host_id': 'host-dead-agent', 'binding:profile': {
                "pci_slot": "0000:03:10.6",
                "physical_network": "physnet1",
                "pci_vendor_info": "8086:10ed"
            }}
        mapping = {'switch_id': self.gateway['systemID'],
                   'port_id': self.gw_port['physicalName'],
                   'host_id': 'host-dead-agent',
                   'pci_slot': '0000:03:10.6'}
        with self.switchport_mapping(**mapping):
            with self.port(topology.network['id'],
                           **create_data) as direct_port:
                topology.direct_port = direct_port
                self._validate_vsd(topology)
                profile = direct_port.get('binding:profile')
                vif_details = direct_port.get('binding:vif_details')
                vif_type = direct_port.get('binding:vif_type')
                self.assertThat(
                    profile, matchers.Equals(self.binding_data.get(
                        'binding:profile')),
                    message="Port binding profiles doesn't match expected")
                self.assertThat(
                    vif_details, matchers.Equals({}),
                    message="Port has unexpected vlan")
                self.assertThat(
                    vif_type, matchers.Equals('binding_failed'),
                    message="Port has unexpected vif_type")

    def _create_topology(self, with_router=False,
                         with_port=False, dualstack=False):
        router = port = subnetv6 = None
        if with_router:
            router = self.create_router()
        kwargs = {'segments': [
            {"provider:network_type": "vxlan"},
            {"provider:network_type": "vlan",
             "provider:physical_network": "physnet1",
             "provider:segmentation_id": "123"}
        ]}
        network = self.create_network(**kwargs)
        subnet = self.create_subnet('10.20.30.0/24', network['id'])
        if dualstack:
            kwargs = {'ipv6_ra_mode': 'dhcpv6-stateful',
                      'ipv6_address_mode': 'dhcpv6-stateful'}
            subnetv6 = self.create_subnet('a1ca:c10d:1111:1111::/64',
                                          network['id'],
                                          **kwargs)
        if with_router:
            self.add_router_interface(router['id'], subnet_id=subnet['id'])
            if dualstack:
                self.add_router_interface(router['id'],
                                          subnet_id=subnetv6['id'])
        if with_port:
            port = self.create_port(network['id'])
        return Topology(self.vsd_client, network,
                        subnet, router, port, subnetv6)

    def _test_direct_port(self, topology, update=False):
        create_data = {'binding:vnic_type': 'direct',
                       'security_groups': []}
        mapping = {'switch_id': self.gateway['systemID'],
                   'port_id': self.gw_port['physicalName'],
                   'host_id': 'host-hierarchical',
                   'pci_slot': '0000:03:10.6'}
        if not update:
            create_data.update(self.binding_data)
        with self.switchport_mapping(**mapping):
            with self.port(topology.network['id'],
                           **create_data) as direct_port:
                topology.direct_port = direct_port
                if update:
                    topology.direct_port = self.update_port(
                        direct_port['id'],
                        as_admin=True,
                        **self.binding_data)
                self._validate_vsd(topology)
                self._validate_os(topology)

    # Validation part

    def _validate_vsd(self, topology):
        self._validate_direct_vport(topology)
        self._validate_vlan(topology)
        self._validate_interface(topology)

    def _validate_direct_vport(self, topology):
        self.assertThat(topology.vsd_direct_vport['type'],
                        matchers.Equals(self.expected_vport_type),
                        message="Vport has wrong type")

    def _validate_vlan(self, topology):
        vsd_vlan = self.vsd_client.get_gateway_vlan_by_id(
            topology.vsd_direct_vport['VLANID'])
        self.assertThat(
            vsd_vlan['value'], matchers.Equals(self.expected_vlan),
            message="Vport has unexpected vlan")

    def _validate_interface(self, topology):
        vsd_vport = topology.vsd_direct_vport
        neutron_port = topology.direct_port

        if vsd_vport['type'] == constants.VPORT_TYPE_HOST:
            self.assertThat(topology.vsd_direct_interface['MAC'],
                            matchers.Equals(neutron_port['mac_address']))
            self.assertThat(
                topology.vsd_direct_interface['IPAddress'],
                matchers.Equals(neutron_port['fixed_ips'][0]['ip_address']))

    def _validate_dhcp_option(self, topology):
        self.assertThat(topology.vsd_direct_dhcp_opts,
                        matchers.HasLength(2))

        DHCP_ROUTER_OPT = 3
        DHCP_SERVER_NAME_OPT = 66
        for dhcp_opt in topology.vsd_direct_dhcp_opts:
            if dhcp_opt['actualType'] == DHCP_ROUTER_OPT:
                self.assertThat(dhcp_opt['actualValues'][0],
                                matchers.Equals(topology.subnet['gateway_ip']))
            elif dhcp_opt['actualType'] == DHCP_SERVER_NAME_OPT:
                os_dhcp_opt = topology.direct_port['extra_dhcp_opts'][0]
                self.assertThat(dhcp_opt['actualValues'][0],
                                matchers.Equals(os_dhcp_opt['opt_value']))

    def _validate_os(self, topology):
        port = topology.direct_port
        profile = port.get('binding:profile')
        vif_details = port.get('binding:vif_details')
        self.assertThat(
            profile, matchers.Equals(self.binding_data.get('binding:profile')),
            message="Port binding profiles doesn't match expected")
        self.assertThat(
            vif_details.get('vlan'), matchers.Equals(str(self.expected_vlan)),
            message="Port has unexpected vlan")
        self.assertThat(
            port['binding:vif_type'], matchers.Equals('hw_veb'),
            message="Port has unexpected vif_type")
