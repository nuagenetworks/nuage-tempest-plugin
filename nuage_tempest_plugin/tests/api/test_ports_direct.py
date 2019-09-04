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

from netaddr import IPNetwork

import testtools
from testtools import matchers

from tempest.common import utils
from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.mixins import l3
from nuage_tempest_plugin.lib.mixins import net_topology as topology_mixin
from nuage_tempest_plugin.lib.mixins import network as network_mixin
from nuage_tempest_plugin.lib.test.nuage_test import skip_because
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.lib.utils import data_utils as lib_utils
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.tests.api.external_id.external_id import ExternalId

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class SriovTopology(object):
    def __init__(self, vsd_client, network, subnet, router, port, subnetv6,
                 trunk, l2domain=None, is_flat_vlan_in_use=False):
        """SriovTopology

        :param vsd_client:
        :param network:
        :param subnet:
        :param router:
        :param port:
        :param subnetv6:
        :param trunk:
        :param l2domain:
        :param is_flat_vlan_in_use: Whether VLAN-0 is in use by another
                                    system, used to test vlan reuse on
                                    flat networks in sriov driver
        """
        self.vsd_client = vsd_client
        self.network = network
        self.subnet = subnet
        self.router = router
        self.normal_port = port
        self.trunk = trunk
        self.direct_port = None
        self.subnetv6 = subnetv6
        self.vsd_managed = l2domain is not None
        self.is_flat_vlan_in_use = is_flat_vlan_in_use

        self.gw_port = None
        self.binding_data = None
        self._direct_port_is_subport = False
        self._vsd_vport_parent = l2domain
        self._vsd_vport_parent_resource = None
        self._vsd_direct_vport = None
        self._vsd_domain = None
        self._vsd_domain_resource = None
        self._vsd_policygroups = None
        self._vsd_direct_interface_resource = None
        self._vsd_direct_interface = None
        self._vsd_egress_acl_templates = None
        self._vsd_egress_acl_entries = None
        self._vsd_direct_dhcp_opts = None

    @property
    def vsd_vport_parent(self):
        if not getattr(self, '_vsd_vport_parent', False):
            self._vsd_vport_parent = self.vsd_client.get_global_resource(
                self.vsd_vport_parent_resource,
                filters=['externalID', 'address'],
                filter_value=[self.subnet['network_id'],
                              self.subnet['cidr']])[0]
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
        """vsd_direct_vport

        :return: The vport or None if not found
        """
        if not getattr(self, '_vsd_direct_vport', False):
            vsd_vports = self.vsd_client.get_vport(
                self.vsd_vport_parent_resource,
                self.vsd_vport_parent['ID'],
                filters='externalID',
                filter_value=self.subnet['network_id'])
            self._vsd_direct_vport = vsd_vports[0] if vsd_vports else None
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
                self.vsd_client.get_egressacl_entrytemplate(
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


class SubPortTopology(object):
        def __init__(self, subport_network, subport_subnet,
                     subport_subnet_ipv6, sub_port):
            super(SubPortTopology, self).__init__()
            self.subport_network = subport_network
            self.subport_subnet = subport_subnet
            self.subport_subnet_ipv6 = subport_subnet_ipv6
            self.direct_subport = sub_port


class PortsDirectTest(network_mixin.NetworkMixin,
                      l3.L3Mixin,
                      topology_mixin.NetTopologyMixin):

    credentials = ['admin']
    personality = 'NUAGE_210_WBX_48_S'

    @classmethod
    def setUpClass(cls):
        super(PortsDirectTest, cls).setUpClass()
        cls.expected_vport_type = constants.VPORT_TYPE_BRIDGE
        cls.expected_vlan = 123
        cls.expected_vlan_subport_2 = 321

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
            data_utils.rand_name(name='sys_id'), cls.personality)[0]

        # for VSD managed
        cls.vsd_l2dom_template = []
        cls.vsd_l2domain = []

    @classmethod
    def resource_cleanup(cls):
        super(PortsDirectTest, cls).resource_cleanup()
        cls.vsd_client.delete_gateway(cls.gateway['ID'])

        for vsd_l2domain in cls.vsd_l2domain:
            cls.vsd_client.delete_l2domain(vsd_l2domain['ID'])

        for vsd_l2dom_template in cls.vsd_l2dom_template:
            cls.vsd_client.delete_l2domaintemplate(
                vsd_l2dom_template['ID'])

    def _is_port_down(self, port_id):
        p = self.show_port(port_id)
        return p['status'] == 'DOWN'

    def _is_port_active(self, port_id):
        p = self.show_port(port_id)
        return p['status'] == 'ACTIVE'

    def _is_trunk_active(self, trunk_id):
        t = self.show_trunk(trunk_id)
        return t['status'] == 'ACTIVE'

    def setUp(self):
        super(PortsDirectTest, self).setUp()
        gw_port_name = data_utils.rand_name(name='gw-port')
        self.gw_port = self.vsd_client.create_gateway_port(
            gw_port_name, gw_port_name, 'ACCESS', self.gateway['ID'],
            extra_params={'VLANRange': '0-4095'})[0]

        gw_port_name1 = data_utils.rand_name(name='gw-port')
        self.gw_port1 = self.vsd_client.create_gateway_port(
            gw_port_name1, gw_port_name1, 'ACCESS', self.gateway['ID'],
            extra_params={'VLANRange': '0-4095'})[0]

        self.clear_binding = {'binding:host_id': '',
                              'binding:profile': {}
                              }

        self.binding_data = {
            'binding:vnic_type': 'direct',
            'binding:host_id': 'host-hierarchical', 'binding:profile': {
                "pci_slot": "0000:03:10.6",
                "physical_network": "physnet1",
                "pci_vendor_info": "8086:10ed"
            }}

        self.binding_data1 = {
            'binding:vnic_type': 'direct',
            'binding:host_id': 'host-hierarchical', 'binding:profile': {
                "pci_slot": "0000:03:10.7",
                "physical_network": "physnet2",
                "pci_vendor_info": "8086:10ed"
            }}

        self.trunk_binding_data = {
            'binding:vnic_type': 'direct',
            'binding:host_id': 'host-hierarchical', 'binding:profile': {
                "pci_slot": "0000:03:10.6",
                "physical_network": "physnet2",
                "pci_vendor_info": "8086:10ed"
            }}

        self.subport_binding_data = {
            'binding:vnic_type': 'direct',
            'binding:host_id': 'host-hierarchical'}

    # os managed

    def test_direct_port_l3_create(self):
        topology = self._create_topology(with_router=True)
        self._test_direct_port(topology, update=False)

    @utils.requires_ext(extension='trunk', service='network')
    def test_direct_port_l3_create_with_trunk(self, is_flat_vlan_in_use=False):
        topology = self._create_topology(
            with_router=True, for_trunk=True,
            is_flat_vlan_in_use=is_flat_vlan_in_use)
        trunk_topology = self._test_direct_port(topology, update=True,
                                                is_trunk=True)
        sub_topology, sub_topology2 = self._create_topology_with_subports(
            trunk_topology,
            with_router=True)

        verify_topology = SriovTopology(
            topology.vsd_client,
            sub_topology.subport_network,
            sub_topology.subport_subnet,
            topology.router,
            port=None,
            subnetv6=sub_topology.subport_subnet_ipv6,
            trunk=trunk_topology.trunk,
            is_flat_vlan_in_use=is_flat_vlan_in_use)
        verify_topology.direct_port = sub_topology.direct_subport
        verify_topology._direct_port_is_subport = True
        subport_mapping = {'switch_id': self.gateway['systemID'],
                           'port_id': self.gw_port['physicalName'],
                           'host_id': 'host-hierarchical',
                           'pci_slot': '0000:03:10.5'}
        if is_flat_vlan_in_use:
            nr_vports = 2
        else:
            nr_vports = 3
        self._test_direct_subport(verify_topology, subport_mapping,
                                  nr_vports=nr_vports)

        verify_topology = SriovTopology(
            topology.vsd_client,
            sub_topology2.subport_network,
            sub_topology2.subport_subnet,
            topology.router,
            port=None,
            subnetv6=sub_topology2.subport_subnet_ipv6,
            trunk=trunk_topology.trunk,
            is_flat_vlan_in_use=is_flat_vlan_in_use)
        verify_topology.direct_port = sub_topology2.direct_subport
        verify_topology._direct_port_is_subport = True
        subport2_mapping = {'switch_id': self.gateway['systemID'],
                            'port_id': self.gw_port['physicalName'],
                            'host_id': 'host-hierarchical',
                            'pci_slot': '0000:03:50.5'}
        self._test_direct_subport(verify_topology, subport2_mapping,
                                  use_subport_check=True, nr_vports=nr_vports)

    @utils.requires_ext(extension='trunk', service='network')
    def test_direct_port_l3_create_with_trunk_vlan0_in_use(self):
        # Make sure VLAN 0 is in use
        self.vsd_client.create_gateway_vlan(self.gw_port['ID'],
                                            "infra_network", 0)
        # run the original test
        kwargs = {"is_flat_vlan_in_use": True}
        if Topology.is_existing_flat_vlan_allowed():
            LOG.info("Nuage SR-IOV with trunking: VLAN-0 is in use but we "
                     "expect port binding to succeed")
            self.test_direct_port_l3_create_with_trunk(**kwargs)
        else:
            LOG.info("Nuage SR-IOV with trunking: VLAN-0 is in use and we "
                     "expect port binding to fail")
            self.assertRaisesRegex(AssertionError,
                                   "Direct port status is not ACTIVE",
                                   self.test_direct_port_l3_create_with_trunk,
                                   **kwargs)

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

    @utils.requires_ext(extension='trunk', service='network')
    def test_direct_port_l2_create_with_trunk(self):
        topology = self._create_topology(with_router=False, for_trunk=True)
        trunk_topology = self._test_direct_port(topology, update=True,
                                                is_trunk=True)
        sub_topology, sub_topology2 = self._create_topology_with_subports(
            trunk_topology,
            with_router=False)
        verify_topology = SriovTopology(
            topology.vsd_client,
            sub_topology.subport_network,
            sub_topology.subport_subnet,
            topology.router,
            port=None,
            subnetv6=sub_topology.subport_subnet_ipv6,
            trunk=trunk_topology.trunk)
        verify_topology.direct_port = sub_topology.direct_subport
        verify_topology._direct_port_is_subport = True
        subport_mapping = {'switch_id': self.gateway['systemID'],
                           'port_id': self.gw_port['physicalName'],
                           'host_id': 'host-hierarchical',
                           'pci_slot': '0000:03:10.5'}
        self._test_direct_subport(verify_topology, subport_mapping)

        verify_topology = SriovTopology(
            topology.vsd_client,
            sub_topology2.subport_network,
            sub_topology2.subport_subnet,
            topology.router,
            port=None,
            subnetv6=sub_topology2.subport_subnet_ipv6,
            trunk=trunk_topology.trunk)
        verify_topology.direct_port = sub_topology2.direct_subport
        verify_topology._direct_port_is_subport = True
        subport2_mapping = {'switch_id': self.gateway['systemID'],
                            'port_id': self.gw_port['physicalName'],
                            'host_id': 'host-hierarchical',
                            'pci_slot': '0000:03:50.5'}
        self._test_direct_subport(verify_topology, subport2_mapping,
                                  use_subport_check=True)

    def test_direct_port_l2_update(self):
        topology = self._create_topology(with_router=False)
        self._test_direct_port(topology, update=True)

    def test_direct_port_l2_ipv6_create(self):
        topology = self._create_topology(with_router=False, dualstack=True)
        self._test_direct_port(topology, update=False)

    def test_direct_port_l2_ipv6_update(self):
        topology = self._create_topology(with_router=False, dualstack=True)
        self._test_direct_port(topology, update=True)

    def test_direct_port_l3_create_with_port_security(self):
        topology = self._create_topology(with_router=True)
        self._test_direct_port(topology, update=False, with_port_security=True)

    def test_direct_port_l3_update_with_port_security(self):
        topology = self._create_topology(with_router=True)
        self._test_direct_port(topology, update=True, with_port_security=True)

    def test_direct_port_l3_ipv6_create_with_port_security(self):
        topology = self._create_topology(with_router=True, dualstack=True)
        self._test_direct_port(topology, update=False, with_port_security=True)

    def test_direct_port_l3_ipv6_update_with_port_security(self):
        topology = self._create_topology(with_router=True, dualstack=True)
        self._test_direct_port(topology, update=True, with_port_security=True)

    def test_direct_port_l2_create_with_port_security(self):
        topology = self._create_topology(with_router=False)
        self._test_direct_port(topology, update=False, with_port_security=True)

    def test_direct_port_l2_update_with_port_security(self):
        topology = self._create_topology(with_router=False)
        self._test_direct_port(topology, update=True, with_port_security=True)

    def test_direct_port_l2_ipv6_create_with_port_security(self):
        topology = self._create_topology(with_router=False, dualstack=True)
        self._test_direct_port(topology, update=False, with_port_security=True)

    def test_direct_port_l2_ipv6_update_with_port_security(self):
        topology = self._create_topology(with_router=False, dualstack=True)
        self._test_direct_port(topology, update=True, with_port_security=True)

    def test_direct_port_l3_create_with_port_security_and_aap(self):
        topology = self._create_topology(with_router=True)
        self._test_direct_port(topology, update=False,
                               with_port_security=True,
                               aap=True)

    def test_direct_port_l3_update_with_port_security_and_aap(self):
        topology = self._create_topology(with_router=True)
        self._test_direct_port(topology, update=True,
                               with_port_security=True,
                               aap=True)

    def test_direct_port_l3_ipv6_create_with_port_security_and_aap(self):
        topology = self._create_topology(with_router=True, dualstack=True)
        self._test_direct_port(topology, update=False, with_port_security=True,
                               aap=True)

    def test_direct_port_l3_ipv6_update_with_port_security_and_aap(self):
        topology = self._create_topology(with_router=True, dualstack=True)
        self._test_direct_port(topology, update=True, with_port_security=True,
                               aap=True)

    def test_direct_port_l2_create_with_port_security_and_aap(self):
        topology = self._create_topology(with_router=False)
        self._test_direct_port(topology, update=False,
                               with_port_security=True,
                               aap=True)

    def test_direct_port_l2_update_with_port_security_and_aap(self):
        topology = self._create_topology(with_router=False)
        self._test_direct_port(topology, update=True,
                               with_port_security=True,
                               aap=True)

    def test_direct_port_l2_ipv6_create_with_port_security_and_aap(self):
        topology = self._create_topology(with_router=False, dualstack=True)
        self._test_direct_port(topology, update=False, with_port_security=True,
                               aap=True)

    def test_direct_port_l2_ipv6_update_with_port_security_and_aap(self):
        topology = self._create_topology(with_router=False, dualstack=True)
        self._test_direct_port(topology, update=True, with_port_security=True,
                               aap=True)

    def test_direct_port_multi_ips_l3_create_with_port_security_and_aap(self):
        topology = self._create_topology(with_router=True)
        self._test_direct_port(topology, update=False,
                               with_port_security=True,
                               aap=True, multi_ips=True)

    def test_direct_port_multi_ips_l3_update_with_port_security_and_aap(self):
        topology = self._create_topology(with_router=True)
        self._test_direct_port(topology, update=True,
                               with_port_security=True,
                               aap=True, multi_ips=True)

    def test_direct_port_multi_ips_l2_create_with_port_security_and_aap(self):
        topology = self._create_topology(with_router=False)
        self._test_direct_port(topology, update=False,
                               with_port_security=True,
                               aap=True, multi_ips=True)

    def test_direct_port_multi_ips_l2_update_with_port_security_and_aap(self):
        topology = self._create_topology(with_router=False)
        self._test_direct_port(topology, update=True,
                               with_port_security=True,
                               aap=True, multi_ips=True)

    @skip_because(reason="PG_ALLOW_ALL_HW for baremetal ports can not move to "
                         "l3 when it is not resolved")
    def test_direct_port_only_one_pg_allow_all_in_one_domain(self):
        topology = self._create_topology()
        self._test_direct_port(topology, update=False)
        router = self.create_router()
        self.add_router_interface(router['id'],
                                  subnet_id=topology.subnet['id'],
                                  cleanup=False)
        create_data = {'binding:vnic_type': 'direct'}
        mapping = {'switch_id': self.gateway['systemID'],
                   'port_id': self.gw_port1['physicalName'],
                   'host_id': 'host-hierarchical',
                   'pci_slot': '0000:03:10.7'}
        create_data.update(self.binding_data1)
        with self.switchport_mapping(do_delete=False, **mapping) as swtch_map:
            self.addCleanup(
                self.switchport_mapping_client_admin.delete_switchport_mapping,
                swtch_map['id'])
            self.create_port(topology.network['id'],
                             cleanup=True, **create_data)
            self._validate_os(topology)
            if topology.is_flat_vlan_in_use:
                self.assertIsNone(topology.vsd_direct_vport,
                                  message="Direct vport found but it"
                                          " should not exists as"
                                          " VLAN-0 is already in use"
                                          " by an another system")
            else:
                self._validate_vsd(topology, nr_vports=2)
        self.remove_router_interface(router['id'],
                                     subnet_id=topology.subnet['id'])
        if topology.is_flat_vlan_in_use:
            self.assertIsNone(topology.vsd_direct_vport,
                              message="Direct vport found but it"
                                      " should not exists as"
                                      " VLAN-0 is already in use"
                                      " by an another system")
        else:
            self._validate_vsd(topology, nr_vports=2)

    # vsd managed

    def test_vsd_mgd_direct_port_l2_create(self):
        topology = self._create_topology(vsd_managed=True)
        self._test_direct_port(topology, aap=True)

    def test_vsd_mgd_direct_port_l2_update(self):
        topology = self._create_topology(vsd_managed=True)
        self._test_direct_port(topology, aap=True)

    # l3 .. skipped

    @testtools.skip("Currently unknown how to trigger vport resolution")
    def test_router_attach(self):
        topology = self._create_topology(with_router=False)
        port = self.create_port(topology.network['id'], **self.binding_data)
        topology.direct_port = port
        with self.router(attached_subnets=[topology.subnet['id']]) as router:
            topology.router = router
            self._validate_vsd(topology)

    # other

    def test_dynamic_segment_allocation(self):
        network = self.create_network()
        subnet = self.create_subnet('10.20.30.0/24', network['id'])
        assert subnet
        create_data = {
            'binding:vnic_type': 'direct',
            'security_groups': [],
            'binding:host_id': 'host-hierarchical', 'binding:profile': {
                "pci_slot": "0000:03:10.6",
                "physical_network": "physnet1",
                "pci_vendor_info": "8086:10ed"
            }}
        mapping = {'switch_id': self.gateway['systemID'],
                   'port_id': self.gw_port['physicalName'],
                   'host_id': 'host-hierarchical',
                   'pci_slot': '0000:03:10.6'}
        with self.switchport_mapping(**mapping):
            with self.port(network['id'],
                           **create_data) as direct_port:
                lib_utils.wait_until_true(
                    lambda: self._is_port_active(direct_port.get('id')))

                profile = direct_port.get('binding:profile')
                vif_type = direct_port.get('binding:vif_type')
                self.assertThat(
                    profile, matchers.Equals(self.binding_data.get(
                        'binding:profile')),
                    message="Port binding profiles doesn't match expected")
                self.assertThat(
                    vif_type, matchers.Equals('hw_veb'),
                    message="Port has unexpected vif_type")

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

    def test_update_binding_nova_evacuate(self):
        topology = self._create_topology()
        # Create a direct port

        # Have two VM's on the first GW to check that migration still works.
        mapping1_1 = {'switch_id': self.gateway['systemID'],
                      'port_id': self.gw_port['physicalName'],
                      'host_id': 'host1',
                      'pci_slot': '0000:03:10.6'}
        mapping1_2 = {'switch_id': self.gateway['systemID'],
                      'port_id': self.gw_port['physicalName'],
                      'host_id': 'host1',
                      'pci_slot': '0000:03:10.8'}
        # Create a new gateway
        gw_port_name = data_utils.rand_name(name='gw-port')
        self.gw_port = self.vsd_client.create_gateway_port(
            gw_port_name, gw_port_name, 'ACCESS', self.gateway['ID'],
            extra_params={'VLANRange': '0-4095'})[0]

        mapping2 = {'switch_id': self.gateway['systemID'],
                    'port_id': self.gw_port['physicalName'],
                    'host_id': 'host2',
                    'pci_slot': '0000:03:10.7'}

        with self.switchport_mapping(do_delete=False, **mapping1_1) as map1_1,\
                self.switchport_mapping(do_delete=False, **mapping1_2) \
                as map1_2, \
                self.switchport_mapping(do_delete=False, **mapping2) as map2:
            self.addCleanup(
                self.switchport_mapping_client_admin.delete_switchport_mapping,
                map1_1['id'])
            self.addCleanup(
                self.switchport_mapping_client_admin.delete_switchport_mapping,
                map1_2['id'])
            self.addCleanup(
                self.switchport_mapping_client_admin.delete_switchport_mapping,
                map2['id'])

            create_data1_1 = {'binding:vnic_type': 'direct',
                              'binding:host_id': 'host1',
                              'binding:profile': {
                                  "pci_slot": "0000:03:10.6",
                                  "physical_network": "physnet1",
                                  "pci_vendor_info": "8086:10ed"
                              }}
            direct_port = self.create_port(topology.network['id'],
                                           **create_data1_1)
            create_data1_2 = {'binding:vnic_type': 'direct',
                              'binding:host_id': 'host1',
                              'binding:profile': {
                                  "pci_slot": "0000:03:10.8",
                                  "physical_network": "physnet1",
                                  "pci_vendor_info": "8086:10ed"
                              }}
            self.create_port(topology.network['id'],
                             **create_data1_2)
            original_vport = topology.vsd_direct_vport
            # Create another gw_port to move sriov port to evacuate to
            # Create a second switchport mapping for this
            update_data = {
                'binding:host_id': 'host2',
                'binding:profile': {
                    "pci_slot": "0000:03:10.7",
                    "physical_network": "physnet1",
                    "pci_vendor_info": "8086:10ed"
                }}
            topology.direct_port = self.update_port(direct_port['id'],
                                                    **update_data)
            self.binding_data = update_data

        # Verification using newly created bridge vport: filter out original
        # bridge vport
        vsd_vports = self.vsd_client.get_vport(
            topology.vsd_vport_parent_resource,
            topology.vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=topology.subnet['network_id'])
        vsd_vports = [v for v in vsd_vports if v['ID'] !=
                      original_vport['ID']]
        self.assertNotEmpty(vsd_vports, "No new bridge port made for migrate")
        topology._vsd_direct_vport = vsd_vports[0]  # Reset for validation
        self._validate_vsd(topology, nr_vports=2)
        self._validate_os(topology)

    def _create_topology(self, with_router=False,
                         with_port=False, dualstack=False,
                         vsd_managed=False, for_trunk=False,
                         is_flat_vlan_in_use=False):
        assert (not with_router or not vsd_managed)  # but not both
        assert (not dualstack or not vsd_managed)  # initially not both (later)

        vsd_l2dom = trunk = router = port = subnetv6 = None
        cidr = IPNetwork('10.20.30.0/24')

        if vsd_managed:
            name = data_utils.rand_name('l2domain-')
            params = {
                'DHCPManaged': True,
                'address': str(cidr.ip),
                'netmask': str(cidr.netmask),
                'gateway': str(cidr[1])
            }
            vsd_l2dom_tmplt = self.vsd_client.create_l2domaintemplate(
                name + '-template', extra_params=params)[0]
            self.vsd_l2dom_template.append(vsd_l2dom_tmplt)
            vsd_l2dom = self.vsd_client.create_l2domain(
                name, templateId=vsd_l2dom_tmplt['ID'])[0]
            self.vsd_l2domain.append(vsd_l2dom)

        if with_router:
            router = self.create_router()
        if for_trunk:
            kwargs = {'segments': [
                {"provider:network_type": "vxlan"},
                {"provider:network_type": "flat",
                 "provider:physical_network": "physnet2",
                 "provider:segmentation_id": "0"}]}
        else:
            kwargs = {'segments': [
                {"provider:network_type": "vxlan"},
                {"provider:network_type": "vlan",
                 "provider:physical_network": "physnet1",
                 "provider:segmentation_id": "123"}
            ]}

        network = self.create_network(**kwargs)

        kwargs = {
            'gateway_ip': None,
            'nuagenet': vsd_l2dom['ID'],
            'net_partition': Topology.def_netpartition
        } if vsd_managed else {}
        subnet = self.create_subnet('10.20.30.0/24', network['id'], **kwargs)
        assert subnet

        if dualstack:
            kwargs = {'ipv6_ra_mode': 'dhcpv6-stateful',
                      'ipv6_address_mode': 'dhcpv6-stateful'}
            subnetv6 = self.create_subnet('a1ca:c10d:1111:1111::/64',
                                          network['id'],
                                          **kwargs)
            assert subnetv6

        if with_router:
            self.add_router_interface(router['id'], subnet_id=subnet['id'])
            if dualstack:
                self.add_router_interface(router['id'],
                                          subnet_id=subnetv6['id'])
        if with_port:
            port = self.create_port(network['id'])
        return SriovTopology(self.vsd_client, network,
                             subnet, router, port, subnetv6,
                             trunk, vsd_l2dom,
                             is_flat_vlan_in_use=is_flat_vlan_in_use)

    def _create_topology_with_subports(self, topology, with_router=False):
        kwargs = {'segments': [
            {"provider:network_type": "vxlan"},
            {"provider:network_type": "vlan",
             "provider:physical_network": "physnet1",
             "provider:segmentation_id": "123"}
        ]}
        subport_network = self.create_network(**kwargs)
        subport_subnet = self.create_subnet('10.2.0.0/24',
                                            subport_network['id'])
        subport_subnet_ipv6 = self.create_subnet(
            "2001:5f74:c4a5:b82e::/64", subport_network['id'])
        subport2_network = self.create_network()
        subport2_subnet = self.create_subnet('2.2.2.0/24',
                                             subport2_network['id'])
        if with_router and topology.router:
            self.add_router_interface(topology.router['id'],
                                      subnet_id=subport_subnet['id'])
            self.add_router_interface(topology.router['id'],
                                      subnet_id=subport2_subnet['id'])
        create_data = {'binding:vnic_type': 'direct',
                       'security_groups': [],
                       'port_security_enabled': False}
        sub_port = self.create_port(subport_network['id'], **create_data)
        sub_port2 = self.create_port(subport2_network['id'], **create_data)
        subportkwargs = [{'port_id': sub_port['id'],
                          'segmentation_type': 'vlan',
                          'segmentation_id': '123'},
                         {'port_id': sub_port2['id'],
                          'segmentation_type': 'vlan',
                          'segmentation_id': '321'}
                         ]
        if topology.trunk:
            self.add_subports(topology.trunk['id'], subportkwargs)
        sub_top1 = SubPortTopology(subport_network, subport_subnet,
                                   subport_subnet_ipv6,
                                   sub_port)
        sub_top2 = SubPortTopology(subport2_network, subport2_subnet,
                                   None,
                                   sub_port2)
        return sub_top1, sub_top2

    def _test_direct_port(self, topology, update=False,
                          with_port_security=False, aap=False,
                          multi_ips=False, is_trunk=False):
        create_data = {'binding:vnic_type': 'direct'}
        if not with_port_security:
            create_data['security_groups'] = []
        if aap:
            create_data['allowed_address_pairs'] = [
                {'ip_address': '30.30.0.0/24',
                 'mac_address': 'fe:a0:36:4b:c8:70'}]
        if multi_ips:
            create_data['fixed_ips'] = [
                {
                    "ip_address": "10.20.30.4",
                    "subnet_id": topology.subnet["id"]
                },
                {
                    "ip_address": "10.20.30.5",
                    "subnet_id": topology.subnet["id"]
                }
            ]

        mapping = {'switch_id': self.gateway['systemID'],
                   'port_id': self.gw_port['physicalName'],
                   'host_id': 'host-hierarchical',
                   'pci_slot': '0000:03:10.6'}
        if not update:
            create_data.update(self.binding_data)
        with self.switchport_mapping(do_delete=False, **mapping) as swtch_map:
            self.addCleanup(
                self.switchport_mapping_client_admin.delete_switchport_mapping,
                swtch_map['id'])
            direct_port = self.create_port(topology.network['id'],
                                           cleanup=True,
                                           **create_data)
            topology.direct_port = direct_port
            if is_trunk:
                trunk = self.create_trunk(direct_port['id'],
                                          subports=None,
                                          cleanup=True,
                                          name="trunk1")
                topology.trunk = trunk
            if update:
                if is_trunk:
                    topology.direct_port = self.update_port(
                        direct_port['id'],
                        as_admin=True,
                        **self.trunk_binding_data)
                    self.addCleanup(self.update_port,
                                    direct_port['id'],
                                    as_admin=True,
                                    **self.clear_binding)
                else:
                    topology.direct_port = self.update_port(
                        direct_port['id'],
                        as_admin=True,
                        **self.binding_data)
            if is_trunk:
                # ensure trunk transitions to ACTIVE
                lib_utils.wait_until_true(
                    lambda: self._is_trunk_active(trunk['id']),
                    exception=RuntimeError(
                        "Timed out waiting for trunk %s to "
                        "transition to ACTIVE." % trunk['id']))
                # ensure all underlying subports transitioned to ACTIVE
                for s in trunk.get('sub_ports'):
                    lib_utils.wait_until_true(
                        lambda: self._is_port_active(s['port_id']))

            self._validate_os(topology, is_trunk=is_trunk)
            if topology.is_flat_vlan_in_use:
                self.assertIsNone(topology.vsd_direct_vport,
                                  message="Direct vport found but it"
                                          " should not exists as"
                                          " VLAN-0 is already in use"
                                          " by an another system")
            else:
                self._validate_vsd(topology, is_trunk=is_trunk)
        return topology

    def _test_direct_subport(self, subport_topology, subport_mapping,
                             use_subport_check=False, nr_vports=1):
        with self.switchport_mapping(do_delete=False, **subport_mapping) as sm:
            self.addCleanup(
                self.switchport_mapping_client_admin.delete_switchport_mapping,
                sm['id'])
            subport_topology.direct_port = self.update_port(
                subport_topology.direct_port['id'], as_admin=True,
                **self.subport_binding_data)
            self.addCleanup(self.update_port,
                            subport_topology.direct_port['id'],
                            as_admin=True,
                            **self.clear_binding)
        self._validate_vsd(subport_topology, is_trunk=False,
                           nr_vports=nr_vports,
                           use_subport_check=use_subport_check)
        self._validate_os(subport_topology, is_subport=True,
                          use_subport_vlan=use_subport_check)

    # Validation part

    def _validate_vsd(self, topology, is_trunk=False, nr_vports=1,
                      use_subport_check=False):
        self._validate_direct_vport(topology)
        self._validate_vlan(topology, is_trunk, use_subport_check)
        self._validate_interface(topology)
        if not topology.vsd_managed:
            self._validate_policygroup(topology, nr_vports=nr_vports)

    def _validate_direct_vport(self, topology):
        direct_vport = topology.vsd_direct_vport
        self.assertIsNotNone(direct_vport, message="No direct vport found")
        self.assertThat(topology.vsd_direct_vport['type'],
                        matchers.Equals(self.expected_vport_type),
                        message="Vport has wrong type")

    def _validate_vlan(self, topology, is_trunk=False, use_subport_vlan=False):
        vsd_vlan = self.vsd_client.get_gateway_vlan_by_id(
            topology.vsd_direct_vport['VLANID'])
        expected_vlan = (self.expected_vlan_subport_2 if use_subport_vlan
                         else self.expected_vlan)
        if is_trunk:
            self.assertThat(
                vsd_vlan['value'], matchers.Equals(0),
                message="Vport has unexpected vlan")
        else:
            self.assertThat(
                vsd_vlan['value'], matchers.Equals(expected_vlan),
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

    def _validate_policygroup(self, topology, nr_vports=1):
        expected_pgs = 1  # Expecting only one hardware
        if self.is_dhcp_agent_present():
            expected_pgs += 1  # Expecting one hardware and one software
        self.assertThat(topology.vsd_policygroups,
                        matchers.HasLength(expected_pgs),
                        message="Unexpected amount of PGs found")
        vsd_policygroup = topology.vsd_policygroups[expected_pgs - 1]
        self.assertEqual(vsd_policygroup['type'], 'HARDWARE')
        self.assertEqual(vsd_policygroup['name'],
                         constants.NUAGE_PLCY_GRP_ALLOW_ALL_HW)
        self.assertEqual(vsd_policygroup['description'],
                         constants.NUAGE_PLCY_GRP_ALLOW_ALL_HW)
        self.assertEqual(vsd_policygroup['externalID'],
                         "hw:" +
                         (ExternalId(constants.NUAGE_PLCY_GRP_ALLOW_ALL)
                          .at_cms_id()))

        vsd_pg_vports = self.vsd_client.get_vport(constants.POLICYGROUP,
                                                  vsd_policygroup['ID'])
        self.assertThat(vsd_pg_vports, matchers.HasLength(nr_vports),
                        message="Expected to find exactly {} "
                                "vport(s) in PG".format(nr_vports))

        vsd_pg_vport_ids = [v['ID'] for v in vsd_pg_vports]
        self.assertIn(topology.vsd_direct_vport['ID'],
                      vsd_pg_vport_ids,
                      "Vport should be part of HARDWARE PG")

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

    def _validate_os(self, topology, is_trunk=False, is_subport=False,
                     use_subport_vlan=False):
        port = topology.direct_port
        self.assertEqual(expected='ACTIVE', observed=port.get('status'),
                         message='Direct port status is not ACTIVE')
        profile = port.get('binding:profile')
        vif_details = port.get('binding:vif_details')
        expected_vlan = (self.expected_vlan_subport_2 if use_subport_vlan
                         else self.expected_vlan)
        if is_trunk:
            self.assertThat(
                profile,
                matchers.Equals(
                    self.trunk_binding_data.get('binding:profile')),
                message="Port binding profiles doesn't match expected")
            self.assertThat(
                vif_details.get('vlan'),
                matchers.Equals(str(0)),
                message="Port has unexpected vlan")
        else:
            self.assertThat(
                vif_details.get('vlan'),
                matchers.Equals(str(expected_vlan)),
                message="Port has unexpected vlan")
            if is_subport:
                for sub_port_details in self.get_subports(topology.trunk['id']
                                                          ):
                    if (sub_port_details['port_id'] ==
                            topology.direct_port['id']):
                        expected = {'port_id': topology.direct_port['id'],
                                    'segmentation_id': expected_vlan,
                                    'segmentation_type': 'vlan'}
                        self.assertThat(expected,
                                        matchers.Equals(sub_port_details),
                                        message="SubPort does not match"
                                                " expected")
                del profile['vlan']
                self.assertThat(
                    profile,
                    matchers.Equals(self.trunk_binding_data.get(
                        'binding:profile')),
                    message="Port binding profiles for subport"
                            " doesn't match expected")
            else:
                self.assertThat(
                    profile,
                    matchers.Equals(self.binding_data.get('binding:profile')),
                    message="Port binding profiles doesn't match expected")
        self.assertThat(
            port['binding:vif_type'], matchers.Equals('hw_veb'),
            message="Port has unexpected vif_type")
