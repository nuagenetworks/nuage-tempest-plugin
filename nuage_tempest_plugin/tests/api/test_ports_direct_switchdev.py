# Copyright 2018 NOKIA
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
import testscenarios
from testtools import matchers

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from nuage_tempest_plugin.lib.mixins import l3
from nuage_tempest_plugin.lib.mixins import network as network_mixin
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.lib.utils import data_utils as lib_utils

from nuage_tempest_plugin.services.nuage_client import NuageRestClient

CONF = Topology.get_conf()

load_tests = testscenarios.load_tests_apply_scenarios


class SwitchdevTopology(object):
    def __init__(self, vsd_client, network, subnet, router, port, subnetv6,
                 trunk, l2domain=None):
        super(SwitchdevTopology, self).__init__()
        self.vsd_client = vsd_client
        self.network = network
        self.subnet = subnet
        self.router = router
        self.normal_port = port
        self.trunk = trunk
        self.switchdev_port = None
        self.subnetv6 = subnetv6
        self.vsd_managed = l2domain is not None

        self.binding_data = None
        self._switchdev_port_is_subport = False
        self._vsd_vport_parent = l2domain
        self._vsd_vport_parent_resource = None
        self._vsd_switchdev_vport = None
        self._vsd_domain = None
        self._vsd_domain_resource = None
        self._vsd_policygroups = None
        self._vsd_switchdev_interface_resource = None
        self._vsd_switchdev_interface = None
        self._vsd_egress_acl_templates = None
        self._vsd_egress_acl_entries = None
        self._vsd_switchdev_dhcp_opts = None

    @property
    def vsd_vport_parent(self):
        if not getattr(self, '_vsd_vport_parent', False):
            filters, filter_values = self.vsd_client.get_subnet_filters(
                self.subnet)
            self._vsd_vport_parent = self.vsd_client.get_global_resource(
                self.vsd_vport_parent_resource,
                filters=filters,
                filter_values=filter_values)[0]
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
    def vsd_switchdev_vport(self):
        if not getattr(self, '_vsd_switchdev_vport', False):
            vsd_vports = self.vsd_client.get_vport(
                self.vsd_vport_parent_resource,
                self.vsd_vport_parent['ID'],
                filters='externalID',
                filter_values=self.switchdev_port['id'])
            self._vsd_switchdev_vport = vsd_vports[0]
        return self._vsd_switchdev_vport

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
    def vsd_switchdev_interface_resource(self):
        if not getattr(self, '_vsd_switchdev_interface_resource', False):
            self._vsd_switchdev_interface_resource = constants.VM_IFACE
        return self._vsd_switchdev_interface_resource

    @property
    def vsd_switchdev_interface(self):
        if not getattr(self, '_vsd_switchdev_interface', False):
            self._vsd_switchdev_interface = self.vsd_client.get_child_resource(
                constants.VPORT,
                self.vsd_switchdev_vport['ID'],
                self.vsd_switchdev_interface_resource)[0]
        return self._vsd_switchdev_interface

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
    def vsd_switchdev_dhcp_opts(self):
        if not getattr(self, '_vsd_switchdev_dhcp_opts', False):
            self._vsd_switchdev_dhcp_opts = self.vsd_client.get_dhcpoption(
                self.vsd_switchdev_interface_resource,
                self.vsd_switchdev_interface['ID'])
        return self._vsd_switchdev_dhcp_opts


class SwitchdevPortTest(network_mixin.NetworkMixin, l3.L3Mixin):

    credentials = ['admin']

    vnic_type = 'direct'
    vif_type = 'ovs'

    # Switchdev with DIRECT and with virtio-forwarder
    scenarios = [
        ('direct', {'vnic_type': 'direct', 'vif_type': 'ovs'}),
        ('virtio-forwarder', {'vnic_type': 'virtio-forwarder',
                              'vif_type': 'vhostuser'})]

    @classmethod
    def setUpClass(cls):
        super(SwitchdevPortTest, cls).setUpClass()
        cls.expected_vport_type = constants.VPORT_TYPE_VM
        cls.expected_vif_type = cls.vif_type

    @classmethod
    def setup_clients(cls):
        super(SwitchdevPortTest, cls).setup_clients()
        cls.vsd_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(SwitchdevPortTest, cls).resource_setup()
        # for VSD managed
        cls.vsd_l2dom_template = []
        cls.vsd_l2domain = []

    @classmethod
    def skip_checks(cls):
        super(SwitchdevPortTest, cls).skip_checks()
        if not CONF.service_available.neutron:
            raise cls.skipException("Neutron is not available")
        if not Topology.has_switchdev_offload_support():
            raise cls.skipException(
                "OVS HW offload is not supported in current release")

    @classmethod
    def resource_cleanup(cls):
        super(SwitchdevPortTest, cls).resource_cleanup()

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
        super(SwitchdevPortTest, self).setUp()

        if (self.vnic_type == 'virtio-forwarder' and not
                Topology.has_switchdev_virtio_forwarder_support()):
            self.skipTest("OVS HW offload with virtio forwarder"
                          " not supported in current release")

        self.clear_binding = {
            'binding:host_id': '',
            'binding:profile': {
                'capabilities': ['switchdev']
            }
        }

        self.binding_data = {
            'binding:host_id': 'host-hierarchical',
            'device_id': data_utils.rand_uuid(),
            'device_owner': 'compute:nova',
            'binding:profile': {
                'capabilities': ['switchdev'],
                "pci_slot": "0000:17:01.1",
                "pci_vendor_info": "15b3:1018"
            }
        }

    def _create_topology(self, with_router=False, with_port=False,
                         dualstack=False, vsd_managed=False, for_trunk=False):
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

        network = self.create_network()

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
        return SwitchdevTopology(self.vsd_client, network, subnet, router,
                                 port, subnetv6, trunk, vsd_l2dom)

    def _test_switchdev_port(self, topology, update=False,
                             with_port_security=True, aap=False,
                             multi_ips=False, is_trunk=False):

        create_data = {
            'binding:vnic_type': self.vnic_type,
            'binding:profile': {
                'capabilities': ['switchdev']
            }
        }

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

        if not update:
            create_data.update(self.binding_data)
        switchdev_port = self.create_port(topology.network['id'], cleanup=True,
                                          **create_data)
        topology.switchdev_port = switchdev_port
        if is_trunk:
            trunk = self.create_trunk(switchdev_port['id'], subports=None,
                                      cleanup=True, name="trunk1")
            self.addCleanup(self.update_port, switchdev_port['id'],
                            as_admin=True, **self.clear_binding)
            topology.trunk = trunk
        if update:
            topology.switchdev_port = self.update_port(switchdev_port['id'],
                                                       as_admin=True,
                                                       **self.binding_data)
        if is_trunk:
            # ensure trunk transitions to ACTIVE
            lib_utils.wait_until_true(
                lambda: self._is_trunk_active(trunk['id']),
                exception=RuntimeError("Timed out waiting for trunk %s to "
                                       "transition to ACTIVE." % trunk['id']))
            # ensure all underlying subports transitioned to ACTIVE
            for s in trunk.get('sub_ports'):
                lib_utils.wait_until_true(
                    lambda: self._is_port_active(s['port_id']))

        self._validate_vsd(topology, is_trunk=is_trunk)
        self._validate_os(topology, is_trunk=is_trunk)
        return topology

    # Validation part

    def _validate_vsd(self, topology, is_trunk=False):
        self._validate_switchdev_port(topology, is_trunk)
        self._validate_interface(topology)
        self._validate_dhcp_option(topology)
        if not topology.vsd_managed:
            self._validate_policygroup(topology)

    def _validate_switchdev_port(self, topology, is_trunk):
        self.assertThat(topology.vsd_switchdev_vport['type'],
                        matchers.Equals(self.expected_vport_type),
                        message="Vport has wrong type")
        if is_trunk:
            self.assertThat(topology.vsd_switchdev_vport['trunkRole'],
                            matchers.Equals('PARENT_PORT'),
                            message="Vport has wrong trunkRole")

    def _validate_interface(self, topology):
        neutron_port = topology.switchdev_port

        self.assertThat(topology.vsd_switchdev_interface['MAC'],
                        matchers.Equals(neutron_port['mac_address']))
        self.assertThat(
            topology.vsd_switchdev_interface['IPAddress'],
            matchers.Equals(neutron_port['fixed_ips'][0]['ip_address']))

    def _validate_policygroup(self, topology, pg_name=None):
        if self.is_dhcp_agent_present():
            expected_pgs = 2
        else:
            expected_pgs = 1
        self.assertThat(topology.vsd_policygroups,
                        matchers.HasLength(expected_pgs),
                        message="Unexpected amount of PGs found")
        for vsd_policygroup in topology.vsd_policygroups:
            self.assertThat(vsd_policygroup['type'],
                            matchers.Equals('SOFTWARE'))
            if pg_name:
                self.assertThat(vsd_policygroup['name'],
                                matchers.Contains(pg_name))

            vsd_pg_vports = self.vsd_client.get_vport(constants.POLICYGROUP,
                                                      vsd_policygroup['ID'])
            self.assertThat(vsd_pg_vports, matchers.HasLength(1),
                            message="Expected to find exactly 1 vport in PG")
            if topology.subnet['id'] in vsd_pg_vports[0]['externalID']:
                self.assertThat(
                    vsd_pg_vports[0]['ID'],
                    matchers.Equals(topology.vsd_switchdev_vport['ID']),
                    message="Vport should be part of PG")

    def _validate_dhcp_option(self, topology):
        expected_len = 0 if topology.router else 1
        self.assertThat(topology.vsd_switchdev_dhcp_opts,
                        matchers.HasLength(expected_len))
        DHCP_ROUTER_OPT = 3

        for dhcp_opt in topology.vsd_switchdev_dhcp_opts:
            if dhcp_opt['actualType'] == DHCP_ROUTER_OPT:
                self.assertThat(dhcp_opt['actualValues'][0],
                                matchers.Equals(topology.subnet['gateway_ip']))

    def _validate_os(self, topology, is_trunk=False, is_subport=False):
        port = topology.switchdev_port
        actual_profile = port.get('binding:profile')
        expected_profile = self.binding_data.get('binding:profile')
        self.assertThat(actual_profile, matchers.Equals(expected_profile),
                        message="Port binding profiles doesn't match expected")
        self.assertThat(
            port['binding:vif_type'], matchers.Equals(self.expected_vif_type),
            message="Port has unexpected vif_type")
        if is_trunk:
            trunk_details = port.get('trunk_details')
            self.assertIsNotNone(trunk_details,
                                 message="Port has no trunk_details")
            self.assertThat(trunk_details.get('trunk_id'),
                            matchers.Equals(topology.trunk['id']),
                            message="Port has unexpected trunk assosciation")
        else:
            if is_subport:
                sub_port_details = self.get_subports(
                    topology.trunk['id'])[0]
                expected = {'port_id': topology.switchdev_port['id'],
                            'segmentation_id': self.expected_vlan,
                            'segmentation_type': 'vlan'}
                self.assertThat(expected, matchers.Equals(sub_port_details),
                                message="SubPort does not match expected")
                self.assertThat(
                    actual_profile,
                    matchers.Equals(self.trunk_binding_data.get(
                        'binding:profile')),
                    message="Port binding profiles for subport"
                            " doesn't match expected")

    # os managed
    @decorators.attr(type='smoke')
    def test_switchdev_port_l3_create(self):
        topology = self._create_topology(with_router=True)
        self._test_switchdev_port(topology, update=False)

    def test_switchdev_port_l3_update(self):
        topology = self._create_topology(with_router=True)
        self._test_switchdev_port(topology, update=True)

    def test_switchdev_port_l3_ipv6_create(self):
        topology = self._create_topology(with_router=True, dualstack=True)
        self._test_switchdev_port(topology, update=False)

    @decorators.attr(type='smoke')
    def test_switchdev_port_l3_ipv6_update(self):
        topology = self._create_topology(with_router=True, dualstack=True)
        self._test_switchdev_port(topology, update=True)

    def test_switchdev_port_l3_create_with_aap(self):
        topology = self._create_topology(with_router=True)
        self._test_switchdev_port(topology, update=False, aap=True)

    def test_switchdev_port_l2_create(self):
        topology = self._create_topology(with_router=False)
        self._test_switchdev_port(topology, update=False)

    def test_switchdev_port_l2_update(self):
        topology = self._create_topology(with_router=False)
        self._test_switchdev_port(topology, update=True)

    @decorators.attr(type='smoke')
    def test_switchdev_port_l2_ipv6_create(self):
        topology = self._create_topology(with_router=False, dualstack=True)
        self._test_switchdev_port(topology, update=False)

    def test_switchdev_port_l2_ipv6_update(self):
        topology = self._create_topology(with_router=False, dualstack=True)
        self._test_switchdev_port(topology, update=True)

    @decorators.attr(type='smoke')
    def test_switchdev_port_l2_update_with_aap(self):
        topology = self._create_topology(with_router=False)
        self._test_switchdev_port(topology, update=True, aap=True)

    @utils.requires_ext(extension='trunk', service='network')
    def test_switchdev_port_l3_create_with_trunk(self):
        topology = self._create_topology(with_router=True, for_trunk=True)
        self._test_switchdev_port(topology, update=True, is_trunk=True)

    @utils.requires_ext(extension='trunk', service='network')
    def test_switchdev_port_l2_create_with_trunk(self):
        topology = self._create_topology(with_router=False, for_trunk=True)
        self._test_switchdev_port(topology, update=True, is_trunk=True)
