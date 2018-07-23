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

import time

import testtools
from testtools import matchers

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from nuage_tempest_plugin.lib.mixins import l3
from nuage_tempest_plugin.lib.mixins import network as network_mixin
from nuage_tempest_plugin.lib.mixins import sg as sg_mixin
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.tests.api.baremetal.baremetal_topology \
    import BaremetalTopology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class BaremetalPortsTest(network_mixin.NetworkMixin,
                         l3.L3Mixin, sg_mixin.SGMixin):
    credentials = ['admin']

    @classmethod
    def setUpClass(cls):
        super(BaremetalPortsTest, cls).setUpClass()
        if (Topology.nuage_baremetal_driver ==
                constants.BAREMETAL_DRIVER_BRIDGE):
            cls.expected_vport_type = constants.VPORT_TYPE_BRIDGE
        elif (Topology.nuage_baremetal_driver ==
              constants.BAREMETAL_DRIVER_HOST):
            cls.expected_vport_type = constants.VPORT_TYPE_HOST
        else:
            raise Exception("Unexpected configuration of "
                            "'nuage_baremetal_driver'")
        cls.expected_vlan_normal = 0
        cls.expected_vlan_transparent = 4095

    @classmethod
    def skip_checks(cls):
        super(BaremetalPortsTest, cls).skip_checks()
        if not CONF.service_available.neutron:
            # this check prevents this test to be run in unittests
            raise cls.skipException("Neutron support is required")

    @classmethod
    def setup_clients(cls):
        super(BaremetalPortsTest, cls).setup_clients()
        cls.vsd_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(BaremetalPortsTest, cls).resource_setup()
        # Only gateway here, to support parallel testing each tests makes its
        # own gateway port so no VLAN overlap should occur.
        cls.gateway = cls.vsd_client.create_gateway(
            data_utils.rand_name(name='vsg'),
            data_utils.rand_name(name='sys_id'), 'VSG')[0]

    @classmethod
    def resource_cleanup(cls):
        super(BaremetalPortsTest, cls).resource_cleanup()
        cls.vsd_client.delete_gateway(cls.gateway['ID'])

    def setUp(self):
        super(BaremetalPortsTest, self).setUp()
        gw_port_name = data_utils.rand_name(name='gw-port')
        self.gw_port = self.vsd_client.create_gateway_port(
            gw_port_name, gw_port_name, 'ACCESS', self.gateway['ID'],
            extra_params={'VLANRange': '0-4095'})[0]
        self.binding_data = {
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy', 'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port['name'],
                     "switch_info": self.gateway['systemID']}]
            }}

    def test_baremetal_port_l3_create(self):
        topology = self._create_topology(with_router=True)
        self._test_baremetal_port(topology, update=False)

    def test_baremetal_port_l3_create_vlan_transparent(self):
        topology = self._create_topology(with_router=True,
                                         vlan_transparent=True)
        self._test_baremetal_port(topology, update=False,
                                  vlan_transparent=True)

    @decorators.attr(type='smoke')
    def test_baremetal_port_l3_update(self):
        topology = self._create_topology(with_router=True)
        self._test_baremetal_port(topology, update=True)

    def test_baremetal_port_l3_update_vlan_transparent(self):
        topology = self._create_topology(with_router=True,
                                         vlan_transparent=True)
        self._test_baremetal_port(topology, update=True,
                                  vlan_transparent=True)

    @decorators.attr(type='smoke')
    def test_baremetal_port_l2_create(self):
        topology = self._create_topology(with_router=False)
        self._test_baremetal_port(topology, update=False)

    @decorators.attr(type='smoke')
    def test_baremetal_port_l2_create_vlan_transparent(self):
        topology = self._create_topology(with_router=False,
                                         vlan_transparent=True)
        self._test_baremetal_port(topology, update=False,
                                  vlan_transparent=True)

    def test_baremetal_port_l2_update(self):
        topology = self._create_topology(with_router=False)
        self._test_baremetal_port(topology, update=True)

    def test_baremetal_port_l2_update_vlan_transparent(self):
        topology = self._create_topology(with_router=False,
                                         vlan_transparent=True)
        self._test_baremetal_port(topology, update=True,
                                  vlan_transparent=True)

    @testtools.skip("Currently unknown how to trigger vport resolution")
    def test_router_attach(self):
        topology = self._create_topology(with_router=False)
        port = self.create_port(topology.network['id'], **self.binding_data)
        topology.baremetal_port = port
        with self.router(attached_subnets=[topology.subnet['id']]) as router:
            topology.router = router
            self._validate_vsd(topology)

    @testtools.skip("Currently not supported")
    def test_port_dhcp_opts_create(self):
        topology = self._create_topology()
        data = {'security_groups': [topology.security_group['id']],
                'extra_dhcp_opts': [{'opt_name': 'tftp-server',
                                     'opt_value': '192.168.0.3'}]}
        data.update(self.binding_data)
        baremetal_port = self.create_port(topology.network['id'], **data)
        # Workaround for https://bugs.launchpad.net/neutron/+bug/1698852
        topology.baremetal_port = self.get_port(baremetal_port['id'])
        self._validate_dhcp_option(topology)

    @testtools.skip("Currently not supported")
    def test_port_dhcp_opts_update(self):
        topology = self._create_topology()
        create_data = {'security_groups': [topology.security_group['id']]}
        create_data.update(self.binding_data)
        data = {'extra_dhcp_opts': [{'opt_name': 'tftp-server',
                                     'opt_value': '192.168.0.3'}]}
        baremetal_port = self.create_port(topology.network['id'],
                                          **create_data)
        baremetal_port = self.update_port(baremetal_port['id'], **data)
        topology.baremetal_port = baremetal_port
        self._validate_dhcp_option(topology)

    @decorators.attr(type='negative')
    def test_fail_create_with_default_sg(self):
        topology = self._create_topology()
        # Creating baremetal port with default sg should fail
        # as it has rules with remote-group-id
        self.assertRaises(lib_exc.BadRequest, self.create_port,
                          topology.network['id'],
                          **self.binding_data)

    @decorators.attr(type='negative')
    def test_fail_create_with_sg_used_by_vm(self):
        topology = self._create_topology(with_router=True, with_port=True)
        # update a normal port with binding and sg
        # this will result in port binding
        data = {'security_groups': [topology.security_group['id']],
                'device_owner': 'compute:nova',
                'device_id': topology.normal_port['id'],
                'binding:host_id': 'dummy'}
        self.update_port(topology.normal_port['id'], **data)
        self.assertRaises(lib_exc.BadRequest, self.create_port,
                          topology.network['id'],
                          **self.binding_data)
        data = {'security_groups': []}
        self.update_port(topology.normal_port['id'], **data)

    @decorators.attr(type='negative')
    def test_fail_create_with_non_existent_gw(self):
        topology = self._create_topology()
        data = {
            'security_groups': [topology.security_group['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy', 'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port['name'],
                     "switch_info": '123.123.123.123'}]
            }}
        self.assertRaises(lib_exc.BadRequest, self.create_port,
                          topology.network['id'],
                          **data)

    @decorators.attr(type='negative')
    def test_fail_create_with_non_existent_port(self):
        topology = self._create_topology()
        data = {
            'security_groups': [topology.security_group['id']],
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy', 'binding:profile': {
                "local_link_information": [
                    {"port_id": data_utils.rand_name(name='gw-port'),
                     "switch_info": self.gateway['systemID']}]
            }}
        self.assertRaises(lib_exc.BadRequest, self.create_port,
                          topology.network['id'],
                          **data)

    def test_create_without_psec(self):
        topology = self._create_topology()
        create_data = {
            'port_security_enabled': False,
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy', 'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port['name'],
                     "switch_info": self.gateway['systemID']}]
            }}
        baremetal_port = self.create_port(topology.network['id'],
                                          **create_data)
        topology.baremetal_port = baremetal_port
        self._validate_baremetal_vport(topology)
        self._validate_vlan(topology, vlan_transparent=False)
        self._validate_interface(topology)
        self._validate_policygroup(topology, pg_name='PG_FOR_LESS_SECURITY')

    def test_update_without_psec(self):
        topology = self._create_topology()
        create_data = {
            'security_groups': [],
            'port_security_enabled': False,
            'binding:vnic_type': 'baremetal',
        }
        baremetal_port = self.create_port(topology.network['id'],
                                          **create_data)
        update_data = {
            'binding:host_id': 'dummy', 'binding:profile': {
                "local_link_information": [
                    {"port_id": self.gw_port['name'],
                     "switch_info": self.gateway['systemID']}]
            }}
        baremetal_port = self.update_port(baremetal_port['id'], **update_data)
        topology.baremetal_port = baremetal_port
        self._validate_baremetal_vport(topology)
        self._validate_vlan(topology, vlan_transparent=False)
        self._validate_interface(topology)
        self._validate_policygroup(topology, pg_name='PG_FOR_LESS_SECURITY')

    def _create_topology(self, with_router=False, with_port=False,
                         vlan_transparent=False):
        router = port = None
        if with_router:
            router = self.create_router()
        if vlan_transparent:
            network = self.create_network(vlan_transparent=True)
        else:
            network = self.create_network()
        subnet = self.create_subnet('10.20.30.0/24', network['id'])
        if with_router:
            self.add_router_interface(router['id'], subnet_id=subnet['id'])
        if with_port:
            port = self.create_port(network['id'])
        security_group = self.create_security_group()
        return BaremetalTopology(self.vsd_client, network, subnet,
                                 router, port, security_group)

    def _test_baremetal_port(self, topology, update=False,
                             vlan_transparent=False):
        create_data = {'security_groups': [topology.security_group['id']]}
        if not update:
            create_data.update(self.binding_data)

        with self.port(topology.network['id'], **create_data) as bm_port:
            topology.baremetal_port = bm_port
            if update:
                self.update_port(bm_port['id'], as_admin=True,
                                 **self.binding_data)
            self._validate_vsd(topology, vlan_transparent=vlan_transparent)

    # Validation part

    def _validate_vsd(self, topology, vlan_transparent=False):
        self._validate_baremetal_vport(topology)
        self._validate_vlan(topology, vlan_transparent=vlan_transparent)
        self._validate_interface(topology)
        self._validate_policygroup(topology)

    def _validate_baremetal_vport(self, topology):
        self.assertThat(topology.vsd_baremetal_vport['type'],
                        matchers.Equals(self.expected_vport_type),
                        message="Vport has wrong type")

    def _validate_vlan(self, topology, vlan_transparent=False):
        vsd_vlan = self.vsd_client.get_gateway_vlan_by_id(
            topology.vsd_baremetal_vport['VLANID'])
        if vlan_transparent:
            self.assertThat(
                vsd_vlan['value'],
                matchers.Equals(self.expected_vlan_transparent),
                message="Vport has unexpected vlan")
        else:
            self.assertThat(
                vsd_vlan['value'], matchers.Equals(self.expected_vlan_normal),
                message="Vport has unexpected vlan")

    def _validate_interface(self, topology):
        vsd_vport = topology.vsd_baremetal_vport
        neutron_port = topology.baremetal_port

        if vsd_vport['type'] == constants.VPORT_TYPE_HOST:
            self.assertThat(topology.vsd_baremetal_interface['MAC'],
                            matchers.Equals(neutron_port['mac_address']))
            self.assertThat(
                topology.vsd_baremetal_interface['IPAddress'],
                matchers.Equals(neutron_port['fixed_ips'][0]['ip_address']))

    def _validate_policygroup(self, topology, pg_name=None):
        if topology.normal_port is not None:
            expected_pgs = 2  # Expecting software + hardware
        else:
            expected_pgs = 1  # Expecting only hardware
        if self.is_dhcp_agent_present():
            expected_pgs += 1  # Extra PG for dhcp agent

            # Repeated check in case of agent
            for attempt in range(Topology.nbr_retries_for_test_robustness):
                if len(topology.get_vsd_policygroups(True)) == expected_pgs:
                    break
                else:
                    LOG.error("Unexpected amount of PGs found, "
                              "expected {} found {} (attempt {})".format(
                                  expected_pgs, len(topology.vsd_policygroups),
                                  attempt + 1))
                    time.sleep(1)

        self.assertThat(topology.get_vsd_policygroups(True),
                        matchers.HasLength(expected_pgs),
                        message="Unexpected amount of PGs found")
        for pg in topology.vsd_policygroups:
            if pg['type'] == 'HARDWARE':
                vsd_policygroup = pg
                break
        else:
            self.fail("Could not find HARDWARE policy group.")
        self.assertThat(vsd_policygroup['type'], matchers.Equals('HARDWARE'))
        if pg_name:
            self.assertThat(vsd_policygroup['name'],
                            matchers.Contains(pg_name))

        vsd_pg_vports = self.vsd_client.get_vport(constants.POLICYGROUP,
                                                  vsd_policygroup['ID'])
        self.assertThat(vsd_pg_vports, matchers.HasLength(1),
                        message="Expected to find exactly 1 vport in PG")
        self.assertThat(vsd_pg_vports[0]['ID'],
                        matchers.Equals(topology.vsd_baremetal_vport['ID']),
                        message="Vport should be part of HARDWARE PG")

    def _validate_interconnect(self, topology):
        self.assertThat(topology.vsd_policygroups, matchers.HasLength(2),
                        message="Expected 2 PGs: 1 hardware, 1 software")
        vsd_policygroups = {pg['type']: pg for pg in topology.vsd_policygroups}
        egress_entries = topology.vsd_egress_acl_entries
        for rule in egress_entries:
            if (rule['locationID'] == vsd_policygroups['SOFTWARE']['ID'] and
                    rule['networkID'] == vsd_policygroups['HARDWARE'][
                    'ID']):
                break
        else:
            self.fail("Could not find interlink egress rule.")

    def _validate_dhcp_option(self, topology):
        self.assertThat(topology.vsd_baremetal_dhcp_opts,
                        matchers.HasLength(2))

        DHCP_ROUTER_OPT = 3
        DHCP_SERVER_NAME_OPT = 66
        for dhcp_opt in topology.vsd_baremetal_dhcp_opts:
            if dhcp_opt['actualType'] == DHCP_ROUTER_OPT:
                self.assertThat(dhcp_opt['actualValues'][0],
                                matchers.Equals(topology.subnet['gateway_ip']))
            elif dhcp_opt['actualType'] == DHCP_SERVER_NAME_OPT:
                os_dhcp_opt = topology.baremetal_port['extra_dhcp_opts'][0]
                self.assertThat(dhcp_opt['actualValues'][0],
                                matchers.Equals(os_dhcp_opt['opt_value']))
