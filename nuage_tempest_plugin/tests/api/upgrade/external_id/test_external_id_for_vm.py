# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from netaddr import IPNetwork

from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.lib.utils import exceptions as n_exceptions
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.tests.api.upgrade.external_id.external_id \
    import ExternalId
from nuage_tempest_plugin.tests.scenario \
    import base_nuage_network_scenario_test

import upgrade_external_id_with_cms_id as upgrade_script

LOG = Topology.get_logger(__name__)


class ExternalIdForVmTest(
        base_nuage_network_scenario_test.NuageNetworkScenarioTest):

    class MatchingVsdVm(object):
        def __init__(self, outer, vm):
            self.test = outer
            self.vm = vm

            self.vsd_vm = None

        def get_by_external_id(self):
            vsd_vms = self.test.nuage_client.get_vm(
                parent=None, parent_id='',
                filters='externalID', filter_value=self.vm['id'])

            # should have exact 1 match
            self.test.assertEqual(len(vsd_vms), 1)
            self.vsd_vm = vsd_vms[0]

            # VSD UUID is the Openstack VM ID
            self.test.assertEqual(self.vsd_vm['UUID'], self.vm['id'])
            self.test.assertEqual(
                self.vsd_vm['externalID'],
                ExternalId(self.vm['id']).at_cms_id())

            return self

        def get_by_uuid(self):
            vsd_vms = self.test.nuage_client.get_vm(
                parent=None, parent_id='',
                filters='UUID', filter_value=self.vm['id'])

            # should have exact 1 match
            self.test.assertEqual(len(vsd_vms), 1)
            self.vsd_vm = vsd_vms[0]

            # VSD UUID is the Openstack VM ID
            self.test.assertEqual(self.vsd_vm['UUID'], self.vm['id'])

            return self

        def has_parent_vm_interface(self, with_external_id=None):
            # vsd vm interface object has external ID
            vsd_vm_interfaces = self.vsd_vm['interfaces']
            self.test.assertEqual(
                1, len(vsd_vm_interfaces), "interface not found")

            vsd_vm_interface = vsd_vm_interfaces[0]

            if with_external_id is None:
                self.test.assertIsNone(vsd_vm_interface['externalID'])
            else:
                self.test.assertEqual(
                    with_external_id, vsd_vm_interface['externalID'])

        def verify_cannot_delete(self):
            # Can't delete vport in VSD
            self.test.assertRaisesRegex(
                n_exceptions.MultipleChoices,
                "Multiple choices",
                self.test.nuage_client.delete_resource,
                n_constants.VM, self.vsd_vm['ID'])

    def setUp(self):
        super(ExternalIdForVmTest, self).setUp()
        self.keypairs = {}
        self.servers = []

    @classmethod
    def skip_checks(cls):
        super(ExternalIdForVmTest, cls).skip_checks()
        cls.test_upgrade = not Topology.within_ext_id_release()

    @classmethod
    def setup_clients(cls):
        super(ExternalIdForVmTest, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    def _create_server(self, name, network, port_id=None):
        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        network = {'uuid': network['id']}
        if port_id is not None:
            network['port'] = port_id

        server = self.create_server(
            name=name,
            networks=[network],
            key_name=keypair['name'],
            wait_until='ACTIVE')
        return server

    @nuage_test.header()
    def test_server_on_neutron_port_matching_vsd_vm(self):
        # Create a network
        network = self._create_network(namestart='network-')
        subnet = self.create_subnet(network, namestart='subnet-')
        self.assertIsNotNone(subnet)  # dummy check to use local variable

        port = self.create_port(network['id'])

        name = data_utils.rand_name('server-smoke')
        server = self._create_server(name, network, port['id'])

        if self.test_upgrade:
            vsd_vm = self.MatchingVsdVm(self, server).get_by_uuid()
            vsd_vm.has_parent_vm_interface(ExternalId(port['id']).at_cms_id())

            upgrade_script.do_run_upgrade_script()

        vsd_vm = self.MatchingVsdVm(self, server).get_by_external_id()
        vsd_vm.has_parent_vm_interface(ExternalId(port['id']).at_cms_id())

        # Delete
        vsd_vm.verify_cannot_delete()

    @nuage_test.header()
    def test_server_on_neutron_network_matching_vsd_vm(self):
        # Create a network
        network = self._create_network(namestart='network-')
        subnet = self.create_subnet(network, namestart='subnet-')
        self.assertIsNotNone(subnet)  # dummy check to use local variable

        name = data_utils.rand_name('server-smoke')
        server = self._create_server(name, network)

        # get the neutron port, based on the servers MAC address
        # (expect only 1 interface)
        port_mac = server['addresses'][network['name']][0][
            'OS-EXT-IPS-MAC:mac_addr']
        ports_response = self.ports_client.list_ports(mac_address=port_mac)
        port = ports_response['ports'][0]

        if self.test_upgrade:
            vsd_vm = self.MatchingVsdVm(self, server).get_by_uuid()
            vsd_vm.has_parent_vm_interface(
                with_external_id=ExternalId(port['id']).at_cms_id())

            upgrade_script.do_run_upgrade_script()

        vsd_vm = self.MatchingVsdVm(self, server).get_by_external_id()
        vsd_vm.has_parent_vm_interface(ExternalId(port['id']).at_cms_id())

        # Delete
        vsd_vm.verify_cannot_delete()

    def create_vsd_dhcpmanaged_l2dom_template(self, **kwargs):
        params = {
            'DHCPManaged': True,
            'address': str(kwargs['cidr'].ip),
            'netmask': str(kwargs['cidr'].netmask),
            'gateway': kwargs['gateway']
        }
        vsd_l2dom_tmplt = self.nuage_client.create_l2domaintemplate(
            kwargs['name'] + '-template', extra_params=params)
        self.addCleanup(self.nuage_client.delete_l2domaintemplate,
                        vsd_l2dom_tmplt[0]['ID'])
        return vsd_l2dom_tmplt

    @nuage_test.header()
    def test_server_on_vsd_managed_network_matching_vsd_vm(self):
        net_name = data_utils.rand_name()
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2domain_templates = self.create_vsd_dhcpmanaged_l2dom_template(
            name=net_name, cidr=cidr, gateway='10.10.100.1')
        self.assertEqual(
            len(vsd_l2domain_templates), 1,
            "Failed to create vsd l2 domain template")

        vsd_l2domain_template = vsd_l2domain_templates[0]
        vsd_l2domains = self.nuage_client.create_l2domain(
            name=net_name, templateId=vsd_l2domain_template['ID'])
        self.assertEqual(
            len(vsd_l2domains), 1, "Failed to create vsd l2 domain")
        vsd_l2domain = vsd_l2domains[0]
        self.addCleanup(
            self.nuage_client.delete_l2domain, vsd_l2domain['ID'])

        network = self._create_network(namestart='network-')
        subnet_kwargs = {
            'name': network['name'],
            'cidr': '10.10.100.0/24',
            'gateway_ip': None,
            'network_id': network['id'],
            'nuagenet': vsd_l2domain['ID'],
            'net_partition': Topology.def_netpartition,
            'enable_dhcp': True,
            'ip_version': 4}

        subnet = self.subnets_client.create_subnet(**subnet_kwargs)
        self.assertIsNotNone(subnet)  # dummy check to use local variable

        name = data_utils.rand_name('server-smoke')
        server = self._create_server(name, network)

        # get the neutron port, based on the servers MAC address
        # (expect only 1 interface)
        port_mac = server['addresses'][network['name']][0][
            'OS-EXT-IPS-MAC:mac_addr']
        ports_response = self.ports_client.list_ports(mac_address=port_mac)
        port = ports_response['ports'][0]

        if self.test_upgrade:
            vsd_vm = self.MatchingVsdVm(self, server).get_by_uuid()
            vsd_vm.has_parent_vm_interface(
                with_external_id=ExternalId(port['id']).at_cms_id())

            upgrade_script.do_run_upgrade_script()

        vsd_vm = self.MatchingVsdVm(self, server).get_by_external_id()
        vsd_vm.has_parent_vm_interface(ExternalId(port['id']).at_cms_id())

        # Delete
        vsd_vm.verify_cannot_delete()

    @nuage_test.header()
    def test_server_on_neutron_port_in_vsd_managed_network_matching_vsd_vm(
            self):
        net_name = data_utils.rand_name()
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2domain_templates = self.create_vsd_dhcpmanaged_l2dom_template(
            name=net_name, cidr=cidr, gateway='10.10.100.1')
        self.assertEqual(
            len(vsd_l2domain_templates), 1,
            "Failed to create vsd l2 domain template")

        vsd_l2domain_template = vsd_l2domain_templates[0]
        vsd_l2domains = self.nuage_client.create_l2domain(
            name=net_name, templateId=vsd_l2domain_template['ID'])
        self.assertEqual(
            len(vsd_l2domains), 1, "Failed to create vsd l2 domain")
        vsd_l2domain = vsd_l2domains[0]
        self.addCleanup(
            self.nuage_client.delete_l2domain, vsd_l2domain['ID'])

        network = self._create_network(namestart='network-')
        subnet_kwargs = {
            'name': network['name'],
            'cidr': '10.10.100.0/24',
            'gateway_ip': None,
            'network_id': network['id'],
            'nuagenet': vsd_l2domain['ID'],
            'net_partition': Topology.def_netpartition,
            'enable_dhcp': True,
            'ip_version': 4}

        subnet = self.subnets_client.create_subnet(**subnet_kwargs)
        self.assertIsNotNone(subnet)  # dummy check to use local variable

        port = self.create_port(network['id'])

        name = data_utils.rand_name('server-smoke')
        server = self._create_server(name, network, port['id'])

        # get the neutron port, based on the servers MAC address
        # (expect only 1 interface)
        port_mac = server['addresses'][network['name']][0][
            'OS-EXT-IPS-MAC:mac_addr']
        ports_response = self.ports_client.list_ports(mac_address=port_mac)
        port = ports_response['ports'][0]

        if self.test_upgrade:
            vsd_vm = self.MatchingVsdVm(self, server).get_by_uuid()
            vsd_vm.has_parent_vm_interface(
                with_external_id=ExternalId(port['id']).at_cms_id())

            upgrade_script.do_run_upgrade_script()

        vsd_vm = self.MatchingVsdVm(self, server).get_by_external_id()
        vsd_vm.has_parent_vm_interface(ExternalId(port['id']).at_cms_id())

        # Delete
        vsd_vm.verify_cannot_delete()
