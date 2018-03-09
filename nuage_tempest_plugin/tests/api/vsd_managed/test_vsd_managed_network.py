# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
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

from netaddr import IPAddress
from netaddr import IPNetwork
import testtools

from tempest.api.compute import base as serv_base
from tempest.api.network import base
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.scenario import manager
from tempest.test import decorators

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES
from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.test import tags
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.lib.utils import data_utils as nuage_data_utils
import nuage_tempest_plugin.tests.api.test_netpartitions as test_netpartitions
from nuage_tempest_plugin.tests.api.vsd_managed \
    import base_vsd_managed_network as base_vsdman

CONF = Topology.get_conf()


@nuage_test.class_header(tags=[tags.VSD_MANAGED])
class VSDManagedTestNetworks(base_vsdman.BaseVSDManagedNetworksTest,
                             test_netpartitions.NetPartitionTestJSON,
                             manager.NetworkScenarioTest,
                             serv_base.BaseV2ComputeTest):

    def __init__(self, *args, **kwargs):
        super(VSDManagedTestNetworks, self).__init__(*args, **kwargs)
        if Topology.before_openstack('Newton'):
            self.failure_type = exceptions.ServerFault
        else:
            self.failure_type = exceptions.BadRequest

    @classmethod
    def get_server_ip_from_vsd(cls, vm_id):
        if Topology.within_ext_id_release():
            vm_details = cls.nuageclient.get_resource(
                constants.VM,
                filters='externalID',
                filter_value=cls.nuageclient.get_vsd_external_id(vm_id))[0]
        else:
            # the prehistory
            vm_details = cls.nuageclient.get_resource(constants.VM,
                                                      filters='UUID',
                                                      filter_value=vm_id)[0]
        interfaces = vm_details.get('interfaces')
        if interfaces:
            return interfaces[0]['IPAddress']

    def _create_vsd_shared_resource(self, managed=True, type=None):
        if managed:
            cidr, gateway, mask_bits = nuage_data_utils.gimme_a_cidr()
            return (self.create_vsd_managed_shared_resource(
                name=data_utils.rand_name('shared-managed'),
                netmask=str(cidr.netmask), address=str(cidr.ip),
                gateway=gateway, DHCPManaged=True, type=type),
                cidr, gateway, mask_bits)
        else:
            return self.create_vsd_managed_shared_resource(
                name=data_utils.rand_name('shared-unmanaged'), type='L2DOMAIN')

    def _verify_vm_ip(self, net_id, net_name):
        name = data_utils.rand_name('server-smoke')
        server = self._create_server(name, net_id)
        self.assertEqual(server.get('OS-EXT-STS:vm_state'), 'active')
        ip_addr_on_openstack = server['addresses'][net_name][0]['addr']
        ip_addr_on_vsd = self.get_server_ip_from_vsd(server['id'])
        return ip_addr_on_openstack == ip_addr_on_vsd

    def _create_server(self, name, network_id):
        return self.create_server(name=name,
                                  networks=[{'uuid': network_id}],
                                  wait_until='ACTIVE')

    def link_subnet_l2(self, cidr=None, mask_bits=None, dhcp_port=None,
                       dhcp_option_3=None,
                       pool=None, vsd_l2dom=None,
                       should_pass=True, create_server=False):
        # create l2domain on VSD
        name = data_utils.rand_name('l2domain-')
        cidr = cidr or IPNetwork('10.10.100.0/24')
        mask_bits = mask_bits or 24
        dhcp_port = dhcp_port or '10.10.100.1'

        if vsd_l2dom is None:
            vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
                name=name,
                cidr=cidr, gateway=dhcp_port)[0]
            vsd_l2dom = self.create_vsd_l2domain(
                name=name, tid=vsd_l2dom_tmplt['ID'])[0]
            self.assertEqual(vsd_l2dom['name'], name)
            if dhcp_option_3:
                self.nuageclient.create_dhcpoption_on_l2dom(
                    vsd_l2dom['ID'], 3, [dhcp_option_3])

        # network
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        # subnet
        kwargs = {
            'gateway': dhcp_option_3,
            'cidr': cidr,
            'mask_bits': mask_bits,
            'nuagenet': vsd_l2dom['ID'],
            'net_partition': Topology.def_netpartition
        }
        if pool:
            kwargs['allocation_pools'] = [pool]
        if should_pass:
            subnet = self.create_subnet(network, **kwargs)
            self.assertEqual(subnet['cidr'], str(cidr))
            sub_pool = subnet['allocation_pools'][0]
            if pool:
                self.assertEqual(sub_pool['start'], pool['start'])
                self.assertEqual(sub_pool['end'], pool['end'])
            else:
                if dhcp_option_3 and dhcp_option_3 == '10.10.100.2':
                    self.assertEqual(2, len(subnet['allocation_pools']))
                    # today we split the allocation pool ...
                    # apparently the pools order can vary ...
                    # so allow for both order permutations ...
                    # TODO(Kris) dig deeper why order is random
                    other_sub_pool = subnet['allocation_pools'][1]
                    if sub_pool['start'] != str(cidr[1]):
                        # swap
                        tmp = other_sub_pool
                        other_sub_pool = sub_pool
                        sub_pool = tmp

                    self.assertEqual(sub_pool['start'], str(cidr[1]))
                    self.assertEqual(sub_pool['end'], str(cidr[1]))

                    self.assertEqual(other_sub_pool['start'], str(cidr[3]))
                    self.assertEqual(other_sub_pool['end'], str(cidr[-2]))

                elif dhcp_option_3 and dhcp_option_3 != '10.10.100.2':
                    raise NotImplementedError  # volunteers, feel free

                else:
                    self.assertEqual(sub_pool['start'], str(cidr[1]))
                    self.assertEqual(sub_pool['end'], str(cidr[-2]))

            if create_server:
                self.assertTrue(self._verify_vm_ip(network['id'], net_name))

        else:
            self.assertRaises(self.failure_type, self.create_subnet,
                              network, **kwargs)

        return vsd_l2dom

    @nuage_test.header(tags=['smoke'])
    def test_link_subnet_l2_no_gw(self):
        self.link_subnet_l2(create_server=True)

        # test recreating a new (identical) vsd mgd sub
        self.link_subnet_l2()

    @nuage_test.header(tags=['smoke'])
    def test_link_subnet_l2_with_gw(self):
        self.link_subnet_l2(dhcp_option_3='10.10.100.2', create_server=True)

    def double_link_subnet_l2(
            self, cidr=None, mask_bits=None, dhcp_port=None,
            dhcp_option_3=None,
            pool1=None, pool2=None,
            should_pass=True):

        cidr = cidr or IPNetwork('10.10.100.0/24')
        mask_bits = mask_bits or 24
        dhcp_port = dhcp_port or '10.10.100.1'

        # 1st net
        vsd_l2dom = self.link_subnet_l2(cidr, mask_bits, dhcp_port,
                                        dhcp_option_3, pool1)

        # 2nd net
        self.link_subnet_l2(cidr, mask_bits, dhcp_port, dhcp_option_3, pool2,
                            vsd_l2dom=vsd_l2dom, should_pass=should_pass)

    @testtools.skipIf(not NUAGE_FEATURES.multi_linked_vsd_mgd_subnets,
                      'Multi-linked VSD mgd subnets are not supported in this '
                      'release')
    @nuage_test.header(tags=['smoke'])
    def test_double_link_subnet_l2_no_gw_no_allocation_pools(self):
        self.double_link_subnet_l2(should_pass=False)

    @testtools.skipIf(not NUAGE_FEATURES.multi_linked_vsd_mgd_subnets,
                      'Multi-linked VSD mgd subnets are not supported in this '
                      'release')
    @nuage_test.header(tags=['smoke'])
    def test_double_link_subnet_l2_no_gw_non_disjunct_allocation_pools(self):
        self.double_link_subnet_l2(
            pool1={'start': '10.10.100.100', 'end': '10.10.100.110'},
            pool2={'start': '10.10.100.110', 'end': '10.10.100.120'},
            should_pass=False)

    @testtools.skipIf(not NUAGE_FEATURES.multi_linked_vsd_mgd_subnets,
                      'Multi-linked VSD mgd subnets are not supported in this '
                      'release')
    @nuage_test.header(tags=['smoke'])
    def test_double_link_subnet_l2_no_gw_disjunct_allocation_pools(self):
        self.double_link_subnet_l2(
            pool1={'start': '10.10.100.100', 'end': '10.10.100.109'},
            pool2={'start': '10.10.100.110', 'end': '10.10.100.120'},
            should_pass=True)

    @testtools.skipIf(not NUAGE_FEATURES.multi_linked_vsd_mgd_subnets,
                      'Multi-linked VSD mgd subnets are not supported in this '
                      'release')
    @nuage_test.header(tags=['smoke'])
    def test_double_link_subnet_l2_with_gw_disjunct_allocation_pools(self):
        self.double_link_subnet_l2(
            dhcp_option_3='10.10.100.2',
            pool1={'start': '10.10.100.100', 'end': '10.10.100.109'},
            pool2={'start': '10.10.100.110', 'end': '10.10.100.120'},
            should_pass=True)

    @nuage_test.header(tags=['smoke'])
    def test_link_vsd_managed_shared_subnet_l2(self):
        vsd_managed_shared_l2dom, cidr, _, mask_bits = \
            self._create_vsd_shared_resource(type='L2DOMAIN')
        name = data_utils.rand_name('l2domain-with-shared')
        vsd_l2dom_tmplt = self.create_vsd_dhcpunmanaged_l2dom_template(
            name=name)
        extra_params = {
            'associatedSharedNetworkResourceID': vsd_managed_shared_l2dom['ID']
        }
        vsd_l2dom_with_shared_managed = self.create_vsd_l2domain(
            name=name,
            tid=vsd_l2dom_tmplt[0]['ID'],
            extra_params=extra_params)
        self.assertEqual(vsd_l2dom_with_shared_managed[0]['name'], name)
        self.assertEqual(
            (vsd_l2dom_with_shared_managed[0]
             ['associatedSharedNetworkResourceID']),
            vsd_managed_shared_l2dom['ID'])

        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('sharedl2-network-')
        network = self.create_network(network_name=net_name)
        subnet = self.create_subnet(
            network,
            gateway=None,
            cidr=cidr,
            mask_bits=mask_bits,
            nuagenet=vsd_l2dom_with_shared_managed[0]['ID'],
            net_partition=Topology.def_netpartition)
        self.assertEqual(
            str(IPNetwork(subnet['cidr']).ip),
            vsd_managed_shared_l2dom['address'])
        self.assertIsNone(subnet['gateway_ip'])
        self.assertEqual(
            subnet['enable_dhcp'],
            vsd_managed_shared_l2dom['DHCPManaged'])
        self.assertTrue(self._verify_vm_ip(network['id'], net_name))

    @nuage_test.header(tags=['smoke'])
    def test_link_vsd_shared_subnet_l3(self):
        vsd_shared_l3dom_subnet, cidr, gateway, mask_bits = \
            self._create_vsd_shared_resource(type='PUBLIC')
        name = data_utils.rand_name('l3dom-with-shared')
        vsd_l3dom_tmplt = self.create_vsd_l3dom_template(
            name=name)
        vsd_l3dom = self.create_vsd_l3domain(name=name,
                                             tid=vsd_l3dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l3dom[0]['name'], name)
        zone_name = data_utils.rand_name('Public-zone-')
        extra_params = {'publicZone': True}
        vsd_zone = self.create_vsd_zone(name=zone_name,
                                        domain_id=vsd_l3dom[0]['ID'],
                                        extra_params=extra_params)

        name = data_utils.rand_name('l3domain-with-shared')
        data = {
            'name': name,
            'associatedSharedNetworkResourceID': vsd_shared_l3dom_subnet['ID']
        }
        resource = '/zones/' + vsd_zone[0]['ID'] + '/subnets'
        vsd_l3dom_subnet = self.nuageclient.restproxy.rest_call(
            'POST', resource, data)
        vsd_l3_dom_public_subnet = vsd_l3dom_subnet.data[0]
        self.assertEqual(vsd_l3_dom_public_subnet['name'], name)
        self.assertEqual(
            vsd_l3_dom_public_subnet['associatedSharedNetworkResourceID'],
            vsd_shared_l3dom_subnet['ID'])

        # create subnet on OS with nuagenet param set to l3domain UUID
        net_name = data_utils.rand_name('shared-l3-network-')
        network = self.create_network(network_name=net_name)
        subnet = self.create_subnet(
            network, cidr=cidr, mask_bits=mask_bits,
            nuagenet=vsd_l3_dom_public_subnet['ID'],
            net_partition=Topology.def_netpartition)
        self.assertEqual(
            str(IPNetwork(subnet['cidr']).ip),
            vsd_shared_l3dom_subnet['address'])
        self.assertEqual(subnet['gateway_ip'], gateway)
        self.assertEqual(
            subnet['enable_dhcp'],
            vsd_shared_l3dom_subnet['DHCPManaged'])
        self.assertTrue(self._verify_vm_ip(network['id'], net_name))

    @nuage_test.header(tags=['smoke'])
    def test_link_vsd_unmanaged_shared_subnet_l2(self):
        vsd_unmanaged_shared_l2dom = self._create_vsd_shared_resource(
            managed=False)
        name = data_utils.rand_name('l2domain-with-shared')
        vsd_l2dom_tmplt = self.create_vsd_dhcpunmanaged_l2dom_template(
            name=name)
        extra_params = {
            'associatedSharedNetwork'
            'ResourceID': vsd_unmanaged_shared_l2dom['ID']
        }
        vsd_l2dom_with_shared_unmanaged = self.create_vsd_l2domain(
            name=name,
            tid=vsd_l2dom_tmplt[0]['ID'],
            extra_params=extra_params)

        self.assertEqual(vsd_l2dom_with_shared_unmanaged[0]['name'], name)
        self.assertEqual(
            (vsd_l2dom_with_shared_unmanaged[0]
             ['associatedSharedNetworkResourceID']),
            vsd_unmanaged_shared_l2dom['ID'])

        net_name = data_utils.rand_name('unmnaged-shared-l2-network-')
        network = self.create_network(network_name=net_name)
        cidr = IPNetwork('10.20.30.0/16')  # whatever
        subnet = self.create_subnet(
            network,
            gateway=None,
            cidr=cidr, mask_bits=16,
            nuagenet=vsd_l2dom_with_shared_unmanaged[0]['ID'],
            net_partition=Topology.def_netpartition,
            enable_dhcp=False)
        self.assertIsNone(subnet['gateway_ip'])
        self.assertEqual(
            subnet['enable_dhcp'],
            vsd_unmanaged_shared_l2dom['DHCPManaged'])

    @nuage_test.header(tags=['smoke'])
    def test_link_subnet_without_gateway_l2(self):
        # create l2domain on VSD
        pass

    @nuage_test.header(tags=['smoke'])
    def test_link_subnet_with_incorrect_gateway_l2(self):
        pass

    @nuage_test.header(tags=['smoke'])
    def test_link_subnet_wo_netpartition_l2(self):
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        self.assertRaises(self.failure_type,
                          self.create_subnet,
                          network,
                          cidr=IPNetwork('10.10.100.0/24'),
                          mask_bits=24,
                          nuagenet=data_utils.rand_uuid())

    @nuage_test.header(tags=['smoke'])
    def test_link_subnet_with_unknown_netpartition_l2(self):
        # netpartition does not exist in neutron DB
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        self.assertRaises(self.failure_type,
                          self.create_subnet,
                          network,
                          cidr=IPNetwork('10.10.100.0/24'),
                          mask_bits=24,
                          nuagenet=data_utils.rand_uuid(),
                          net_partition=data_utils.rand_name())

    @decorators.attr(type='smoke')
    def test_link_subnet_with_incorrect_netpartition_l2(self):
        # netpartition does exist in neutron DB but it is not
        # where the l2domain is created
        # create l2domain on VSD in default net-partition
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name, cidr=cidr, gateway='10.10.100.1')
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        netpart_name = data_utils.rand_name('netpart-')
        netpart = self.create_netpartition(netpart_name)
        self.assertRaises(self.failure_type,
                          self.create_subnet,
                          network,
                          cidr=cidr,
                          mask_bits=24,
                          nuagenet=vsd_l2dom[0]['ID'],
                          net_partition=netpart['name'])

    @nuage_test.header(tags=['smoke'])
    def test_link_subnet_with_incorrect_cidr_l2(self):
        # netpartition does exist in neutron DB but it is not
        # where the l2domain is created
        # create l2domain on VSD in default net-partition
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name, cidr=cidr, gateway='10.10.100.1')
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        self.assertRaises(
            self.failure_type,
            self.create_subnet,
            network,
            cidr=IPNetwork('10.10.200.0/24'),
            mask_bits=24,
            nuagenet=vsd_l2dom[0]['ID'],
            net_partition=Topology.def_netpartition)

    @nuage_test.header(tags=['smoke'])
    def test_link_subnet_with_disable_dhcp_unmanaged_l2(self):
        # create l2domain on VSD
        name = data_utils.rand_name('l2domain-')
        vsd_l2dom_tmplt = self.create_vsd_dhcpunmanaged_l2dom_template(
            name=name)
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l2dom[0][u'name'], name)
        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        subnet = self.create_subnet(
            network,
            gateway=None,
            cidr=IPNetwork('10.10.100.0/24'),
            mask_bits=24, nuagenet=vsd_l2dom[0]['ID'],
            net_partition=Topology.def_netpartition,
            enable_dhcp=False)
        self.assertEqual(subnet['enable_dhcp'], False)

    @nuage_test.header(tags=['smoke'])
    def test_link_subnet_with_enable_dhcp_unmanaged_l2(self):
        # create unmanaged l2domain on VSD
        name = data_utils.rand_name('l2domain-')
        vsd_l2dom_tmplt = self.create_vsd_dhcpunmanaged_l2dom_template(
            name=name)
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l2dom[0][u'name'], name)
        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        # Try creating subnet with enable_dhcp=True (default)
        self.assertRaises(
            self.failure_type,
            self.create_subnet,
            network,
            cidr=IPNetwork('10.10.100.0/24'),
            mask_bits=24, nuagenet=vsd_l2dom[0]['ID'],
            net_partition=Topology.def_netpartition)

    @nuage_test.header(tags=['smoke'])
    def test_link_subnet_with_enable_dhcp_managed_l2(self):
        # This is same as test_link_subnet_l2
        # Only difference being enable_dhcp is explicitly set to True
        # create l2domain on VSD
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name, cidr=cidr, gateway='10.10.100.1')
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l2dom[0][u'name'], name)
        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        subnet = self.create_subnet(
            network, gateway=None,
            cidr=cidr, mask_bits=24, nuagenet=vsd_l2dom[0]['ID'],
            net_partition=Topology.def_netpartition,
            enable_dhcp=True)
        self.assertEqual(subnet['cidr'], str(cidr))

    @nuage_test.header(tags=['smoke'])
    def test_link_subnet_with_disable_dhcp_managed_l2(self):
        # create managed l2domain on VSD
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name, cidr=cidr, gateway='10.10.100.1')
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l2dom[0][u'name'], name)
        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        self.assertRaises(
            self.failure_type,
            self.create_subnet,
            network,
            cidr=cidr, mask_bits=24, nuagenet=vsd_l2dom[0]['ID'],
            net_partition=Topology.def_netpartition,
            enable_dhcp=False)

    @nuage_test.header(tags=['smoke'])
    def test_link_subnet_l3(self):
        # create l3domain on VSD
        name = data_utils.rand_name('l3domain-')
        vsd_l3dom_tmplt = self.create_vsd_l3dom_template(name=name)
        vsd_l3dom = self.create_vsd_l3domain(name=name,
                                             tid=vsd_l3dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l3dom[0]['name'], name)
        zone_name = data_utils.rand_name('l3dom-zone-')
        vsd_zone = self.create_vsd_zone(name=zone_name,
                                        domain_id=vsd_l3dom[0]['ID'])
        self.assertEqual(vsd_zone[0]['name'], zone_name)
        sub_name = data_utils.rand_name('l3dom-sub-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_domain_subnet = self.create_vsd_l3domain_subnet(
            name=sub_name,
            zone_id=vsd_zone[0]['ID'],
            cidr=cidr,
            gateway='10.10.100.1')
        self.assertEqual(vsd_domain_subnet[0]['name'], sub_name)
        # create subnet on OS with nuagenet param set to subnet UUID
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        subnet = self.create_subnet(
            network,
            cidr=cidr, mask_bits=24, nuagenet=vsd_domain_subnet[0]['ID'],
            net_partition=Topology.def_netpartition)
        self.assertEqual(subnet['cidr'], str(cidr))
        self.assertTrue(self._verify_vm_ip(network['id'], net_name))

    @decorators.attr(type='smoke')
    def test_link_subnet_with_incorrect_gateway_l3(self):
        # create l3domain on VSD
        name = data_utils.rand_name('l3domain-')
        vsd_l3dom_tmplt = self.create_vsd_l3dom_template(name=name)
        vsd_l3dom = self.create_vsd_l3domain(name=name,
                                             tid=vsd_l3dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l3dom[0]['name'], name)
        zone_name = data_utils.rand_name('l3dom-zone-')
        vsd_zone = self.create_vsd_zone(name=zone_name,
                                        domain_id=vsd_l3dom[0]['ID'])
        self.assertEqual(vsd_zone[0]['name'], zone_name)
        sub_name = data_utils.rand_name('l3dom-sub-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_domain_subnet = self.create_vsd_l3domain_subnet(
            name=sub_name,
            zone_id=vsd_zone[0]['ID'],
            cidr=cidr,
            gateway='10.10.100.1')[0]
        self.assertEqual(vsd_domain_subnet['name'], sub_name)

        # create subnet on OS with nuagenet param set to subnet UUID
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        if (Topology.from_openstack('Newton') and Topology.is_ml2 and
                Topology.before_nuage('5.2')):
            subnet = self.create_subnet(
                network,
                cidr=IPNetwork('10.10.100.0/24'),
                mask_bits=24, nuagenet=vsd_domain_subnet['ID'],
                gateway='10.10.100.5',
                net_partition=Topology.def_netpartition)
            self.assertEqual(subnet['cidr'], str(cidr))
            self.assertTrue(self._verify_vm_ip(network['id'], net_name))
        else:
            # since 5.2.2 we correctly check gw
            self.assertRaises(
                self.failure_type,
                self.create_subnet,
                network,
                cidr=IPNetwork('10.10.100.0/24'),
                mask_bits=24, nuagenet=vsd_domain_subnet['ID'],
                gateway='10.10.100.5',
                net_partition=Topology.def_netpartition)

    # Originally part of _m2 suite

    @nuage_test.header(tags=['smoke'])
    def test_create_port_subnet_l2_managed(self):
        net_name = data_utils.rand_name()
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=net_name, cidr=cidr, gateway='10.10.100.1')
        vsd_l2dom = self.create_vsd_l2domain(name=net_name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])[0]

        network = self.create_network(network_name=net_name)
        subnet = self.create_subnet(
            network, gateway=None, cidr=cidr,
            mask_bits=24, nuagenet=vsd_l2dom['ID'],
            net_partition=Topology.def_netpartition,
            enable_dhcp=True)
        self.assertIsNotNone(subnet, "Subnet should be created.")

        port = self.create_port(network)
        nuage_vport = self.nuageclient.get_vport(constants.L2_DOMAIN,
                                                 vsd_l2dom['ID'],
                                                 filters='externalID',
                                                 filter_value=port['id'])
        self.assertIsNotNone(nuage_vport, "vport should be created.")

        # External ID tests
        vsd_l2domains = self.nuageclient.get_l2domain(
            filters='ID', filter_value=vsd_l2dom['ID'])
        self.assertEqual(len(vsd_l2domains), 1,
                         "Failed to get vsd l2 domain")
        vsd_l2domain = vsd_l2domains[0]
        self.assertIsNone(vsd_l2domain['externalID'],
                          "Should not get an External ID")

        # When I delete the OS linked network with the port
        # Then I get an exception
        self.assertRaisesRegex(exceptions.Conflict,
                               "There are one or more ports still in use",
                               self.networks_client.delete_network,
                               network['id'])

        # When I delete the OS linked subnet after deletion of the port
        self.ports_client.delete_port(port['id'])

        # Then the vport on the VSD is also deleted
        nuage_vport = self.nuageclient.get_vport(constants.L2_DOMAIN,
                                                 vsd_l2dom['ID'],
                                                 filters='externalID',
                                                 filter_value=port['id'])
        self.assertEqual('', nuage_vport, "vport should be deleted.")

        # Then I can delete the network
        self.networks_client.delete_network(network['id'])

        # Then the VSD managed network is still there
        vsd_l2domains = self.nuageclient.get_l2domain(
            filters='ID', filter_value=vsd_l2dom['ID'])
        self.assertEqual(len(vsd_l2domains), 1, "Failed to get vsd l2 domain")

    # HP - Unica scenario with DHCP-options defined in VSD
    @nuage_test.header(tags=['smoke'])
    def test_link_vsd_shared_subnet_l3_with_dhcp_option(self):
        vsd_shared_l3dom_subnet, cidr, gateway, mask_bits = \
            self._create_vsd_shared_resource(type='PUBLIC')
        self.nuageclient.create_dhcpoption_on_shared(
            vsd_shared_l3dom_subnet['ID'], '03',  # TODO(Kris) bad '03'?
            [str(IPAddress(cidr) + 2)])

        name = data_utils.rand_name('l3dom-with-shared')
        vsd_l3dom_tmplt = self.create_vsd_l3dom_template(name=name)
        vsd_l3dom = self.create_vsd_l3domain(name=name,
                                             tid=vsd_l3dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l3dom[0]['name'], name)
        zone_name = data_utils.rand_name('Public-zone-')
        extra_params = {'publicZone': True}
        vsd_zone = self.create_vsd_zone(name=zone_name,
                                        domain_id=vsd_l3dom[0]['ID'],
                                        extra_params=extra_params)

        name = data_utils.rand_name('l3domain-with-shared')
        data = {
            'name': name,
            'associatedSharedNetworkResourceID': vsd_shared_l3dom_subnet['ID']
        }
        resource = '/zones/' + vsd_zone[0]['ID'] + '/subnets'
        vsd_l3dom_subnet = self.nuageclient.restproxy.rest_call(
            'POST', resource, data)
        vsd_l3_dom_public_subnet = vsd_l3dom_subnet.data[0]
        self.assertEqual(vsd_l3_dom_public_subnet['name'], name)
        self.assertEqual(
            vsd_l3_dom_public_subnet['associatedSharedNetworkResourceID'],
            vsd_shared_l3dom_subnet['ID'])

        # create subnet on OS with nuagenet param set to l3domain UUID
        net_name = data_utils.rand_name('shared-l3-network-')
        network = self.create_network(network_name=net_name)
        subnet = self.create_subnet(
            network, cidr=cidr, mask_bits=mask_bits,
            nuagenet=vsd_l3_dom_public_subnet['ID'],
            net_partition=Topology.def_netpartition)
        self.assertEqual(
            str(IPNetwork(subnet['cidr']).ip),
            vsd_shared_l3dom_subnet['address'])
        self.assertEqual(subnet['gateway_ip'], gateway)
        self.assertEqual(
            subnet['enable_dhcp'],
            vsd_shared_l3dom_subnet['DHCPManaged'])
        self.assertTrue(self._verify_vm_ip(network['id'], net_name))


class VSDManagedAdminTestNetworks(base.BaseAdminNetworkTest):
    @decorators.attr(type='smoke')
    def test_link_subnet_on_provider_net_l2(self):
        pass

    @decorators.attr(type='smoke')
    def test_link_subnet_on_external_net_l2(self):
        self.assertRaises(
            exceptions.BadRequest,
            self.admin_subnets_client.create_subnet,
            network_id=CONF.network.public_network_id,
            cidr='10.10.100.0/24',
            ip_version=self._ip_version,
            net_partition=Topology.def_netpartition,
            nuagenet=data_utils.rand_uuid())
