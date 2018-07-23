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

from tempest.api.network import base
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.test import tags
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.lib.utils import data_utils as nuage_data_utils

from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON
from nuage_tempest_plugin.tests.api.vsd_managed.base_vsd_managed_networks \
    import BaseVSDManagedNetwork

CONF = Topology.get_conf()


@nuage_test.class_header(tags=[tags.VSD_MANAGED])
class VSDManagedTestNetworks(BaseVSDManagedNetwork):

    def __init__(self, *args, **kwargs):
        super(VSDManagedTestNetworks, self).__init__(*args, **kwargs)
        self.failure_type = exceptions.BadRequest

    @classmethod
    def setup_clients(cls):
        super(VSDManagedTestNetworks, cls).setup_clients()
        cls.client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)

    @classmethod
    def setUpClass(cls):
        super(VSDManagedTestNetworks, cls).setUpClass()
        cls.net_partitions = []

    @classmethod
    def resource_cleanup(cls):
        super(VSDManagedTestNetworks, cls).resource_cleanup()
        for netpartition in cls.net_partitions:
            cls.client.delete_netpartition(netpartition['id'])

    def _create_vsd_shared_resource(self, managed=True, type=None):
        """_create_vsd_shared_resource

        :rtype: dict
        """
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

    def _create_and_verify_vm(self, network):
        name = data_utils.rand_name('server-smoke')
        server = self.create_tenant_server(name=name,
                                           networks=[network])
        ip_addr_on_openstack = server.get_server_details()['addresses'][
            network['name']][0]['addr']
        ip_addr_on_vsd = self.get_server_ip_from_vsd(server.id())
        return ip_addr_on_openstack == ip_addr_on_vsd

    @classmethod
    def create_netpartition(cls, np_name=None):
        """Wrapper utility that returns a test network."""
        np_name = np_name or data_utils.rand_name('tempest-np-')

        body = cls.client.create_netpartition(np_name)
        netpartition = body['net_partition']
        cls.net_partitions.append(netpartition)
        return netpartition

    @decorators.attr(type='smoke')
    def test_create_list_verify_delete_netpartition(self):
        name = data_utils.rand_name('tempest-np')
        body = self.client.create_netpartition(name)
        self.assertEqual('201', body.response['status'])
        netpart = body['net_partition']
        self.assertEqual(name, netpart['name'])
        if Topology.within_ext_id_release():
            net_partition = self.nuage_client.get_global_resource(
                resource=constants.NET_PARTITION,
                filters='externalID',
                filter_value=netpart['id'] + '@openstack')
            self.assertEqual(name, net_partition[0]['name'])
            default_l2dom_template = self.nuage_client.get_resource(
                resource=constants.L2_DOMAIN_TEMPLATE,
                filters='externalID',
                filter_value=netpart['id'] + '@openstack',
                netpart_name=name)
            self.assertIsNot(default_l2dom_template, "", "Default L2Domain "
                                                         "Template Not Found")
            default_dom_template = self.nuage_client.get_resource(
                resource=constants.DOMAIN_TEMPLATE,
                filters='externalID',
                filter_value=netpart['id'] + '@openstack',
                netpart_name=name)
            self.assertIsNot(default_dom_template, "", "Default Domain "
                                                       "Template Not Found")
            zone_templates = self.nuage_client.get_child_resource(
                resource=constants.DOMAIN_TEMPLATE,
                resource_id=default_dom_template[0]['ID'],
                child_resource=constants.ZONE_TEMPLATE,
                filters='externalID',
                filter_value=netpart['id'] + '@openstack')
            self.assertEqual(2, len(zone_templates))
        body = self.client.list_netpartition()
        netpartition_idlist = list()
        netpartition_namelist = list()
        for netpartition in body['net_partitions']:
            netpartition_idlist.append(netpartition['id'])
            netpartition_namelist.append(netpartition['name'])
        self.assertIn(netpart['id'], netpartition_idlist)
        self.assertIn(netpart['name'], netpartition_namelist)
        body = self.client.delete_netpartition(netpart['id'])
        self.assertEqual('204', body.response['status'])

    def link_subnet_l2(self, cidr=None, mask_bits=None, dhcp_port=None,
                       dhcp_option_3=None,
                       pool=None, vsd_l2dom=None,
                       net_partition=None,
                       should_pass=True, create_server=False, network=None):

        def verify_subnet_info(i_subnet, i_vsd_l2dom, i_cidr, i_pool,
                               i_dhcp_option_3):
            self.assertEqual(i_subnet['cidr'], str(i_cidr))
            # self.assertEqual(i_subnet['vsd_managed'], True)
            # self.assertEqual(i_subnet['nuagenet'], i_vsd_l2dom['ID'])
            sub_pool = i_subnet['allocation_pools'][0]
            if i_pool:
                self.assertEqual(sub_pool['start'], i_pool['start'])
                self.assertEqual(sub_pool['end'], i_pool['end'])
            else:
                if i_dhcp_option_3 and i_dhcp_option_3 == '10.10.100.2':
                    self.assertEqual(2, len(i_subnet['allocation_pools']))
                    # today we split the allocation pool ...
                    # apparently the pools order can vary ...
                    # so allow for both order permutations ...
                    # TODO(Kris) dig deeper why order is random
                    other_sub_pool = i_subnet['allocation_pools'][1]
                    if sub_pool['start'] != str(i_cidr[1]):
                        # swap
                        tmp = other_sub_pool
                        other_sub_pool = sub_pool
                        sub_pool = tmp

                    self.assertEqual(sub_pool['start'], str(i_cidr[1]))
                    self.assertEqual(sub_pool['end'], str(i_cidr[1]))

                    self.assertEqual(other_sub_pool['start'], str(i_cidr[3]))
                    self.assertEqual(other_sub_pool['end'], str(i_cidr[-2]))

                elif i_dhcp_option_3 and i_dhcp_option_3 != '10.10.100.2':
                    raise NotImplementedError  # volunteers, feel free

                else:
                    self.assertEqual(sub_pool['start'], str(i_cidr[1]))
                    self.assertEqual(sub_pool['end'], str(i_cidr[-2]))

        # create l2domain on VSD
        name = data_utils.rand_name('l2domain-')
        cidr = cidr or IPNetwork('10.10.100.0/24')
        mask_bits = mask_bits or 24
        dhcp_port = dhcp_port or '10.10.100.1'

        if vsd_l2dom is None:
            vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
                netpart_name=net_partition['name'] if net_partition else None,
                name=name, cidr=cidr, gateway=dhcp_port)[0]
            vsd_l2dom = self.create_vsd_l2domain(
                netpart_name=net_partition['name'] if net_partition else None,
                name=name, tid=vsd_l2dom_tmplt['ID'])[0]
            self.assertEqual(vsd_l2dom['name'], name)
            if dhcp_option_3:
                self.nuage_client.create_dhcpoption_on_l2dom(
                    vsd_l2dom['ID'], 3, [dhcp_option_3])

        # network
        if not network:
            net_name = data_utils.rand_name('network-')
            network = self.create_network(network_name=net_name)

        # subnet
        kwargs = {
            'gateway': dhcp_option_3,
            'cidr': cidr,
            'mask_bits': mask_bits,
            'nuagenet': vsd_l2dom['ID'],
            'net_partition': (net_partition['id'] if net_partition
                              else Topology.def_netpartition)
        }
        if pool:
            kwargs['allocation_pools'] = [pool]
        if should_pass:
            subnet = self.create_subnet(network, **kwargs)
            verify_subnet_info(subnet, vsd_l2dom, cidr, pool, dhcp_option_3)

            # now refetch the subnet and verify again
            subnet = self.client.show_subnet(subnet['id'])['subnet']
            verify_subnet_info(subnet, vsd_l2dom, cidr, pool, dhcp_option_3)

            if create_server:
                self.assertTrue(self._create_and_verify_vm(network))
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

    # @nuage_test.header(tags=['smoke'])
    # def test_link_subnet_l2_using_preconfigured_netpartition_id(self):
    #     np = self.create_netpartition()
    #     self.link_subnet_l2(net_partition=np)

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

    @nuage_test.header(tags=['smoke'])
    def test_double_link_subnet_l2_no_gw_no_allocation_pools(self):
        self.double_link_subnet_l2(should_pass=False)

    @nuage_test.header(tags=['smoke'])
    def test_double_link_subnet_l2_no_gw_non_disjunct_allocation_pools(self):
        self.double_link_subnet_l2(
            pool1={'start': '10.10.100.100', 'end': '10.10.100.110'},
            pool2={'start': '10.10.100.110', 'end': '10.10.100.120'},
            should_pass=False)

    @nuage_test.header(tags=['smoke'])
    def test_double_link_subnet_l2_no_gw_disjunct_allocation_pools(self):
        self.double_link_subnet_l2(
            pool1={'start': '10.10.100.100', 'end': '10.10.100.109'},
            pool2={'start': '10.10.100.110', 'end': '10.10.100.120'},
            should_pass=True)

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
        self.assertTrue(self._create_and_verify_vm(network))

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

        self.assertEqual(vsd_l2dom[0]['name'], name)
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

        self.assertEqual(vsd_l2dom[0]['name'], name)
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

        self.assertEqual(vsd_l2dom[0]['name'], name)
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

        self.assertEqual(vsd_l2dom[0]['name'], name)
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

    def link_subnet_l3(self, net_partition=None):
        # create l3domain on VSD
        name = data_utils.rand_name('l3domain-')
        vsd_l3dom_tmplt = self.create_vsd_l3dom_template(
            name=name,
            netpart_name=net_partition['name'] if net_partition else None)
        vsd_l3dom = self.create_vsd_l3domain(
            name=name, tid=vsd_l3dom_tmplt[0]['ID'],
            netpart_name=net_partition['name'] if net_partition else None)

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
            net_partition=(net_partition['id'] if net_partition
                           else Topology.def_netpartition))
        self.assertEqual(subnet['cidr'], str(cidr))
        # self.assertEqual(subnet['vsd_managed'], True)
        # self.assertEqual(subnet['nuagenet'], vsd_domain_subnet[0]['ID'])

        # now refetch the subnet and verify again
        subnet = self.client.show_subnet(subnet['id'])['subnet']
        self.assertEqual(subnet['cidr'], str(cidr))
        # self.assertEqual(subnet['vsd_managed'], True)
        # self.assertEqual(subnet['nuagenet'], vsd_domain_subnet[0]['ID'])

        self.assertTrue(self._create_and_verify_vm(network))

    @nuage_test.header(tags=['smoke'])
    def test_link_subnet_l3(self):
        self.link_subnet_l3()

    # @nuage_test.header(tags=['smoke'])
    # def test_link_subnet_l3_using_preconfigured_netpartition_id(self):
    #     np = self.create_netpartition()
    #     self.link_subnet_l3(net_partition=np)

    @decorators.attr(type='smoke')
    def test_link_subnet_with_incorrect_gw_l3(self):
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
            self.assertTrue(self._create_and_verify_vm(network))
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
        vsd_l3dom_subnet = self.nuage_client.restproxy.rest_call(
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
        self.assertTrue(self._create_and_verify_vm(network))

    # Originally part of _m2 suite

    @nuage_test.header(tags=['smoke'])
    def test_create_port_subnet_l2_managed(self):
        net_name = data_utils.rand_name()
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=net_name, cidr=cidr, gateway='10.10.100.1')
        vsd_l2dom = self.create_vsd_l2domain(name=net_name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])[0]

        network = self.create_network(network_name=net_name, cleanup=False)
        self.create_subnet(
            network, gateway=None, cidr=cidr,
            mask_bits=24, nuagenet=vsd_l2dom['ID'],
            net_partition=Topology.def_netpartition,
            enable_dhcp=True, cleanup=False)

        port = self.create_port(network, cleanup=False)
        nuage_vport = self.nuage_client.get_vport(constants.L2_DOMAIN,
                                                  vsd_l2dom['ID'],
                                                  filters='externalID',
                                                  filter_value=port['id'])
        self.assertIsNotNone(nuage_vport, "vport should be created.")

        # External ID tests
        vsd_l2domains = self.nuage_client.get_l2domain(
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
        nuage_vport = self.nuage_client.get_vport(constants.L2_DOMAIN,
                                                  vsd_l2dom['ID'],
                                                  filters='externalID',
                                                  filter_value=port['id'])
        self.assertEqual('', nuage_vport, "vport should be deleted.")

        # Then I can delete the network
        self.networks_client.delete_network(network['id'])

        # Then the VSD managed network is still there
        vsd_l2domains = self.nuage_client.get_l2domain(
            filters='ID', filter_value=vsd_l2dom['ID'])
        self.assertEqual(len(vsd_l2domains), 1, "Failed to get vsd l2 domain")

    # HP - Unica scenario with DHCP-options defined in VSD
    @nuage_test.header(tags=['smoke'])
    def test_link_vsd_shared_subnet_l3_with_dhcp_option(self):
        vsd_shared_l3dom_subnet, cidr, gateway, mask_bits = \
            self._create_vsd_shared_resource(type='PUBLIC')
        self.nuage_client.create_dhcpoption_on_shared(
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
        vsd_l3dom_subnet = self.nuage_client.restproxy.rest_call(
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
        self.assertTrue(self._create_and_verify_vm(network))

    # Telenor scenario with multiple vsd managed subnets in a network
    @nuage_test.header(tags=['smoke'])
    def test_link_multi_l2domain_to_network(self):
        net_name = data_utils.rand_name('shared-l3-network-')
        network = self.create_network(network_name=net_name)

        self.link_subnet_l2(network=network,
                            cidr=IPNetwork('10.0.0.0/24'),
                            dhcp_port='10.0.0.1')
        if not self.is_dhcp_agent_present():
            self.link_subnet_l2(network=network,
                                cidr=IPNetwork('10.1.0.0/24'),
                                dhcp_port='10.1.0.1')
        else:
            # Agent enabled, no multilinking allowed
            self.assertRaises(
                exceptions.BadRequest,
                self.link_subnet_l2,
                network=network,
                cidr=IPNetwork('10.1.0.0/24'),
                dhcp_port='10.1.0.1')

    # Telenor scenario with multiple vsd managed subnets in a network
    @nuage_test.header(tags=['smoke'])
    def test_link_multi_l3domain_subnets_to_network(self):
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
        cidr = IPNetwork('10.0.0.0/24')
        vsd_domain_subnet1 = self.create_vsd_l3domain_subnet(
            name=sub_name,
            zone_id=vsd_zone[0]['ID'],
            cidr=cidr,
            gateway='10.0.0.1')[0]
        sub_name = data_utils.rand_name('l3dom-sub-')
        cidr = IPNetwork('10.1.0.0/24')
        vsd_domain_subnet2 = self.create_vsd_l3domain_subnet(
            name=sub_name,
            zone_id=vsd_zone[0]['ID'],
            cidr=cidr,
            gateway='10.1.0.1')[0]

        # create subnet on OS with nuagenet param set to subnet UUID
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        self.create_subnet(
            network,
            cidr=IPNetwork('10.0.0.0/24'),
            mask_bits=24, nuagenet=vsd_domain_subnet1['ID'],
            gateway='10.0.0.1',
            net_partition=Topology.def_netpartition)
        if not self.is_dhcp_agent_present():
            self.create_subnet(
                network,
                cidr=IPNetwork('10.1.0.0/24'),
                mask_bits=24, nuagenet=vsd_domain_subnet2['ID'],
                gateway='10.1.0.1',
                net_partition=Topology.def_netpartition)
        else:
            # Agent enabled, no multilinking allowed
            self.assertRaises(
                exceptions.BadRequest,
                self.create_subnet,
                network,
                cidr=IPNetwork('10.1.0.0/24'),
                mask_bits=24, nuagenet=vsd_domain_subnet2['ID'],
                gateway='10.1.0.1',
                net_partition=Topology.def_netpartition)


class VSDManagedAdminTestNetworks(base.BaseAdminNetworkTest):

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
