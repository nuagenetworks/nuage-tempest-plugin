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

from tempest.api.network import base
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.lib.utils import data_utils as nuage_data_utils

from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON
from nuage_tempest_plugin.tests.api.vsd_managed.base_vsd_managed_networks \
    import BaseVSDManagedNetwork

import uuid

CONF = Topology.get_conf()


class VSDManagedTestNetworks(BaseVSDManagedNetwork):

    def __init__(self, *args, **kwargs):
        super(VSDManagedTestNetworks, self).__init__(*args, **kwargs)
        self.failure_type = exceptions.BadRequest
        self.shared_infrastructure = 'Shared Infrastructure'

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

    def _create_and_verify_vm(self, network):
        name = data_utils.rand_name('server-smoke')
        server = self.create_tenant_server([network], name=name)
        ip_addr_on_openstack = server.get_server_details()['addresses'][
            network['name']][0]['addr']
        ip_addr_on_vsd = self.get_server_ip_from_vsd(server.id)
        return ip_addr_on_openstack == ip_addr_on_vsd

    def _create_unmgd_link_unmanaged_shared_subnet_l2(self):
        vsd_unmanaged_shared_l2dom_tmplt = \
            self.create_vsd_dhcpunmanaged_l2dom_template(
                netpart_name=self.shared_infrastructure)[0]
        vsd_unmanaged_shared_l2dom = self.create_vsd_l2domain(
            tid=vsd_unmanaged_shared_l2dom_tmplt['ID'],
            netpart_name=self.shared_infrastructure)[0]

        name = data_utils.rand_name('l2domain-with-shared')
        vsd_l2dom_tmplt = self.create_vsd_dhcpunmanaged_l2dom_template(
            name=name)[0]
        extra_params = {
            'associatedSharedNetwork'
            'ResourceID': vsd_unmanaged_shared_l2dom['ID']
        }
        vsd_l2dom_with_shared_unmanaged = self.create_vsd_l2domain(
            name=name,
            tid=vsd_l2dom_tmplt['ID'],
            extra_params=extra_params)[0]
        self.assertEqual(vsd_l2dom_with_shared_unmanaged['name'], name)
        self.assertEqual(
            (vsd_l2dom_with_shared_unmanaged[
                'associatedSharedNetworkResourceID']),
            vsd_unmanaged_shared_l2dom['ID'])
        return vsd_unmanaged_shared_l2dom, vsd_l2dom_with_shared_unmanaged

    def _create_link_managed_no_dhcp_shared_subnet_l2(self):
        vsd_managed_shared_l2dom_tmplt = \
            self.create_vsd_dhcpmanaged_l2dom_template(
                netpart_name=self.shared_infrastructure,
                cidr=IPNetwork('10.0.0.0/24'),
                gateway=None,
                cidrv6=IPNetwork('cafe:babe::/64'),
                IPv6Gateway=None,
                enableDHCPv4=False,
                enableDHCPv6=False,
                IPType='DUALSTACK')[0]
        vsd_managed_shared_l2dom = self.create_vsd_l2domain(
            tid=vsd_managed_shared_l2dom_tmplt['ID'],
            netpart_name=self.shared_infrastructure)[0]

        name = data_utils.rand_name('l2domain-with-shared')
        vsd_l2dom_tmplt = self.create_vsd_dhcpunmanaged_l2dom_template(
            name=name)[0]
        extra_params = {
            'associatedSharedNetwork'
            'ResourceID': vsd_managed_shared_l2dom['ID']
        }
        vsd_l2dom_with_shared_unmanaged = self.create_vsd_l2domain(
            name=name,
            tid=vsd_l2dom_tmplt['ID'],
            extra_params=extra_params)[0]
        self.assertEqual(vsd_l2dom_with_shared_unmanaged['name'], name)
        self.assertEqual(
            (vsd_l2dom_with_shared_unmanaged[
                'associatedSharedNetworkResourceID']),
            vsd_managed_shared_l2dom['ID'])
        return vsd_managed_shared_l2dom, vsd_l2dom_with_shared_unmanaged

    def create_netpartition(self, np_name=None):
        """Wrapper utility that returns a test network."""
        np_name = np_name or self.get_randomized_name()
        body = self.client.create_netpartition(np_name)
        netpartition = body['net_partition']
        self.net_partitions.append(netpartition)
        return netpartition

    def link_subnet_l2(self, cidr=None, mask_bits=None, dhcp_port=None,
                       dhcp_option_3=None,
                       pool=None, vsd_l2dom=None,
                       net_partition=None,
                       should_pass=True, create_server=False, network=None):

        def verify_subnet_info(i_subnet, i_vsd_l2dom, i_cidr, i_pool,
                               i_dhcp_option_3, net_part):
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
            if net_part:
                self.assertEqual(i_subnet['net_partition'],
                                 i_vsd_l2dom['parentID'])

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
            if net_partition:
                self.assertEqual(net_partition['id'], vsd_l2dom['parentID'])
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

        subnet = None
        if should_pass:
            subnet = self.create_subnet(network, **kwargs)
            verify_subnet_info(subnet, vsd_l2dom, cidr, pool, dhcp_option_3,
                               net_partition)

            # now refetch the subnet and verify again
            subnet = self.client.show_subnet(subnet['id'])['subnet']
            verify_subnet_info(subnet, vsd_l2dom, cidr, pool, dhcp_option_3,
                               net_partition)

            if create_server:
                self.assertTrue(self._create_and_verify_vm(network))
        else:
            self.assertRaises(self.failure_type, self.create_subnet,
                              network, **kwargs)
        return vsd_l2dom, subnet

    @decorators.attr(type='smoke')
    def test_link_subnet_l2_no_gw_with_vm(self):
        self.link_subnet_l2(create_server=True)

        # test recreating a new (identical) vsd mgd sub
        self.link_subnet_l2()

    @decorators.attr(type='smoke')
    def test_link_subnet_l2_with_gw_with_vm(self):
        self.link_subnet_l2(dhcp_option_3='10.10.100.2', create_server=True)

    @decorators.attr(type='smoke')
    def test_update_linked_subnet_l2(self):
        initial_pool = {"start": "10.10.100.10", "end": "10.10.100.20"}
        updated_pool = {"start": "10.10.100.5", "end": "10.10.100.25"}
        new_pool = {"start": "10.10.100.50", "end": "10.10.100.60"}
        overlapping_pool = {"start": "10.10.100.60", "end": "10.10.100.70"}

        vsd_l2dom, subnet = self.link_subnet_l2(pool=initial_pool)
        self.assertIsNotNone(subnet)

        # change the name, and description (should be allowed)
        new_name = str(uuid.uuid4())
        new_desc = str(uuid.uuid4())
        self.update_subnet(subnet, name=new_name, description=new_desc)
        updated_subnet = self.get_subnet(subnet['id'])

        subnet['name'] = new_name
        subnet['description'] = new_desc
        self.assertDictEqual(
            subnet,
            updated_subnet,
            ['updated_at', 'revision_number'],
            "Original subnet and updated subnet unexpectedly differ")

        # change/add allocation pool
        self.update_subnet(subnet, allocation_pools=[updated_pool, new_pool])
        updated_subnet = self.get_subnet(subnet['id'])
        self.assertItemsEqual(updated_subnet['allocation_pools'],
                              [updated_pool, new_pool])
        self.assertDictEqual(
            subnet,
            updated_subnet,
            ['updated_at', 'revision_number', 'allocation_pools'],
            "Original subnet and updated subnet unexpectedly differ")

        # remove an allocation pool
        self.update_subnet(subnet, allocation_pools=[new_pool])
        updated_subnet = self.get_subnet(subnet['id'])
        self.assertItemsEqual(updated_subnet['allocation_pools'], [new_pool])
        self.assertDictEqual(
            subnet,
            updated_subnet,
            ['updated_at', 'revision_number', 'allocation_pools'],
            "Original subnet and updated subnet unexpectedly differ")

        # change another attribute (should not be allowed)
        self.assertRaisesRegexp(
            exceptions.BadRequest,
            ".*Update is not supported for attributes other than.*",
            self.update_subnet,
            subnet,
            enable_dhcp=False   # the attribute that should not be changed
        )

        # set an overlapping allocation pool (should not be allowed)
        _, subnet2 = self.link_subnet_l2(pool=initial_pool,
                                         vsd_l2dom=vsd_l2dom)
        self.assertIsNotNone(subnet2)
        self.assertRaisesRegexp(
            exceptions.BadRequest,
            ".*Found overlapping allocation pools.*",
            self.update_subnet,
            subnet2,
            allocation_pools=[overlapping_pool]
        )

    def double_link_subnet_l2(
            self, cidr=None, mask_bits=None, dhcp_port=None,
            dhcp_option_3=None,
            pool1=None, pool2=None,
            should_pass=True):

        cidr = cidr or IPNetwork('10.10.100.0/24')
        mask_bits = mask_bits or 24
        dhcp_port = dhcp_port or '10.10.100.1'

        # 1st net
        vsd_l2dom, _ = self.link_subnet_l2(cidr, mask_bits, dhcp_port,
                                           dhcp_option_3, pool1)
        # 2nd net
        self.link_subnet_l2(cidr, mask_bits, dhcp_port, dhcp_option_3, pool2,
                            vsd_l2dom=vsd_l2dom, should_pass=should_pass)

    @decorators.attr(type='smoke')
    def test_double_link_subnet_l2_no_gw_no_allocation_pools(self):
        self.double_link_subnet_l2(should_pass=False)

    @decorators.attr(type='smoke')
    def test_double_link_subnet_l2_no_gw_non_disjunct_allocation_pools(self):
        self.double_link_subnet_l2(
            pool1={'start': '10.10.100.100', 'end': '10.10.100.110'},
            pool2={'start': '10.10.100.110', 'end': '10.10.100.120'},
            should_pass=False)

    @decorators.attr(type='smoke')
    def test_double_link_subnet_l2_no_gw_disjunct_allocation_pools(self):
        self.double_link_subnet_l2(
            pool1={'start': '10.10.100.100', 'end': '10.10.100.109'},
            pool2={'start': '10.10.100.110', 'end': '10.10.100.120'},
            should_pass=True)

    @decorators.attr(type='smoke')
    def test_double_link_subnet_l2_with_gw_disjunct_allocation_pools(self):
        self.double_link_subnet_l2(
            dhcp_option_3='10.10.100.2',
            pool1={'start': '10.10.100.100', 'end': '10.10.100.109'},
            pool2={'start': '10.10.100.110', 'end': '10.10.100.120'},
            should_pass=True)

    @decorators.attr(type='smoke')
    def test_link_vsd_managed_shared_subnet_l2_with_vm(self):
        cidr = IPNetwork('10.10.100.0/24')
        gateway = str(IPAddress(cidr) + 1)
        vsd_managed_shared_l2dom_tmplt = \
            self.create_vsd_dhcpmanaged_l2dom_template(
                cidr=cidr,
                gateway=gateway,
                netpart_name=self.shared_infrastructure)[0]
        vsd_managed_shared_l2dom = self.create_vsd_l2domain(
            tid=vsd_managed_shared_l2dom_tmplt['ID'],
            netpart_name=self.shared_infrastructure)[0]

        name = data_utils.rand_name('l2domain-with-shared')
        vsd_l2dom_tmplt = self.create_vsd_dhcpunmanaged_l2dom_template(
            name=name)[0]
        extra_params = {
            'associatedSharedNetworkResourceID':
                vsd_managed_shared_l2dom['ID']
        }
        vsd_l2dom_with_shared_managed = self.create_vsd_l2domain(
            name=name,
            tid=vsd_l2dom_tmplt['ID'],
            extra_params=extra_params)[0]
        self.assertEqual(vsd_l2dom_with_shared_managed['name'], name)
        self.assertEqual(
            (vsd_l2dom_with_shared_managed
             ['associatedSharedNetworkResourceID']),
            vsd_managed_shared_l2dom['ID'])

        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('sharedl2-network-')
        network = self.create_network(network_name=net_name)
        subnet = self.create_subnet(
            network,
            gateway=None,
            cidr=cidr,
            mask_bits=24,
            nuagenet=vsd_l2dom_with_shared_managed['ID'],
            net_partition=Topology.def_netpartition)
        self.assertEqual(
            str(IPNetwork(subnet['cidr']).ip),
            vsd_managed_shared_l2dom['address'])
        self.assertIsNone(subnet['gateway_ip'])
        self.assertEqual(
            subnet['enable_dhcp'],
            vsd_managed_shared_l2dom['DHCPManaged'])
        self.assertTrue(self._create_and_verify_vm(network))

    @nuage_test.skip_because(bug='OPENSTACK-2548')
    @decorators.attr(type='smoke')
    def test_link_vsd_unmanaged_shared_subnet_l2(self):
        vsd_unmanaged_shared_l2dom, vsd_l2dom_with_shared_unmanaged =\
            self._create_unmgd_link_unmanaged_shared_subnet_l2()
        net_name = data_utils.rand_name('unmnaged-shared-l2-network-')
        network = self.create_network(network_name=net_name)
        cidr = IPNetwork('10.20.30.0/16')  # whatever
        subnet = self.create_subnet(
            network,
            gateway=None,
            cidr=cidr, mask_bits=16,
            nuagenet=vsd_l2dom_with_shared_unmanaged['ID'],
            net_partition=Topology.def_netpartition,
            enable_dhcp=False)
        self.assertIsNone(subnet['gateway_ip'])
        self.assertEqual(
            subnet['enable_dhcp'],
            vsd_unmanaged_shared_l2dom['DHCPManaged'])

    @decorators.attr(type='smoke')
    @testtools.skipIf(CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed',
                      'Unmanaged domains not supported with nuage_vsd_managed '
                      'ipam.')
    def test_port_update_link_vsd_unmanaged_shared_subnet_l2_with_vm(self):
        vsd_unmanaged_shared_l2dom, vsd_l2dom_with_shared_unmanaged = \
            self._create_unmgd_link_unmanaged_shared_subnet_l2()
        net_name = data_utils.rand_name('unmnaged-shared-l2-network-')
        network = self.create_network(network_name=net_name)
        subnetv4 = self.create_subnet(
            network,
            gateway=None,
            cidr=IPNetwork('10.0.0.0/24'),
            nuagenet=vsd_l2dom_with_shared_unmanaged['ID'],
            net_partition=Topology.def_netpartition,
            enable_dhcp=False)
        subnetv6 = self.create_subnet(
            network,
            gateway=None,
            cidr=IPNetwork('cafe:babe::/64'),
            ip_version=6,
            nuagenet=vsd_l2dom_with_shared_unmanaged['ID'],
            net_partition=Topology.def_netpartition,
            enable_dhcp=False)
        self.assertIsNone(subnetv4['gateway_ip'])
        self.assertFalse(subnetv4['enable_dhcp'])
        self.assertFalse(subnetv6['enable_dhcp'])
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "cafe:babe::3",
                "subnet_id": subnetv6["id"]
            },
            {
                "ip_address": "cafe:babe::4",
                "subnet_id": subnetv6["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        server = self.create_tenant_server(ports=[port])
        ipv4_ip, ipv6_ip = self.get_server_ip_from_vsd(server.id,
                                                       type='DUALSTACK')
        self.assertIsNone(ipv4_ip)
        self.assertIsNone(ipv6_ip)
        fixed_ips = [
            {
                "ip_address": "10.0.0.5",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "10.0.0.6",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "cafe:babe::5",
                "subnet_id": subnetv6["id"]
            },
            {
                "ip_address": "cafe:babe::6",
                "subnet_id": subnetv6["id"]
            }
        ]
        port = self.update_port(port=port, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to update port")
        self.assertEqual(port["fixed_ips"], fixed_ips,
                         message="The port did not update properly.")
        ipv4_ip, ipv6_ip = self.get_server_ip_from_vsd(server.id,
                                                       type='DUALSTACK')
        self.assertIsNone(ipv4_ip)
        self.assertIsNone(ipv6_ip)

    @decorators.attr(type='smoke')
    def test_port_update_link_vsd_managed_shared_subnet_l2_with_vm(self):
        vsd_managed_shared_l2dom, vsd_l2dom_with_shared_unmanaged = \
            self._create_link_managed_no_dhcp_shared_subnet_l2()
        net_name = data_utils.rand_name('unmnaged-shared-l2-network-')
        network = self.create_network(network_name=net_name)
        subnetv4 = self.create_subnet(
            network,
            gateway=None,
            cidr=IPNetwork('10.0.0.0/24'),
            mask_bits=24,
            nuagenet=vsd_l2dom_with_shared_unmanaged['ID'],
            net_partition=Topology.def_netpartition,
            enable_dhcp=False)
        subnetv6 = self.create_subnet(
            network,
            gateway=None,
            cidr=IPNetwork('cafe:babe::/64'),
            ip_version=6,
            nuagenet=vsd_l2dom_with_shared_unmanaged['ID'],
            net_partition=Topology.def_netpartition,
            enable_dhcp=False)
        self.assertIsNone(subnetv4['gateway_ip'])
        self.assertFalse(subnetv4['enable_dhcp'])
        self.assertFalse(subnetv6['enable_dhcp'])
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "cafe:babe::3",
                "subnet_id": subnetv6["id"]
            },
            {
                "ip_address": "cafe:babe::4",
                "subnet_id": subnetv6["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        server = self.create_tenant_server(ports=[port])
        ipv4_ip, ipv6_ip = self.get_server_ip_from_vsd(server.id,
                                                       type='DUALSTACK')
        self.assertEqual("10.0.0.4", ipv4_ip)
        self.assertEqual("cafe:babe::4/64", ipv6_ip)
        fixed_ips = [
            {
                "ip_address": "10.0.0.5",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "10.0.0.6",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "cafe:babe::5",
                "subnet_id": subnetv6["id"]
            },
            {
                "ip_address": "cafe:babe::6",
                "subnet_id": subnetv6["id"]
            }
        ]
        port = self.update_port(port=port, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to update port")
        self.assertEqual(port["fixed_ips"], fixed_ips,
                         message="The port did not update properly.")
        ipv4_ip, ipv6_ip = self.get_server_ip_from_vsd(server.id,
                                                       type='DUALSTACK')
        self.assertEqual("10.0.0.6", ipv4_ip)
        self.assertEqual("cafe:babe::6/64", ipv6_ip)

    @decorators.attr(type='smoke')
    def test_link_subnet_with_diff_netpartition_l2(self):
        # link l2domain on VSD in different net-partition
        netpart_name = data_utils.rand_name('netpart-')
        netpart = self.create_netpartition(netpart_name)
        self.link_subnet_l2(net_partition=netpart)

    @decorators.attr(type='smoke')
    def test_link_subnet_wo_netpartition_l2(self):
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        cidr = nuage_data_utils.gimme_a_cidr()
        l2dom_id = data_utils.rand_uuid()
        msg = "Cannot find l2domain with ID {}".format(l2dom_id)
        self.assertRaisesRegex(self.failure_type,
                               msg,
                               self.create_subnet,
                               network,
                               cidr=cidr,
                               mask_bits=24,
                               nuagenet=l2dom_id)

    @decorators.attr(type='smoke')
    def test_link_subnet_with_unknown_netpartition_l2(self):
        # netpartition does not exist in neutron DB
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        cidr = nuage_data_utils.gimme_a_cidr()
        l2dom_id = data_utils.rand_uuid()
        netpart_name = data_utils.rand_name()
        msg = "Can't find netpartition '{}'".format(netpart_name)
        self.assertRaisesRegex(self.failure_type,
                               msg,
                               self.create_subnet,
                               network,
                               cidr=cidr,
                               mask_bits=24,
                               nuagenet=l2dom_id,
                               net_partition=netpart_name)

    @decorators.attr(type='smoke')
    def test_link_subnet_with_incorrect_netpartition_l2(self):
        # netpartition does exist in neutron DB but it is not
        # where the l2domain is created
        # create l2domain on VSD in default net-partition
        name = data_utils.rand_name('l2domain-')
        cidr = nuage_data_utils.gimme_a_cidr()
        _, _, gateway = nuage_data_utils.get_cidr_attributes(cidr)
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name, cidr=cidr, gateway=gateway)
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        netpart_name = data_utils.rand_name('netpart-')
        netpart = self.create_netpartition(netpart_name)
        msg = "Provided Nuage subnet not in the provided Nuage net-partition"
        self.assertRaisesRegex(self.failure_type,
                               msg,
                               self.create_subnet,
                               network,
                               cidr=cidr,
                               mask_bits=24,
                               nuagenet=vsd_l2dom[0]['ID'],
                               net_partition=netpart['name'])

    @decorators.attr(type='smoke')
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

    @decorators.attr(type='smoke')
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

    def test_link_subnet_with_enable_dhcp_unmanaged_l2_neg(self):
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

    @decorators.attr(type='smoke')
    def test_link_subnet_with_disable_dhcp_vsd_managed_l2(self):
        # create l2domain on VSD
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name, cidr=cidr, enableDHCPv4=False)
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

    @decorators.attr(type='smoke')
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

    @decorators.attr(type='smoke')
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

    @decorators.attr(type='smoke')
    def test_link_subnet_l3_with_vm(self):
        self.link_subnet_l3()

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

    @decorators.attr(type='smoke')
    def test_link_subnet_with_diff_types_in_shared_infrastructure_l3(self):
        # create l3domain on VSD
        vsd_l3dom_tmplt = self.create_vsd_l3dom_template(
            netpart_name=self.shared_infrastructure)[0]
        vsd_l3dom = self.create_vsd_l3domain(
            tid=vsd_l3dom_tmplt['ID'],
            netpart_name=self.shared_infrastructure)[0]
        vsd_zone = self.create_vsd_zone(domain_id=vsd_l3dom['ID'])[0]
        # create shared subnet on VSD
        shared_sub_cidr = nuage_data_utils.gimme_a_cidr()
        _, _, shared_sub_gateway = nuage_data_utils.get_cidr_attributes(
            shared_sub_cidr)
        extra_params = {'resourceType': 'PUBLIC'}
        shared_sub_name = data_utils.rand_name('public-subnet-')
        vsd_shared_l3dom_subnet = self.create_vsd_l3domain_managed_subnet(
            zone_id=vsd_zone['ID'],
            name=shared_sub_name,
            cidr=shared_sub_cidr,
            gateway=shared_sub_gateway,
            extra_params=extra_params)[0]
        # create floating subnet on VSD
        floating_sub_cidr = nuage_data_utils.gimme_a_cidr()
        _, _, floating_sub_gateway = nuage_data_utils.get_cidr_attributes(
            floating_sub_cidr)
        extra_params = {'resourceType': 'FLOATING'}
        floating_sub_name = data_utils.rand_name('floating-subnet-')
        vsd_floating_l3dom_subnet = self.create_vsd_l3domain_managed_subnet(
            zone_id=vsd_zone['ID'],
            name=floating_sub_name,
            cidr=floating_sub_cidr,
            gateway=floating_sub_gateway,
            extra_params=extra_params)[0]
        # create standard subnet on VSD
        standard_sub_cidr = nuage_data_utils.gimme_a_cidr()
        _, _, standard_sub_gateway = nuage_data_utils.get_cidr_attributes(
            standard_sub_cidr)
        extra_params = {'resourceType': 'STANDARD'}
        standard_sub_name = data_utils.rand_name('standard-subnet-')
        vsd_standard_l3dom_subnet = self.create_vsd_l3domain_managed_subnet(
            zone_id=vsd_zone['ID'],
            name=standard_sub_name,
            cidr=standard_sub_cidr,
            gateway=standard_sub_gateway,
            extra_params=extra_params)[0]

        network = self.create_network()
        msg = (("The nuage subnet type is {}. Only STANDARD type subnet is "
                "allowed to be linked.")
               .format(vsd_shared_l3dom_subnet['resourceType']))
        # create os subnet linking to shared subnet on VSD
        self.assertRaisesRegex(
            exceptions.BadRequest,
            msg,
            self.create_subnet,
            network,
            cidr=shared_sub_cidr,
            mask_bits=24,
            nuagenet=vsd_shared_l3dom_subnet['ID'],
            gateway=shared_sub_gateway,
            net_partition=self.shared_infrastructure)
        # create os subnet linking to floating subnet on VSD
        msg = (("The nuage subnet type is {}. Only STANDARD type subnet is "
                "allowed to be linked.")
               .format(vsd_floating_l3dom_subnet['resourceType']))
        self.assertRaisesRegex(
            exceptions.BadRequest,
            msg,
            self.create_subnet,
            network,
            cidr=floating_sub_cidr,
            mask_bits=24,
            nuagenet=vsd_floating_l3dom_subnet['ID'],
            gateway=floating_sub_gateway,
            net_partition=self.shared_infrastructure)
        # create os subnet linking to standard subnet on VSD
        vsd_managed_standard_subnet = self.create_subnet(
            network,
            cidr=standard_sub_cidr,
            mask_bits=24,
            nuagenet=vsd_standard_l3dom_subnet['ID'],
            gateway=standard_sub_gateway,
            net_partition=self.shared_infrastructure)
        self.assertEqual(str(standard_sub_cidr),
                         vsd_managed_standard_subnet['cidr'])

    @decorators.attr(type='smoke')
    def test_link_vsd_dualstack_shared_subnet_l3(self):
        # create public dualstack l3 subnet in shared infrastructure
        shared_vsd_l3dom_tmplt = self.create_vsd_l3dom_template(
            netpart_name=self.shared_infrastructure)[0]
        shared_vsd_l3dom = self.create_vsd_l3domain(
            tid=shared_vsd_l3dom_tmplt['ID'],
            netpart_name=self.shared_infrastructure)[0]

        vsd_zone = self.create_vsd_zone(domain_id=shared_vsd_l3dom['ID'])[0]

        subnet_cidr = IPNetwork('10.10.100.0/24')
        subnet_gateway = str(IPAddress(subnet_cidr) + 1)

        subnet_ipv6_cidr = IPNetwork("2001:5f74:c4a5:b82e::/64")
        subnet_ipv6_gateway = str(IPAddress(subnet_ipv6_cidr) + 1)

        extra_params = {'IPType': "DUALSTACK",
                        'IPv6Address': str(subnet_ipv6_cidr),
                        'IPv6Gateway': subnet_ipv6_gateway,
                        'resourceType': 'PUBLIC'}
        subnet_name = data_utils.rand_name('public-subnet-')

        vsd_shared_l3dom_subnet = self.create_vsd_l3domain_managed_subnet(
            zone_id=vsd_zone['ID'],
            name=subnet_name,
            cidr=subnet_cidr,
            gateway=subnet_gateway,
            extra_params=extra_params)[0]

        # create l3 subnet linked to public subnet
        vsd_l3dom_tmplt = self.create_vsd_l3dom_template(
            netpart_name=Topology.def_netpartition)[0]
        vsd_l3dom = self.create_vsd_l3domain(
            tid=vsd_l3dom_tmplt['ID'],
            netpart_name=Topology.def_netpartition)[0]

        zone_name = data_utils.rand_name('public-zone-')
        extra_params = {'publicZone': True}
        vsd_public_zone = self.create_vsd_zone(name=zone_name,
                                               domain_id=vsd_l3dom['ID'],
                                               extra_params=extra_params)[0]

        name = data_utils.rand_name('l3domain-with-shared')
        extra_params = {
            'associatedSharedNetworkResourceID': vsd_shared_l3dom_subnet['ID']
        }
        vsd_l3_dom_public_subnet = self.create_vsd_l3domain_unmanaged_subnet(
            name=name,
            zone_id=vsd_public_zone['ID'],
            extra_params=extra_params)[0]
        self.assertEqual(vsd_l3_dom_public_subnet['name'], name)
        self.assertEqual(
            vsd_l3_dom_public_subnet['associatedSharedNetworkResourceID'],
            vsd_shared_l3dom_subnet['ID'])

        # create subnet on OS with nuagenet param set to l3 subnet ID
        net_name = data_utils.rand_name('shared-l3-network-')
        network = self.create_network(network_name=net_name)

        subnet_v4 = self.create_subnet(
            network,
            cidr=subnet_cidr,
            mask_bits=24,
            nuagenet=vsd_l3_dom_public_subnet['ID'],
            gateway=subnet_gateway,
            net_partition=Topology.def_netpartition)
        self.assertEqual(
            str(IPNetwork(subnet_v4['cidr']).ip),
            vsd_shared_l3dom_subnet['address'])
        self.assertEqual(subnet_v4['gateway_ip'], subnet_gateway)

        subnet_v6 = self.create_subnet(
            network,
            ip_version=6,
            cidr=subnet_ipv6_cidr,
            mask_bits=64,
            nuagenet=vsd_l3_dom_public_subnet['ID'],
            gateway=subnet_ipv6_gateway,
            net_partition=Topology.def_netpartition,
            enable_dhcp=False)
        self.assertEqual(
            str(subnet_v6['cidr']),
            vsd_shared_l3dom_subnet['IPv6Address'])
        self.assertEqual(subnet_v6['gateway_ip'], subnet_ipv6_gateway)

    # Originally part of _m2 suite

    @decorators.attr(type='smoke')
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
                                                  filter_values=port['id'])
        self.assertIsNotNone(nuage_vport, "vport should be created.")

        # External ID tests
        vsd_l2domains = self.nuage_client.get_l2domain(
            filters='ID', filter_values=vsd_l2dom['ID'])
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
                                                  filter_values=port['id'])
        self.assertEqual('', nuage_vport, "vport should be deleted.")

        # Then I can delete the network
        self.networks_client.delete_network(network['id'])

        # Then the VSD managed network is still there
        vsd_l2domains = self.nuage_client.get_l2domain(
            filters='ID', filter_values=vsd_l2dom['ID'])
        self.assertEqual(len(vsd_l2domains), 1, "Failed to get vsd l2 domain")

    # HP - Unica scenario with DHCP-options defined in VSD
    @decorators.attr(type='smoke')
    def test_link_vsd_shared_subnet_l3_with_dhcp_option_with_vm(self):
        shared_vsd_l3dom_tmplt = self.create_vsd_l3dom_template(
            netpart_name=self.shared_infrastructure)[0]
        shared_vsd_l3dom = self.create_vsd_l3domain(
            tid=shared_vsd_l3dom_tmplt['ID'],
            netpart_name=self.shared_infrastructure)[0]

        vsd_zone = self.create_vsd_zone(domain_id=shared_vsd_l3dom['ID'])[0]

        cidr = IPNetwork('10.10.100.0/24')
        gateway = str(IPAddress(cidr) + 1)

        extra_params = {'resourceType': 'PUBLIC'}
        subnet_name = data_utils.rand_name('public-subnet-')

        vsd_shared_l3dom_subnet = self.create_vsd_l3domain_managed_subnet(
            zone_id=vsd_zone['ID'],
            name=subnet_name,
            cidr=cidr,
            gateway=gateway,
            extra_params=extra_params)[0]
        self.nuage_client.create_dhcpoption_on_shared(
            vsd_shared_l3dom_subnet['ID'], '03',  # TODO(Kris) bad '03'?
            [str(IPAddress(cidr) + 2)])

        name = data_utils.rand_name('l3dom-with-shared')
        vsd_l3dom_tmplt = self.create_vsd_l3dom_template(name=name)[0]
        vsd_l3dom = self.create_vsd_l3domain(name=name,
                                             tid=vsd_l3dom_tmplt['ID'])[0]

        self.assertEqual(vsd_l3dom['name'], name)
        zone_name = data_utils.rand_name('Public-zone-')
        extra_params = {'publicZone': True}
        vsd_zone = self.create_vsd_zone(name=zone_name,
                                        domain_id=vsd_l3dom['ID'],
                                        extra_params=extra_params)[0]

        name = data_utils.rand_name('l3domain-with-shared')
        extra_params = {
            'associatedSharedNetworkResourceID': vsd_shared_l3dom_subnet['ID']
        }
        vsd_l3_dom_public_subnet = self.create_vsd_l3domain_unmanaged_subnet(
            name=name,
            zone_id=vsd_zone['ID'],
            extra_params=extra_params)[0]
        self.assertEqual(vsd_l3_dom_public_subnet['name'], name)
        self.assertEqual(
            vsd_l3_dom_public_subnet['associatedSharedNetworkResourceID'],
            vsd_shared_l3dom_subnet['ID'])

        # create subnet on OS with nuagenet param set to l3domain UUID
        net_name = data_utils.rand_name('shared-l3-network-')
        network = self.create_network(network_name=net_name)
        subnet = self.create_subnet(
            network, cidr=cidr, mask_bits=24,
            nuagenet=vsd_l3_dom_public_subnet['ID'],
            net_partition=Topology.def_netpartition)
        self.assertEqual(
            str(IPNetwork(subnet['cidr']).ip),
            vsd_shared_l3dom_subnet['address'])
        self.assertEqual(subnet['gateway_ip'], gateway)
        self.assertTrue(self._create_and_verify_vm(network))

    # Telenor scenario with multiple vsd managed subnets in a network
    @decorators.attr(type='smoke')
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
    @decorators.attr(type='smoke')
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

    @decorators.attr(type='smoke')
    def test_link_no_dhcp_subnet_with_dhcp_vsd_managed_l2_ipv6_neg(self):
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
        self.assertRaisesRegex(exceptions.BadRequest,
                               "Bad request: enable_dhcp in subnet must "
                               "be True",
                               self.create_subnet, network, gateway=None,
                               cidr=cidr, mask_bits=24,
                               nuagenet=vsd_l2dom[0]['ID'],
                               net_partition=Topology.def_netpartition,
                               enable_dhcp=False)

    @decorators.attr(type='smoke')
    def test_link_dhcp_subnet_with_no_dhcp_vsd_managed_l2_ipv4_neg(self):
        # create l2domain on VSD
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name, cidr=cidr, enableDHCPv4=False)
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l2dom[0]['name'], name)
        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        self.assertRaisesRegex(exceptions.BadRequest,
                               "Bad request: enable_dhcp in subnet must "
                               "be False",
                               self.create_subnet, network,
                               gateway=None,
                               cidr=IPNetwork('10.10.100.0/24'),
                               mask_bits=24, nuagenet=vsd_l2dom[0]['ID'],
                               net_partition=Topology.def_netpartition,
                               enable_dhcp=True)

    @testtools.skipIf(not Topology.has_single_stack_v6_support(),
                      'There is no single-stack v6 support in current release')
    @decorators.attr(type='smoke')
    def test_link_dhcp_subnet_with_no_dhcp_vsd_managed_l2_ipv6_neg(self):
        # Provision VSD managed network resources
        l2domain_template = self.vsd_create_l2domain_template(
            ip_type="IPV6",
            cidr6=self.cidr6,
            gateway6=None,
            enable_dhcpv6=False)
        vsd_l2domain = self.vsd_create_l2domain(template=l2domain_template)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        self.assertRaisesRegex(exceptions.BadRequest,
                               "Bad request: enable_dhcp in subnet must "
                               "be False",
                               self.create_subnet, network, gateway=None,
                               cidr=IPNetwork('cafe:babe::/64'),
                               nuagenet=vsd_l2domain.id,
                               net_partition=Topology.def_netpartition,
                               enable_dhcp=True, ip_version=6)


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
