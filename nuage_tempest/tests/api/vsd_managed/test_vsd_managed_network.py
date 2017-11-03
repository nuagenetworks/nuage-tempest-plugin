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

from tempest.api.compute import base as serv_base
from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.scenario import manager
from tempest.test import decorators

from nuage_tempest.lib.nuage_tempest_test_loader import Release
from nuage_tempest.lib.test import nuage_test
from nuage_tempest.lib.test import tags
from nuage_tempest.lib.utils import constants
import nuage_tempest.tests.api.test_netpartitions as test_netpartitions
from nuage_tempest.tests.api.vsd_managed \
    import base_vsd_managed_network as base_vsdman

CONF = config.CONF
external_id_release = Release(constants.EXTERNALID_RELEASE)
conf_release = CONF.nuage_sut.release
current_release = Release(conf_release)


@nuage_test.class_header(tags=[tags.VSD_MANAGED, tags.MONOLITHIC])
class VSDManagedTestNetworks(base_vsdman.BaseVSDManagedNetworksTest,
                             test_netpartitions.NetPartitionTestJSON,
                             manager.NetworkScenarioTest,
                             serv_base.BaseV2ComputeTest):

    def __init__(self, *args, **kwargs):
        super(VSDManagedTestNetworks, self).__init__(*args, **kwargs)
        self.failure_type = exceptions.BadRequest

    @classmethod
    def resource_setup(cls):
        super(VSDManagedTestNetworks, cls).resource_setup()

    @classmethod
    def resource_cleanup(cls):
        super(VSDManagedTestNetworks, cls).resource_cleanup()

    @classmethod
    def get_server_ip_from_vsd(cls, vm_id):
        if external_id_release <= current_release:
            vm_details = cls.nuageclient.get_resource(
                constants.VM,
                filters='externalID',
                filter_value=cls.nuageclient.get_vsd_external_id(vm_id))[0]
        else:
            vm_details = cls.nuageclient.get_resource(constants.VM,
                                                      filters='UUID',
                                                      filter_value=vm_id)[0]
        interfaces = vm_details.get('interfaces')
        if interfaces:
            return interfaces[0]['IPAddress']

    def _verify_vm_ip(self, net_id, net_name):
        name = data_utils.rand_name('server-smoke')
        server = self._create_server(name, net_id)
        self.assertEqual(server.get('OS-EXT-STS:vm_state'), 'active')
        ip_addr_on_openstack = server['addresses'][net_name][0]['addr']
        ip_addr_on_vsd = self.get_server_ip_from_vsd(server['id'])
        return ip_addr_on_openstack == ip_addr_on_vsd

    def _create_server(self, name, network_id):
        network = {'uuid': network_id}
        server = self.create_server(name=name,
                                    networks=[network],
                                    wait_until='ACTIVE')
        return server

    @nuage_test.header(tags=['smoke'])
    def test_link_subnet_l2(self):
        # create l2domain on VSD
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name,
            cidr=cidr, gateway='10.10.100.1')
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l2dom[0][u'name'], name)
        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        subnet = self.create_subnet(
            network,
            gateway=None,
            cidr=cidr,
            mask_bits=24,
            nuagenet=vsd_l2dom[0]['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(subnet['cidr'], str(cidr))
        self.assertTrue(self._verify_vm_ip(network['id'], net_name))

    # @nuage_test.header(tags=['smoke'])
    # OPENSTACK-1809
    # this test fails already at create_subnet  (at least with core plugin)
    # because L2domaintemplate is made with 'gateway' 10.10.100.1.
    # however in our mapping of L2domains to subnets in openstack,
    # gateway  is 3: router  DHCP option.
    # The test wrongly believes a L2 domain on VSD is made with gateway,
    # and will try to make subnet in openstack with that gateway,
    # but in plugin this is on VSD a subnet with --no-gateway as the
    # router option is not set.
    # TODO(FIXME) - FIX TEST AND TAKE OUT FIXME prefix which i added
    def FIXME_test_link_subnet_l2_allocation_pool(self):
        # create l2domain on VSD
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name,
            cidr=cidr, gateway='10.10.100.1')
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l2dom[0][u'name'], name)
        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        start_ip = IPAddress(cidr) + 3
        end_ip = IPAddress(cidr) + 5
        pool_dict = [{'start': start_ip, 'end': end_ip}]

        subnet = self.create_subnet(
            network,
            cidr=cidr,
            mask_bits=24,
            gateway=vsd_l2dom[0]['gateway'],
            allocation_pools=pool_dict,
            nuagenet=vsd_l2dom[0]['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)  # fails here
        self.assertEqual(subnet['cidr'], str(cidr))
        pool = subnet['allocation_pools'][0]
        self.assertEqual(pool['start'], start_ip.format())
        self.assertEqual(pool['end'], end_ip.format())
        self.assertTrue(self._verify_vm_ip(network['id'], net_name))

    @nuage_test.header(tags=['smoke'])
    def test_link_vsd_managed_sharedsubnet_l2(self):
        name = data_utils.rand_name('shared-l2-managed')
        cidr = IPNetwork('10.20.0.0/16')
        vsd_managed_shared_l2dom = self.create_vsd_managed_shared_resource(
            name=name,
            netmask=str(cidr.netmask),
            address=str(cidr.ip),
            DHCPManaged=True,
            gateway='10.20.0.1',
            type='L2DOMAIN')
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
            mask_bits=16,
            nuagenet=vsd_l2dom_with_shared_managed[0]['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(
            str(IPNetwork(subnet['cidr']).ip),
            vsd_managed_shared_l2dom['address'])
        self.assertIsNone(subnet['gateway_ip'])
        self.assertEqual(
            subnet['enable_dhcp'],
            vsd_managed_shared_l2dom['DHCPManaged'])
        self.assertTrue(self._verify_vm_ip(network['id'], net_name))

    @nuage_test.header(tags=['smoke'])
    def test_link_vsd_sharedsubnet_l3(self):
        name = data_utils.rand_name('shared-l3-')
        cidr = IPNetwork('10.20.0.0/16')
        vsd_shared_l3dom_subnet = self.create_vsd_managed_shared_resource(
            name=name, netmask=str(cidr.netmask), address=str(cidr.ip),
            DHCPManaged=True,
            gateway='10.20.0.1',
            type='PUBLIC')

        name = data_utils.rand_name('l3dom-with-shared')
        vsd_l3dom_tmplt = self.create_vsd_l3dom_template(
            name=name)
        vsd_l3dom = self.create_vsd_l3domain(name=name,
                                             tid=vsd_l3dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l3dom[0]['name'], name)
        zonename = data_utils.rand_name('Public-zone-')
        extra_params = {'publicZone': True}
        vsd_zone = self.create_vsd_zone(name=zonename,
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
            network, cidr=cidr,
            mask_bits=16,
            nuagenet=vsd_l3_dom_public_subnet['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(
            str(IPNetwork(subnet['cidr']).ip),
            vsd_shared_l3dom_subnet['address'])
        self.assertEqual(subnet['gateway_ip'], '10.20.0.1')
        self.assertEqual(
            subnet['enable_dhcp'],
            vsd_shared_l3dom_subnet['DHCPManaged'])
        self.assertTrue(self._verify_vm_ip(network['id'], net_name))

    @nuage_test.header(tags=['smoke'])
    def test_link_vsd_unmanaged_sharedsubnet_l2(self):
        cidr = IPNetwork('10.20.30.0/16')
        name = data_utils.rand_name('shared-l2-unmanaged')
        vsd_unmanaged_shared_l2dom = self.create_vsd_managed_shared_resource(
            name=name,
            type='L2DOMAIN')
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
        subnet = self.create_subnet(
            network,
            gateway=None,
            cidr=cidr, mask_bits=16,
            nuagenet=vsd_l2dom_with_shared_unmanaged[0]['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition,
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
    def test_link_duplicate_subnet_l2(self):
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
            network,
            gateway=None,
            cidr=cidr,
            mask_bits=24,
            nuagenet=vsd_l2dom[0]['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(subnet['cidr'], str(cidr))
        # Try linking 2nd subnet to same VSD subnet. It should fail.
        network = self.create_network(network_name=net_name)
        self.assertRaises(
            self.failure_type, self.create_subnet,
            network, cidr=cidr,
            mask_bits=24, nuagenet=vsd_l2dom[0]['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)

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
            net_partition=CONF.nuage.nuage_default_netpartition)

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
            net_partition=CONF.nuage.nuage_default_netpartition,
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
            net_partition=CONF.nuage.nuage_default_netpartition)

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
            net_partition=CONF.nuage.nuage_default_netpartition,
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
            net_partition=CONF.nuage.nuage_default_netpartition,
            enable_dhcp=False)

    @nuage_test.header(tags=['smoke'])
    def test_link_subnet_l3(self):
        # create l3domain on VSD
        name = data_utils.rand_name('l3domain-')
        vsd_l3dom_tmplt = self.create_vsd_l3dom_template(
            name=name)
        vsd_l3dom = self.create_vsd_l3domain(name=name,
                                             tid=vsd_l3dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l3dom[0]['name'], name)
        zonename = data_utils.rand_name('l3dom-zone-')
        vsd_zone = self.create_vsd_zone(name=zonename,
                                        domain_id=vsd_l3dom[0]['ID'])
        self.assertEqual(vsd_zone[0]['name'], zonename)
        subname = data_utils.rand_name('l3dom-sub-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_domain_subnet = self.create_vsd_l3domain_subnet(
            name=subname,
            zone_id=vsd_zone[0]['ID'],
            cidr=cidr,
            gateway='10.10.100.1')
        self.assertEqual(vsd_domain_subnet[0]['name'], subname)
        # create subnet on OS with nuagenet param set to subnet UUID
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        subnet = self.create_subnet(
            network,
            cidr=cidr, mask_bits=24, nuagenet=vsd_domain_subnet[0]['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition)
        self.assertEqual(subnet['cidr'], str(cidr))
        self.assertTrue(self._verify_vm_ip(network['id'], net_name))

    @decorators.attr(type='smoke')
    def test_link_subnet_with_incorrect_gateway_l3(self):
        # create l3domain on VSD
        name = data_utils.rand_name('l3domain-')
        vsd_l3dom_tmplt = self.create_vsd_l3dom_template(
            name=name)
        vsd_l3dom = self.create_vsd_l3domain(name=name,
                                             tid=vsd_l3dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l3dom[0]['name'], name)
        zonename = data_utils.rand_name('l3dom-zone-')
        vsd_zone = self.create_vsd_zone(name=zonename,
                                        domain_id=vsd_l3dom[0]['ID'])
        self.assertEqual(vsd_zone[0]['name'], zonename)
        subname = data_utils.rand_name('l3dom-sub-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_domain_subnet = self.create_vsd_l3domain_subnet(
            name=subname,
            zone_id=vsd_zone[0]['ID'],
            cidr=cidr,
            gateway='10.10.100.1')
        self.assertEqual(vsd_domain_subnet[0]['name'], subname)
        # create subnet on OS with nuagenet param set to subnet UUID
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)
        if Release(CONF.nuage_sut.openstack_version) >= Release('Newton') and \
                CONF.nuage_sut.nuage_plugin_mode == 'ml2':
            subnet = self.create_subnet(
                network,
                cidr=IPNetwork('10.10.100.0/24'),
                mask_bits=24, nuagenet=vsd_domain_subnet[0]['ID'],
                gateway='10.10.100.5',
                net_partition=CONF.nuage.nuage_default_netpartition)
            self.assertEqual(subnet['cidr'], str(cidr))
            self.assertTrue(self._verify_vm_ip(network['id'], net_name))
        else:
            self.assertRaises(
                self.failure_type,
                self.create_subnet,
                network,
                cidr=IPNetwork('10.10.100.0/24'),
                mask_bits=24, nuagenet=vsd_domain_subnet[0]['ID'],
                gateway='10.10.100.5',
                net_partition=CONF.nuage.nuage_default_netpartition)


class VSDManagedAdminTestNetworks(base.BaseAdminNetworkTest):
    @decorators.attr(type='smoke')
    def test_link_subnet_on_provider_net_l2(self):
        pass

    @decorators.attr(type='smoke')
    def test_link_subnet_on_external_net_l2(self):
        self.assertRaises(
            exceptions.BadRequest, self.admin_subnets_client.create_subnet,
            network_id=CONF.network.public_network_id,
            cidr='10.10.100.0/24',
            ip_version=self._ip_version,
            net_partition=CONF.nuage.nuage_default_netpartition,
            nuagenet=data_utils.rand_uuid())
