# Copyright 2018 NOKIA
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
from netaddr import IPNetwork

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.topology import Topology

from nuage_tempest_plugin.tests.api.l2bridge.base_nuage_l2bridge \
    import BaseNuageL2Bridge

from nuage_tempest_plugin.tests.api.vsd_managed \
    import base_vsd_managed_networks as base_vsd_managed

CONF = Topology.get_conf()


class TestNuageL2Bridge(BaseNuageL2Bridge,
                        base_vsd_managed.BaseVSDManagedNetwork):
    # This class assumes that the following resources are available:
    # physnet1,100,vlan
    # physnet2,100,vlan
    # physnet2,101,vlan

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_create_and_update(self):
        phys_nets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-create-l2bridge-')
        bridge = self.create_l2bridge(name, phys_nets)
        self.assertIsNotNone(bridge, "Unable to create l2bridge")
        self._validate_bridge_config(bridge, name, phys_nets)
        # Update with same info
        self.update_l2bridge(bridge['id'], name=bridge['name'],
                             physnets=phys_nets)
        bridge = self.get_l2bridge(bridge['id'])
        self.assertIsNotNone(bridge, "Unable to find updated l2bridge")
        self._validate_bridge_config(bridge, name, phys_nets)
        # Update with different data of two phys-nets
        phys_nets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 200,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-update-l2bridge-')
        self.update_l2bridge(bridge['id'], name=name, physnets=phys_nets)
        bridge = self.get_l2bridge(bridge['id'])
        self.assertIsNotNone(bridge, "Unable to find updated l2bridge")
        self._validate_bridge_config(bridge, name, phys_nets)
        # Update with different data of one physnet and different VLAN
        phys_nets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 300,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-update-l2bridge-version-2')
        self.update_l2bridge(bridge['id'], name=name, physnets=phys_nets)
        bridge = self.get_l2bridge(bridge['id'])
        self.assertIsNotNone(bridge, "Unable to find updated l2bridge")
        self._validate_bridge_config(bridge, name, phys_nets)

        # check with phys_net not existing in config.
        name = data_utils.rand_name('test-create-l2bridge-')
        phys_nets = [{
            'physnet_name': 'physnet3',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        bridge = self.create_l2bridge(name, phys_nets)
        self.assertIsNotNone(bridge, "Unable to create l2bridge")
        self._validate_bridge_config(bridge, name, phys_nets)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_create_and_update_non_admin_negative(self):
        phys_nets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-create-l2bridge-')
        msg = ".*rule:create_nuage_l2bridge.*"
        self.assertRaisesRegex(exceptions.Forbidden,
                               msg,
                               self.create_l2bridge,
                               name, phys_nets, is_admin=False)

        bridge = self.create_l2bridge(name, phys_nets)

        # Update with different data of two phys-nets
        phys_nets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 200,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-update-l2bridge-')
        msg = "The resource could not be found"
        self.assertRaisesRegex(exceptions.NotFound,
                               msg,
                               self.update_l2bridge,
                               bridge['id'],
                               name,
                               phys_nets,
                               is_admin=False)

    def _validate_bridge_config(self, bridge, name, phys_nets):
        self.assertEqual(name, bridge['name'])
        self.assertEqual(len(phys_nets), len(bridge['physnets']))
        for phys_net in phys_nets:
            found_matching_phys_net = False
            for bridge_physnet in bridge['physnets']:
                if phys_net['physnet_name'] == bridge_physnet['physnet']:
                    self.assertEqual(phys_net['segmentation_id'],
                                     bridge_physnet['segmentation_id'])
                    self.assertEqual(phys_net['segmentation_type'],
                                     bridge_physnet['segmentation_type'])
                    found_matching_phys_net = True
                    break
            self.assertEqual(True, found_matching_phys_net)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_create_update_vlan_negative(self):
        phys_nets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-create-l2bridge-')
        bridge = self.create_l2bridge(name, phys_nets)
        self.assertIsNotNone(bridge, "Unable to create l2bridge")
        self._validate_bridge_config(bridge, name, phys_nets)

        name = data_utils.rand_name('test-create-l2bridge-')
        msg = ("Bad request: Physnet {}, segmentation_id {} and"
               " segmentation_type {} are already in use by"
               " l2bridge {}").format(phys_nets[0]['physnet_name'],
                                      phys_nets[0]['segmentation_id'],
                                      phys_nets[0]['segmentation_type'],
                                      bridge['id'])

        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_l2bridge,
                               name,
                               phys_nets)

        phys_nets = [{
            'physnet_name': 'physnet2',
            'segmentation_id': 300,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-create-l2bridge-2-')
        bridge = self.create_l2bridge(name, phys_nets)
        self.assertIsNotNone(bridge, "Unable to create l2bridge")
        self._validate_bridge_config(bridge, name, phys_nets)

        phys_nets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]

        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.update_l2bridge,
                               bridge['id'],
                               name,
                               phys_nets)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_update_with_networks_neg(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge-dualipv4')
        bridge = self.create_l2bridge(name, physnets)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        self.assertEqual(n1['nuage_l2bridge'], bridge['id'])
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet2'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n2 = self.create_network(network_name=name + '-2',
                                 client=self.admin_manager,
                                 **kwargs)
        self.assertEqual(n2['nuage_l2bridge'], bridge['id'])

        # Update with same info
        self.update_l2bridge(bridge['id'], name=bridge['name'],
                             physnets=physnets)
        bridge = self.get_l2bridge(bridge['id'])
        self._validate_bridge_config(bridge, name, physnets)
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 200,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet3',
            'segmentation_id': 200,
            'segmentation_type': 'vlan'
        }]
        # Update with different info
        msg = ("Physical network physnet1 with segmentation_id 100 and "
               "segmentation_type vlan is currently in use. It is not "
               "allowed to remove a physical network that is in use "
               "from a nuage_l2bridge.")
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.update_l2bridge,
                               bridge['id'], name=bridge['name'],
                               physnets=physnets)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_update_bridged_networks_with_subnets_neg(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge-dualipv4')
        bridge = self.create_l2bridge(name, physnets)
        bridge = self.get_l2bridge(bridge['id'])
        self._validate_bridge_config(bridge, name, physnets)

        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'
                }, {
                    'provider:network_type': 'vxlan'
                }]
        }

        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)

        msg = ("Bad request: A network cannot be attached to an l2bridge"
               " when neutron-dhcp-agent is enabled'")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1,
                                   subnet_name=name + '-subnet-1',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            self.create_subnet(n1, subnet_name=name + '-subnet-1',
                               client=self.admin_manager,
                               cidr=IPNetwork('10.10.1.0/24'),
                               mask_bits=24)
            kwargs = {
                'segments': [
                    {
                        'provider:network_type': 'vlan',
                        'provider:segmentation_id': 20,
                        'provider:physical_network': 'physnet1'
                    }, {
                        'provider:network_type': 'vxlan'
                    }
                ]
            }
            msg = ("Bad request: It is not allowed to change the "
                   "nuage_l2bridge this network is attached to.")

            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.update_network,
                                   network_id=n1['id'],
                                   client=self.admin_manager,
                                   **kwargs)

            msg = ("Bad request: Physical network {} with"
                   " segmentation_id {} and segmentation_type {} belonging to"
                   " this nuage_l2bridge is currently in use. It is not"
                   " allowed to delete it from this nuage_l2bridge").format(
                physnets[0]['physnet_name'],
                physnets[0]['segmentation_id'],
                physnets[0]['segmentation_type'])

            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.delete_l2bridge,
                                   bridge['id'])

            msg = "nuage_l2bridge " + name + " could not be found"

            # update with malformed request
            self.assertRaisesRegex(exceptions.NotFound,
                                   msg,
                                   self.update_l2bridge,
                                   name,
                                   bridge['id'],
                                   physnets)

            # update with same data
            self.update_l2bridge(bridge['id'], name, physnets)

            msg = ("Bad request: Physical network {} with segmentation_id {}"
                   " and segmentation_type {} is currently in use. It is not"
                   " allowed to remove a physical network that is in use"
                   " from a nuage_l2bridge.").format(
                physnets[0]['physnet_name'],
                physnets[0]['segmentation_id'],
                physnets[0]['segmentation_type'],
                bridge['id'])

            physnets = [{
                'physnet_name': 'physnet1',
                'segmentation_id': 200,
                'segmentation_type': 'vlan'
            }, {
                'physnet_name': 'physnet2',
                'segmentation_id': 200,
                'segmentation_type': 'vlan'
            }
            ]
            # update with subnet with a correct request not allowed
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.update_l2bridge,
                                   bridge['id'],
                                   name,
                                   physnets)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_add_segments_to_bridge_with_subnet_with_vm(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'}]
        name = data_utils.rand_name('test-l2bridge-dualipv4')
        bridge = self.create_l2bridge(name, physnets)
        bridge = self.get_l2bridge(bridge['id'])
        self._validate_bridge_config(bridge, name, physnets)

        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }

        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        msg = ("Bad request: A network cannot be attached to an l2bridge"
               " when neutron-dhcp-agent is enabled'")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1, subnet_name=name + '-subnet-1',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            s1 = self.create_subnet(n1, subnet_name=name + '-subnet-1',
                                    client=self.admin_manager,
                                    cidr=IPNetwork('10.10.1.0/24'),
                                    mask_bits=24)

            bridge = self.get_l2bridge(bridge['id'])
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)
            self.assertEqual(s1['nuage_l2bridge'], bridge['id'])

            kwargs = {
                'fixed_ips': [{
                    'ip_address': '10.10.1.10',
                    'subnet_id': s1['id']
                }]
            }
            p1 = self.create_port(n1, self.admin_manager,
                                  **kwargs)

            vport_1 = self.vsd.get_vport(l2domain=l2domain,
                                         by_port_id=p1['id'])
            self.assertIsNotNone(vport_1,
                                 "Vport not created for port in network 1")

            ntw = {'uuid': n1['id'], 'port': p1['id']}
            vm = self.create_server(name='port1-vm-1',
                                    clients=self.admin_manager,
                                    networks=[ntw],
                                    wait_until='ACTIVE')
            self.assertEqual(p1['fixed_ips'][0]['ip_address'],
                             vm['addresses'][n1['name']][0]['addr'])
            self.assertEqual(
                p1['mac_address'],
                vm['addresses'][n1['name']][0]['OS-EXT-IPS-MAC:mac_addr'])
            self.assertEqual(vm['status'], 'ACTIVE')

            physnets = [{
                'physnet_name': 'physnet1',
                'segmentation_id': 100,
                'segmentation_type': 'vlan'
            }, {
                'physnet_name': 'physnet2',
                'segmentation_id': 100,
                'segmentation_type': 'vlan'
            }]

            # Extend the bridge physnets

            self.update_l2bridge(bridge['id'], physnets=physnets)
            bridge = self.get_l2bridge(bridge['id'])
            self._validate_bridge_config(bridge, name, physnets)

            kwargs = {
                'segments': [
                    {
                        'provider:network_type': 'vlan',
                        'provider:segmentation_id': 100,
                        'provider:physical_network': 'physnet2'},
                    {
                        'provider:network_type': 'vxlan'
                    }
                ]
            }

            n2 = self.create_network(network_name=name + '-2',
                                     client=self.admin_manager,
                                     **kwargs)

            s2 = self.create_subnet(n2, subnet_name=name + '-subnet-2',
                                    client=self.admin_manager,
                                    cidr=IPNetwork('10.10.1.0/24'),
                                    mask_bits=24)

            bridge = self.get_l2bridge(bridge['id'])
            self.assertEqual(s2['nuage_l2bridge'], bridge['id'])
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)

            kwargs = {
                'fixed_ips': [{
                    'ip_address': '10.10.1.11',
                    'subnet_id': s2['id']
                }]
            }
            p2 = self.create_port(n2, self.admin_manager,
                                  **kwargs)

            vport_2 = self.vsd.get_vport(l2domain=l2domain,
                                         by_port_id=p2['id'])
            self.assertIsNotNone(vport_2,
                                 "Vport not created for port in network 2")
            ntw = {'uuid': n2['id'], 'port': p2['id']}
            vm2 = self.create_server(name='port2-vm-2',
                                     clients=self.admin_manager,
                                     networks=[ntw],
                                     wait_until='ACTIVE')
            self.assertEqual(p2['fixed_ips'][0]['ip_address'],
                             vm2['addresses'][n2['name']][0]['addr'])
            self.assertEqual(
                p2['mac_address'],
                vm2['addresses'][n2['name']][0]['OS-EXT-IPS-MAC:mac_addr'])
            self.assertEqual(vm2['status'], 'ACTIVE')

            physnets = [{
                'physnet_name': 'physnet1',
                'segmentation_id': 100,
                'segmentation_type': 'vlan'
            }, {
                'physnet_name': 'physnet2',
                'segmentation_id': 100,
                'segmentation_type': 'vlan'
            }, {
                'physnet_name': 'physnet3',
                'segmentation_id': 200,
                'segmentation_type': 'vlan'
            }]

            # Extend the bridge physnets

            self.update_l2bridge(bridge['id'], physnets=physnets)
            bridge = self.get_l2bridge(bridge['id'])
            self._validate_bridge_config(bridge, name, physnets)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_create_bridge_with_network_and_subnet_neg(self):
        name = data_utils.rand_name('test-l2bridge-dualipv4')
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }

        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)

        self.create_subnet(n1, subnet_name=name + '-subnet-subnet-1',
                           client=self.admin_manager,
                           cidr=IPNetwork('10.10.1.0/24'),
                           mask_bits=24)
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]

        msg = ("Bad request: Physical network {} with segmentation_id {} and"
               " segmentation_type {} is currently in use. It is not allowed"
               " to add a physical network that is in use to this"
               " nuage_l2bridge.").format(physnets[0]['physnet_name'],
                                          physnets[0]['segmentation_id'],
                                          physnets[0]['segmentation_type']
                                          )

        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_l2bridge,
                               name,
                               physnets)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_dual_ipv4(self):
        # Scenario 6
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge-dualipv4')
        bridge = self.create_l2bridge(name, physnets)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet2'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n2 = self.create_network(network_name=name + '-2',
                                 client=self.admin_manager,
                                 **kwargs)
        msg = ("Bad request: A network cannot be attached to an l2bridge"
               " when neutron-dhcp-agent is enabled'")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1, subnet_name=name + '-subnet-1',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            s1 = self.create_subnet(n1, subnet_name=name + '-subnet-1',
                                    client=self.admin_manager,
                                    cidr=IPNetwork('10.10.1.0/24'),
                                    mask_bits=24)
            s2 = self.create_subnet(n2, subnet_name=name + '-subnet-2',
                                    client=self.admin_manager,
                                    cidr=IPNetwork('10.10.1.0/24'),
                                    mask_bits=24)
            bridge = self.get_l2bridge(bridge['id'])
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)
            self.assertEqual(s1['nuage_l2bridge'], bridge['id'])
            self.assertEqual(s2['nuage_l2bridge'], bridge['id'])
            kwargs = {
                'fixed_ips': [{
                    'ip_address': '10.10.1.10',
                    'subnet_id': s1['id']
                }]
            }
            p1 = self.create_port(n1, self.admin_manager,
                                  **kwargs)
            kwargs = {
                'fixed_ips': [{
                    'ip_address': '10.10.1.11',
                    'subnet_id': s2['id']
                }]
            }
            p2 = self.create_port(n2, self.admin_manager,
                                  **kwargs)
            vport_1 = self.vsd.get_vport(l2domain=l2domain,
                                         by_port_id=p1['id'])
            self.assertIsNotNone(vport_1,
                                 "Vport not created for port in network 1")
            vport_2 = self.vsd.get_vport(l2domain=l2domain,
                                         by_port_id=p2['id'])
            self.assertIsNotNone(vport_2,
                                 "Vport not created for port in network 2")
            msg = ("Bad request: It is not allowed to update a subnet when"
                   " it is attached to a nuage_l2bridge connected"
                   " to multiple subnets.")

            for sb in [s1, s2]:
                self.assertRaisesRegex(exceptions.BadRequest,
                                       msg,
                                       self.update_subnet,
                                       subnet=sb,
                                       client=self.admin_manager,
                                       enable_dhcp=False)
                host_routes = [{'destination': '10.20.0.0/32',
                                'nexthop': '10.100.1.2'}]
                self.assertRaisesRegex(exceptions.BadRequest,
                                       msg,
                                       self.update_subnet,
                                       subnet=sb,
                                       client=self.admin_manager,
                                       name='update-should-have-failed',
                                       host_routes=host_routes,
                                       dns_nameservers=['7.8.8.8', '7.8.4.4'])
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))

            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)

    def _validate_l2domain_on_vsd(self, bridge, expected_ext_id, l2domain):
        self.assertEqual(expected_ext_id, l2domain.external_id)
        self.assertEqual(bridge['id'], l2domain.name)
        self.assertEqual(bridge['name'], l2domain.description)
        dhcp_options = self.vsd.get_l2domain_dhcp_options(l2domain)
        for dhcp_option in dhcp_options:
            self.assertEqual(expected_ext_id, dhcp_option.external_id)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_dual_dualstack(self):
        # Scenario 5
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 101,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 101,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge-dualipv4')
        bridge = self.create_l2bridge(name, physnets)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 101,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 101,
                    'provider:physical_network': 'physnet2'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n2 = self.create_network(network_name=name + '-2',
                                 client=self.admin_manager,
                                 **kwargs)
        msg = ("Bad request: A network cannot be attached to an l2bridge"
               " when neutron-dhcp-agent is enabled'")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1,
                                   subnet_name=name + '-subnet-14',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            s14 = self.create_subnet(n1, subnet_name=name + '-subnet-14',
                                     client=self.admin_manager,
                                     cidr=IPNetwork('10.10.1.0/24'),
                                     mask_bits=24)
            s16 = self.create_subnet(n1, subnet_name=name + '-subnet-16',
                                     client=self.admin_manager,
                                     ip_version=6,
                                     cidr=IPNetwork('cafe::babe/64'),
                                     mask_bits=64)
            s24 = self.create_subnet(n2, subnet_name=name + '-subnet-24',
                                     client=self.admin_manager,
                                     cidr=IPNetwork('10.10.1.0/24'),
                                     mask_bits=24)
            s26 = self.create_subnet(n2, subnet_name=name + '-subnet-26',
                                     client=self.admin_manager,
                                     ip_version=6,
                                     cidr=IPNetwork('cafe::babe/64'),
                                     mask_bits=64)

            bridge = self.get_l2bridge(bridge['id'])
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)
            self.assertEqual(s16['nuage_l2bridge'], bridge['id'])
            self.assertEqual(s26['nuage_l2bridge'], bridge['id'])
            kwargs = {
                'fixed_ips': [{
                    'ip_address': '10.10.1.10',
                    'subnet_id': s14['id']
                }, {
                    'ip_address': 'cafe::babe:3',
                    'subnet_id': s16['id']
                }]
            }
            p1 = self.create_port(n1, self.admin_manager,
                                  **kwargs)
            kwargs = {
                'fixed_ips': [{
                    'ip_address': '10.10.1.11',
                    'subnet_id': s24['id']
                }, {
                    'ip_address': 'cafe::babe:4',
                    'subnet_id': s26['id']
                }]
            }
            p2 = self.create_port(n2, self.admin_manager,
                                  **kwargs)
            vport_1 = self.vsd.get_vport(l2domain=l2domain,
                                         by_port_id=p1['id'])
            self.assertIsNotNone(vport_1,
                                 "Vport not created for port in network 1")
            vport_2 = self.vsd.get_vport(l2domain=l2domain,
                                         by_port_id=p2['id'])
            self.assertIsNotNone(vport_2,
                                 "Vport not created for port in network 2")
            msg = ("Bad request: It is not allowed to update a subnet when"
                   " it is attached to a nuage_l2bridge connected"
                   " to multiple subnets.")
            for sb in [s14, s16, s24, s26]:
                self.assertRaisesRegex(exceptions.BadRequest,
                                       msg,
                                       self.update_subnet,
                                       subnet=sb,
                                       client=self.admin_manager,
                                       enable_dhcp=False)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_dualstack_ipv4(self):
        # Scenario 4
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 102,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 102,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge-dualipv4')
        bridge = self.create_l2bridge(name, physnets)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 102,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 102,
                    'provider:physical_network': 'physnet2'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n2 = self.create_network(network_name=name + '-2',
                                 client=self.admin_manager,
                                 **kwargs)
        msg = ("Bad request: A network cannot be attached to an l2bridge"
               " when neutron-dhcp-agent is enabled'")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1, subnet_name=name + '-subnet-14',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            s14 = self.create_subnet(n1, subnet_name=name + '-subnet-14',
                                     client=self.admin_manager,
                                     cidr=IPNetwork('10.10.1.0/24'),
                                     mask_bits=24)
            s16 = self.create_subnet(n1, subnet_name=name + '-subnet-16',
                                     client=self.admin_manager,
                                     ip_version=6,
                                     cidr=IPNetwork('cafe::babe/64'),
                                     mask_bits=64)
            s24 = self.create_subnet(n2, subnet_name=name + '-subnet-24',
                                     client=self.admin_manager,
                                     cidr=IPNetwork('10.10.1.0/24'),
                                     mask_bits=24)
            bridge = self.get_l2bridge(bridge['id'])
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)

            kwargs = {
                'fixed_ips': [{
                    'ip_address': '10.10.1.10',
                    'subnet_id': s14['id']
                }, {
                    'ip_address': 'cafe::babe:3',
                    'subnet_id': s16['id']
                }]
            }
            p1 = self.create_port(n1, self.admin_manager,
                                  **kwargs)
            kwargs = {
                'fixed_ips': [{
                    'ip_address': '10.10.1.11',
                    'subnet_id': s24['id']
                }]
            }
            p2 = self.create_port(n2, self.admin_manager,
                                  **kwargs)
            vport_1 = self.vsd.get_vport(l2domain=l2domain,
                                         by_port_id=p1['id'])
            self.assertIsNotNone(vport_1,
                                 "Vport not created for port in network 1")
            vport_2 = self.vsd.get_vport(l2domain=l2domain,
                                         by_port_id=p2['id'])
            self.assertIsNotNone(vport_2,
                                 "Vport not created for port in network 2")
            msg = ("Bad request: It is not allowed to update a subnet when"
                   " it is attached to a nuage_l2bridge connected"
                   " to multiple subnets.")
            for sb in [s14, s16, s24]:
                self.assertRaisesRegex(exceptions.BadRequest,
                                       msg,
                                       self.update_subnet,
                                       subnet=sb,
                                       client=self.admin_manager,
                                       enable_dhcp=False)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_dual_ipv6_negative(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 102,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 102,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge-dualipv4')
        bridge = self.create_l2bridge(name, physnets)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 102,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 102,
                    'provider:physical_network': 'physnet2'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n2 = self.create_network(network_name=name + '-2',
                                 client=self.admin_manager,
                                 **kwargs)
        msg = ("Bad request: A network cannot be attached to an l2bridge"
               " when neutron-dhcp-agent is enabled'")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1, subnet_name=name + '-subnet-16',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            self.create_subnet(n1, subnet_name=name + '-subnet-16',
                               client=self.admin_manager,
                               ip_version=6,
                               cidr=IPNetwork('cafe::babe/64'),
                               mask_bits=64)
            self.create_subnet(n2, subnet_name=name + '-subnet-26',
                               client=self.admin_manager,
                               ip_version=6,
                               cidr=IPNetwork('cafe::babe/64'),
                               mask_bits=64)

            bridge = self.get_l2bridge(bridge['id'])
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            self.assertIsNone(l2domain, 'L2domain was erronously created ')

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_non_normalized_ipv6_negative(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 102,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 102,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge-dualipv4')
        bridge = self.create_l2bridge(name, physnets)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 102,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 102,
                    'provider:physical_network': 'physnet2'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n2 = self.create_network(network_name=name + '-2',
                                 client=self.admin_manager,
                                 **kwargs)
        msg = ("Bad request: A network cannot be attached to an l2bridge"
               " when neutron-dhcp-agent is enabled'")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1, subnet_name=name + '-subnet-16',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            self.create_subnet(n1, subnet_name=name + '-subnet-16',
                               client=self.admin_manager,
                               ip_version=6,
                               cidr=IPNetwork('cafe::babe/64'),
                               mask_bits=64)
            self.create_subnet(n2, subnet_name=name + '-subnet-26',
                               client=self.admin_manager,
                               ip_version=6,
                               cidr=IPNetwork('cafe::babe:0:0/64'),
                               mask_bits=64)

            bridge = self.get_l2bridge(bridge['id'])
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            self.assertIsNone(l2domain, 'L2domain was erronously created ')

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_ipv4_ipv6(self):
        # Scenario 8
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 101,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 101,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge-dualipv4')
        bridge = self.create_l2bridge(name, physnets)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 101,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 101,
                    'provider:physical_network': 'physnet2'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n2 = self.create_network(network_name=name + '-2',
                                 client=self.admin_manager,
                                 **kwargs)
        msg = ("Bad request: A network cannot be attached to an l2bridge"
               " when neutron-dhcp-agent is enabled'")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1, subnet_name=name + '-subnet-14',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            s14 = self.create_subnet(n1, subnet_name=name + '-subnet-14',
                                     client=self.admin_manager,
                                     cidr=IPNetwork('10.10.1.0/24'),
                                     mask_bits=24)
            self.create_subnet(n2, subnet_name=name + '-subnet-26',
                               client=self.admin_manager,
                               ip_version=6,
                               cidr=IPNetwork('cafe::babe/64'),
                               mask_bits=64)
            bridge = self.get_l2bridge(bridge['id'])
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)

            kwargs = {
                'fixed_ips': [{
                    'ip_address': '10.10.1.10',
                    'subnet_id': s14['id']
                }]
            }
            p1 = self.create_port(n1, self.admin_manager,
                                  **kwargs)
            self.assertIsNone(l2domain.ipv6_address)
            vport_1 = self.vsd.get_vport(l2domain=l2domain,
                                         by_port_id=p1['id'])
            self.assertIsNotNone(vport_1,
                                 "Vport not created for port in network 1")

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_first_ipv6_then_ipv4(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 101,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 101,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge-dualipv6')
        bridge = self.create_l2bridge(name, physnets)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 101,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 101,
                    'provider:physical_network': 'physnet2'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n2 = self.create_network(network_name=name + '-2',
                                 client=self.admin_manager,
                                 **kwargs)
        if self.is_dhcp_agent_present():
            msg = ("Bad request: A network cannot be attached to an l2bridge"
                   " when neutron-dhcp-agent is enabled'")
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1, subnet_name=name + '-subnet-14',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            self.create_subnet(n1, subnet_name=name + '-subnet-16',
                               client=self.admin_manager,
                               ip_version=6,
                               cidr=IPNetwork('cafe::/64'),
                               mask_bits=64)
            self.create_subnet(n2, subnet_name=name + '-subnet-24',
                               client=self.admin_manager,
                               cidr=IPNetwork('10.10.1.0/24'),
                               mask_bits=24)
            subnet2_ipv6 = self.create_subnet(n2, subnet_name=name +
                                              '-subnet-26',
                                              client=self.admin_manager,
                                              ip_version=6,
                                              cidr=IPNetwork('cafe::/64'),
                                              mask_bits=64,
                                              cleanup=False)
            bridge = self.get_l2bridge(bridge['id'])
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            self.assertEqual('cafe::/64', l2domain.ipv6_address)
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)
            # Delete + validate
            self.delete_subnet(subnet2_ipv6, client=self.admin_manager)
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            self.assertIsNone(l2domain.ipv6_address,
                              "l2domain is still dualstack")

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_first_ipv4_then_ipv4_then_ipv6(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 101,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 101,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge-dualipv6')
        bridge = self.create_l2bridge(name, physnets)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 101,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 101,
                    'provider:physical_network': 'physnet2'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n2 = self.create_network(network_name=name + '-2',
                                 client=self.admin_manager,
                                 **kwargs)
        if self.is_dhcp_agent_present():
            msg = ("Bad request: A network cannot be attached to an l2bridge"
                   " when neutron-dhcp-agent is enabled'")
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1, subnet_name=name + '-subnet-14',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            self.create_subnet(n1, subnet_name=name + '-subnet-14',
                               client=self.admin_manager,
                               cidr=IPNetwork('10.10.1.0/24'),
                               mask_bits=24)
            self.create_subnet(n2, subnet_name=name + '-subnet-26',
                               client=self.admin_manager,
                               ip_version=6,
                               cidr=IPNetwork('cafe::babe/64'),
                               mask_bits=64)
            self.create_subnet(n2, subnet_name=name + '-subnet-24',
                               client=self.admin_manager,
                               cidr=IPNetwork('10.10.1.0/24'),
                               mask_bits=24)

            bridge = self.get_l2bridge(bridge['id'])
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            self.assertEqual('cafe::/64', l2domain.ipv6_address)
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)
            # Validate subnet mapping of second ipv6?

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_ipv4_ipv6_same_cidr(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        physnets2 = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 200,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 200,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge1-dualipv4-ipv6')
        bridge = self.create_l2bridge(name, physnets)
        name2 = data_utils.rand_name('test-l2bridge2-dualipv4-ipv6')
        bridge2 = self.create_l2bridge(name2, physnets2)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 200,
                    'provider:physical_network': 'physnet2'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n2 = self.create_network(network_name=name2 + '-2',
                                 client=self.admin_manager,
                                 **kwargs)

        msg = ("Bad request: A network cannot be attached to an l2bridge"
               " when neutron-dhcp-agent is enabled'")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1, subnet_name=name + '-subnet-16',
                                   client=self.admin_manager,
                                   ip_version=6,
                                   cidr=IPNetwork('cafe::babe/64'),
                                   mask_bits=64)
        else:
            s14 = self.create_subnet(n1, subnet_name=name + '-subnet-14',
                                     client=self.admin_manager,
                                     cidr=IPNetwork('10.10.1.0/24'),
                                     mask_bits=24)
            self.create_subnet(n1, subnet_name=name + '-subnet-16',
                               client=self.admin_manager,
                               ip_version=6,
                               cidr=IPNetwork('cafe::babe/64'),
                               mask_bits=64)
            s24 = self.create_subnet(n2, subnet_name=name2 + '-subnet-24',
                                     client=self.admin_manager,
                                     cidr=IPNetwork('10.10.1.0/24'),
                                     mask_bits=24)
            self.create_subnet(n2, subnet_name=name2 + '-subnet-26',
                               client=self.admin_manager,
                               ip_version=6,
                               cidr=IPNetwork('cafe::babe/64'),
                               mask_bits=64)
            bridge = self.get_l2bridge(bridge['id'])
            bridge2 = self.get_l2bridge(bridge2['id'])

            self.assertNotEqual(bridge['nuage_subnet_id'],
                                bridge2['nuage_subnet_id'])

            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)

            l2domain2 = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge2['nuage_subnet_id']))
            expected_ext_id = bridge2['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge2, expected_ext_id, l2domain2)

            p1 = self.create_port(n1, self.admin_manager)
            vport_1 = self.vsd.get_vport(l2domain=l2domain,
                                         by_port_id=p1['id'])
            self.assertIsNotNone(vport_1,
                                 "Vport not created for port in network 1")
            p2 = self.create_port(n2, self.admin_manager)
            vport_2 = self.vsd.get_vport(l2domain=l2domain2,
                                         by_port_id=p2['id'])
            self.assertIsNotNone(vport_2,
                                 "Vport not created for port in network 2")

            host_routes = [{'destination': '10.20.0.0/32',
                            'nexthop': '10.100.1.2'}]
            self.update_subnet(subnet=s14, client=self.admin_manager,
                               host_routes=host_routes)

            self.update_subnet(subnet=s24,
                               client=self.admin_manager,
                               host_routes=host_routes,
                               dns_nameservers=['7.8.8.8', '7.8.4.4'])

            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)

            l2domain2 = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge2['nuage_subnet_id']))
            expected_ext_id = bridge2['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge2, expected_ext_id, l2domain2)

            # update bridge name and validate l2-domain.

            self.update_l2bridge(l2bridge_id=bridge['id'],
                                 name=bridge['name'] + '-updated')
            bridge = self.get_l2bridge(bridge['id'])
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_same_cidr_different_bridges_ipv4(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        physnets2 = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 200,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 200,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge1-dualipv4-ipv6')
        bridge = self.create_l2bridge(name, physnets)
        name2 = data_utils.rand_name('test-l2bridge2-dualipv4-ipv6')
        bridge2 = self.create_l2bridge(name2, physnets2)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 200,
                    'provider:physical_network': 'physnet2'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n2 = self.create_network(network_name=name + '-2',
                                 client=self.admin_manager,
                                 **kwargs)
        msg = ("Bad request: A network cannot be attached to an l2bridge"
               " when neutron-dhcp-agent is enabled'")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1,
                                   subnet_name=name + '-subnet-1',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            s1 = self.create_subnet(n1, subnet_name=name + '-subnet-1',
                                    client=self.admin_manager,
                                    cidr=IPNetwork('10.10.1.0/24'),
                                    mask_bits=24)
            s2 = self.create_subnet(n2, subnet_name=name + '-subnet-2',
                                    client=self.admin_manager,
                                    cidr=IPNetwork('10.10.1.0/24'),
                                    mask_bits=24)
            bridge = self.get_l2bridge(bridge['id'])
            bridge2 = self.get_l2bridge(bridge2['id'])
            self.assertNotEqual(bridge['nuage_subnet_id'],
                                bridge2['nuage_subnet_id'])
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)

            l2domain2 = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge2['nuage_subnet_id']))
            expected_ext_id = bridge2['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge2, expected_ext_id, l2domain2)
            kwargs = {
                'fixed_ips': [{
                    'ip_address': '10.10.1.10',
                    'subnet_id': s1['id']
                }]
            }
            p1 = self.create_port(n1, self.admin_manager,
                                  **kwargs)
            kwargs = {
                'fixed_ips': [{
                    'ip_address': '10.10.1.11',
                    'subnet_id': s2['id']
                }]
            }
            p2 = self.create_port(n2, self.admin_manager,
                                  **kwargs)
            vport_1 = self.vsd.get_vport(l2domain=l2domain,
                                         by_port_id=p1['id'])
            self.assertIsNotNone(vport_1,
                                 "Vport not created for port in network 1")
            vport_2 = self.vsd.get_vport(l2domain=l2domain2,
                                         by_port_id=p2['id'])
            self.assertIsNotNone(vport_2,
                                 "Vport not created for port in network 2")

            self.update_subnet(subnet=s1, client=self.admin_manager,
                               enable_dhcp=False)
            host_routes = [{'destination': '10.20.0.0/32',
                            'nexthop': '10.100.1.2'}]
            self.update_subnet(subnet=s2,
                               client=self.admin_manager,
                               host_routes=host_routes,
                               dns_nameservers=['7.8.8.8', '7.8.4.4'])

            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)

            l2domain2 = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge2['nuage_subnet_id']))
            expected_ext_id = bridge2['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge2, expected_ext_id, l2domain2)

            # update bridge name and validate l2-domain.

            self.update_l2bridge(l2bridge_id=bridge['id'],
                                 name=bridge['name'] + '-updated')
            bridge = self.get_l2bridge(bridge['id'])
            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_same_cidr_one_bridged_other_non_bridged(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge-dualipv4')
        bridge = self.create_l2bridge(name, physnets)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        n2 = self.create_network(network_name=name + '-2')
        msg = ("Bad request: A network cannot be attached to an l2bridge"
               " when neutron-dhcp-agent is enabled'")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1,
                                   subnet_name=name + '-subnet-1',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            s1 = self.create_subnet(n1, subnet_name=name + '-subnet-1',
                                    client=self.admin_manager,
                                    cidr=IPNetwork('10.10.1.0/24'),
                                    mask_bits=24)
            s2 = self.create_subnet(n2, subnet_name=name + '-subnet-2',
                                    client=self.admin_manager,
                                    cidr=IPNetwork('10.10.1.0/24'),
                                    mask_bits=24)
            bridge = self.get_l2bridge(bridge['id'])

            l2domain2 = self.vsd.get_l2domain(by_subnet_id=s2['id'])

            self.assertNotEqual(bridge['nuage_subnet_id'],
                                l2domain2.id)
            expected_ext_id = s2['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(s2, expected_ext_id, l2domain2)

            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)

            kwargs = {
                'fixed_ips': [{
                    'ip_address': '10.10.1.10',
                    'subnet_id': s1['id']
                }]
            }
            p1 = self.create_port(n1, self.admin_manager,
                                  **kwargs)
            kwargs = {
                'fixed_ips': [{
                    'ip_address': '10.10.1.11',
                    'subnet_id': s2['id']
                }]
            }
            p2 = self.create_port(n2, self.admin_manager,
                                  **kwargs)
            vport_1 = self.vsd.get_vport(l2domain=l2domain,
                                         by_port_id=p1['id'])
            self.assertIsNotNone(vport_1,
                                 "Vport not created for port in network 1")
            vport_2 = self.vsd.get_vport(l2domain=l2domain2,
                                         by_port_id=p2['id'])
            self.assertIsNotNone(vport_2,
                                 "Vport not created for port in network 2")

            self.update_subnet(subnet=s1, client=self.admin_manager,
                               enable_dhcp=False)
            host_routes = [{'destination': '10.20.0.0/32',
                            'nexthop': '10.100.1.2'}]
            self.update_subnet(subnet=s2,
                               client=self.admin_manager,
                               host_routes=host_routes,
                               dns_nameservers=['7.8.8.8', '7.8.4.4'])

            expected_ext_id = s2['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(s2, expected_ext_id, l2domain2)

            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_multiple_subnets_bridged_other_non_bridged(self):
        phys_nets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge-dualipv4')
        bridge = self.create_l2bridge(name, phys_nets)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet2'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n2 = self.create_network(network_name=name + '-2',
                                 client=self.admin_manager,
                                 **kwargs)
        msg = ("Bad request: A network cannot be attached to an l2bridge"
               " when neutron-dhcp-agent is enabled'")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1,
                                   subnet_name=name + '-subnet-1',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            self.create_subnet(n1, subnet_name=name + '-subnet-1',
                               client=self.admin_manager,
                               cidr=IPNetwork('10.10.1.0/24'),
                               mask_bits=24)
            msg = ('Bad request: A network attached to a nuage_l2bridge cannot'
                   ' have more than one ipv4 or more than one ipv6 subnet.')
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1, subnet_name=name + '-subnet-2',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('1.1.1.0/24'),
                                   mask_bits=24)
            msg = ('Bad request: The gateway_ip associated with nuage_l2bridge'
                   ' {} is'
                   ' 10.10.1.1. 10.10.1.2 is not compatible.').format(
                bridge['id'])
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n2, subnet_name=name + '-subnet-2',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   gateway='10.10.1.2',
                                   mask_bits=24)
            msg = ('Bad request: The enable_dhcp associated with '
                   'nuage_l2bridge {} is'
                   ' True. False is not compatible.').format(
                bridge['id'])
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n2, subnet_name=name + '-subnet-2',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   enable_dhcp=False,
                                   mask_bits=24)
            host_routes = [{'destination': '10.20.0.0/32',
                            'nexthop': '10.100.1.2'}]
            msg = ('Bad request: The host_routes associated with '
                   'nuage_l2bridge {}').format(bridge['id'])
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n2,
                                   subnet_name='create-subnet-fails',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24,
                                   host_routes=host_routes)
            msg = ('Bad request: The dns_nameservers associated with '
                   'nuage_l2bridge {}').format(bridge['id'])
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n2,
                                   subnet_name='create-subnet-fails',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24,
                                   dns_nameservers=['7.8.8.8'])
            # ipv6
            self.create_subnet(n1, subnet_name=name + '-subnet-1-ipv6',
                               client=self.admin_manager,
                               cidr=IPNetwork('cafe::/64'),
                               ip_version=6,
                               mask_bits=64)
            msg = ('Bad request: The cidr associated with nuage_l2bridge {} is'
                   ' cafe::/64. 10::/64 is not compatible.').format(
                bridge['id'])
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n2, subnet_name=name + '-subnet-2',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10::/64'),
                                   ip_version=6,
                                   mask_bits=64)
            msg = ('Bad request: The gateway_ip associated with '
                   'nuage_l2bridge {} is'
                   ' cafe::1. cafe::2 is not compatible.').format(
                bridge['id'])
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n2, subnet_name=name + '-subnet-2',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('cafe::/64'),
                                   ip_version=6,
                                   gateway='cafe::2',
                                   mask_bits=64)
            msg = ('Bad request: The enable_dhcp associated with '
                   'nuage_l2bridge {} is'
                   ' True. False is not compatible.').format(
                bridge['id'])
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n2, subnet_name=name + '-subnet-2',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('cafe::/64'),
                                   ip_version=6,
                                   enable_dhcp=False,
                                   mask_bits=64)
            msg = ('Bad request: The ipv6_ra_mode associated with '
                   'nuage_l2bridge {} is'
                   ' None. dhcpv6-stateful is not compatible.').format(
                bridge['id'])
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n2, subnet_name=name + '-subnet-2',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('cafe::/64'),
                                   ip_version=6,
                                   ipv6_ra_mode='dhcpv6-stateful',
                                   mask_bits=64)
            msg = ('Bad request: The ipv6_address_mode associated with '
                   'nuage_l2bridge {} is'
                   ' None. dhcpv6-stateful is not compatible.').format(
                bridge['id'])
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n2, subnet_name=name + '-subnet-2',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('cafe::/64'),
                                   ip_version=6,
                                   ipv6_address_mode='dhcpv6-stateful',
                                   mask_bits=64)

            bridge = self.get_l2bridge(bridge['id'])

            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)

            kwargs = {
                'segments': [
                    {
                        'provider:network_type': 'vlan',
                        'provider:segmentation_id': 500,
                        'provider:physical_network': 'physnet2'},
                    {
                        'provider:network_type': 'vxlan'
                    }
                ]
            }
            n3 = self.create_network(network_name=name + '-3',
                                     client=self.admin_manager,
                                     **kwargs)

            s1_non_bridge = self.create_subnet(n3,
                                               subnet_name=name + '-subnet-2',
                                               client=self.admin_manager,
                                               cidr=IPNetwork('10.10.1.0/24'),
                                               mask_bits=24)

            s2_non_bridge = self.create_subnet(n3,
                                               subnet_name=name + '-subnet-2',
                                               client=self.admin_manager,
                                               cidr=IPNetwork('1.1.1.0/24'),
                                               mask_bits=24)

            non_bridge_l2domain1 = self.vsd.get_l2domain(
                by_subnet_id=s1_non_bridge['id'])
            non_bridge_l2domain2 = self.vsd.get_l2domain(
                by_subnet_id=s2_non_bridge['id'])

            self.assertNotEqual(bridge['nuage_subnet_id'],
                                non_bridge_l2domain1.id)
            self.assertIsNotNone(non_bridge_l2domain2)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_dualstack_subnets_bridged_and_non_bridged(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge1-dualipv4-ipv6')
        bridge = self.create_l2bridge(name, physnets)
        name2 = data_utils.rand_name('test-l2bridge2-dualipv4-ipv6')
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 200,
                    'provider:physical_network': 'physnet2'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n2 = self.create_network(network_name=name2 + '-2',
                                 client=self.admin_manager,
                                 **kwargs)
        msg = ("Bad request: A network cannot be attached to an l2bridge"
               " when neutron-dhcp-agent is enabled'")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1,
                                   subnet_name=name + '-subnet-14',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            s14 = self.create_subnet(n1, subnet_name=name + '-subnet-14',
                                     client=self.admin_manager,
                                     cidr=IPNetwork('10.10.1.0/24'),
                                     mask_bits=24)
            self.create_subnet(n1, subnet_name=name + '-subnet-16',
                               client=self.admin_manager,
                               ip_version=6,
                               cidr=IPNetwork('cafe::babe/64'),
                               mask_bits=64)
            s24 = self.create_subnet(n2, subnet_name=name2 + '-subnet-24',
                                     client=self.admin_manager,
                                     cidr=IPNetwork('10.10.1.0/24'),
                                     mask_bits=24)
            self.create_subnet(n2, subnet_name=name2 + '-subnet-26',
                               client=self.admin_manager,
                               ip_version=6,
                               cidr=IPNetwork('cafe::babe/64'),
                               mask_bits=64)
            bridge = self.get_l2bridge(bridge['id'])

            non_bridge_l2domain1 = self.vsd.get_l2domain(
                by_subnet_id=s24['id'])
            self.assertNotEqual(bridge['nuage_subnet_id'],
                                non_bridge_l2domain1.id)

            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)

            host_routes = [{'destination': '10.20.0.0/32',
                            'nexthop': '10.100.1.2'}]

            self.update_subnet(subnet=s24,
                               client=self.admin_manager,
                               host_routes=host_routes,
                               dns_nameservers=['7.8.8.8', '7.8.4.4'])

            self.update_subnet(subnet=s14, client=self.admin_manager,
                               host_routes=host_routes)

            l2domain = self.vsd.get_l2domain(
                vspk_filter='ID == "{}"'.format(bridge['nuage_subnet_id']))
            expected_ext_id = bridge['id'] + '@' + CONF.nuage.nuage_cms_id
            self._validate_l2domain_on_vsd(bridge, expected_ext_id, l2domain)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_vsd_managed_subnet_negative(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge1-vsd-managed')
        bridge = self.create_l2bridge(name, physnets)
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name, cidr=cidr, gateway='10.10.100.1')
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])[0]
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)

        msg = ("Bad request: The network is attached to nuage_l2bridge " +
               bridge['id'] + ".Please consult"
                              " documentation on how to achieve SRIOVduplex "
                              "for VSD managed subnets")
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_subnet,
                               n1, subnet_name=name + '-subnet-1',
                               client=self.admin_manager,
                               gateway=None, cidr=cidr,
                               mask_bits=24, nuagenet=vsd_l2dom['ID'],
                               net_partition=Topology.def_netpartition,
                               enable_dhcp=True)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_router_external_network_negative(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge1-router-external')
        self.create_l2bridge(name, physnets)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ],
            'router:external': True
        }
        msg = ('Bad request: It is not allowed to create a network as external'
               ' in a physical_network attached to a nuage_l2bridge')
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_network,
                               network_name=name + '-1',
                               client=self.admin_manager,
                               **kwargs)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_shared_network_negative(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge1-router-external')
        self.create_l2bridge(name, physnets)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ],
            'shared': True
        }
        msg = ('Bad request: It is not allowed to create a shared network'
               ' in a physical_network attached to a nuage_l2bridge')
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_network,
                               network_name=name + '-1',
                               client=self.admin_manager,
                               **kwargs)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_with_subnet_delete_check_bridge_mapping(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge-dualipv4')
        bridge = self.create_l2bridge(name, physnets)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        msg = ("Bad request: A network cannot be attached to an l2bridge"
               " when neutron-dhcp-agent is enabled'")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1, subnet_name=name + '-subnet-1',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            s1 = self.create_subnet(n1, subnet_name=name + '-subnet-1',
                                    client=self.admin_manager,
                                    cidr=IPNetwork('10.10.1.0/24'),
                                    mask_bits=24, cleanup=False)

            self.delete_subnet(s1, client=self.admin_manager)

            bridge = self.get_l2bridge(bridge['id'])

            self.assertEqual(bridge['nuage_subnet_id'], None)

    @decorators.attr(type='smoke')
    def test_nuage_l2bridge_with_dualstack_delete_check_bridge_mapping(self):
        physnets = [{
            'physnet_name': 'physnet1',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }, {
            'physnet_name': 'physnet2',
            'segmentation_id': 100,
            'segmentation_type': 'vlan'
        }]
        name = data_utils.rand_name('test-l2bridge-dualipv4')
        bridge = self.create_l2bridge(name, physnets)
        kwargs = {
            'segments': [
                {
                    'provider:network_type': 'vlan',
                    'provider:segmentation_id': 100,
                    'provider:physical_network': 'physnet1'},
                {
                    'provider:network_type': 'vxlan'
                }
            ]
        }
        n1 = self.create_network(network_name=name + '-1',
                                 client=self.admin_manager,
                                 **kwargs)
        msg = ("Bad request: A network cannot be attached to an l2bridge"
               " when neutron-dhcp-agent is enabled'")
        if self.is_dhcp_agent_present():
            self.assertRaisesRegex(exceptions.BadRequest,
                                   msg,
                                   self.create_subnet,
                                   n1, subnet_name=name + '-subnet-1',
                                   client=self.admin_manager,
                                   cidr=IPNetwork('10.10.1.0/24'),
                                   mask_bits=24)
        else:
            s1 = self.create_subnet(n1, subnet_name=name + '-subnet-1',
                                    client=self.admin_manager,
                                    cidr=IPNetwork('10.10.1.0/24'),
                                    mask_bits=24, cleanup=False)
            s16 = self.create_subnet(n1, subnet_name=name + '-subnet-16',
                                     client=self.admin_manager,
                                     ip_version=6,
                                     cidr=IPNetwork('cafe::babe/64'),
                                     mask_bits=64, cleanup=False)

            self.delete_subnet(s16, client=self.admin_manager)
            bridge = self.get_l2bridge(bridge['id'])

            self.assertNotEmpty(bridge['nuage_subnet_id'])
            self.delete_subnet(s1, client=self.admin_manager)

            bridge = self.get_l2bridge(bridge['id'])
            self.assertEqual(bridge['nuage_subnet_id'], None)
