# Copyright 2020 NOKIA
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
from oslo_utils import uuidutils
import testtools

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology

from tempest.lib import exceptions
from tempest.test import decorators

CONF = Topology.get_conf()


class NuageHybridMplsTest(NuageBaseTest):

    @classmethod
    def skip_checks(cls):
        super(NuageHybridMplsTest, cls).skip_checks()
        if not CONF.nuage_sut.nuage_hybrid_mpls_enabled:
            raise cls.skipException('nuage_hybrid_mpls type driver '
                                    'not enabled in tempest.conf')

    def create_l2_domain_tunnel_type(self, tunnel_type):
        l2template = self.vsd_create_l2domain_template(
            cidr4=IPNetwork('100.0.0.0/24'),
            gateway4='100.0.0.1')
        kwargs = {'l2_encap_type': tunnel_type}
        l2domain = self.vsd_create_l2domain(template=l2template, **kwargs)
        return l2domain

    def create_l3_subnet_tunnel_type(self, tunnel_type):
        l3template = self.vsd_create_l3domain_template()
        l3domain = self.vsd_create_l3domain(template_id=l3template.id)
        zone = self.vsd_create_zone(domain=l3domain)
        kwargs = {'l2_encap_type': tunnel_type}
        l3subnet = self.create_vsd_subnet(zone=zone,
                                          cidr4=IPNetwork('20.0.0.0/24'),
                                          gateway4='20.0.0.1',
                                          **kwargs)
        return l3subnet

    @decorators.attr(type='smoke')
    def test_os_managed_subnet_tunnel_type_mpls(self):
        # Nuage Hybrid MPLS Network
        kwargs = {'provider:network_type': 'nuage_hybrid_mpls'}
        network = self.create_network(manager=self.admin_manager, **kwargs)
        subnet = self.create_subnet(network,
                                    ip_version=4,
                                    manager=self.admin_manager)

        l2domain = self.vsd.get_l2domain(by_network_id=network['id'],
                                         cidr=subnet['cidr'])
        self.assertEqual('MPLS', l2domain.l2_encap_type)

        # Nuage Hybrid MPLS Segment
        segments = [{'provider:network_type': 'nuage_hybrid_mpls'},
                    {'provider:network_type': 'vlan',
                     'provider:segmentation_id': 210,
                     'provider:physical_network': 'physnet2'}]
        kwargs = {'segments': segments}
        network = self.create_network(manager=self.admin_manager, **kwargs)

        subnet = self.create_subnet(network,
                                    ip_version=4,
                                    manager=self.admin_manager)
        self.assertIsNotNone(subnet)

        l2domain = self.vsd.get_l2domain(by_network_id=network['id'],
                                         cidr=subnet['cidr'])
        self.assertEqual('MPLS', l2domain.l2_encap_type)

    @decorators.attr(type='smoke')
    def test_vsd_managed_subnet_tunnel_type_mpls(self):
        # L2 Domain
        l2domain = self.create_l2_domain_tunnel_type('MPLS')
        kwargs = {'provider:network_type': 'nuage_hybrid_mpls'}
        network = self.create_network(manager=self.admin_manager, **kwargs)
        self.create_l2_vsd_managed_subnet(network, l2domain,
                                          manager=self.admin_manager)

        # L3 Subnet
        network = self.create_network(manager=self.admin_manager, **kwargs)
        l3subnet = self.create_l3_subnet_tunnel_type('MPLS')
        self.create_l3_vsd_managed_subnet(network, l3subnet,
                                          manager=self.admin_manager)

    def test_vsd_managed_subnet_tunnel_type_mpls_neg(self):
        # L2 Domain
        l2domain = self.create_l2_domain_tunnel_type('MPLS')
        network = self.create_network()
        kwargs = {'vsd_l2domain': l2domain}
        msg = ('Bad request: Provided Nuage subnet has tunnel type MPLS '
               'which is not supported by VXLAN networks')
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_l2_vsd_managed_subnet,
                               network,
                               **kwargs)

        # L3 Subnet
        l3subnet = self.create_l3_subnet_tunnel_type('MPLS')
        kwargs = {'vsd_subnet': l3subnet}
        msg = ('Bad request: Provided Nuage subnet has tunnel type MPLS '
               'which is not supported by VXLAN networks')
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_l3_vsd_managed_subnet,
                               network,
                               **kwargs)

    def test_vsd_managed_subnet_tunnel_type_vxlan_neg(self):
        # L2 Domain
        l2domain = self.create_l2_domain_tunnel_type('VXLAN')
        kwargs = {'provider:network_type': 'nuage_hybrid_mpls'}
        network = self.create_network(manager=self.admin_manager, **kwargs)

        kwargs = {'vsd_l2domain': l2domain,
                  "manager": self.admin_manager}
        msg = ('Bad request: Provided Nuage subnet has tunnel type VXLAN '
               'which is not supported by NUAGE_HYBRID_MPLS networks')
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_l2_vsd_managed_subnet,
                               network,
                               **kwargs)

        # L3 Subnet
        l3subnet = self.create_l3_subnet_tunnel_type('VXLAN')
        kwargs = {'vsd_subnet': l3subnet,
                  "manager": self.admin_manager}
        msg = ('Bad request: Provided Nuage subnet has tunnel type VXLAN '
               'which is not supported by NUAGE_HYBRID_MPLS networks')
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_l3_vsd_managed_subnet,
                               network,
                               **kwargs)

    @decorators.attr(type='smoke')
    @testtools.skipIf(Topology.at_openstack('queens'),
                      'SegmentClient not loaded')
    def test_router_interface_blocked_tunnel_type_mpls(self):
        # Nuage Hybrid MPLS Network
        kwargs = {'provider:network_type': 'nuage_hybrid_mpls'}
        network = self.create_network(manager=self.admin_manager, **kwargs)
        subnet = self.create_subnet(network,
                                    ip_version=4,
                                    manager=self.admin_manager)

        router = self.create_router(manager=self.admin_manager)
        kwargs = {'router_id': router['id'],
                  "subnet_id": subnet['id'],
                  "manager": self.admin_manager}
        msg = ("It is not allowed to add a router interface to a "
               "network type nuage_hybrid_mpls, or if it has a "
               "segment of this type.")
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_router_interface,
                               **kwargs)

        # Nuage Hybrid MPLS Segment
        kwargs = {'provider:network_type': 'nuage_hybrid_mpls'}
        network = self.create_network(manager=self.admin_manager, **kwargs)
        subnet = self.create_subnet(network,
                                    ip_version=4,
                                    manager=self.admin_manager)

        kwargs = {'network_id': network['id'],
                  'network_type': 'vlan',
                  'physical_network': 'physnet2',
                  'segmentation_id': 210}
        # This goes to update_network_precommit
        self.create_segment(**kwargs)
        router = self.create_router(manager=self.admin_manager)
        kwargs = {'router_id': router['id'],
                  "subnet_id": subnet['id'],
                  "manager": self.admin_manager}
        msg = ("It is not allowed to add a router interface to a "
               "network type nuage_hybrid_mpls, or if it has a "
               "segment of this type.")
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_router_interface,
                               **kwargs)

    @decorators.attr(type='smoke')
    @testtools.skipIf(Topology.at_openstack('queens'),
                      'SegmentClient not loaded')
    def test_vxlan_mpls_segments_blocked_single_network(self):
        # Vxlan must be the default segment. Otherwise neutron rejects
        # the operation because the default MTU of vlan or nuage_hybrid_mpls
        # is greater than the one of vxlan

        # This goes to create_network_precommit
        segments = [{"provider:network_type": "vxlan"},
                    {"provider:network_type": "vxlan"},
                    {"provider:network_type": "nuage_hybrid_mpls"},
                    {"provider:network_type": "vlan",
                     "provider:physical_network": "physnet2",
                     "provider:segmentation_id": 210}]
        kwargs = {'segments': segments,
                  "manager": self.admin_manager}
        msg = ("It is not allowed to have both vxlan and "
               "nuage_hybrid_mpls segments in a single network")
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_network,
                               **kwargs)

        # This goes to update_network_precommit
        kwargs = {'provider:network_type': 'vxlan'}
        network = self.create_network(manager=self.admin_manager, **kwargs)
        kwargs = {'network_id': network['id'],
                  'network_type': 'vlan',
                  'physical_network': 'physnet2',
                  'segmentation_id': 210}
        self.assertIsNotNone(self.create_segment(**kwargs))
        kwargs = {'network_id': network['id'],
                  'network_type': 'nuage_hybrid_mpls'}
        msg = ("It is not allowed to have both vxlan and "
               "nuage_hybrid_mpls segments in a single network")
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_segment,
                               **kwargs)

    @decorators.attr(type='smoke')
    def test_virtio_port_blocked_tunnel_type_mpls(self):
        kwargs = {'provider:network_type': 'nuage_hybrid_mpls'}
        network = self.create_network(manager=self.admin_manager, **kwargs)

        # L3 Subnet
        l3subnet = self.create_l3_subnet_tunnel_type('MPLS')
        self.create_l3_vsd_managed_subnet(network, l3subnet,
                                          manager=self.admin_manager)

        kwargs = {
            'device_owner': 'compute:nova',
            'device_id': uuidutils.generate_uuid(),
            'binding:host_id': 'dummy',
            'network': network,
            'manager': self.admin_manager
        }
        msg = ('Bad request: Virtio port is not allowed in nuage_'
               'mpls_hybrid networks')
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_port,
                               **kwargs)
