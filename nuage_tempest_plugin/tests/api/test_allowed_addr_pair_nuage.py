# Copyright 2014 OpenStack Foundation
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

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

from tempest.api.network import base
from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.test import decorators

CONF = Topology.get_conf()


class AllowedAddressPairTest(base.BaseNetworkTest):
    _interface = 'json'
    _address_in_vsd = 'address'

    @classmethod
    def setup_clients(cls):
        super(AllowedAddressPairTest, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(AllowedAddressPairTest, cls).resource_setup()
        if not utils.is_extension_enabled('allowed-address-pairs', 'network'):
            msg = "Allowed Address Pairs extension not enabled."
            raise cls.skipException(msg)

        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)

        cls.ext_net_id = CONF.network.public_network_id
        cls.l3network = cls.create_network()
        cls.l3subnet = cls.create_subnet(cls.l3network)
        cls.router = cls.create_router(data_utils.rand_name('router-'),
                                       external_network_id=cls.ext_net_id)
        cls.create_router_interface(cls.router['id'], cls.l3subnet['id'])

    def _create_port_with_allowed_address_pair(self, allowed_address_pairs,
                                               net_id, **kwargs):

        if CONF.network.port_vnic_type and 'binding:vnic_type' not in kwargs:
            kwargs['binding:vnic_type'] = CONF.network.port_vnic_type
        if CONF.network.port_profile and 'binding:profile' not in kwargs:
            kwargs['binding:profile'] = CONF.network.port_profile

        body = self.ports_client.create_port(
            network_id=net_id,
            allowed_address_pairs=allowed_address_pairs, **kwargs)
        self.addCleanup(self.ports_client.delete_port, body['port']['id'])
        return body

    def _verify_port_by_id(self, port_id):
        body = self.ports_client.list_ports()
        ports = body['ports']
        port = [p for p in ports if p['id'] == port_id]
        msg = 'Created port not found in list of ports returned by Neutron'
        self.assertTrue(port, msg)

    def _verify_port_allowed_address_fields(self, port,
                                            addrpair_ip, addrpair_mac):
        ip_address = port['allowed_address_pairs'][0]['ip_address']
        mac_address = port['allowed_address_pairs'][0]['mac_address']
        self.assertEqual(ip_address, addrpair_ip)
        self.assertEqual(mac_address, addrpair_mac)

    def create_port(self, network, cleanup=True, **kwargs):
        port = super(AllowedAddressPairTest, self).create_port(network,
                                                               **kwargs)
        if cleanup:
            self.addCleanup(self.ports_client.delete_port, port['id'])
        return port

    def test_create_address_pair_on_l2domain_with_no_mac(self):
        # Create port with allowed address pair attribute
        # For /32 cidr
        addrpair_port = self.create_port(self.network)
        allowed_address_pairs = [{'ip_address':
                                  addrpair_port['fixed_ips'][0]['ip_address']}]
        body = self._create_port_with_allowed_address_pair(
            allowed_address_pairs, self.network['id'])
        port = body['port']

        # routersubnetbind
        new_router = self.create_router('r')
        self.create_router_interface(new_router['id'],
                                     port['fixed_ips'][0]['subnet_id'])
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, addrpair_port['fixed_ips'][0]['ip_address'],
            port['mac_address'])
        self.routers_client.remove_router_interface(
            new_router['id'], subnet_id=port['fixed_ips'][0]['subnet_id'])
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, addrpair_port['fixed_ips'][0]['ip_address'],
            port['mac_address'])
        # Check address spoofing is disabled on vport in VSD
        nuage_subnet = self.nuage_client.get_l2domain(
            filters=['externalID', self._address_in_vsd],
            filter_value=[self.subnet['network_id'],
                          self.subnet['cidr']])
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.L2_DOMAIN,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])

    def test_create_address_pair_on_l2domain_update_fixed_ip(self):
        # Create port with allowed address pair attribute
        # For /32 cidr
        port = self.create_port(self.network)
        allowed_address_pairs = [{'ip_address':
                                  port['fixed_ips'][0]['ip_address'],
                                  'mac_address': port['mac_address']}]
        port = self.update_port(port,
                                allowed_address_pairs=allowed_address_pairs)

        # Check address spoofing is disabled on vport in VSD
        nuage_subnet = self.nuage_client.get_l2domain(
            filters=['externalID', self._address_in_vsd],
            filter_value=[self.subnet['network_id'],
                          self.subnet['cidr']])
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.L2_DOMAIN,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.DISABLED,
                         nuage_vport[0]['addressSpoofing'])

        # Update fixed ip
        # Get free IP in subnet
        addrpair_port = self.create_port(self.network, cleanup=False)
        ip = addrpair_port['fixed_ips'][0]['ip_address']
        self.ports_client.delete_port(addrpair_port['id'])
        subnet_id = port['fixed_ips'][0]['subnet_id']
        self.update_port(port, fixed_ips=[{
            'subnet_id': subnet_id,
            'ip_address': ip}])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.L2_DOMAIN,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])

    @decorators.attr(type='smoke')
    def test_create_address_pair_on_l2domain_with_mac_routersubnetbind(self):
        # Create port with allowed address pair attribute
        # For /32 cidr

        addrpair_port = self.create_port(self.network)
        allowed_address_pairs = [{'ip_address':
                                  addrpair_port['fixed_ips'][0]['ip_address'],
                                  'mac_address':
                                  addrpair_port['mac_address']}]
        body = self._create_port_with_allowed_address_pair(
            allowed_address_pairs, self.network['id'])
        port = body['port']

        # routersubnetbind
        new_router = self.create_router('r')
        self.create_router_interface(new_router['id'],
                                     port['fixed_ips'][0]['subnet_id'])
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, addrpair_port['fixed_ips'][0]['ip_address'],
            addrpair_port['mac_address'])
        self.routers_client.remove_router_interface(
            new_router['id'], subnet_id=port['fixed_ips'][0]['subnet_id'])
        self._verify_port_by_id(port['id'])

        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, addrpair_port['fixed_ips'][0]['ip_address'],
            addrpair_port['mac_address'])

        # Check address spoofing is disabled on vport in VSD
        nuage_subnet = self.nuage_client.get_l2domain(
            filters=['externalID', self._address_in_vsd],
            filter_value=[self.subnet['network_id'],
                          self.subnet['cidr']])
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.L2_DOMAIN,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])

    def test_create_address_pair_on_l2domain_with_cidr(self):
        # Create port with AAP for non /32 cidr
        ip_address = '30.30.0.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        body = self._create_port_with_allowed_address_pair(
            allowed_address_pairs, self.network['id'])
        port = body['port']
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, ip_address, mac_address)
        # Check address spoofing is disabled on vport in VSD
        nuage_subnet = self.nuage_client.get_l2domain(
            filters=['externalID', self._address_in_vsd],
            filter_value=[self.subnet['network_id'],
                          self.subnet['cidr']])
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.L2_DOMAIN,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])

    def test_create_address_pair_on_l2domain_with_cidr_routersubnetbind(self):
        # Create port with AAP for non /32 cidr
        ip_address = '30.30.0.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        body = self._create_port_with_allowed_address_pair(
            allowed_address_pairs, self.network['id'])
        port = body['port']

        # routersubnetbind
        new_router = self.create_router('r')
        self.create_router_interface(new_router['id'],
                                     port['fixed_ips'][0]['subnet_id'])
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, ip_address, mac_address)
        self.routers_client.remove_router_interface(
            new_router['id'], subnet_id=port['fixed_ips'][0]['subnet_id'])
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, ip_address, mac_address)
        # Check address spoofing is disabled on vport in VSD
        nuage_subnet = self.nuage_client.get_l2domain(
            filters=['externalID', self._address_in_vsd],
            filter_value=[self.subnet['network_id'],
                          self.subnet['cidr']])
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.L2_DOMAIN,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])

    @decorators.attr(type='smoke')
    def test_create_address_pair_on_l3subnet_with_mac(self):
        # Create port with allowed address pair attribute
        addrpair_port = self.create_port(self.l3network)
        allowed_address_pairs = [{'ip_address':
                                  addrpair_port['fixed_ips'][0]['ip_address'],
                                  'mac_address':
                                  addrpair_port['mac_address']}]
        body = self._create_port_with_allowed_address_pair(
            allowed_address_pairs, self.l3network['id'])
        port = body['port']

        # routersubnetbind
        self.routers_client.remove_router_interface(
            self.router['id'], subnet_id=port['fixed_ips'][0]['subnet_id'])
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, addrpair_port['fixed_ips'][0]['ip_address'],
            addrpair_port['mac_address'])
        self.create_router_interface(self.router['id'],
                                     port['fixed_ips'][0]['subnet_id'])

        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, addrpair_port['fixed_ips'][0]['ip_address'],
            addrpair_port['mac_address'])
        # Check VIP is created in VSD
        l3domain_ext_id = self.nuage_client.get_vsd_external_id(
            self.router['id'])
        nuage_domain = self.nuage_client.get_resource(
            n_constants.DOMAIN,
            filters='externalID',
            filter_value=l3domain_ext_id)
        nuage_subnet = self.nuage_client.get_domain_subnet(
            n_constants.DOMAIN, nuage_domain[0]['ID'],
            filters=['externalID', self._address_in_vsd],
            filter_value=[self.l3subnet['network_id'],
                          self.l3subnet['cidr']])
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.SUBNETWORK,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.DISABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vip = self.nuage_client.get_virtual_ip(
            n_constants.VPORT,
            nuage_vport[0]['ID'],
            filters='virtualIP',
            filter_value=str(addrpair_port['fixed_ips'][0]['ip_address']))
        self.assertEqual(addrpair_port['mac_address'], nuage_vip[0]['MAC'])
        self.assertEqual(nuage_vip[0]['externalID'],
                         self.nuage_client.get_vsd_external_id(
                             port['id']))

    @decorators.attr(type='smoke')
    def test_create_address_pair_on_l3subnet_with_mac_routersubnetbind(self):
        # Create port with allowed address pair attribute
        addrpair_port = self.create_port(self.l3network)
        allowed_address_pairs = [{'ip_address':
                                  addrpair_port['fixed_ips'][0]['ip_address'],
                                  'mac_address':
                                  addrpair_port['mac_address']}]
        body = self._create_port_with_allowed_address_pair(
            allowed_address_pairs, self.l3network['id'])
        port = body['port']

        # routersubnetbind
        self.routers_client.remove_router_interface(
            self.router['id'], subnet_id=port['fixed_ips'][0]['subnet_id'])
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, addrpair_port['fixed_ips'][0]['ip_address'],
            addrpair_port['mac_address'])
        self.create_router_interface(
            self.router['id'], port['fixed_ips'][0]['subnet_id'])
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, addrpair_port['fixed_ips'][0]['ip_address'],
            addrpair_port['mac_address'])
        # Check VIP is created in VSD
        l3domain_ext_id = self.nuage_client.get_vsd_external_id(
            self.router['id'])
        nuage_domain = self.nuage_client.get_resource(
            n_constants.DOMAIN,
            filters='externalID',
            filter_value=l3domain_ext_id)
        nuage_subnet = self.nuage_client.get_domain_subnet(
            n_constants.DOMAIN, nuage_domain[0]['ID'],
            filters=['externalID', self._address_in_vsd],
            filter_value=[self.l3subnet['network_id'],
                          self.l3subnet['cidr']])
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.SUBNETWORK,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.DISABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vip = self.nuage_client.get_virtual_ip(
            n_constants.VPORT,
            nuage_vport[0]['ID'],
            filters='virtualIP',
            filter_value=str(addrpair_port['fixed_ips'][0]['ip_address']))
        self.assertEqual(addrpair_port['mac_address'], nuage_vip[0]['MAC'])
        self.assertEqual(nuage_vip[0]['externalID'],
                         self.nuage_client.get_vsd_external_id(
                             port['id']))

    def test_create_address_pair_on_l3subnet_with_no_mac(self):
        # Create port with allowed address pair attribute
        addrpair_port = self.create_port(self.l3network)
        allowed_address_pairs = [{'ip_address':
                                  addrpair_port['fixed_ips'][0]['ip_address']}]
        body = self._create_port_with_allowed_address_pair(
            allowed_address_pairs, self.l3network['id'])
        port = body['port']
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_by_id(port['id'])
        self._verify_port_allowed_address_fields(
            port, addrpair_port['fixed_ips'][0]['ip_address'],
            port['mac_address'])
        # Check VIP is created in VSD
        l3domain_ext_id = self.nuage_client.get_vsd_external_id(
            self.router['id'])
        nuage_domain = self.nuage_client.get_resource(
            n_constants.DOMAIN,
            filters='externalID',
            filter_value=l3domain_ext_id)
        nuage_subnet = self.nuage_client.get_domain_subnet(
            n_constants.DOMAIN, nuage_domain[0]['ID'],
            filters=['externalID', self._address_in_vsd],
            filter_value=[self.l3subnet['network_id'],
                          self.l3subnet['cidr']])
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.SUBNETWORK,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.DISABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vip = self.nuage_client.get_virtual_ip(
            n_constants.VPORT,
            nuage_vport[0]['ID'],
            filters='virtualIP',
            filter_value=str(addrpair_port['fixed_ips'][0]['ip_address']))
        self.assertEqual(port['mac_address'], nuage_vip[0]['MAC'])
        self.assertEqual(nuage_vip[0]['externalID'],
                         self.nuage_client.get_vsd_external_id(
                             port['id']))

    def test_create_address_pair_on_l3subnet_with_cidr(self):
        # Create port with allowed address pair attribute
        ip_address = '30.30.0.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address':
                                  ip_address, 'mac_address': mac_address}]
        body = self._create_port_with_allowed_address_pair(
            allowed_address_pairs, self.l3network['id'])
        port = body['port']
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, ip_address, mac_address)
        # Check VIP is created in VSD
        l3domain_ext_id = self.nuage_client.get_vsd_external_id(
            self.router['id'])
        nuage_domain = self.nuage_client.get_resource(
            n_constants.DOMAIN,
            filters='externalID',
            filter_value=l3domain_ext_id)
        nuage_subnet = self.nuage_client.get_domain_subnet(
            n_constants.DOMAIN,
            nuage_domain[0]['ID'],
            filters=['externalID', self._address_in_vsd],
            filter_value=[self.l3subnet['network_id'],
                          self.l3subnet['cidr']])
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.SUBNETWORK,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])

    def test_create_address_pair_on_l3subnet_with_cidr_routersubnetbind(self):
        # Create port with allowed address pair attribute
        ip_address = '30.30.0.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address':
                                 ip_address, 'mac_address': mac_address}]
        body = self._create_port_with_allowed_address_pair(
            allowed_address_pairs, self.l3network['id'])
        port = body['port']

        # routersubnetbind
        self.routers_client.remove_router_interface(
            self.router['id'], subnet_id=port['fixed_ips'][0]['subnet_id'])
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, ip_address, mac_address)
        self.create_router_interface(
            self.router['id'], port['fixed_ips'][0]['subnet_id'])
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, ip_address, mac_address)
        # Check VIP is created in VSD
        l3domain_ext_id = self.nuage_client.get_vsd_external_id(
            self.router['id'])
        nuage_domain = self.nuage_client.get_resource(
            n_constants.DOMAIN,
            filters='externalID',
            filter_value=l3domain_ext_id)
        nuage_subnet = self.nuage_client.get_domain_subnet(
            n_constants.DOMAIN,
            nuage_domain[0]['ID'],
            filters=['externalID', self._address_in_vsd],
            filter_value=[self.l3subnet['network_id'],
                          self.l3subnet['cidr']])
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.SUBNETWORK,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])

    @decorators.attr(type='smoke')
    def test_update_address_pair_on_l3subnet(self):
        addrpair_port_1 = self.create_port(self.l3network)
        allowed_address_pairs = [
            {'ip_address': addrpair_port_1['fixed_ips'][0]['ip_address'],
             'mac_address': addrpair_port_1['mac_address']}]
        body = self._create_port_with_allowed_address_pair(
            allowed_address_pairs, self.l3network['id'])
        port = body['port']
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, allowed_address_pairs[0]['ip_address'],
            allowed_address_pairs[0]['mac_address'])
        # Check VIP is created in VSD
        l3domain_ext_id = self.nuage_client.get_vsd_external_id(
            self.router['id'])
        nuage_domain = self.nuage_client.get_resource(
            n_constants.DOMAIN,
            filters='externalID',
            filter_value=l3domain_ext_id)
        nuage_subnet = self.nuage_client.get_domain_subnet(
            n_constants.DOMAIN, nuage_domain[0]['ID'],
            filters=['externalID', self._address_in_vsd],
            filter_value=[self.l3subnet['network_id'],
                          self.l3subnet['cidr']])
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.SUBNETWORK,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.DISABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vip = self.nuage_client.get_virtual_ip(
            n_constants.VPORT,
            nuage_vport[0]['ID'],
            filters='virtualIP',
            filter_value=str(addrpair_port_1['fixed_ips'][0]['ip_address']))
        self.assertEqual(addrpair_port_1['mac_address'], nuage_vip[0]['MAC'])
        self.assertEqual(nuage_vip[0]['externalID'],
                         self.nuage_client.get_vsd_external_id(
                             port['id']))
        # Update the address pairs
        # Create port with allowed address pair attribute
        addrpair_port_2 = self.create_port(self.l3network)
        allowed_address_pairs = [
            {'ip_address': addrpair_port_2['fixed_ips'][0]['ip_address'],
             'mac_address': addrpair_port_2['mac_address']}]
        port = self.update_port(
            port, allowed_address_pairs=allowed_address_pairs)
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, addrpair_port_2['fixed_ips'][0]['ip_address'],
            addrpair_port_2['mac_address'])
        # Verify new VIP is created
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.SUBNETWORK,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.DISABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vip = self.nuage_client.get_virtual_ip(
            n_constants.VPORT,
            nuage_vport[0]['ID'],
            filters='virtualIP',
            filter_value=str(addrpair_port_2['fixed_ips'][0]['ip_address']))
        self.assertEqual(addrpair_port_2['mac_address'], nuage_vip[0]['MAC'])
        self.assertEqual(nuage_vip[0]['externalID'],
                         self.nuage_client.get_vsd_external_id(
                             port['id']))
        # Verify old VIP is deleted
        nuage_vip = self.nuage_client.get_virtual_ip(
            n_constants.VPORT,
            nuage_vport[0]['ID'],
            filters='virtualIP',
            filter_value=str(addrpair_port_1['fixed_ips'][0]['ip_address']))
        self.assertEmpty(nuage_vip)

    # Subnet attach/detach are not fully synchronous
    @decorators.attr(type='smoke')
    def test_update_address_pair_on_l3subnet_routersubnetbind(self):
        # Test now uses fixed ips, so random error when a port is created
        # with the ip of the dhcp port in L2 is prevented.
        ip = IPAddress(self.l3subnet['allocation_pools'][0]['start'])
        ip += 1  # first ip is external dhcp port

        addrpair_port_1 = self.create_port(
            self.l3network,
            fixed_ips=[{'subnet_id': self.l3subnet['id'],
                        'ip_address': str(ip)}])
        ip += 1
        allowed_address_pairs = [
            {'ip_address': addrpair_port_1['fixed_ips'][0]['ip_address'],
             'mac_address': addrpair_port_1['mac_address']}]
        body = self._create_port_with_allowed_address_pair(
            allowed_address_pairs, self.l3network['id'],
            fixed_ips=[{'subnet_id': self.l3subnet['id'],
                        'ip_address': str(ip)}]
        )
        port = body['port']
        ip += 1

        # routersubnetbind
        self.routers_client.remove_router_interface(
            self.router['id'], subnet_id=port['fixed_ips'][0]['subnet_id'])
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, allowed_address_pairs[0]['ip_address'],
            allowed_address_pairs[0]['mac_address'])
        self.create_router_interface(
            self.router['id'], port['fixed_ips'][0]['subnet_id'])
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, allowed_address_pairs[0]['ip_address'],
            allowed_address_pairs[0]['mac_address'])
        # Check VIP is created in VSD
        l3domain_ext_id = self.nuage_client.get_vsd_external_id(
            self.router['id'])
        nuage_domain = self.nuage_client.get_resource(
            n_constants.DOMAIN,
            filters='externalID',
            filter_value=l3domain_ext_id)
        nuage_subnet = self.nuage_client.get_domain_subnet(
            n_constants.DOMAIN, nuage_domain[0]['ID'],
            filters=['externalID', self._address_in_vsd],
            filter_value=[self.l3subnet['network_id'],
                          self.l3subnet['cidr']])
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.SUBNETWORK,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.DISABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vip = self.nuage_client.get_virtual_ip(
            n_constants.VPORT,
            nuage_vport[0]['ID'],
            filters='virtualIP',
            filter_value=str(addrpair_port_1['fixed_ips'][0]['ip_address']))
        self.assertEqual(addrpair_port_1['mac_address'], nuage_vip[0]['MAC'])
        self.assertEqual(nuage_vip[0]['externalID'],
                         self.nuage_client.get_vsd_external_id(
                             port['id']))
        # Update the address pairs
        # Create port with allowed address pair attribute

        addrpair_port_2 = self.create_port(
            self.l3network,
            fixed_ips=[{'subnet_id': self.l3subnet['id'],
                        'ip_address': str(ip)}])
        ip += 1
        allowed_address_pairs = [
            {'ip_address': addrpair_port_2['fixed_ips'][0]['ip_address'],
             'mac_address': addrpair_port_2['mac_address']}]
        port = self.update_port(
            port, allowed_address_pairs=allowed_address_pairs)

        # routersubnetbind
        self.routers_client.remove_router_interface(
            self.router['id'], subnet_id=port['fixed_ips'][0]['subnet_id'])
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, addrpair_port_2['fixed_ips'][0]['ip_address'],
            addrpair_port_2['mac_address'])
        self.create_router_interface(
            self.router['id'], port['fixed_ips'][0]['subnet_id'])
        nuage_subnet = self.nuage_client.get_domain_subnet(
            n_constants.DOMAIN, nuage_domain[0]['ID'],
            filters=['externalID', self._address_in_vsd],
            filter_value=[self.l3subnet['network_id'],
                          self.l3subnet['cidr']])

        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, addrpair_port_2['fixed_ips'][0]['ip_address'],
            addrpair_port_2['mac_address'])
        # Verify new VIP is created
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.SUBNETWORK,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.DISABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vip = self.nuage_client.get_virtual_ip(
            n_constants.VPORT,
            nuage_vport[0]['ID'],
            filters='virtualIP',
            filter_value=str(addrpair_port_2['fixed_ips'][0]['ip_address']))
        self.assertEqual(addrpair_port_2['mac_address'], nuage_vip[0]['MAC'])
        self.assertEqual(nuage_vip[0]['externalID'],
                         self.nuage_client.get_vsd_external_id(
                             port['id']))
        # Verify old VIP is deleted
        nuage_vip = self.nuage_client.get_virtual_ip(
            n_constants.VPORT,
            nuage_vport[0]['ID'],
            filters='virtualIP',
            filter_value=str(addrpair_port_1['fixed_ips'][0]['ip_address']))
        self.assertEmpty(nuage_vip)

    def test_fip_allowed_address_pairs_assoc(self):
        if self._ip_version == 6:
            self.skipTest('Skipping FIP to VIP in IPV6')
        post_body = {"device_owner": 'nuage:vip'}
        addrpair_port = self.create_port(self.l3network, **post_body)
        allowed_address_pairs = [
            {'ip_address': addrpair_port['fixed_ips'][0]['ip_address'],
             'mac_address': addrpair_port['mac_address']}]
        port = self.create_port(
            network=self.l3network,
            allowed_address_pairs=allowed_address_pairs)
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, allowed_address_pairs[0]['ip_address'],
            allowed_address_pairs[0]['mac_address'])
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=addrpair_port['id'])
        created_floating_ip = body['floatingip']
        self.assertIsNotNone(created_floating_ip['id'])
        self.assertEqual(created_floating_ip['fixed_ip_address'],
                         addrpair_port['fixed_ips'][0]['ip_address'])
        # VSD validation of VIP to FIP association
        l3dom_ext_id = self.nuage_client.get_vsd_external_id(
            self.router['id'])
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID',
            filter_value=l3dom_ext_id)
        nuage_domain_fip = self.nuage_client.get_floatingip(
            n_constants.DOMAIN,
            nuage_domain[0]['ID'])
        nuage_subnet = self.nuage_client.get_domain_subnet(
            n_constants.DOMAIN,
            nuage_domain[0]['ID'],
            filters=['externalID', self._address_in_vsd],
            filter_value=[self.l3subnet['network_id'],
                          self.l3subnet['cidr']])
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.SUBNETWORK,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        nuage_vip = self.nuage_client.get_virtual_ip(
            n_constants.VPORT, nuage_vport[0]['ID'],
            filters='virtualIP',
            filter_value=str(addrpair_port['fixed_ips'][0]['ip_address']))
        self.assertEqual(nuage_domain_fip[0]['ID'],
                         nuage_vip[0]['associatedFloatingIPID'])
        self.assertEqual(nuage_domain_fip[0]['assignedToObjectType'],
                         'virtualip')
        self.assertEqual(nuage_vip[0]['externalID'],
                         self.nuage_client.get_vsd_external_id(
                             port['id']))
        self.floating_ips_client.delete_floatingip(created_floating_ip['id'])

    def test_allowed_address_pair_extraroute(self):
        addrpair_port = self.create_port(self.l3network)
        allowed_address_pairs = [{'ip_address':
                                  addrpair_port['fixed_ips'][0]['ip_address'],
                                  'mac_address':
                                  addrpair_port['mac_address']}]
        body = self._create_port_with_allowed_address_pair(
            allowed_address_pairs, self.l3network['id'])
        port = body['port']
        self._verify_port_by_id(port['id'])
        # Confirm port was created with allowed address pair attribute
        self._verify_port_allowed_address_fields(
            port, addrpair_port['fixed_ips'][0]['ip_address'],
            addrpair_port['mac_address'])
        # update the extra route
        next_hop = addrpair_port['fixed_ips'][0]['ip_address']
        destination = ('2003:a:b::5/128' if self._ip_version == 6
                       else '201.1.1.5/32')

        test_routes = [{'nexthop': next_hop, 'destination': destination}]

        extra_route = self.routers_client.update_router(
            self.router['id'],
            routes=test_routes)

        self.addCleanup(self.routers_client.update_router,
                        self.router['id'], routes=None)

        self.assertEqual(1, len(extra_route['router']['routes']))
        self.assertEqual(destination,
                         extra_route['router']['routes'][0]['destination'])
        self.assertEqual(next_hop,
                         extra_route['router']['routes'][0]['nexthop'])
        show_body = self.routers_client.show_router(self.router['id'])
        self.assertEqual(destination,
                         show_body['router']['routes'][0]['destination'])
        self.assertEqual(next_hop,
                         show_body['router']['routes'][0]['nexthop'])

        # Check VIP is created in VSD
        l3domain_ext_id = self.nuage_client.get_vsd_external_id(
            self.router['id'])
        nuage_domain = self.nuage_client.get_resource(
            n_constants.DOMAIN,
            filters='externalID',
            filter_value=l3domain_ext_id)
        nuage_subnet = self.nuage_client.get_domain_subnet(
            n_constants.DOMAIN, nuage_domain[0]['ID'],
            filters=['externalID', self._address_in_vsd],
            filter_value=[self.l3subnet['network_id'],
                          self.l3subnet['cidr']])
        port_ext_id = self.nuage_client.get_vsd_external_id(port['id'])
        nuage_vport = self.nuage_client.get_vport(
            n_constants.SUBNETWORK,
            nuage_subnet[0]['ID'],
            filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(n_constants.DISABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vip = self.nuage_client.get_virtual_ip(
            n_constants.VPORT,
            nuage_vport[0]['ID'],
            filters='virtualIP',
            filter_value=str(addrpair_port['fixed_ips'][0]['ip_address']))
        self.assertEqual(addrpair_port['mac_address'], nuage_vip[0]['MAC'])
        self.assertEqual(nuage_vip[0]['externalID'],
                         self.nuage_client.get_vsd_external_id(
                             port['id']))
        # Check static roues on VSD
        nuage_static_route = self.nuage_client.get_staticroute(
            parent=n_constants.DOMAIN, parent_id=nuage_domain[0]['ID'])
        self.assertEqual(
            nuage_static_route[0]['nextHopIp'], next_hop, "wrong nexthop")


class AllowedAddressPairV6Test(AllowedAddressPairTest):
    _ip_version = 6
    _address_in_vsd = 'IPv6Address'
