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
import uuid

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

from tempest.api.network import test_floating_ips
from tempest.common.utils import net_utils
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from testtools.matchers import ContainsDict
from testtools.matchers import Equals

CONF = Topology.get_conf()


class FloatingIPTestJSONNuage(test_floating_ips.FloatingIPTestJSON):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(FloatingIPTestJSONNuage, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(FloatingIPTestJSONNuage, cls).resource_setup()

        # Creating two more ports which will be added in VSD
        for i in range(2):
            post_body = {
                "device_owner": "compute:None", "device_id": str(uuid.uuid1())}
            if CONF.network.port_vnic_type:
                post_body['binding:vnic_type'] = CONF.network.port_vnic_type
            if CONF.network.port_profile:
                post_body['binding:profile'] = CONF.network.port_profile
            port = cls.create_port(cls.network, **post_body)
            cls.ports.append(port)

    def _verify_fip_on_vsd(self, created_floating_ip,
                           router_id, port_id, subnet, associated=True):
        # verifying on Domain level that the floating ip is added
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID',
            filter_value=router_id)
        nuage_domain_fip = self.nuage_client.get_floatingip(
            constants.DOMAIN, nuage_domain[0]['ID'])
        if associated:
            # verifying on vminterface level that the floating ip is associated
            subnet_ext_id = self.nuage_client.get_vsd_external_id(
                subnet['network_id'])
            vsd_subnets = self.nuage_client.get_domain_subnet(
                None, None, ['externalID', 'address'],
                [subnet_ext_id, self.subnet['cidr']])
            nuage_vport = self.nuage_client.get_vport(constants.SUBNETWORK,
                                                      vsd_subnets[0]['ID'],
                                                      'externalID',
                                                      port_id)
            validation = False
            for fip in nuage_domain_fip:
                if (fip['address'] ==
                        created_floating_ip['floating_ip_address'] and
                        nuage_vport[0]['associatedFloatingIPID'] == fip['ID']):
                    validation = True
            error_message = ("FIP IP on OpenStack " +
                             created_floating_ip['floating_ip_address'] +
                             " does not match VSD FIP IP" + " (OR) FIP is not"
                             " associated to the port" + port_id + " on VSD")
            self.assertTrue(validation, msg=error_message)

        else:
            vsd_fip_list = [fip['address'] for fip in nuage_domain_fip]
            self.assertNotIn(created_floating_ip['floating_ip_address'],
                             vsd_fip_list)

    @decorators.attr(type='smoke')
    def test_create_list_show_update_delete_floating_ip(self):
        # Creates a floating IP
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[2]['id'])

        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['tenant_id'])
        self.assertIsNotNone(created_floating_ip['floating_ip_address'])
        self.assertEqual(created_floating_ip['port_id'], self.ports[2]['id'])
        self.assertEqual(created_floating_ip['floating_network_id'],
                         self.ext_net_id)
        self.assertIn(created_floating_ip['fixed_ip_address'],
                      [ip['ip_address'] for ip in self.ports[2]['fixed_ips']])

        # Verifies the details of a floating_ip
        floating_ip = self.floating_ips_client.show_floatingip(
            created_floating_ip['id'])
        shown_floating_ip = floating_ip['floatingip']
        self.assertEqual(shown_floating_ip['id'], created_floating_ip['id'])
        self.assertEqual(shown_floating_ip['floating_network_id'],
                         self.ext_net_id)
        self.assertEqual(shown_floating_ip['tenant_id'],
                         created_floating_ip['tenant_id'])
        self.assertEqual(shown_floating_ip['floating_ip_address'],
                         created_floating_ip['floating_ip_address'])
        self.assertEqual(shown_floating_ip['port_id'], self.ports[2]['id'])

        # VSD Validation
        self._verify_fip_on_vsd(
            created_floating_ip, created_floating_ip['router_id'],
            self.ports[2]['id'], self.subnet, True)

        # Verify the floating ip exists in the list of all floating_ips
        floating_ips = self.floating_ips_client.list_floatingips()
        floatingip_id_list = list()
        for f in floating_ips['floatingips']:
            floatingip_id_list.append(f['id'])
        self.assertIn(created_floating_ip['id'], floatingip_id_list)

        # Disassociate floating IP from the port
        floating_ip = self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            port_id=None)
        updated_floating_ip = floating_ip['floatingip']
        self.assertIsNone(updated_floating_ip['port_id'])
        self.assertIsNone(updated_floating_ip['fixed_ip_address'])
        self.assertIsNone(updated_floating_ip['router_id'])

        # Associate floating IP to the other port
        floating_ip = self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            port_id=self.ports[3]['id'])
        updated_floating_ip = floating_ip['floatingip']
        self.assertEqual(updated_floating_ip['port_id'], self.ports[3]['id'])
        self.assertEqual(updated_floating_ip['fixed_ip_address'],
                         self.ports[3]['fixed_ips'][0]['ip_address'])
        self.assertEqual(updated_floating_ip['router_id'], self.router['id'])

        # VSD Validation
        self._verify_fip_on_vsd(
            created_floating_ip, created_floating_ip['router_id'],
            self.ports[3]['id'], self.subnet, True)

        # Disassociate floating IP from the port
        floating_ip = self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            port_id=None)
        updated_floating_ip = floating_ip['floatingip']
        self.assertIsNone(updated_floating_ip['port_id'])
        self.assertIsNone(updated_floating_ip['fixed_ip_address'])
        self.assertIsNone(updated_floating_ip['router_id'])

        # VSD Validation
        self._verify_fip_on_vsd(
            created_floating_ip, self.router['id'], None, None, False)

    @decorators.attr(type='smoke')
    def test_create_update_floating_ip(self):
        # Creates a floating IP
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[2]['id'])

        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['tenant_id'])
        self.assertIsNotNone(created_floating_ip['floating_ip_address'])
        self.assertEqual(created_floating_ip['port_id'], self.ports[2]['id'])
        self.assertEqual(created_floating_ip['floating_network_id'],
                         self.ext_net_id)
        self.assertIn(created_floating_ip['fixed_ip_address'],
                      [ip['ip_address'] for ip in self.ports[2]['fixed_ips']])

        # Verifies the details of a floating_ip
        floating_ip = self.floating_ips_client.show_floatingip(
            created_floating_ip['id'])
        shown_floating_ip = floating_ip['floatingip']
        self.assertEqual(shown_floating_ip['id'], created_floating_ip['id'])
        self.assertEqual(shown_floating_ip['floating_network_id'],
                         self.ext_net_id)
        self.assertEqual(shown_floating_ip['tenant_id'],
                         created_floating_ip['tenant_id'])
        self.assertEqual(shown_floating_ip['floating_ip_address'],
                         created_floating_ip['floating_ip_address'])
        self.assertEqual(shown_floating_ip['port_id'], self.ports[2]['id'])

        # VSD Validation
        self._verify_fip_on_vsd(
            created_floating_ip, created_floating_ip['router_id'],
            self.ports[2]['id'], self.subnet, True)

        # Verify the floating ip exists in the list of all floating_ips
        floating_ips = self.floating_ips_client.list_floatingips()
        floatingip_id_list = list()
        for f in floating_ips['floatingips']:
            floatingip_id_list.append(f['id'])
        self.assertIn(created_floating_ip['id'], floatingip_id_list)

        if Topology.from_openstack('Newton') and Topology.is_ml2:
            self.floating_ips_client.update_floatingip(
                created_floating_ip['id'],
                port_id=self.ports[3]['id'])
            updated_floating_ip = self.floating_ips_client.show_floatingip(
                created_floating_ip['id'])['floatingip']
            self.assertEqual(updated_floating_ip['port_id'],
                             self.ports[3]['id'])
            self._verify_fip_on_vsd(
                updated_floating_ip, updated_floating_ip['router_id'],
                self.ports[3]['id'], self.subnet, True)
        else:
            # Associate floating IP to the other port
            self.assertRaises(exceptions.ServerFault,
                              self.floating_ips_client.update_floatingip,
                              created_floating_ip['id'],
                              port_id=self.ports[3]['id'])

    @decorators.attr(type='smoke')
    def test_floating_ip_delete_port(self):
        # Create a floating IP
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id)
        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        # Create a port
        post_body = {
            "device_owner": "compute:None", "device_id": str(uuid.uuid1())}
        port = self.ports_client.create_port(
            network_id=self.network['id'], **post_body)
        created_port = port['port']
        floating_ip = self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            port_id=created_port['id'])

        self.assertIsNotNone(floating_ip)

        # VSD Validation
        self._verify_fip_on_vsd(created_floating_ip, self.router['id'],
                                created_port['id'], self.subnet,
                                True)
        # Delete port
        self.ports_client.delete_port(created_port['id'])
        # Verifies the details of the floating_ip
        floating_ip = self.floating_ips_client.show_floatingip(
            created_floating_ip['id'])
        shown_floating_ip = floating_ip['floatingip']
        # Confirm the fields are back to None
        self.assertEqual(shown_floating_ip['id'], created_floating_ip['id'])
        self.assertIsNone(shown_floating_ip['port_id'])
        self.assertIsNone(shown_floating_ip['fixed_ip_address'])
        self.assertIsNone(shown_floating_ip['router_id'])

    def test_floating_ip_update_different_router(self):
        # Associate a floating IP to a port on a router
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[3]['id'])
        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertEqual(created_floating_ip['router_id'], self.router['id'])

        # VSD Validation
        self._verify_fip_on_vsd(
            created_floating_ip, created_floating_ip['router_id'],
            self.ports[3]['id'], self.subnet, True)

        network2 = self.create_network()
        subnet2 = self.create_subnet(network2)
        router2 = self.create_router(data_utils.rand_name('router-'),
                                     external_network_id=self.ext_net_id)
        self.create_router_interface(router2['id'], subnet2['id'])
        post_body = {
            "device_owner": "compute:None", "device_id": str(uuid.uuid1())}
        port_other_router = self.create_port(network2, **post_body)

        self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            port_id=port_other_router['id'])
        updated_floating_ip = self.floating_ips_client.show_floatingip(
            created_floating_ip['id'])['floatingip']
        self.assertEqual(updated_floating_ip['port_id'],
                         port_other_router['id'])
        self._verify_fip_on_vsd(
            updated_floating_ip, updated_floating_ip['router_id'],
            port_other_router['id'], subnet2, True)

    def test_floating_ip_disassociate_delete_router_associate(self):
        # Create topology
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(data_utils.rand_name('router-'),
                                    external_network_id=self.ext_net_id)
        self.create_router_interface(router['id'], subnet['id'])
        post_body = {
            "device_owner": "compute:None", "device_id": str(uuid.uuid1())}
        port1 = self.create_port(network, **post_body)

        # Associate a floating IP to a port on a router
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=port1['id'])
        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertEqual(created_floating_ip['router_id'], router['id'])

        # VSD Validation
        self._verify_fip_on_vsd(
            created_floating_ip, created_floating_ip['router_id'],
            port1['id'], subnet, True)

        # Disassociate fip from port
        self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            port_id=None)

        # Delete existing router
        self.delete_router(router)

        # Associate to second router
        network2 = self.create_network()
        subnet2 = self.create_subnet(network2)
        router2 = self.create_router(data_utils.rand_name('router-'),
                                     external_network_id=self.ext_net_id)
        self.create_router_interface(router2['id'], subnet2['id'])
        post_body = {
            "device_owner": "compute:None", "device_id": str(uuid.uuid1())}
        port_other_router = self.create_port(network2, **post_body)

        self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            port_id=port_other_router['id'])
        updated_floating_ip = self.floating_ips_client.show_floatingip(
            created_floating_ip['id'])['floatingip']
        self.assertEqual(updated_floating_ip['port_id'],
                         port_other_router['id'])
        self._verify_fip_on_vsd(
            updated_floating_ip, updated_floating_ip['router_id'],
            port_other_router['id'], subnet2, True)

    @decorators.attr(type='smoke')
    def test_create_floating_ip_specifying_a_fixed_ip_address(self):
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=self.ports[3]['id'],
            fixed_ip_address=self.ports[3]['fixed_ips'][0]['ip_address'])
        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['id'])
        self.assertEqual(created_floating_ip['fixed_ip_address'],
                         self.ports[3]['fixed_ips'][0]['ip_address'])
        # VSD validation
        self._verify_fip_on_vsd(
            created_floating_ip, created_floating_ip['router_id'],
            self.ports[3]['id'], self.subnet, True)

        floating_ip = self.floating_ips_client.update_floatingip(
            created_floating_ip['id'],
            port_id=None)
        self.assertIsNone(floating_ip['floatingip']['port_id'])

        # VSD Validation
        self._verify_fip_on_vsd(
            created_floating_ip, self.router['id'], None, None, False)

    @decorators.attr(type='smoke')
    def test_create_update_floatingip_with_port_multiple_ip_address(self):
        # TODO(Team) Adapt once we are on 5.3.2
        # Find out ips that can be used for tests
        list_ips = net_utils.get_unused_ip_addresses(
            self.ports_client,
            self.subnets_client,
            self.subnet['network_id'],
            self.subnet['id'],
            2)
        fixed_ips = [{'ip_address': list_ips[0]}, {'ip_address': list_ips[1]}]
        # Create port
        body = self.ports_client.create_port(network_id=self.network['id'],
                                             fixed_ips=fixed_ips)
        port = body['port']
        self.addCleanup(self.ports_client.delete_port, port['id'])
        # Create floating ip
        self.assertRaises(exceptions.BadRequest,
                          self.floating_ips_client.create_floatingip,
                          floating_network_id=self.ext_net_id,
                          port_id=port['id'],
                          fixed_ip_address=list_ips[0])

    @decorators.attr(type='smoke')
    def test_create_floatingip_with_rate_limiting(self):
        rate_limit = 10000
        # Create port
        post_body = {"network_id": self.network['id']}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])

        # Associate a fip to the port
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=port['id'],
            fixed_ip_address=port['fixed_ips'][0]['ip_address'],
            nuage_egress_fip_rate_kbps=rate_limit)
        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['id'])

        fip_id = created_floating_ip['id']
        body = self.floating_ips_client.show_floatingip(fip_id)
        fip = body['floatingip']

        # rate_limit is in kbps now!
        self.assertThat(fip, ContainsDict(
            {'nuage_ingress_fip_rate_kbps': Equals(-1)}))
        self.assertThat(fip, ContainsDict(
            {'nuage_egress_fip_rate_kbps': Equals(rate_limit)}))

        # attribute 'nuage_fip_rate' is no longer in response
        self.assertIsNone(fip.get('nuage_fip_rate'))

        # Check vsd
        subnet_ext_id = self.nuage_client.get_vsd_external_id(
            self.subnet['network_id'])
        vsd_subnets = self.nuage_client.get_domain_subnet(
            None, None, ['externalID', 'address'],
            [subnet_ext_id, self.subnet['cidr']])
        self.assertEqual(1, len(vsd_subnets))
        vports = self.nuage_client.get_vport(constants.SUBNETWORK,
                                             vsd_subnets[0]['ID'],
                                             'externalID',
                                             port['id'])
        self.assertEqual(1, len(vports))
        qos = self.nuage_client.get_qos(constants.VPORT, vports[0]['ID'])
        self.assertEqual(1, len(qos))

        self.assertThat(qos[0], ContainsDict(
            {'externalID':
             Equals(self.nuage_client.get_vsd_external_id(fip_id))}))
        self.assertThat(qos[0], ContainsDict(
            {'FIPRateLimitingActive': Equals(True)}))
        self.assertThat(qos[0], ContainsDict(
            {'FIPPeakInformationRate': Equals(str(float(rate_limit / 1000)))}))
        self.assertThat(qos[0], ContainsDict(
            {'FIPPeakBurstSize': Equals(str(100))}))

        self.assertThat(qos[0], ContainsDict(
            {'EgressFIPPeakInformationRate': Equals('INFINITY')}))
        self.assertThat(qos[0], ContainsDict(
            {'EgressFIPPeakBurstSize': Equals(str(100))}))

    @decorators.attr(type='smoke')
    def test_create_floatingip_without_rate_limiting(self):
        # Create port
        post_body = {"network_id": self.network['id']}
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])

        # Associate a fip to the port
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=port['id'],
            fixed_ip_address=port['fixed_ips'][0]['ip_address'])
        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['id'])

        fip_id = created_floating_ip['id']
        body = self.floating_ips_client.show_floatingip(fip_id)
        fip = body['floatingip']

        self.assertIsNotNone(fip.get('nuage_ingress_fip_rate_kbps'))
        self.assertIsNotNone(fip.get('nuage_egress_fip_rate_kbps'))

        # Check vsd
        subnet_ext_id = self.nuage_client.get_vsd_external_id(
            self.subnet['network_id'])
        vsd_subnets = self.nuage_client.get_domain_subnet(
            None, None, ['externalID', 'address'],
            [subnet_ext_id, self.subnet['cidr']])
        self.assertEqual(1, len(vsd_subnets))
        vports = self.nuage_client.get_vport(constants.SUBNETWORK,
                                             vsd_subnets[0]['ID'],
                                             'externalID',
                                             port['id'])
        self.assertEqual(1, len(vports))
        qos = self.nuage_client.get_qos(constants.VPORT, vports[0]['ID'])
        self.assertEqual(1, len(qos))
        self.assertEqual(self.nuage_client.get_vsd_external_id(fip_id),
                         qos[0]['externalID'])
        self.assertEqual(True, qos[0]['FIPRateLimitingActive'])

        self.assertEqual('INFINITY', qos[0]['FIPPeakInformationRate'])
        self.assertEqual('INFINITY',
                         qos[0]['EgressFIPPeakInformationRate'])

    @decorators.attr(type='smoke')
    def test_delete_associated_port_fip_cleanup(self):
        port = self.create_port(self.network)
        fip = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=port['id'])['floatingip']
        self.ports_client.delete_port(port['id'])
        self.floating_ips_client.delete_floatingip(fip['id'])

        vsd_l3domain = self.nuage_client.get_l3domain(
            filters='externalID',
            filter_value=fip['router_id'])
        vsd_fips = self.nuage_client.get_floatingip(
            constants.DOMAIN, vsd_l3domain[0]['ID'])
        for vsd_fip in vsd_fips:
            if vsd_fip['address'] == fip['floating_ip_address']:
                self.fail("No cleanup happened. Floatingip still exists on "
                          "VSD and not in Neutron.")

    @decorators.attr(type='smoke')
    def test_fip_on_multiple_ip_port(self):
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")
        subnet = self.create_subnet(network)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        # 1. Assigning fip to port with multiple ip address
        cidr4 = IPNetwork(CONF.network.project_network_cidr)
        port_args = {
            'fixed_ips': [
                {'subnet_id': subnet['id'],
                 'ip_address': str(IPAddress(cidr4.first) + 4)},
                {'subnet_id': subnet['id'],
                 'ip_address': str(IPAddress(cidr4.first) + 5)},
                {'subnet_id': subnet['id'],
                 'ip_address': str(IPAddress(cidr4.first) + 6)},
                {'subnet_id': subnet['id'],
                 'ip_address': str(IPAddress(cidr4.first) + 7)}],
        }
        port = self.create_port(network=network, **port_args)
        floating_ip = self.create_floatingip(
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(floating_ip, "Unabe to create floating ip")
        msg = 'floating ip cannot be associated to port %s ' \
              'because it has multiple ipv4 or multiple ipv6ips' % port['id']
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.floating_ips_client.update_floatingip,
                               floating_ip['id'],
                               port_id=port['id'])
        # 2. Assigning multiple ip address to a port with fip
        port = self.create_port(network=network)
        floating_ip = self.create_floatingip(
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(floating_ip, "Unable to create floating ip")

        self.floating_ips_client.update_floatingip(
            floating_ip['id'], port_id=port['id'])

        port_args = {
            'fixed_ips': [
                {'subnet_id': subnet['id'],
                 'ip_address': str(IPAddress(cidr4.first) + 8)},
                {'subnet_id': subnet['id'],
                 'ip_address': str(IPAddress(cidr4.first) + 9)}]}
        msg = ("It is not possible to add multiple ipv4 or multiple ipv6"
               " addresses on port {} since it has fip {} associated"
               "to it.").format(port['id'], floating_ip['id'])
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.update_port,
                               port=port, **port_args)
