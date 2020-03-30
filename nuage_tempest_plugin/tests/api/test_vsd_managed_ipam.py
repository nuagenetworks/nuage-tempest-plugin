# Copyright 2020 NOKIA
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
from netaddr import IPRange

from tempest.lib import decorators
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()


class VSDManagedIPAMTest(nuage_test.NuageBaseTest):

    @classmethod
    def skip_checks(cls):
        super(VSDManagedIPAMTest, cls).skip_checks()
        if not CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed':
            raise cls.skipException("VSD managed ipam is required")

    def _test_router_attach_detach_with_vm(self, is_ipv4=True, is_ipv6=False):
        network = self.create_network()
        ipv4_subnet = ipv6_subnet = None
        if is_ipv6:
            ipv6_subnet = self.create_subnet(network, ip_version=6)
        if is_ipv4:
            ipv4_subnet = self.create_subnet(network)
        router = self.create_router()

        # Resources under test
        port = self.create_port(network)
        vm = self.create_tenant_server(networks=[network],
                                       prepare_for_connectivity=False)

        # Verify reservations
        if is_ipv4:
            l2domain = self.vsd.get_l2domain(by_network_id=network['id'],
                                             cidr=ipv4_subnet['cidr'],
                                             ip_type=4)
        else:
            l2domain = self.vsd.get_l2domain(by_network_id=network['id'],
                                             cidr=ipv6_subnet['cidr'],
                                             ip_type=6)

        ipreservations = l2domain.vmip_reservations.get()
        self._verify_vmipreservations(ipreservations, ipv4_subnet, ipv6_subnet,
                                      network, port, vm)
        # Attach router interface
        if is_ipv4:
            self.router_attach(router, ipv4_subnet)
        if is_ipv6:
            self.router_attach(router, ipv6_subnet)

        if is_ipv4:
            vsd_subnet = self.vsd.get_subnet(by_network_id=network['id'],
                                             cidr=ipv4_subnet['cidr'])
        else:
            vsd_subnet = self.vsd.get_subnet(by_network_id=network['id'],
                                             cidr=ipv6_subnet['cidr'])
        ipreservations = vsd_subnet.vmip_reservations.get()
        self._verify_vmipreservations(ipreservations, ipv4_subnet, ipv6_subnet,
                                      network, port, vm)
        # Create a new port and check ipreservation
        self.delete_port(port)
        port = self.create_port(network)
        ipreservations = vsd_subnet.vmip_reservations.get()
        self._verify_vmipreservations(ipreservations, ipv4_subnet, ipv6_subnet,
                                      network, port, vm)

        # Detach router interface
        if is_ipv4:
            self.router_detach(router, ipv4_subnet)
        if is_ipv6:
            self.router_detach(router, ipv6_subnet)
        if is_ipv4:
            l2domain = self.vsd.get_l2domain(by_network_id=network['id'],
                                             cidr=ipv4_subnet['cidr'],
                                             ip_type=4)
        else:
            l2domain = self.vsd.get_l2domain(by_network_id=network['id'],
                                             cidr=ipv6_subnet['cidr'],
                                             ip_type=6)

        ipreservations = l2domain.vmip_reservations.get()
        self._verify_vmipreservations(ipreservations, ipv4_subnet, ipv6_subnet,
                                      network, port, vm)

    def _verify_vmipreservations(self, ipreservations, ipv4_subnet,
                                 ipv6_subnet, network, port,
                                 vm):
        if ipv4_subnet:
            reserved_ips = [ipreservation.ipv4_address for ipreservation in
                            ipreservations if ipreservation.ip_type == 'IPV4']
            vm_ip = vm.get_server_ip_in_network(network['name'], ip_version=4)
            self.assertIn(vm_ip, reserved_ips)
            port_ip = [ip['ip_address'] for ip in port['fixed_ips']
                       if ip['subnet_id'] == ipv4_subnet['id']][0]
            self.assertIn(port_ip, reserved_ips)
            self.assertEqual(2, len(reserved_ips),
                             "More IP reservations found than expected")
            vm_ipreservation = [ipreservation for ipreservation
                                in ipreservations
                                if ipreservation.ipv4_address == vm_ip][0]
            self.assertEqual('ASSIGNED', vm_ipreservation.state)
        if ipv6_subnet:
            reserved_ips = [ipreservation.ipv6_address for ipreservation in
                            ipreservations if ipreservation.ip_type == 'IPV6']
            vm_ip = vm.get_server_ip_in_network(network['name'], ip_version=6)
            self.assertIn(vm_ip, reserved_ips)
            port_ip = [ip['ip_address'] for ip in port['fixed_ips']
                       if ip['subnet_id'] == ipv6_subnet['id']][0]
            self.assertIn(port_ip, reserved_ips)
            self.assertEqual(2, len(reserved_ips),
                             "More IP reservations found than expected")
            vm_ipreservation = [ipreservation for ipreservation
                                in ipreservations
                                if ipreservation.ipv6_address == vm_ip][0]
            self.assertEqual('ASSIGNED', vm_ipreservation.state)

    @decorators.attr(type='smoke')
    def test_router_attach_detach_ipv4_with_vm(self):
        self._test_router_attach_detach_with_vm(is_ipv4=True, is_ipv6=False)

    @decorators.attr(type='smoke')
    def test_router_attach_detach_ipv6_with_vm(self):
        self._test_router_attach_detach_with_vm(is_ipv4=False, is_ipv6=True)

    @decorators.attr(type='smoke')
    def test_router_attach_detach_dualstack_with_vm(self):
        self._test_router_attach_detach_with_vm(is_ipv4=True, is_ipv6=True)

    @decorators.attr(type='smoke')
    def test_illegal_reservation(self):
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network,
                                         cidr=IPNetwork('10.0.0.0/24'),
                                         mask_bits=24)
        ipv6_subnet = self.create_subnet(network, ip_version=6,
                                         cidr=IPNetwork('cafe:babe::/64'),
                                         mask_bits=64)

        router = self.create_router()
        # l2domain verify
        l2domain = self.vsd.get_l2domain(by_network_id=network['id'],
                                         cidr=ipv4_subnet['cidr'],
                                         ip_type=4)
        # Simulate other OS cloud by doing reservations
        vmipreservation = self.vsd.vspk.NUVMIPReservation(
            ip_type='IPV4', ipv4_address='10.0.0.10')
        l2domain.create_child(vmipreservation)
        vmipreservation = self.vsd.vspk.NUVMIPReservation(
            ip_type='IPV6', ipv6_address='cafe:babe::10')
        l2domain.create_child(vmipreservation)

        # Assert error occurs
        error_message = ('The address allocation request could not be '
                         'satisfied because: The requested ip address is '
                         'already reserved on VSD by another entity.')
        self._create_verify_illegal_ports(
            ipv4_subnet, ipv6_subnet, network,
            expected_exception=exceptions.BadRequest,
            expected_error_msg=error_message)

        self.router_attach(router, ipv4_subnet)
        self.router_attach(router, ipv6_subnet)

        # Assert error occurs
        self._create_verify_illegal_ports(
            ipv4_subnet, ipv6_subnet, network,
            expected_exception=exceptions.BadRequest,
            expected_error_msg=error_message)

    def _create_verify_illegal_ports(self, ipv4_subnet, ipv6_subnet, network,
                                     expected_exception, expected_error_msg,
                                     dynamic=False):
        if ipv4_subnet:
            if not dynamic:
                port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                            'ip_address': '10.0.0.10'}]}
            else:
                port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id']}]}
            self.assertRaisesRegex(expected_exception,
                                   expected_error_msg,
                                   self.create_port, network, **port_args)
        if ipv6_subnet:
            if not dynamic:
                port_args = {'fixed_ips': [{'subnet_id': ipv6_subnet['id'],
                                            'ip_address': 'cafe:babe::10'}]}
            else:
                port_args = {'fixed_ips': [{'subnet_id': ipv6_subnet['id']}]}
            self.assertRaisesRegex(expected_exception,
                                   expected_error_msg,
                                   self.create_port, network, **port_args)

    @decorators.attr(type='smoke')
    def test_full_subnet(self):
        # Fill up the test subnets so dynamic allocation fails
        # For ipv6 we cannot fill up the subnet as /64 is too big so we make
        # a small allocation pool and fill that up
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network,
                                         cidr=IPNetwork('10.0.0.0/29'),
                                         mask_bits=29)
        pool = {'start': 'cafe:babe::2', 'end': 'cafe:babe::6'}
        kwargs = {'allocation_pools': [pool]}
        ipv6_subnet = self.create_subnet(network, ip_version=6,
                                         cidr=IPNetwork('cafe:babe::/64'),
                                         mask_bits=64, **kwargs)

        router = self.create_router()
        # l2domain verify
        l2domain = self.vsd.get_l2domain(by_network_id=network['id'],
                                         cidr=ipv4_subnet['cidr'],
                                         ip_type=4)
        for ip in IPRange('10.0.0.3', '10.0.0.6'):
            vmipreservation = self.vsd.vspk.NUVMIPReservation(
                ip_type='IPV4', ipv4_address=str(ip))
            l2domain.create_child(vmipreservation)
        for ip in IPRange('cafe:babe::3', 'cafe:babe::6'):
            vmipreservation = self.vsd.vspk.NUVMIPReservation(
                ip_type='IPV6', ipv6_address=str(ip))
            l2domain.create_child(vmipreservation)

        # Assert error occurs
        expected_error_message = 'No more IP addresses available on network'
        self._create_verify_illegal_ports(
            ipv4_subnet, ipv6_subnet, network,
            expected_exception=exceptions.Conflict,
            expected_error_msg=expected_error_message, dynamic=True)

        self.router_attach(router, ipv4_subnet)
        self.router_attach(router, ipv6_subnet)
        # After router attach nuage:dhcp ports are freed up
        vsd_subnet = self.vsd.get_subnet(by_network_id=network['id'],
                                         cidr=ipv4_subnet['cidr'])
        vmipreservation = self.vsd.vspk.NUVMIPReservation(
            ip_type='IPV4', ipv4_address='10.0.0.2')
        vsd_subnet.create_child(vmipreservation)
        vmipreservation = self.vsd.vspk.NUVMIPReservation(
            ip_type='IPV6', ipv6_address='cafe:babe::2')
        vsd_subnet.create_child(vmipreservation)

        # Assert error occurs
        self._create_verify_illegal_ports(
            ipv4_subnet, ipv6_subnet, network,
            expected_exception=exceptions.Conflict,
            expected_error_msg=expected_error_message, dynamic=True)

    @decorators.attr(type='smoke')
    def test_verify_allocation_pool_address_range(self):
        network = self.create_network()
        pool = {'start': '10.0.0.2', 'end': '10.0.0.6'}
        kwargs = {'allocation_pools': [pool]}
        ipv4_subnet = self.create_subnet(network,
                                         cidr=IPNetwork('10.0.0.0/24'),
                                         mask_bits=24, **kwargs)

        pool = {'start': 'cafe:babe::2', 'end': 'cafe:babe::6'}
        kwargs = {'allocation_pools': [pool]}
        ipv6_subnet = self.create_subnet(network, ip_version=6,
                                         cidr=IPNetwork('cafe:babe::/64'),
                                         mask_bits=64, **kwargs)
        # Create non-overlapping address ranges
        l2dom_template = self.vsd.get_l2domain_template(
            by_network_id=network['id'], cidr=ipv4_subnet['cidr'], ip_type=4)
        address_range = self.vsd.vspk.NUAddressRange(
            ip_type='IPV4', min_address='10.0.0.7', max_address='10.0.0.10',
            dhcp_pool_type='HOST')
        l2dom_template.create_child(address_range)
        address_range = self.vsd.vspk.NUAddressRange(
            ip_type='IPV6', min_address='cafe:babe::7',
            max_address='cafe:babe::10', dhcp_pool_type='HOST')
        l2dom_template.create_child(address_range)

        # Try to allocate ip
        expected_error_message = 'No more IP addresses available on network'
        self._create_verify_illegal_ports(
            ipv4_subnet, ipv6_subnet, network,
            expected_exception=exceptions.Conflict,
            expected_error_msg=expected_error_message, dynamic=True)
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                    'ip_address': '10.0.0.10'}]}
        valid_port = self.create_port(network, cleanup=False, **port_args)
        self.delete_port(valid_port)
        self.assertEqual('10.0.0.10', valid_port['fixed_ips'][0]['ip_address'])
        port_args = {'fixed_ips': [{'subnet_id': ipv6_subnet['id'],
                                    'ip_address': 'cafe:babe::10'}]}
        valid_port = self.create_port(network, cleanup=False, **port_args)
        self.delete_port(valid_port)
        self.assertEqual('cafe:babe::10',
                         valid_port['fixed_ips'][0]['ip_address'])

        router = self.create_router()
        self.router_attach(router, ipv4_subnet)
        self.router_attach(router, ipv6_subnet)

        # Address ranges are not transferred to l3
        l3subnet = self.vsd.get_subnet(
            by_network_id=network['id'], cidr=ipv4_subnet['cidr'])
        address_range = self.vsd.vspk.NUAddressRange(
            ip_type='IPV4', min_address='10.0.0.7', max_address='10.0.0.10',
            dhcp_pool_type='HOST')
        l3subnet.create_child(address_range)
        address_range = self.vsd.vspk.NUAddressRange(
            ip_type='IPV6', min_address='cafe:babe::7',
            max_address='cafe:babe::10', dhcp_pool_type='HOST')
        l3subnet.create_child(address_range)

        self._create_verify_illegal_ports(
            ipv4_subnet, ipv6_subnet, network,
            expected_exception=exceptions.Conflict,
            expected_error_msg=expected_error_message, dynamic=True)
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                    'ip_address': '10.0.0.10'}]}
        valid_port = self.create_port(network, cleanup=False, **port_args)
        self.delete_port(valid_port)
        self.assertEqual('10.0.0.10', valid_port['fixed_ips'][0]['ip_address'])
        port_args = {'fixed_ips': [{'subnet_id': ipv6_subnet['id'],
                                    'ip_address': 'cafe:babe::10'}]}
        valid_port = self.create_port(network, cleanup=False, **port_args)
        self.delete_port(valid_port)
        self.assertEqual('cafe:babe::10',
                         valid_port['fixed_ips'][0]['ip_address'])

    @decorators.attr(type='smoke')
    def test_rollback(self):
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network,
                                         cidr=IPNetwork('10.0.0.0/24'),
                                         mask_bits=24)
        ipv6_subnet = self.create_subnet(network, ip_version=6,
                                         cidr=IPNetwork('cafe:babe::/64'),
                                         mask_bits=64)
        port1 = self.create_port(network)
        vm = self.create_tenant_server(ports=[port1])
        port2 = self.create_port(network)
        port2_ipv4_address = [
            ip['ip_address'] for ip in port2['fixed_ips'] if
            ip['subnet_id'] == ipv4_subnet['id']][0]
        port2_ipv6_address = [
            ip['ip_address'] for ip in port2['fixed_ips'] if
            ip['subnet_id'] == ipv6_subnet['id']][0]

        # Try to update port, assert rollback went well
        expected_errormsg = 'IP address .* already allocated in subnet'
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                    'ip_address': port2_ipv4_address}]}
        self.assertRaisesRegex(exceptions.Conflict,
                               expected_errormsg,
                               self.update_port, port1, **port_args)
        port_args = {'fixed_ips': [{'subnet_id': ipv6_subnet['id'],
                                    'ip_address': port2_ipv6_address}]}
        self.assertRaisesRegex(exceptions.Conflict,
                               expected_errormsg,
                               self.update_port, port1, **port_args)

        # l2domain verify
        l2domain = self.vsd.get_l2domain(by_network_id=network['id'],
                                         cidr=ipv4_subnet['cidr'],
                                         ip_type=4)
        ipreservations = l2domain.vmip_reservations.get()
        self._verify_vmipreservations(ipreservations, ipv4_subnet, ipv6_subnet,
                                      network, port2, vm)

        router = self.create_router()
        self.router_attach(router, ipv4_subnet)
        self.router_attach(router, ipv6_subnet)

        # Try to update port, assert rollback went well
        expected_errormsg = 'IP address .* already allocated in subnet'
        port_args = {'fixed_ips': [{'subnet_id': ipv4_subnet['id'],
                                    'ip_address': port2_ipv4_address}]}
        self.assertRaisesRegex(exceptions.Conflict,
                               expected_errormsg,
                               self.update_port, port1, **port_args)
        port_args = {'fixed_ips': [{'subnet_id': ipv6_subnet['id'],
                                    'ip_address': port2_ipv6_address}]}
        self.assertRaisesRegex(exceptions.Conflict,
                               expected_errormsg,
                               self.update_port, port1, **port_args)

        vsd_subnet = self.vsd.get_subnet(by_network_id=network['id'],
                                         cidr=ipv4_subnet['cidr'])
        ipreservations = vsd_subnet.vmip_reservations.get()
        self._verify_vmipreservations(ipreservations, ipv4_subnet, ipv6_subnet,
                                      network, port2, vm)

    @decorators.attr(type='smoke')
    def test_public_subnet(self):

        network = self.create_network(manager=self.admin_manager,
                                      **{'router:external': True})
        ipv4_subnet = self.create_subnet(network,
                                         manager=self.admin_manager,
                                         cidr=IPNetwork('10.0.0.0/24'),
                                         mask_bits=24, underlay=False)
        self.create_floatingip(manager=self.admin_manager,
                               external_network_id=network['id'],
                               floating_ip_address='10.0.0.10')
        fip2 = self.create_floatingip(manager=self.admin_manager,
                                      external_network_id=network['id'])

        vsd_subnet = self.vsd.get_subnet(by_network_id=network['id'],
                                         cidr=ipv4_subnet['cidr'])
        ipreservations = vsd_subnet.vmip_reservations.get()
        reserved_ips = [ipreservation.ipv4_address for ipreservation in
                        ipreservations]
        self.assertEqual(2, len(reserved_ips))
        self.assertIn('10.0.0.10', reserved_ips)
        self.assertIn(fip2['floating_ip_address'], reserved_ips)

        # Check that an error occurs when trying to reserve existing fip
        vmipreservation = self.vsd.vspk.NUVMIPReservation(
            ip_type='IPV4', ipv4_address='10.0.0.11')
        vsd_subnet.create_child(vmipreservation)
        error_message = ('The address allocation request could not be '
                         'satisfied because: The requested ip address is '
                         'already reserved on VSD by another entity.')
        self.assertRaisesRegex(exceptions.BadRequest,
                               error_message,
                               self.create_floatingip,
                               manager=self.admin_manager,
                               external_network_id=network['id'],
                               floating_ip_address='10.0.0.11')

    @decorators.attr(type='smoke')
    def test_unmananged_domain_negative(self):
        l2domain_template = self.vsd.create_l2domain_template(
            dhcp_managed=False)
        l2domain = self.vsd.create_l2domain(template=l2domain_template)
        network = self.create_network()
        kwargs = {
            'network': network,
            'cidr': IPNetwork('10.0.0.0/24'),
            'enable_dhcp': False,
            'gateway': None,
            'mask_bits': 24,
            'net_partition': Topology.def_netpartition,
            'nuagenet': l2domain.id
        }
        self.create_subnet(**kwargs)

        # Assert that creating a port fails
        self.assertRaisesRegex(
            exceptions.BadRequest,
            'The address allocation request could not be satisfied because: '
            'Unable to reserve IP on VSD',
            self.create_port,
            network)
