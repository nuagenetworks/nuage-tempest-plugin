import time

from tempest.api.compute import base as serv_base
from tempest.scenario import manager

from nuage_tempest_plugin.tests.api import test_ip_anti_spoofing as antispoof


class IpAntiSpoofingTestScenario(antispoof.IpAntiSpoofingTestBase,
                                 manager.NetworkScenarioTest,
                                 serv_base.BaseV2ComputeTest):

    @classmethod
    def skip_checks(cls):
        super(IpAntiSpoofingTestScenario, cls).skip_checks()
        raise cls.skipException('Skipping as needs VRS whitebox tests, '
                                'which is work in progress - TODO(Kris)')

    @classmethod
    def resource_setup(cls):
        super(IpAntiSpoofingTestScenario, cls).resource_setup()

    def test_vm_in_sec_disabled_port_l2domain(self):
        """test_vm_in_sec_disabled_port_l2domain

        L2domain testcase to spawn VM in port with port-security-enabled set to
        False at port level only.
        """
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=False,
            l2domain_name='scn-l2dom1-1',
            port_name='scn-port1-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], False)
        ntw = {'uuid': network['id'], 'port': port['id']}
        vm = self.create_server(name='scn-port1-vm-1', networks=[ntw],
                                wait_until='ACTIVE')
        self.assertEqual(port['fixed_ips'][0]['ip_address'],
                         vm['addresses'][network['name']][0]['addr'])
        self.assertEqual(
            port['mac_address'],
            vm['addresses'][network['name']][0]['OS-EXT-IPS-MAC:mac_addr'])
        self.assertEqual(vm['status'], 'ACTIVE')
        # tag_name = 'verify_vm_in_sec_disabled_port_l2domain'
        # nuage_ext.nuage_extension.nuage_components(
        #     nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    def test_vm_in_sec_disabled_port_l3domain(self):
        """test_vm_in_sec_disabled_port_l3domain

        L3domain testcase to spawn VM in port with port-security-enabled set
        to False at port level only.
        """
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=False,
            router_name='scn-router11-1',
            subnet_name='scn-subnet11-1',
            port_name='scn-port11-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], False)
        ntw = {'uuid': network['id'], 'port': port['id']}
        vm = self.create_server(name='scn-port11-vm-1', networks=[ntw],
                                wait_until='ACTIVE')
        self.assertEqual(port['fixed_ips'][0]['ip_address'],
                         vm['addresses'][network['name']][0]['addr'])
        self.assertEqual(
            port['mac_address'],
            vm['addresses'][network['name']][0]['OS-EXT-IPS-MAC:mac_addr'])
        self.assertEqual(vm['status'], 'ACTIVE')
        # tag_name = 'verify_vm_in_sec_disabled_port_l3domain'
        # nuage_ext.nuage_extension.nuage_components(
        #     nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

    def test_vm_with_port_parameters_1_0_0_1_l3domain(self):
        """test_vm_with_port_parameters_1_0_0_1_l3domain

        IP Anti Spoofing scenario test for vip parameters having
        full cidr(/32 IP), same mac, same ip, different subnet in
        comparison with the corresponding port parameters.
        """
        ip_address = '30.30.30.100'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=True,
            router_name='scn-router12-1',
            subnet_name='scn-subnet12-1',
            port_name='scn-port12-1',
            netpart=self.def_netpartition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        ntw = {'uuid': network['id'], 'port': port['id']}
        vm = self.create_server(name='scn-port12-vm-1', networks=[ntw],
                                wait_until='ACTIVE')
        self.assertEqual(port['fixed_ips'][0]['ip_address'],
                         vm['addresses'][network['name']][0]['addr'])
        self.assertEqual(
            port['mac_address'],
            vm['addresses'][network['name']][0]['OS-EXT-IPS-MAC:mac_addr'])
        self.assertEqual(vm['status'], 'ACTIVE')
        time.sleep(30)
        # tag_name = 'verify_vm_vip_and_anit_spoof_l3domain'
        # nuage_ext.nuage_extension.nuage_components(
        #     nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)
