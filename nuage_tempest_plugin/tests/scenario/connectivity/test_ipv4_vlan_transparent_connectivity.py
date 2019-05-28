# Copyright 2017 - Nokia
# All Rights Reserved.

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.test.nuage_test import skip_because
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

from netaddr import IPNetwork
import testtools

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class VlanTransparentConnectivityTest(NuageBaseTest):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(VlanTransparentConnectivityTest, cls).setup_clients()
        cls.nuage_client = NuageRestClient()
        cls.client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)

    def setUp(self):
        self.addCleanup(self.resource_cleanup)
        super(VlanTransparentConnectivityTest, self).setUp()

    @classmethod
    def resource_setup(cls):
        super(VlanTransparentConnectivityTest, cls).resource_setup()

    @testtools.skipUnless(
        CONF.nuage_sut.image_is_advanced,
        "Advanced image is required to run this test.")
    def test_l2_transparent_network(self):
        kwargs = {
            'vlan_transparent': 'true'
        }
        network = self.create_network(**kwargs)
        self.create_subnet(network, gateway=None)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        vm1 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True)
        vm2 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True)

        vm1_ip = '13.13.13.13/24'
        vm2_ip = '13.13.13.14/24'
        ping_tgt = IPNetwork(vm2_ip)

        vm1.configure_vlan_interface(vm1_ip, 'eth1', vlan='10')
        vm2.configure_vlan_interface(vm2_ip, 'eth1', vlan='10')

        self.assert_ping(vm1, vm2, network,
                         address=str(ping_tgt.ip), interface='eth1.10')

    @testtools.skipUnless(
        CONF.nuage_sut.image_is_advanced,
        "Advanced image is required to run this test.")
    @skip_because(bug='OPENSTACK-2325')
    def test_l3_transparent_network(self):
        kwargs = {
            'vlan_transparent': 'true'
        }
        router = self.create_test_router()
        l3network = self.create_network(**kwargs)
        subnet = self.create_subnet(l3network)
        self.router_attach(router, subnet)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        vm1 = self.create_tenant_server(
            networks=[l3network],
            security_groups=[ssh_security_group],
            name='vm1',
            make_reachable=True)

        vm2 = self.create_tenant_server(
            networks=[l3network],
            security_groups=[ssh_security_group],
            name='vm2',
            make_reachable=True)

        vm1_ip = '13.13.13.13/24'
        vm2_ip = '13.13.13.14/24'
        ping_tgt = IPNetwork(vm2_ip)

        vm1.configure_vlan_interface(vm1_ip, 'eth0', vlan='10')
        vm2.configure_vlan_interface(vm2_ip, 'eth0', vlan='10')

        self.assert_ping(vm1, vm2, l3network,
                         address=str(ping_tgt.ip), interface='eth0.10')
