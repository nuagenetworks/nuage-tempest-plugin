# Copyright 2017 - Nokia
# All Rights Reserved.

from oslo_log import log as logging
import testtools

from tempest import config

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

CONF = config.CONF
LOG = logging.getLogger(__name__)


class VlanTransparentConnectivityTest(NuageBaseTest):
    _interface = 'json'

    image_profile = 'advanced'

    @classmethod
    def setup_clients(cls):
        super(VlanTransparentConnectivityTest, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()
        cls.client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os_primary.default_params)

    def setUp(self):
        self.addCleanup(self.resource_cleanup)
        super(VlanTransparentConnectivityTest, self).setUp()

    @classmethod
    def resource_setup(cls):
        super(VlanTransparentConnectivityTest, cls).resource_setup()

    @testtools.skipIf(not Topology.access_to_l2_supported(),
                      'Access to vm\'s in l2 networks is unsupported.')
    def test_l2_transparent_network(self):
        kwargs = {
            'vlan_transparent': 'true'
        }
        l2network = self.create_network(**kwargs)
        self.create_subnet(l2network)

        vm1 = self.create_tenant_server(
            tenant_networks=[l2network], name='vm1',
            image_profile=self.image_profile)

        vm2 = self.create_tenant_server(
            tenant_networks=[l2network], name='vm2',
            image_profile=self.image_profile)

        vm1_ip = vm1.get_server_ip_in_network(l2network['name'])
        vm2_ip = vm2.get_server_ip_in_network(l2network['name'])

        try:
            vm1.configure_vlan_interface(vm1_ip, 'eth0', vlan='10')
            vm2.configure_vlan_interface(vm2_ip, 'eth0', vlan='10')
        except OSError as e:
            self.skipTest('Skipping test as of ' + str(e))

        vm1.bring_down_interface('eth0')
        vm2.bring_down_interface('eth0')

        self.assert_ping(vm1, vm2, l2network, interface='eth0.10')

    @testtools.skipIf(not Topology.run_connectivity_tests(),
                      'Connectivity tests are disabled.')
    def test_l3_transparent_network(self):
        kwargs = {
            'vlan_transparent': 'true'
        }
        router = self.create_test_router()
        l3network = self.create_network(**kwargs)
        subnet = self.create_subnet(l3network)
        self.router_attach(router, subnet)

        ssh_security_group = self._create_security_group(
            namestart='tempest-open-ssh')

        vm1 = self.create_tenant_server(
            tenant_networks=[l3network],
            security_groups=[{'name': ssh_security_group['name']}],
            name='vm1', image_profile=self.image_profile)

        vm2 = self.create_tenant_server(
            tenant_networks=[l3network],
            security_groups=[{'name': ssh_security_group['name']}],
            name='vm2', image_profile=self.image_profile)

        self.prepare_for_nic_provisioning(vm1)
        self.prepare_for_nic_provisioning(vm2)

        vm1_ip = vm1.get_server_ip_in_network(l3network['name'])
        vm2_ip = vm2.get_server_ip_in_network(l3network['name'])

        try:
            vm1.configure_vlan_interface(vm1_ip, 'eth0', vlan='10')
            vm2.configure_vlan_interface(vm2_ip, 'eth0', vlan='10')
        except OSError as e:
            self.skipTest('Skipping test as of ' + str(e))

        vm1.bring_down_interface('eth0')
        vm2.bring_down_interface('eth0')

        self.assert_ping(vm1, vm2, l3network, interface='eth0.10')
