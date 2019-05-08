# Copyright 2017 NOKIA
# All Rights Reserved.

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology

from . import nuage_base

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class OrchestrationRouterTest(nuage_base.NuageBaseOrchestrationTest):

    @classmethod
    def setup_clients(cls):
        super(OrchestrationRouterTest, cls).setup_clients()

    @classmethod
    def resource_setup(cls):
        super(OrchestrationRouterTest, cls).resource_setup()
        if not utils.is_extension_enabled('router', 'network'):
            msg = "router extension not enabled."
            raise cls.skipException(msg)

        system_configurations = cls.vsd_client.get_system_configuration()
        cls.system_configuration = system_configurations[0]

    @classmethod
    def resource_cleanup(cls):
        super(OrchestrationRouterTest, cls).resource_cleanup()

    def _get_vsd_l3domain(self, external_id):
        nuage_domain = self.vsd_client.get_l3domain(
            filters='externalID',
            filter_value=external_id)
        return nuage_domain[0]

    def _verify_router_with_vsd_l3domain(self, router):
        nuage_domain = self._get_vsd_l3domain(
            self.vsd_client.get_vsd_external_id(router['id']))
        external_id = self.vsd_client.get_vsd_external_id(router['id'])

        self.assertEqual(nuage_domain['externalID'], external_id,
                         "External ID")
        self.assertEqual(nuage_domain['routeDistinguisher'], router['rd'],
                         "Route distinguisher")
        self.assertEqual(nuage_domain['routeTarget'], router['rt'],
                         "Route target")
        self.assertEqual(nuage_domain['tunnelType'], router['tunnel_type'],
                         "Domain tunnel type")
        # enable_snat = False if router['external_gateway_info'] is \
        #     None else router['external_gateway_info']['enable_snat']

        # TODO(team) adapt to new logic
        # If enable snat was not explicit defined at OS router creation,
        # PAT_VSD_Enabled does NOT match the enable snat value
        # self.assertEqual(
        #     nuage_domain['PATEnabled'],
        #     nuage_constants.NUAGE_PAT_VSD_ENABLED if enable_snat else
        #     nuage_constants.NUAGE_PAT_VSD_DISABLED)

    @decorators.attr(type=['smoke'])
    @nuage_test.header()
    def test_router_extended_attributes(self):
        default_tunnel_type = self.system_configuration['domainTunnelType']

        # ext_net_id = self.public_net['id']
        ext_net_id = CONF.network.public_network_id

        unique_int = data_utils.rand_int_id(start=1, end=0x7fff)
        rd = "10:" + str(unique_int)
        rt = "12:" + str(unique_int)

        # launch a heat stack
        # Exclude snat = True router
        stack_file_name = 'router_extended_attributes_underlay'
        stack_parameters = {
            'public_net': ext_net_id,
            'netpartition_name': self.net_partition_name,
            'rd': rd,
            'rt': rt}
        self.launch_stack(stack_file_name, stack_parameters)

        # Verifies created resources
        expected_resources = ['router_minimal',
                              'router_net_partition',
                              'router_rd_dt',
                              'router_snat_false',
                              'router_tunnel_type_gre',
                              'router_tunnel_type_vxlan',
                              'router_tunnel_type_default']

        self.verify_stack_resources(expected_resources,
                                    self.template_resources,
                                    self.test_resources)

        # Test minimal
        router = self.verify_created_router('router_minimal')
        self.assertEqual(default_tunnel_type, router['tunnel_type'],
                         "Router default tunnel type")
        self.assertTrue(router['admin_state_up'], "Admin state")
        self.assertNotEmpty(router['rd'], "Route distinguisher")
        self.assertNotEmpty(router['rt'], "Route target")
        self._verify_router_with_vsd_l3domain(router)

        # Test rd dt
        router = self.verify_created_router('router_rd_dt')
        self.assertEqual(rd, router['rd'], "Route distinguisher")
        self.assertEqual(rt, router['rt'], "Route target")
        self.assertEqual(ext_net_id, router['external_gateway_info'][
            'network_id'], "External gateway info")
        self._verify_router_with_vsd_l3domain(router)

        # Test tunnel type GRE
        router = self.verify_created_router('router_tunnel_type_gre')
        self.assertEqual("GRE", router['tunnel_type'],
                         "Domain tunnel type")
        self._verify_router_with_vsd_l3domain(router)

        # Test tunnel type VXLAN
        router = self.verify_created_router('router_tunnel_type_vxlan')
        self.assertEqual("VXLAN", router['tunnel_type'],
                         "Domain tunnel type")
        self._verify_router_with_vsd_l3domain(router)

        # Test tunnel type default
        router = self.verify_created_router('router_tunnel_type_default')
        self.assertEqual(default_tunnel_type, router['tunnel_type'],
                         "Domain tunnel type")
        self._verify_router_with_vsd_l3domain(router)

    def test_multiple_subnets_in_external_network(self):
        stack_file_name = 'multiple_subnets_in_external_network'
        self.launch_stack(stack_file_name, {})
        network = self.verify_created_network('Network')
        subnet1 = self.verify_created_subnet('Subnet1', network)
        subnet2 = self.verify_created_subnet('Subnet2', network)
        self.assertEqual(subnet1['nuage_uplink'], subnet2['nuage_uplink'])
