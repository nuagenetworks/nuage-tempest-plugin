# Copyright 2017 NOKIA
# All Rights Reserved.

from tempest.common import utils
from tempest.lib import decorators

from nuage_tempest_plugin.lib.topology import Topology

from . import nuage_base

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class OrchestrationServerTest(nuage_base.NuageBaseOrchestrationTest):

    @classmethod
    def setup_clients(cls):
        super(OrchestrationServerTest, cls).setup_clients()

    @classmethod
    def resource_setup(cls):
        super(OrchestrationServerTest, cls).resource_setup()
        if not utils.is_extension_enabled('router', 'network'):
            msg = "router extension not enabled."
            raise cls.skipException(msg)

        system_configurations = cls.vsd_client.get_system_configuration()
        cls.system_configuration = system_configurations[0]

    @classmethod
    def resource_cleanup(cls):
        super(OrchestrationServerTest, cls).resource_cleanup()

    def _get_vsd_l3domain(self, external_id):
        nuage_domain = self.vsd_client.get_l3domain(
            filters='externalID',
            filter_value=external_id)
        return nuage_domain[0]

    @decorators.attr(type=['smoke'])
    def test_servers_in_new_neutron_net_nokey(self):
        # ext_net_id = self.public_net['id']
        ext_net_id = CONF.network.public_network_id

        stack_file_name = 'servers_in_new_neutron_net_nokey'
        stack_parameters = {
            'image': CONF.compute.image_ref,
            'flavor': CONF.compute.flavor_ref,
            'public_net': ext_net_id,
            'private_net_name': "servers_in_new_neutron_net_nokey-net",
            'private_net_cidr': "8.7.6.0/24"}
        self.launch_stack(stack_file_name, stack_parameters)

        # Verifies created resources
        expected_resources = ['private_net',
                              'private_subnet',
                              'router',
                              'router_interface',
                              'server1',
                              'server1_port',
                              'server1_floating_ip',
                              'server2',
                              'server2_port',
                              'server2_floating_ip'
                              ]

        self.verify_stack_resources(expected_resources,
                                    self.template_resources,
                                    self.test_resources)
