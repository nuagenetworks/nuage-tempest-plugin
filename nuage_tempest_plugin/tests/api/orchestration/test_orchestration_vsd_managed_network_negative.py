# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from netaddr import IPNetwork

from tempest import exceptions
from tempest.lib.common.utils import data_utils
from tempest.test import decorators

from nuage_tempest_plugin.tests.api.orchestration import nuage_base

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology

LOG = Topology.get_logger(__name__)


class VsdManagedNetworkTest(nuage_base.NuageBaseOrchestrationTest):

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_link_subnet_to_vsd_l2domain_without_valid_vsd_l2domain(self):
        """test_link_subnet_to_vsd_l2domain_without_valid_vsd_l2domain

        Test heat creation should raise exception for a private VSD managed
        network without valid l2_domain id
        """
        cidr = IPNetwork('10.10.100.0/24')

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_minimal'
        stack_parameters = {
            'vsd_subnet_id': 'not a valid UUID',
            'netpartition_name': self.net_partition_name,
            'private_net_name': self.private_net_name,
            'private_net_cidr': str(cidr)}

        msg = "Invalid input for nuagenet. " \
              "Reason: 'not a valid UUID' is not a valid UUID."

        # Small difference between El7 and Ubuntu heat results in different
        # output: check the neutron output only
        self.assertRaisesRegex(exceptions.StackBuildErrorException,
                               msg,
                               self.launch_stack,
                               stack_file_name,
                               stack_parameters)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_link_subnet_to_vsd_l2domain_without_existing_vsd_l2domain(self):
        """test_link_subnet_to_vsd_l2domain_without_existing_vsd_l2domain

        Test heat creation should raise exception for a private VSD managed
        network without valid l2_domain id
        """
        cidr = IPNetwork('10.10.100.0/24')

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_minimal'
        stack_parameters = {
            'vsd_subnet_id': data_utils.rand_uuid(),
            'netpartition_name': self.net_partition_name,
            'private_net_name': self.private_net_name,
            'private_net_cidr': str(cidr)}

        msg = "Cannot find l2domain with ID"

        # Small difference between El7 and Ubuntu heat results in different
        # output: check the neutron output only
        self.assertRaisesRegex(exceptions.StackBuildErrorException,
                               msg,
                               self.launch_stack,
                               stack_file_name,
                               stack_parameters)
