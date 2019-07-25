# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from netaddr import IPNetwork

from tempest import exceptions
from tempest.lib.common.utils import data_utils
from tempest.test import decorators

from . import nuage_base

from nuage_tempest_plugin.lib.topology import Topology

LOG = Topology.get_logger(__name__)


class VsdManagedNetworkTest(nuage_base.NuageBaseOrchestrationTest):
    @decorators.attr(type=['negative'])
    def test_link_subnet_to_vsd_l2domain_with_empty_net_partition(self):
        """test_link_subnet_to_vsd_l2domain_without_net_partition

        Test heat creation should raise exception for a private VSD managed
        network without net-partition
        """
        # Create the VSD l2 domain from a template
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')

        vsd_l2domain_template = self.create_vsd_dhcp_managed_l2domain_template(
            name=name, cidr=cidr, gateway=str(cidr[1]))
        vsd_l2domain = self.create_vsd_l2domain(
            name=name, tid=vsd_l2domain_template[0]['ID'])

        self.assertIsInstance(vsd_l2domain, list)
        self.assertEqual(vsd_l2domain[0]['name'], name)

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_minimal'
        stack_parameters = {
            'vsd_subnet_id': vsd_l2domain[0]['ID'],
            'private_net_name': self.private_net_name,
            'private_net_cidr': str(cidr),
            'netpartition_name': None}

        msg = 'Bad request'

        # Small difference between El7 and Ubuntu heat results in different
        # output: check the neutron output only
        self.assertRaisesRegex(exceptions.StackBuildErrorException,
                               msg,
                               self.launch_stack,
                               stack_file_name,
                               stack_parameters)

    def test_link_subnet_to_vsd_l2domain_without_net_partition(self):
        """test_link_subnet_to_vsd_l2domain_without_net_partition

        Test heat creation should raise exception for a private VSD managed
        network without net-partition
        """
        # Create the VSD l2 domain from a template
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')

        vsd_l2domain_template = self.create_vsd_dhcp_managed_l2domain_template(
            name=name, cidr=cidr, gateway=str(cidr[1]))
        vsd_l2domain = self.create_vsd_l2domain(
            name=name, tid=vsd_l2domain_template[0]['ID'])

        self.assertIsInstance(vsd_l2domain, list)
        self.assertEqual(vsd_l2domain[0]['name'], name)

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_no_netpartition'
        stack_parameters = {
            'vsd_subnet_id': vsd_l2domain[0]['ID'],
            'private_net_name': self.private_net_name,
            'private_net_cidr': str(cidr)}

        msg = ('Bad request: Parameter net-partition required when '
               'passing nuagenet')

        # Small difference between El7 and Ubuntu heat results in different
        # output: check the neutron output only
        self.assertRaisesRegex(exceptions.StackBuildErrorException,
                               msg,
                               self.launch_stack,
                               stack_file_name,
                               stack_parameters)

    @decorators.attr(type=['negative'])
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
