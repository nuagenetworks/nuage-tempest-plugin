# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

import logging

from netaddr import IPAddress

from tempest import config
from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.test import nuage_test

from nuage_tempest_plugin.tests.api.ipv6.base_nuage_networks \
    import NetworkTestCaseMixin
from nuage_tempest_plugin.tests.api.ipv6.base_nuage_networks \
    import VsdTestCaseMixin
from nuage_tempest_plugin.tests.api.ipv6.base_nuage_orchestration \
    import NuageBaseOrchestrationTest

CONF = config.CONF

LOG = logging.getLogger(__name__)


class OrchestrationVsdManagedNetworkDualStackTest(NuageBaseOrchestrationTest,
                                                  NetworkTestCaseMixin,
                                                  VsdTestCaseMixin):
    @nuage_test.header()
    def test_link_subnet_to_vsd_l2domain_dhcp_managed_vm_on_port(self):
        """test_link_subnet_to_vsd_l2domain_dhcp_managed_vm_on_port

        Test heat creation of a private VSD managed network from
        dhcp-managed l2 domain template

        OpenStack network is created with minimal attributes.
        """

        # create l2domain on VSD
        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=self.cidr4,
            cidr6=self.cidr6,
            gateway=self.gateway4,
            gateway6=self.gateway6)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=self.cidr4,
                                           cidr6=self.cidr6,
                                           IPv6Gateway=self.gateway6,
                                           gateway=self.gateway4)

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
        self._verify_vsd_l2domain_with_template(vsd_l2domain,
                                                vsd_l2domain_template)

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_dualstack_vm_on_port'
        stack_parameters = {
            'vsd_subnet_id': vsd_l2domain['ID'],
            'netpartition_name': self.net_partition_name,
            'net_name': self.private_net_name,
            'cidr4': str(self.cidr4),
            'gateway4': self.gateway4,
            'maskbits4': self.mask_bits4,
            'cidr6': str(self.cidr6),
            'gateway6': self.gateway6,
            'maskbits6': self.mask_bits6,
            'pool_start6': str(IPAddress(self.gateway6) + 1),
            'pool_end6': str(IPAddress(self.cidr6.last)),
            'image': CONF.compute.image_ref
        }

        self.launch_stack(stack_file_name, stack_parameters)

        # Verifies created resources
        expected_resources = ['dualstack_net', 'subnet4', 'subnet6']
        self.verify_stack_resources(
            expected_resources, self.template_resources, self.test_resources)

        # Test network
        network = self.verify_created_network('dualstack_net')
        self.verify_created_subnet('subnet4', network)
        self.verify_created_subnet('subnet6', network)

    @nuage_test.header()
    def test_link_subnet_to_vsd_l2domain_dhcp_managed_vm_in_net(self):
        """test_link_subnet_to_vsd_l2domain_dhcp_managed_vm_in_net

        Test heat creation of a private VSD managed network from
        dhcp-managed l2 domain template

        OpenStack network is created with minimal attributes.
        """
        # create l2domain on VSD
        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type="DUALSTACK",
            dhcp_managed=True,
            cidr4=self.cidr4,
            cidr6=self.cidr6,
            gateway=self.gateway4,
            gateway6=self.gateway6)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           ip_type="DUALSTACK",
                                           dhcp_managed=True,
                                           cidr4=self.cidr4,
                                           cidr6=self.cidr6,
                                           IPv6Gateway=self.gateway6,
                                           gateway=self.gateway4)

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])
        self._verify_vsd_l2domain_with_template(
            vsd_l2domain, vsd_l2domain_template)

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_dualstack_vm_in_net'
        stack_parameters = {
            'vsd_subnet_id': vsd_l2domain['ID'],
            'netpartition_name': self.net_partition_name,
            'net_name': self.private_net_name,
            'cidr4': str(self.cidr4),
            'gateway4': self.gateway4,
            'maskbits4': self.mask_bits4,
            'cidr6': str(self.cidr6),
            'gateway6': self.gateway6,
            'maskbits6': self.mask_bits6,
            'image': CONF.compute.image_ref
        }
        self.launch_stack(stack_file_name, stack_parameters)

        # Verifies created resources
        expected_resources = ['dualstack_net', 'subnet4', 'subnet6']
        self.verify_stack_resources(
            expected_resources, self.template_resources, self.test_resources)

        # Test network
        network = self.verify_created_network('dualstack_net')
        self.verify_created_subnet('subnet4', network)
        self.verify_created_subnet('subnet6', network)

    @nuage_test.header()
    def test_link_subnet_to_vsd_l3domain_dhcp_managed_vm_on_port(self):
        """test_link_subnet_to_vsd_l3domain_dhcp_managed_vm_on_port

        Test heat creation of a private VSD managed network from
        dhcp-managed l3 domain
        """

        name = data_utils.rand_name('l3domain-')
        vsd_l3domain_template = self.create_vsd_l3dom_template(
            name=name)
        vsd_l3domain = self.create_vsd_l3domain(
            name=name, tid=vsd_l3domain_template['ID'])

        self.assertEqual(vsd_l3domain['name'], name)
        zone_name = data_utils.rand_name('zone-')
        extra_params = None
        vsd_zone = self.create_vsd_zone(name=zone_name,
                                        domain_id=vsd_l3domain['ID'],
                                        extra_params=extra_params)

        subnet_name = data_utils.rand_name('l3domain-subnet-')

        vsd_l3domain_subnet = self.create_vsd_l3domain_dualstack_subnet(
            zone_id=vsd_zone['ID'],
            subnet_name=subnet_name,
            cidr=self.cidr4,
            gateway=self.gateway4,
            cidr6=self.cidr6,
            gateway6=self.gateway6)

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_l3_dualstack_vm_on_port'
        stack_parameters = {
            'vsd_subnet_id': vsd_l3domain_subnet['ID'],
            'netpartition_name': self.net_partition_name,
            'net_name': self.private_net_name,
            'cidr4': str(self.cidr4),
            'gateway4': self.gateway4,
            'maskbits4': self.mask_bits4,
            'cidr6': str(self.cidr6),
            'gateway6': self.gateway6,
            'maskbits6': self.mask_bits6,
            'image': CONF.compute.image_ref
        }
        self.launch_stack(stack_file_name, stack_parameters)

        # Verifies created resources
        expected_resources = ['dualstack_net', 'subnet4', 'subnet6']
        self.verify_stack_resources(
            expected_resources, self.template_resources, self.test_resources)

        # Test network
        network = self.verify_created_network('dualstack_net')
        self.verify_created_subnet('subnet4', network)
        self.verify_created_subnet('subnet6', network)
