# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from netaddr import IPNetwork

from tempest.lib.common.utils import data_utils

from . import nuage_base

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology

LOG = Topology.get_logger(__name__)


class OrchestrationVsdManagedNetworkTest(
        nuage_base.NuageBaseOrchestrationTest):

    @classmethod
    def resource_setup(cls):
        if Topology.is_ml2:
            # create default netpartition if it is not there
            netpartition_name = cls.vsd_client.def_netpart_name
            net_partition = cls.vsd_client.get_net_partition(netpartition_name)
            if not net_partition:
                net_partition = cls.vsd_client.create_net_partition(
                    netpartition_name,
                    fip_quota=100,
                    extra_params=None)
        super(OrchestrationVsdManagedNetworkTest, cls).resource_setup()

    @nuage_test.header()
    def test_link_subnet_to_vsd_l2domain_dhcp_managed_minimal(self):
        """test_link_subnet_to_vsd_l2domain_dhcp_managed_minimal

        Test heat creation of a private VSD managed network from
        dhcp-managed l2 domain template

        OpenStack network is created with minimal attributes.
        """
        # Create the VSD l2 domain from a template
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        gateway = '10.10.100.1'

        vsd_l2domain_template = self.create_vsd_dhcp_managed_l2domain_template(
            name=name,
            cidr=cidr,
            gateway=str(cidr[254])  # the DHCP server (!)
        )
        vsd_l2domain = self.create_vsd_l2domain(
            name=name, tid=vsd_l2domain_template[0]['ID'])

        self.assertIsInstance(vsd_l2domain, list)
        self.assertEqual(vsd_l2domain[0]['name'], name)

        self.vsd_client.create_dhcpoption_on_l2dom(
            vsd_l2domain[0]['ID'], 3, [gateway])

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network_minimal'
        stack_parameters = {
            'vsd_subnet_id': vsd_l2domain[0]['ID'],
            'netpartition_name': self.net_partition_name,
            'private_net_name': self.private_net_name,
            'private_net_cidr': str(cidr)}
        self.launch_stack(stack_file_name, stack_parameters)

        # Verifies created resources
        expected_resources = ['private_net', 'private_subnet']
        self.verify_stack_resources(expected_resources,
                                    self.template_resources,
                                    self.test_resources)
        # Test network
        network = self.verify_created_network('private_net')
        subnet = self.verify_created_subnet('private_subnet', network)

        self.assertTrue(
            subnet['enable_dhcp'],
            "Shall have DHCP enabled from the l2 domain template")
        self.assertEqual(
            str(cidr), subnet['cidr'],
            "Shall get the CIDR from the l2 domain")
        self.assertEqual(
            str(cidr[2]), subnet['allocation_pools'][0]['start'],
            "Shall start allocation pool at second address in l2 domain")
        self.assertEqual(
            str(cidr[-2]), subnet['allocation_pools'][0]['end'],
            "Shall end allocation pool at last address in l2 domain")

    @nuage_test.header()
    def test_link_subnet_to_vsd_l2domain_dhcp_managed(self):
        """test_link_subnet_to_vsd_l2domain_dhcp_managed

        Test heat creation of a private VSD managed network from
        dhcp-managed l2 domain template

        OpenStack network is created with maximal attributes.
        """

        # Create the VSD l2 domain from a template
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        gateway = '10.10.100.1'

        vsd_l2domain_template = self.create_vsd_dhcp_managed_l2domain_template(
            name=name, cidr=cidr,
            gateway=str(cidr[254])  # the DHCP server (!)
        )
        vsd_l2domain = self.create_vsd_l2domain(
            name=name, tid=vsd_l2domain_template[0]['ID'])

        self.assertIsInstance(vsd_l2domain, list)
        self.assertEqual(vsd_l2domain[0]['name'], name)

        self.vsd_client.create_dhcpoption_on_l2dom(
            vsd_l2domain[0]['ID'], 3, [gateway])

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network'
        stack_parameters = {
            'vsd_subnet_id': vsd_l2domain[0]['ID'],
            'netpartition_name': self.net_partition_name,
            'private_net_name': self.private_net_name,
            'private_net_cidr': str(cidr),
            'private_net_dhcp': True,
            'private_net_pool_start': str(cidr[2]),  # neutron won't allow .1
            # unless we give --no-gateway - TODO(KRIS) Add such tests
            'private_net_pool_end': str(cidr[254])}

        self.launch_stack(stack_file_name, stack_parameters)

        # Verifies created resources
        expected_resources = ['private_net', 'private_subnet']
        self.verify_stack_resources(expected_resources,
                                    self.template_resources,
                                    self.test_resources)
        # Test network
        network = self.verify_created_network('private_net')
        subnet = self.verify_created_subnet('private_subnet', network)

        self.assertTrue(subnet['enable_dhcp'],
                        "Shall have DHCP enabled from the l2 domain template")
        self.assertEqual(str(cidr), subnet['cidr'],
                         "Shall get the CIDR from the l2 domain")
        self.assertEqual(str(cidr[1]), subnet['gateway_ip'],
                         "Shall get .1 gateway ip as default")
        self.assertEqual(str(cidr[2]), subnet['allocation_pools'][0]['start'],
                         "Shall start allocation pool at second address in "
                         "l2 domain")
        self.assertEqual(str(cidr[254]), subnet['allocation_pools'][0]['end'],
                         "Shall end allocation pool at last address in "
                         "l2 domain")

    @nuage_test.header()
    def test_link_subnet_to_vsd_l2domain_dhcp_unmanaged(self):
        """test_link_subnet_to_vsd_l2domain_dhcp_unmanaged

        Test heat creation of a private VSD managed network from
        dhcp-unmanaged l2 domain template
        """
        # Create the VSD l2 domain from a template
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        gateway = '10.10.100.1'

        vsd_l2domain_template = \
            self.create_vsd_dhcp_unmanaged_l2domain_template(
                name=name,
                cidr=cidr,
                gateway=str(cidr[254]))  # the DHCP server (!)
        vsd_l2domain = self.create_vsd_l2domain(
            name=name, tid=vsd_l2domain_template[0]['ID'])

        self.assertIsInstance(vsd_l2domain, list)
        self.assertEqual(vsd_l2domain[0]['name'], name)

        self.vsd_client.create_dhcpoption_on_l2dom(
            vsd_l2domain[0]['ID'], 3, [gateway])

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network'
        stack_parameters = {
            'vsd_subnet_id': vsd_l2domain[0]['ID'],
            'netpartition_name': self.net_partition_name,
            'private_net_name': self.private_net_name,
            'private_net_cidr': str(cidr),
            'private_net_dhcp': False,
            # note that dhcp as false, the below to my view is useless ......
            'private_net_pool_start': str(cidr[2]),  # neutron won't allow .1
            # unless we give --no-gateway - TODO(KRIS) Add such tests
            'private_net_pool_end': str(cidr[254])}
        self.launch_stack(stack_file_name, stack_parameters)

        # Verifies created resources
        expected_resources = ['private_net', 'private_subnet']
        self.verify_stack_resources(expected_resources,
                                    self.template_resources,
                                    self.test_resources)
        # Test network
        network = self.verify_created_network('private_net')
        subnet = self.verify_created_subnet('private_subnet', network)

        self.assertFalse(subnet['enable_dhcp'],
                         "Shall have DHCP enabled from the l2 domain template")
        self.assertEqual(str(cidr), subnet['cidr'],
                         "Shall get the CIDR from the l2 domain")
        self.assertEqual(str(cidr[1]), subnet['gateway_ip'],
                         "Shall get .1 gateway ip as default")
        self.assertEqual(str(cidr[2]), subnet['allocation_pools'][0]['start'],
                         "Shall start allocation pool at second address in "
                         "l2 domain")
        self.assertEqual(str(cidr[254]), subnet['allocation_pools'][0]['end'],
                         "Shall end allocation pool at last address in "
                         "l2 domain")

    @nuage_test.header()
    def test_link_subnet_to_vsd_l3domain(self):
        """test_link_subnet_to_vsd_l3domain

        Test heat creation of a private VSD mgd network from l3 domain template
        """
        # Create the VSD l3 domain from a template
        name = data_utils.rand_name('l3domain-')
        cidr = IPNetwork('10.10.100.0/24')
        gateway_ip = str(cidr[1])

        vsd_l3domain_template = self.create_vsd_l3domain_template(
            name=name)
        vsd_l3domain = self.create_vsd_l3domain(
            name=name, tid=vsd_l3domain_template[0]['ID'])

        self.assertIsInstance(vsd_l3domain, list)
        self.assertEqual(vsd_l3domain[0]['name'], name)

        zone_name = data_utils.rand_name('l3domain-zone-')
        vsd_zone = self.create_vsd_zone(name=zone_name,
                                        domain_id=vsd_l3domain[0]['ID'])
        self.assertEqual(vsd_zone[0]['name'], zone_name)

        subnet_name = data_utils.rand_name('l3domain-sub-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_domain_subnet = self.create_vsd_l3domain_subnet(
            name=subnet_name,
            zone_id=vsd_zone[0]['ID'],
            cidr=cidr,
            gateway=gateway_ip)
        self.assertEqual(vsd_domain_subnet[0]['name'], subnet_name)

        # launch a heat stack
        stack_file_name = 'nuage_vsd_managed_network'
        stack_parameters = {
            'vsd_subnet_id': vsd_domain_subnet[0]['ID'],
            'netpartition_name': self.net_partition_name,
            'private_net_name': self.private_net_name,
            'private_net_cidr': str(cidr),
            'private_net_dhcp': True,
            'private_net_pool_start': str(cidr[2]),
            'private_net_pool_end': str(cidr[254])}
        self.launch_stack(stack_file_name, stack_parameters)

        # Verifies created resources
        expected_resources = ['private_net', 'private_subnet']
        self.verify_stack_resources(expected_resources,
                                    self.template_resources,
                                    self.test_resources)
        # Test network
        network = self.verify_created_network('private_net')
        subnet = self.verify_created_subnet('private_subnet', network)

        self.assertTrue(subnet['enable_dhcp'],
                        "Shall have DHCP enabled from the l2 domain template")
        self.assertEqual(str(cidr), subnet['cidr'],
                         "Shall get the CIDR from the l2 domain")
        self.assertEqual(gateway_ip, subnet['gateway_ip'],
                         "Shall get the dhcp IP from the l2 domain")
        # in this case we get .2 correctly
        self.assertEqual(str(cidr[2]), subnet['allocation_pools'][0]['start'],
                         "Shall start allocation pool at first address in "
                         "l2 domain")
        self.assertEqual(str(cidr[254]), subnet['allocation_pools'][0]['end'],
                         "Shall end allocation pool at last address in "
                         "l2 domain")
