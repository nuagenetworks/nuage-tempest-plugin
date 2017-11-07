# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

import logging
from netaddr import IPAddress

from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils

import nuage_base

from nuage_tempest.lib.utils import constants
from nuage_tempest.tests.api.vsd_managed \
    import base_vsd_managed_networks
from nuage_tempest.tests.api.vsd_managed \
    import base_vsd_managed_port_attributes

CONF = config.CONF
LOG = logging.getLogger(__name__)

VALID_MAC_ADDRESS = 'fa:fa:3e:e8:e8:c0'


class HeatVsdManagedPortAttributesTest(
        base_vsd_managed_port_attributes.BaseVSDManagedPortAttributes,
        nuage_base.NuageBaseOrchestrationTest):

    @classmethod
    def setup_clients(cls):
        super(base_vsd_managed_port_attributes.BaseVSDManagedPortAttributes,
              cls).setup_clients()
        super(nuage_base.NuageBaseOrchestrationTest, cls).setup_clients()
        pass

    @classmethod
    def resource_setup(cls):
        super(HeatVsdManagedPortAttributesTest, cls).resource_setup()
        super(nuage_base.NuageBaseOrchestrationTest, cls).resource_setup()

        if not utils.is_extension_enabled('nuage-redirect-target', 'network'):
            msg = "Nuage extension 'nuage-redirect-target' not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_cleanup(cls):
        super(nuage_base.NuageBaseOrchestrationTest, cls).resource_cleanup()
        super(base_vsd_managed_port_attributes.BaseVSDManagedPortAttributes,
              cls).resource_cleanup()
        pass

    def _check_l2_heat_port_attributes(self, l2_policy_group,
                                       l2_aap_ip_address, l2_aap_mac_address):
        expected_resources = ['l2_port']
        self.verify_stack_resources(expected_resources,
                                    self.template_resources,
                                    self.test_resources)

        l2_subnet_id = self.test_resources['l2_subnet'][
            'physical_resource_id']
        l2_show_subnet = self.admin_subnets_client.show_subnet(
            l2_subnet_id)['subnet']

        l2_port_id = self.test_resources['l2_port'][
            'physical_resource_id']
        l2_show_port = self.admin_ports_client.show_port(l2_port_id)['port']

        l2_rt_id = self.test_resources['rt_l2']['physical_resource_id']
        l2_show_rt = self.nuage_network_client.show_redirection_target(
            l2_rt_id)

        rt_present = self._check_port_in_show_redirect_target(l2_show_port,
                                                              l2_show_rt)
        self.assertTrue(rt_present,
                        "Associated port not present in show nuage "
                        "redirect target response")
        # When I disassociate the red0rect-target from the port
        self._disassociate_rt_port(l2_show_port, l2_show_rt)
        # I expect the port to be gone from the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(l2_show_port,
                                                                l2_show_rt)
        self.assertEqual(port_present, False,
                         message="Disassociated port still present in "
                                 "show nuage-redirect-target-response")
        # Then I expect the redirection-target in my list
        my_rt_found = self._find_redirect_target_in_list(l2_rt_id,
                                                         l2_show_subnet)
        self.assertTrue(my_rt_found, "Did not find my redirect-target in "
                                     "the list")

        port_present = self._check_port_in_policy_group(
            l2_port_id, l2_policy_group[0]['ID'])
        self.assertTrue(port_present, "Port(%s) associated to policy group "
                                      "(%s) is not present" %
                        (l2_port_id, l2_policy_group[0]['ID']))
        # When I disassociate the port from the policy group
        self._disassociate_port_from_policy_group(l2_show_port)
        # I expect the policy group to be gone from the port
        port_present = self._check_port_in_policy_group(
            l2_port_id, l2_policy_group[0]['ID'])
        self.assertFalse(port_present, "Port(%s) associated to policy group "
                                       "(%s) is still present" %
                         (l2_port_id, l2_policy_group[0]['ID']))

        # Allowed Address Pairs
        self._verify_port_allowed_address_fields(l2_show_port,
                                                 l2_aap_ip_address,
                                                 l2_aap_mac_address)
        pass

    def _check_l3_heat_port_attributes(self, l3_policy_group,
                                       l3_aap_ip_address, l3_aap_mac_address,
                                       claimed_fip_id):
        expected_resources = ['l3_port']
        self.verify_stack_resources(expected_resources,
                                    self.template_resources,
                                    self.test_resources)

        l3_subnet_id = self.test_resources['l3_subnet']['physical_resource_id']
        l3_show_subnet = self.admin_subnets_client.show_subnet(
            l3_subnet_id)['subnet']

        l3_port_id = self.test_resources['l3_port']['physical_resource_id']
        l3_show_port = self.admin_ports_client.show_port(l3_port_id)['port']

        l3_rt_id = self.test_resources['rt_l3']['physical_resource_id']
        l3_show_rt = self.nuage_network_client.show_redirection_target(
            l3_rt_id)

        rt_present = self._check_port_in_show_redirect_target(
            l3_show_port, l3_show_rt)
        self.assertTrue(rt_present,
                        "Associated port not present in show nuage "
                        "redirect target response")
        # When I disassociate the redirect-target from the port
        self._disassociate_rt_port(l3_show_port, l3_show_rt)
        # I expect the port to be gone from the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(l3_show_port,
                                                                l3_show_rt)
        self.assertEqual(port_present, False,
                         message="Disassociated port still present in "
                                 "show nuage-redirect-target-response")
        # Then I expect the redirection-target in my list
        my_rt_found = self._find_redirect_target_in_list(l3_rt_id,
                                                         l3_show_subnet)
        self.assertTrue(my_rt_found, "Did not find my redirect-target in "
                                     "the list")

        port_present = self._check_port_in_policy_group(
            l3_port_id, l3_policy_group[0]['ID'])
        self.assertTrue(port_present, "Port(%s) associated to policy group "
                                      "(%s) is not present" %
                        (l3_port_id, l3_policy_group[0]['ID']))
        # When I disassociate the port from the policy group
        self._disassociate_port_from_policy_group(l3_show_port)
        # I expect the policy group to be gone from the port
        port_present = self._check_port_in_policy_group(
            l3_port_id, l3_policy_group[0]['ID'])
        self.assertFalse(port_present, "Port(%s) associated to policy group "
                                       "(%s) is still present" %
                         (l3_port_id, l3_policy_group[0]['ID']))
        #
        # Allowed Address Pairs
        #
        self._verify_port_allowed_address_fields(l3_show_port,
                                                 l3_aap_ip_address,
                                                 l3_aap_mac_address)
        #
        #  Floating IP
        #
        # I expect the claimed floating ip in the port show response
        if CONF.nuage_sut.nuage_plugin_mode != 'ml2':
            fip_present = self._check_fip_in_port_show(l3_port_id,
                                                       claimed_fip_id)
            self.assertTrue(fip_present,
                            msg="associated VSD claimed FIP (%s) not found "
                                "in port (%s)" %
                                (claimed_fip_id, l3_port_id))

        # When I disassociate the claimed fip from the port
        self._disassociate_fip_from_port(l3_show_port)
        # Then I no longer expect the claimed floating ip in the port
        # show response
        if CONF.nuage_sut.nuage_plugin_mode != 'ml2':
            fip_present = self._check_fip_in_port_show(l3_port_id,
                                                       claimed_fip_id)
            self.assertFalse(fip_present,
                             msg="disassociated VSD claimed FIP (%s) still "
                                 "found in port (%s)" %
                                 (claimed_fip_id, l3_port_id))
        pass

    def test_heat_vsd_managed_l2_l3_port_attributes(self):
        # Prepare all the stuff which can be created only on VSD
        l2_cidr = base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR
        l3_cidr = base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR
        vsd_l2_subnet, l2_dom_tmpl = self._create_vsd_l2_managed_subnet()
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        # Policy group on L2/L3
        l2_policy_group = self.vsd_client.create_policygroup(
            constants.L2_DOMAIN,
            vsd_l2_subnet[0]['ID'],
            name='myHEAT-VSD-L2-pg-1',
            type='SOFTWARE',
            extra_params=None)
        l3_policy_group = self.vsd_client.create_policygroup(
            constants.DOMAIN,
            vsd_l3_domain[0]['ID'],
            name='myHEAT-VSD-pg-L3-1',
            type='SOFTWARE',
            extra_params=None)
        # FIP pool for L3
        self.vsd_fip_pool = self._create_vsd_floatingip_pool()
        claimed_fip = self.nuage_vsd_client.claim_floatingip(
            vsd_l3_domain[0]['ID'], self.vsd_fip_pool[0]['ID'])

        stack_name = 'port_attributes'
        l2_port_fixed_ip = str(IPAddress(l2_cidr) + 10)
        l2_aap_fixed_ip = str(IPAddress(l2_port_fixed_ip) + 5)
        l2_aap_mac_address = VALID_MAC_ADDRESS

        l3_port_fixed_ip = str(IPAddress(l3_cidr) + 10)
        l3_aap_fixed_ip = str(IPAddress(l3_port_fixed_ip) + 5)
        l3_aap_mac_address = VALID_MAC_ADDRESS

        stack_parameters = {
            'vsd_l2_subnet_id': vsd_l2_subnet[0]['ID'],
            'netpartition_name': CONF.nuage.nuage_default_netpartition,
            'l2_net_name': data_utils.rand_name('l2-net'),
            'l2_subnet_name': data_utils.rand_name('l2-subnet'),
            'l2_net_cidr': str(l2_cidr.cidr),
            'l2_policy_group_id': l2_policy_group[0]['ID'],
            'l2_fixed_ip_address': l2_port_fixed_ip,
            'l2_aap_ip_address': l2_aap_fixed_ip,
            'l2_aap_mac_address': l2_aap_mac_address,
            'vsd_l3_subnet_id': vsd_l3_subnet[0]['ID'],
            'l3_net_name': data_utils.rand_name('l3-net'),
            'l3_subnet_name': data_utils.rand_name('l3-subnet'),
            'l3_net_cidr': str(l3_cidr.cidr),
            'l3_policy_group_id': l3_policy_group[0]['ID'],
            'l3_fixed_ip_address': l3_port_fixed_ip,
            'l3_aap_ip_address': l3_aap_fixed_ip,
            'l3_aap_mac_address': l3_aap_mac_address,
            'claimed_fip_id': claimed_fip[0]['ID'],
            'image': CONF.compute.image_ref
        }
        self.launch_stack(stack_name, stack_parameters)
        self.client.wait_for_stack_status(self.stack_id, 'CREATE_COMPLETE')

        self._check_l2_heat_port_attributes(
            l2_policy_group, l2_aap_fixed_ip, l2_aap_mac_address)
        self._check_l3_heat_port_attributes(
            l3_policy_group, l3_aap_fixed_ip, l3_aap_mac_address,
            claimed_fip[0]['ID'])
