# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from netaddr import IPAddress

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.tests.api.external_id.external_id \
    import ExternalId
from nuage_tempest_plugin.tests.api.vsd_managed \
    import base_vsd_managed_networks
from nuage_tempest_plugin.tests.api.vsd_managed \
    import base_vsd_managed_port_attributes

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)

# # Stuff for the inter-connectivity VM
# OS_CONNECTING_NW_CIDR = IPNetwork('33.33.33.0/24')
# OS_CONNECTING_NW_GW = '33.33.33.1'

# Constants used in this file
SEVERAL_REDIRECT_TARGETS = 3
EXPECT_NO_MULTIPLE_RT_MSG = "Bad request: Multiple redirect targets on a " \
                            "port not supported"
SEVERAL_POLICY_GROUPS = 3
SEVERAL_PORTS = 3
SEVERAL_VSD_FIP_POOLS = 3
SEVERAL_VSD_CLAIMED_FIPS = 3

VALID_MAC_ADDRESS = 'fa:fa:3e:e8:e8:c0'

SPOOFING_ENABLED = constants.ENABLED
SPOOFING_DISABLED = (constants.INHERITED if Topology.is_v5
                     else constants.DISABLED)


class VSDManagedRedirectTargetTest(
        base_vsd_managed_port_attributes.BaseVSDManagedPortAttributes):

    if Topology.from_nuage('20.5'):
        expected_exception_from_topology = exceptions.BadRequest
    else:
        expected_exception_from_topology = exceptions.ServerFault

    if Topology.from_nuage('6.0'):
        base_err_msg = 'Error in REST call to VSD: '
    else:
        base_err_msg = 'Nuage API: '

    @classmethod
    def resource_setup(cls):
        super(VSDManagedRedirectTargetTest, cls).resource_setup()
        # cls.iacl_template = ''
        # cls.eacl_templace = ''

    ###########################################################################
    ###########################################################################
    # Redirect targets
    ###########################################################################
    ###########################################################################

    def test_create_delete_os_redirection_target_l2_mgd_subnet(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        #  When I create a redirect-target in the VSD-L2-Managed-Subnet
        os_redirect_target = self._create_redirect_target_in_l2_subnet(subnet)

        # Then I expect the redirect-target in my list
        my_rt_found = self._find_redirect_target_in_list(
            os_redirect_target['nuage_redirect_target']['id'], subnet)
        self.assertTrue(my_rt_found,
                        "Did not find my redirect-target in the list")
        # And, as I do not trust the VSD, I expect the redirect-target
        # to be present in the VSD as well ;-)
        vsd_redirect_target = self.nuage_client.get_redirection_target(
            constants.L2_DOMAIN, vsd_l2_subnet[0]['ID'], filters='ID',
            filter_values=os_redirect_target['nuage_redirect_target']['id'])
        self.assertNotEmpty(vsd_redirect_target,
                            "Redirect target not found on VSD")

        # with externalID
        self.assertEqual(vsd_redirect_target[0]['externalID'],
                         ExternalId(subnet['id'] if Topology.is_v5
                                    else subnet['network_id']).at_cms_id())

        # When I associate a port to the redirect-target
        rtport = self.create_port(network)
        self._associate_rt_port(rtport, os_redirect_target)
        # Then I expect the port in the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(
            rtport, os_redirect_target)
        self.assertTrue(port_present,
                        "Associated port not present in show nuage "
                        "redirect target response")
        # When I disassociate the redirect-target from the port
        self._disassociate_rt_port(rtport, os_redirect_target)
        # I expect the port to be gone from the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(
            rtport, os_redirect_target)
        self.assertEqual(port_present, False,
                         message="Disassociated port still present in "
                                 "show nuage-redirect-target-response")
        # When I delete the redirect-target
        self.nuage_network_client.delete_redirection_target(
            os_redirect_target['nuage_redirect_target']['id'])
        # I expect the redirect-target to be gone from the list
        my_rt_found = self._find_redirect_target_in_list(
            os_redirect_target, subnet)
        self.assertEqual(False, my_rt_found,
                         message="Deleted nuage_redirect_target still "
                                 "present in subnet")
        # And the redirect-target is also deleted on the VSD
        vsd_redirect_target = self.nuage_client.get_redirection_target(
            constants.L2_DOMAIN, vsd_l2_subnet[0]['ID'], filters='ID',
            filter_values=os_redirect_target['nuage_redirect_target']['id'])
        self.assertEqual(vsd_redirect_target, '')

    @decorators.attr(type='smoke')
    def test_create_delete_vsd_redirection_target_l2_mgd_subnet(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        #  When I create a redirect-target in the VSD-L2-Managed-Subnet
        # on the VSD
        vsd_redirect_target = \
            self.nuage_client.create_l2_redirect_target(
                vsd_l2_subnet[0]['ID'], data_utils.rand_name("vsd-rt"))
        # Fetch this redirect_target in OS, as this structure is used through
        # the test
        redirect_target = self.nuage_network_client.show_redirection_target(
            vsd_redirect_target[0]['ID'])
        # Then I expect the redirect-target in my list
        my_rt_found = self._find_redirect_target_in_list(
            vsd_redirect_target[0]['ID'], subnet)
        self.assertTrue(my_rt_found,
                        "Did not find my redirect-target in the list")
        # Verifying Redirect Target on VSD
        # redirect_target = self._verify_redirect_target(
        #     os_redirect_target, 'l2domains', vsd_l2_subnet[0], post_body)
        # When I associate a port to the redirect-target
        rtport = self.create_port(network)
        self._associate_rt_port(rtport, redirect_target)
        # Then I expect the port in the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(
            rtport, redirect_target)
        message = "Associated port not present in show nuage redirect " \
                  "target response"
        self.assertTrue(port_present, message)
        # When I disassociate the redirect-target from the port
        self._disassociate_rt_port(rtport, redirect_target)
        # I expect the port to be gone from the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(
            rtport, redirect_target)
        self.assertEqual(port_present, False,
                         message="Disassociated port still present in "
                                 "show nuage-redirect-target-response")
        # When I delete the redirect-target
        self.nuage_network_client.delete_redirection_target(
            redirect_target['nuage_redirect_target']['id'])
        # I expect the redirect-target to be gone from the list
        my_rt_found = self._find_redirect_target_in_list(
            redirect_target, subnet)
        self.assertEqual(False, my_rt_found,
                         message="Deleteed nuage_redirect_target still "
                                 "present in subnet")
        # Verifying RT is deleted from VSD
        vsd_redirect_target = self.nuage_client.get_redirection_target(
            constants.L2_DOMAIN, vsd_l2_subnet[0]['ID'], filters='ID',
            filter_values=vsd_redirect_target[0]['ID'])
        self.assertEqual(vsd_redirect_target, '')

    def test_create_delete_several_redirection_targets_l2_mgd_subnet(self):
        os_redirect_targets = []
        vsd_redirect_targets = []
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        # When I create several redirect-target in the
        # VSD-L2-Managed-Subnet, both on openstack and VSD
        for i in range(SEVERAL_REDIRECT_TARGETS):
            os_redirect_targets.append(
                self._create_redirect_target_in_l2_subnet(subnet))
            vsd_redirect_target = \
                self.nuage_client.create_l2_redirect_target(
                    vsd_l2_subnet[0]['ID'], data_utils.rand_name("vsd-rt"))
            # Fetch this redirect_target in OS, as this structure is used
            # through the test
            vsd_redirect_targets.append(
                self.nuage_network_client.show_redirection_target(
                    vsd_redirect_target[0]['ID']))
        # Then I expect the redirect-target in my list
        for i in range(SEVERAL_REDIRECT_TARGETS):
            my_os_rt_found = self._find_redirect_target_in_list(
                os_redirect_targets[i]['nuage_redirect_target']['id'], subnet)
            self.assertTrue(my_os_rt_found,
                            "Did not find my redirect-target in the list")
            my_vsd_rt_found = self._find_redirect_target_in_list(
                vsd_redirect_targets[i]['nuage_redirect_target']['id'], subnet)
            self.assertTrue(my_vsd_rt_found,
                            "Did not find my redirect-target in the list")
        for i in range(SEVERAL_REDIRECT_TARGETS):
            rtport = self.create_port(network)
            # When I associate a port to the redirect-target
            self._associate_rt_port(rtport, os_redirect_targets[i])
            # Then I expect the port in the show redirect-target response
            port_present = self._check_port_in_show_redirect_target(
                rtport, os_redirect_targets[i])
            self.assertTrue(port_present,
                            "Associated port not present in show nuage "
                            "redirect target response")
            # When I disassociate the redirect-target from the port
            self._disassociate_rt_port(rtport, os_redirect_targets[i])
            # Then I expect the port to be gone from the show redirect-target
            # response
            port_present = self._check_port_in_show_redirect_target(
                rtport, os_redirect_targets[i])
            self.assertEqual(port_present, False,
                             message="Disassociated port still present in "
                                     "show nuage-redirect-target-response")
        for i in range(SEVERAL_REDIRECT_TARGETS):
            # When I delete the redirect-target
            self.nuage_network_client.delete_redirection_target(
                os_redirect_targets[i]['nuage_redirect_target']['id'])
            # I expect the redirect-target to be gone from the list
            my_rt_found = self._find_redirect_target_in_list(
                os_redirect_targets[i], subnet)
            self.assertEqual(False, my_rt_found,
                             message="Deleted nuage_redirect_target still "
                                     "present in subnet")
            # And the redirect-target on VSD is also gone
            vsd_redirect_target = self.nuage_client.get_redirection_target(
                constants.L2_DOMAIN, vsd_l2_subnet[0]['ID'], filters='ID',
                filter_values=os_redirect_targets[i][
                    'nuage_redirect_target']['id'])
            self.assertEqual(vsd_redirect_target, '')
            # When I delete the VSD created redirect-target
            self.nuage_client.delete_redirect_target(
                vsd_redirect_targets[i]['nuage_redirect_target']['id'])
            # Then I expect the redirect_target to be gone from my list
            my_vsd_rt_found = self._find_redirect_target_in_list(
                vsd_redirect_targets[i], subnet)
            self.assertEqual(False, my_vsd_rt_found,
                             message="Deleted nuage_redirect_target still "
                                     "present in subnet")
            # And the redirect-target on VSD is also gone
            vsd_redirect_target = self.nuage_client.get_redirection_target(
                constants.L2_DOMAIN, vsd_l2_subnet[0]['ID'], filters='ID',
                filter_values=vsd_redirect_targets[i][
                    'nuage_redirect_target']['id'])
            self.assertEqual(vsd_redirect_target, '')

    @decorators.attr(type='smoke')
    def test_create_delete_os_redirection_target_l3_mgd_subnet(self):
        # Given I have a VSD-L3-Managed-Subnet in openstack        #
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        #  When I create a redirect-target in the VSD-L3-Managed-Subnet
        os_redirect_target = self._create_redirect_target_in_l3_subnet(subnet)
        # Then I expect the redirect-target in my list
        my_rt_found = self._find_redirect_target_in_list(
            os_redirect_target['nuage_redirect_target']['id'], subnet)
        self.assertTrue(my_rt_found,
                        "Did not find my redirect-target in the list")
        # check on VSD
        vsd_redirect_target = self.nuage_client.get_redirection_target(
            constants.DOMAIN, vsd_l3_domain[0]['ID'], filters='ID',
            filter_values=os_redirect_target['nuage_redirect_target']['id'])
        self.assertIsNotNone(
            vsd_redirect_target,
            message="OS created redirect target not found on VSD")
        # When I associate a port to the redirect-target
        rtport = self.create_port(network)
        self._associate_rt_port(rtport, os_redirect_target)
        # Then I expect the port in the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(
            rtport, os_redirect_target)
        message = "Associated port not present in show nuage " \
                  "redirect target response"
        self.assertTrue(port_present, message)
        # When I disassociate the redirect-target from the port
        self._disassociate_rt_port(rtport, os_redirect_target)
        # I expect the port to be gone from the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(
            rtport, os_redirect_target)
        self.assertEqual(
            port_present, False,
            message="Disassociated port still present in show "
                    "nuage-redirect-target-response")
        # When I delete the redirect-target
        self.nuage_network_client.delete_redirection_target(
            os_redirect_target['nuage_redirect_target']['id'])
        # I expect the redirect-target to be gone from the list
        my_rt_found = self._find_redirect_target_in_list(
            os_redirect_target['nuage_redirect_target']['id'], subnet)
        self.assertEqual(False, my_rt_found,
                         message="Deleted nuage_redirect_target "
                                 "still present in subnet")
        # And the redirect target on VSD is gone as well
        vsd_redirect_target = self.nuage_client.get_redirection_target(
            constants.DOMAIN, vsd_l3_domain[0]['ID'], filters='ID',
            filter_values=os_redirect_target['nuage_redirect_target']['id'])
        self.assertEqual(vsd_redirect_target, '')

    def test_create_delete_vsd_redirection_target_l3_mgd_subnet(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        #  When I create a redirect-target in the VSD-L2-Managed-Subnet
        # on the VSD
        vsd_redirect_target = \
            self.nuage_client.create_l3_redirect_target(
                vsd_l3_domain[0]['ID'], data_utils.rand_name("vsd-rt"))
        # Fetch this redircet_target in OS, as this structure is used
        # through the test
        redirect_target = self.nuage_network_client.show_redirection_target(
            vsd_redirect_target[0]['ID'])
        # Then I expect the redirect-target in my list
        my_rt_found = self._find_redirect_target_in_list(
            vsd_redirect_target[0]['ID'], subnet)
        self.assertTrue(my_rt_found,
                        "Did not find my redirect-target in the list")
        # When I associate a port to the redirect-target
        rtport = self.create_port(network)
        self._associate_rt_port(rtport, redirect_target)
        # Then I expect the port in the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(
            rtport, redirect_target)
        message = "Associated port not present in show nuage " \
                  "redirect target response"
        self.assertTrue(port_present, message)
        # When I disassociate the redirect-target from the port
        self._disassociate_rt_port(rtport, redirect_target)
        # I expect the port to be gone from the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(
            rtport, redirect_target)
        self.assertEqual(port_present, False,
                         message="Disassociated port still present in "
                                 "show nuage-redirect-target-response")
        # When I delete the redirect-target
        self.nuage_network_client.delete_redirection_target(
            redirect_target['nuage_redirect_target']['id'])
        # I expect the redirect-target to be gone from the list
        my_rt_found = self._find_redirect_target_in_list(
            redirect_target, subnet)
        self.assertEqual(False, my_rt_found,
                         message="Deleted nuage_redirect_target "
                                 "still present in subnet")
        # Verifying RT is deleted from VSD
        vsd_redirect_target = self.nuage_client.get_redirection_target(
            constants.DOMAIN, vsd_l3_domain[0]['ID'], filters='ID',
            filter_values=vsd_redirect_target[0]['ID'])
        self.assertEqual(vsd_redirect_target, '')

    def test_create_delete_several_redirection_targets_l3_mgd_subnet(self):
        os_redirect_targets = []
        vsd_redirect_targets = []
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        # When I create several redirect-target in the
        # VSD-L2-Managed-Subnet, both on openstack and VSD
        for i in range(SEVERAL_REDIRECT_TARGETS):
            os_redirect_targets.append(
                self._create_redirect_target_in_l3_subnet(subnet))
            vsd_redirect_target = \
                self.nuage_client.create_l3_redirect_target(
                    vsd_l3_domain[0]['ID'], data_utils.rand_name("vsd-l3-rt"))
            # Fetch this redirect_target in OS, as this structure is used
            # through the test
            vsd_redirect_targets.append(
                self.nuage_network_client.show_redirection_target(
                    vsd_redirect_target[0]['ID']))
        # Then I expect the redirect-target in my list
        for i in range(SEVERAL_REDIRECT_TARGETS):
            my_os_rt_found = self._find_redirect_target_in_list(
                os_redirect_targets[i]['nuage_redirect_target']['id'], subnet)
            self.assertTrue(my_os_rt_found,
                            "Did not find my redirect-target in the list")
            my_vsd_rt_found = self._find_redirect_target_in_list(
                vsd_redirect_targets[i]['nuage_redirect_target']['id'], subnet)
            self.assertTrue(my_vsd_rt_found,
                            "Did not find my redirect-target in the list")
        #
        for i in range(SEVERAL_REDIRECT_TARGETS):
            rtport = self.create_port(network)
            # When I associate a port to the redirect-target
            self._associate_rt_port(rtport, os_redirect_targets[i])
            # Then I expect the port in the show redirect-target response
            port_present = self._check_port_in_show_redirect_target(
                rtport, os_redirect_targets[i])
            self.assertTrue(port_present,
                            "Associated port not present in show nuage "
                            "redirect target response")
            # When I disassociate the redirect-target from the port
            self._disassociate_rt_port(rtport, os_redirect_targets[i])
            # Then I expect the port to be gone from the show
            # redirect-target response
            port_present = self._check_port_in_show_redirect_target(
                rtport, os_redirect_targets[i])
            self.assertEqual(port_present, False,
                             message="Disassociated port still present in "
                                     "show nuage-redirect-target-response")
        for i in range(SEVERAL_REDIRECT_TARGETS):
            # When I delete the redirect-target
            self.nuage_network_client.delete_redirection_target(
                os_redirect_targets[i]['nuage_redirect_target']['id'])
            # I expect the redirect-target to be gone from the list
            my_rt_found = self._find_redirect_target_in_list(
                os_redirect_targets[i], subnet)
            self.assertEqual(False, my_rt_found,
                             message="Deleted nuage_redirect_target still "
                                     "present in subnet")
            # And the redirect-target on VSD is also gone
            vsd_redirect_target = self.nuage_client.get_redirection_target(
                constants.DOMAIN, vsd_l3_domain[0]['ID'], filters='ID',
                filter_values=os_redirect_targets[i][
                    'nuage_redirect_target']['id'])
            self.assertEqual(vsd_redirect_target, '')
            # When I delete the VSD created redirect-target
            self.nuage_client.delete_redirect_target(
                vsd_redirect_targets[i]['nuage_redirect_target']['id'])
            # Then I expect the redirect_target to be gone from my list
            my_vsd_rt_found = self._find_redirect_target_in_list(
                vsd_redirect_targets[i], subnet)
            self.assertEqual(False, my_vsd_rt_found,
                             message="Deleted nuage_redirect_target still "
                                     "present in subnet")
            # And the redirect-target on VSD is also gone
            vsd_redirect_target = self.nuage_client.get_redirection_target(
                constants.DOMAIN, vsd_l3_domain[0]['ID'], filters='ID',
                filter_values=vsd_redirect_targets[i][
                    'nuage_redirect_target']['id'])
            self.assertEqual(vsd_redirect_target, '')

    def test_create_os_redirection_target_same_name_diff_l2_mgd_subnet(self):
        # Given I have a VSD-L2-Managed-Subnet-x in openstack
        vsd_l2_subnet_x, l2dom_template_x = \
            self._create_vsd_l2_managed_subnet()
        network_x, subnet_x = self._create_os_l2_vsd_managed_subnet(
            vsd_l2_subnet_x)
        # And I have created a redirect-target in the
        # VSD-L2-Managed-Subnet-x
        name = data_utils.rand_name("rt-same-name")
        os_redirect_target_x = self._create_redirect_target_in_l2_subnet(
            subnet_x, name)
        self.addCleanup(self.nuage_network_client.delete_redirection_target,
                        os_redirect_target_x['nuage_redirect_target']['id'])

        # When I have a VSD-L2-Managed-Subnet-y in openstack
        vsd_l2_subnet_y, l2dom_template_y = \
            self._create_vsd_l2_managed_subnet()
        network_y, subnet_y = self._create_os_l2_vsd_managed_subnet(
            vsd_l2_subnet_y)
        # When I create in VSD-L2-Managed-Subnet-y a redirect--target
        # with the same name as in subnet_x
        os_redirect_target_y = self._create_redirect_target_in_l2_subnet(
            subnet_y, name)
        self.addCleanup(self.nuage_network_client.delete_redirection_target,
                        os_redirect_target_y['nuage_redirect_target']['id'])

        # I expect rt-y  to be in my list-y
        my_rt_found_y = self._find_redirect_target_in_list(
            os_redirect_target_y['nuage_redirect_target']['id'], subnet_y)
        self.assertTrue(my_rt_found_y,
                        "Did not find my redirect-target in the list")
        # And rt-x in my list-x
        my_rt_found_x = self._find_redirect_target_in_list(
            os_redirect_target_x['nuage_redirect_target']['id'], subnet_x)
        self.assertTrue(my_rt_found_x,
                        "Did not find my redirect-target in the list")
        pass

    @decorators.attr(type=['negative'])
    def test_create_os_redirection_target_same_name_same_l2_mgd_subnet_neg(
            self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        #  And I have created a redirect-target in the VSD-L2-Managed-Subnet
        name = data_utils.rand_name("rt-same-name")
        os_redirect_target_x1 = self._create_redirect_target_in_l2_subnet(
            subnet, name)
        self.addCleanup(self.nuage_network_client.delete_redirection_target,
                        os_redirect_target_x1['nuage_redirect_target']['id'])

        #  When I try to create a redirect target with the same name,
        # I expect this to fail
        msg = "A Nuage redirect target with name '%s' already exists" % name
        self.assertRaisesRegex(
            exceptions.BadRequest,
            msg,
            self._create_redirect_target_in_l2_subnet,
            subnet,
            name)

    @decorators.attr(type=['negative'])
    def test_associate_two_port_same_l2_os_redirection_target_neg(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        #  And I have created a redirect-target in the VSD-L2-Managed-Subnet
        os_redirect_target = self._create_redirect_target_in_l2_subnet(subnet)
        self.addCleanup(self.nuage_network_client.delete_redirection_target,
                        os_redirect_target['nuage_redirect_target']['id'])

        # And this rt is associated to a port
        rtport_1 = self.create_port(network)
        self._associate_rt_port(rtport_1, os_redirect_target)
        port_present = self._check_port_in_show_redirect_target(
            rtport_1, os_redirect_target)
        self.assertTrue(port_present,
                        "Associated port not present in show nuage redirect "
                        "target response")
        # When I disassociate the red0rect-target from the port
        # When I try to create associate another port to the same redirect
        # target, which has redundancy disabled (l2)
        # I expect this to fail
        rtport_2 = self.create_port(network)

        msg = "Cannot have more than 1 vPort under a redirectiontarget with " \
              "redundancy disabled"
        expected_exception = exceptions.BadRequest

        self.assertRaisesRegex(
            expected_exception,
            msg,
            self._associate_rt_port,
            rtport_2,
            os_redirect_target)

    @decorators.attr(type=['negative'])
    def test_create_os_l2_redirection_target_redundancy_enabled_neg(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        # And I have created a redirect-target in the VSD-L2-Managed-Subnet
        post_body = {'insertion_mode': 'VIRTUAL_WIRE',
                     'redundancy_enabled': 'True',
                     'subnet_id': subnet['id'],
                     'name': "rt-l2-redundancy-enabled-fail"}
        self.assertRaisesRegex(
            self.expected_exception_from_topology,
            self.base_err_msg + (
                'vPort Tag with endpoint type as NONE/VIRTUAL_WIRE '
                'cannot have redundancy enabled and trigger type as GARP'),
            self.nuage_network_client.create_redirection_target,
            **post_body
        )

    @decorators.attr(type=['negative'])
    def test_create_os_l2_redirection_target_insertion_mode_l3_neg(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        #  And I have created a redirect-target in the VSD-L2-Managed-Subnet
        post_body = {'insertion_mode': 'L3',
                     'redundancy_enabled': 'False',
                     'subnet_id': subnet['id'],
                     'name': "rt-l2-insertion-mode-l3-fail"}
        self.assertRaisesRegex(
            self.expected_exception_from_topology,
            self.base_err_msg + ('An L2 domain redirectiontarget cannot have '
                                 'an L3 endpoint.'),
            self.nuage_network_client.create_redirection_target,
            **post_body
        )

    @decorators.attr(type=['negative'])
    def test_os_redirection_targets_bad_insertion_mode_neg(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)

        #  When I try to create a redirect-target w/ unknown insertion_mode
        post_body = {'insertion_mode': 'L2',
                     'redundancy_enabled': 'False',
                     'subnet_id': subnet['id'],
                     'name': "rt-l2-insertion-mode-l2-fail"}

        # I expect a badRequest
        self.assertRaisesRegex(
            self.expected_exception_from_topology,
            self.base_err_msg + 'Invalid input',
            self.nuage_network_client.create_redirection_target,
            **post_body
        )

    @decorators.attr(type=['negative'])
    def test_multiple_l2_vsd_redirection_targets_per_port_neg(self):
        vsd_redirect_targets = []
        # Given I have a VSD-L2-Managed-Subnet in openstack
        vsd_l2_subnet, l2dom_templ = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        #  And I have several VSD created redirect-target in the
        # VSD-L2-Managed-Subnet
        for i in range(2):
            vsd_redirect_target = \
                self.nuage_client.create_l2_redirect_target(
                    vsd_l2_subnet[0]['ID'], data_utils.rand_name("vsd-rt"))
            # Fetch this redirect_target in OS, as this structure is used
            # through the test
            vsd_redirect_targets.append(
                self.nuage_network_client.show_redirection_target(
                    vsd_redirect_target[0]['ID']))
        # When I try to associate these multiple vsd created redirect targets
        # per port with redundancy disabled
        # Then I expect a failure
        rtport = self.create_port(network)

        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_NO_MULTIPLE_RT_MSG,
            self._associate_multiple_rt_port,
            rtport,
            vsd_redirect_targets)

###############################################################################
###############################################################################
# PolicyGroups
###############################################################################
###############################################################################


class VSDManagedPolicyGroupsTest(
        base_vsd_managed_port_attributes.BaseVSDManagedPortAttributes):

    @classmethod
    def resource_setup(cls):
        super(VSDManagedPolicyGroupsTest, cls).resource_setup()
        cls.iacl_template = ''
        cls.eacl_templace = ''

    def test_l2_create_update_associate_port_to_policygroup(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a
        # VSD created policy group
        vsd_l2_subnet, l2_domtmpl = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        policy_group = self.nuage_client.create_policygroup(
            constants.L2_DOMAIN,
            vsd_l2_subnet[0]['ID'],
            name='myVSDpg-1',
            type='SOFTWARE',
            extra_params=None)
        # When I retrieve the VSD-L2-Managed-Subnet
        policy_group_list = \
            self.nuage_network_client.list_nuage_policy_group_for_subnet(
                subnet['id'])
        # I expect the policyGroup in my list
        pg_present = self._check_policy_group_in_list(policy_group[0]['ID'],
                                                      policy_group_list)
        self.assertTrue(pg_present,
                        "Did not find vsd policy group in policy group list")
        # And it has no external ID
        self.assertIsNone(policy_group[0]['externalID'],
                          "Policy Group has an external ID, "
                          "while it should not")

        # When I create a port in the subnet
        # And I associate the port with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-pg'
        }
        port = self.create_port(network, **kwargs)
        # self.update_port(port, **kwargs)
        # Then I expect the port in the show policy group response
        port_present = self._check_port_in_policy_group(
            port['id'], policy_group[0]['ID'])
        self.assertTrue(port_present,
                        "Port(%s) assiociated to policy group (%s) "
                        "is not present" %
                        (port['id'], policy_group[0]['ID']))
        # When I disassociate the port from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg'
        }
        self.update_port(port, **kwargs)
        # Then I do NOT expect the port in the show policy group response
        port_present = self._check_port_in_policy_group(
            port['id'], policy_group[0]['ID'])
        self.assertFalse(port_present, "Port(%s) disassiociated to "
                                       "policy group (%s) is still present" %
                         (port['id'], policy_group[0]['ID']))

    @decorators.attr(type='smoke')
    def test_l2_associate_port_to_policygroup(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a
        # VSD created policy group
        vsd_l2_subnet, l2_domtmpl = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        policy_group = self.nuage_client.create_policygroup(
            constants.L2_DOMAIN,
            vsd_l2_subnet[0]['ID'],
            name='myVSDpg-1',
            type='SOFTWARE',
            extra_params=None)
        # When I retrieve the VSD-L2-Managed-Subnet
        policy_group_list = \
            self.nuage_network_client.list_nuage_policy_group_for_subnet(
                subnet['id'])
        # I expect the policyGroup in my list
        pg_present = self._check_policy_group_in_list(
            policy_group[0]['ID'], policy_group_list)
        self.assertTrue(pg_present, "Did not find vsd policy group in "
                                    "policy group list")
        # And it has no external ID
        self.assertIsNone(policy_group[0]['externalID'],
                          "Policy Group has an external ID, "
                          "while it should not")

        # When I create a port in the subnet
        port = self.create_port(network)
        # And I associate the port with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-pg'
        }
        self.update_port(port, **kwargs)
        # Then I expect the port in the show policy group response
        port_present = self._check_port_in_policy_group(
            port['id'], policy_group[0]['ID'])
        self.assertTrue(port_present, "Port(%s) associated to "
                                      "policy group (%s) is not present" %
                        (port['id'], policy_group[0]['ID']))
        # When I disassociate the port from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg'
        }
        self.update_port(port, **kwargs)
        # Then I do NOT expect the port in the show policy group response
        port_present = self._check_port_in_policy_group(
            port['id'], policy_group[0]['ID'])
        self.assertFalse(port_present, "Port(%s) disassociated to "
                                       "policy group (%s) is still present" %
                         (port['id'], policy_group[0]['ID']))

    def test_l2_associate_port_to_policygroups(self):
        policy_groups = []
        # Given I have a VSD-L2-Managed-Subnet
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        # And I have multiple policy_groups
        for i in range(SEVERAL_POLICY_GROUPS):
            policy_groups.append(self.nuage_client.create_policygroup(
                constants.L2_DOMAIN,
                vsd_l2_subnet[0]['ID'],
                name='myVSDpg-%s' % i,
                type='SOFTWARE',
                extra_params=None))
        # When I create  a port
        port = self.create_port(network)
        # And associate this port with all these policy groups
        pg_id_list = []
        for i in range(SEVERAL_POLICY_GROUPS):
            pg_id_list.append(policy_groups[i][0]['ID'])
        kwargs = {
            'nuage_policy_groups': pg_id_list,
        }
        self.update_port(port, **kwargs)
        # When I retrieve the port
        show_port = self.ports_client.show_port(port['id'])

        # Then I expect all policy groups in the response
        if not Topology.is_ml2:
            all_pg_present = self._check_all_policy_groups_in_show_port(
                pg_id_list, show_port)
            self.assertTrue(all_pg_present,
                            "Port does not contain all associated "
                            "policy groups")

        # When I disassociate 1 policy group from the port (e.g. the last one)
        pg_id_list = []
        for i in range(SEVERAL_POLICY_GROUPS - 1):
            pg_id_list.append(policy_groups[i][0]['ID'])
        kwargs = {
            'nuage_policy_groups': pg_id_list,
        }
        self.update_port(port, **kwargs)
        # Then I do NOT expect this policy group in the show port response
        show_port = self.ports_client.show_port(port['id'])

        if not Topology.is_ml2:
            for i in range(SEVERAL_POLICY_GROUPS):
                pg_present = self._check_policy_group_in_show_port(
                    [policy_groups[i][0]['ID']], show_port)
                self.assertFalse(pg_present, "Disassociated policygroup "
                                             "still present in show port")

        # When I disassociate all policy groups from the port
        kwargs = {
            'nuage_policy_groups': []
        }
        self.update_port(port, **kwargs)

        # Then I do NOT expect the policy Groups in the show port response
        show_port = self.ports_client.show_port(port['id'])
        if not Topology.is_ml2:
            self.assertEmpty(show_port['port']['nuage_policy_groups'],
                             "Port-show list disassociated ports")

    def test_l2_associate_multiple_ports_to_policygroups(self):
        policy_groups = []
        ports = []
        # Given I have a VSD-L2-Managed-Subnet
        vsd_l2_subnet, l2dom_template = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        # And I have multiple policy_groups
        for i in range(SEVERAL_POLICY_GROUPS):
            policy_groups.append(self.nuage_client.create_policygroup(
                constants.L2_DOMAIN,
                vsd_l2_subnet[0]['ID'],
                name='myVSDpg-%s' % i,
                type='SOFTWARE',
                extra_params=None))
        for i in range(SEVERAL_PORTS):
            # When I create multiple ports
            ports.append(self.create_port(network))
        # And associate each port with all these policy groups
        pg_id_list = []
        for i in range(SEVERAL_POLICY_GROUPS):
            pg_id_list.append(policy_groups[i][0]['ID'])
        kwargs = {
            'nuage_policy_groups': pg_id_list,
        }
        for i in range(SEVERAL_PORTS):
            self.update_port(ports[i], **kwargs)
        # When I retrieve each port
        for i in range(SEVERAL_PORTS):
            show_port = self.ports_client.show_port(ports[i]['id'])
            # Then I expect all policy groups in the response

            if not Topology.is_ml2:
                all_pg_present = self._check_all_policy_groups_in_show_port(
                    pg_id_list, show_port)
                self.assertTrue(all_pg_present,
                                "Port does not contain all associated "
                                "policy groups")
        # When I retrieve each policy group
        for i in range(SEVERAL_POLICY_GROUPS):
            # Then I expect the response to contain all the ports
            for j in range(SEVERAL_PORTS):
                port_present = self._check_port_in_policy_group(
                    ports[j]['id'], policy_groups[i][0]['ID'])
                self.assertTrue(port_present,
                                "Port(%s) not present in policy group(%s)" %
                                (ports[j]['id'], policy_groups[i][0]['ID']))
        # When I disassociate all policy groups from each port
        kwargs = {
            'nuage_policy_groups': []
        }
        for i in range(SEVERAL_PORTS):
            self.update_port(ports[i], **kwargs)
            # Then I do NOT expect the policy Groups in the show port response
            show_port = self.ports_client.show_port(ports[i]['id'])

            if not Topology.is_ml2:
                self.assertEmpty(show_port['port']['nuage_policy_groups'],
                                 "Port-show list disassociated ports")

            # And I do not expect this port in any of the policy groups
            for j in range(SEVERAL_POLICY_GROUPS):
                port_present = self._check_port_in_policy_group(
                    ports[i]['id'], policy_groups[j][0]['ID'])
                self.assertFalse(port_present,
                                 'disassociated port (%s) still present in '
                                 'policy group(%s)' %
                                 (ports[i]['id'], policy_groups[j][0]['ID']))

    def test_vsd_multiple_l2_policygroup(self):
        policy_groups = []
        # Given I have a VSD-L2-Managed-Subnet
        vsd_l2_subnet, l2dom_templ = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        # When I create several policy groups
        for i in range(SEVERAL_POLICY_GROUPS):
            policy_groups.append(self.nuage_client.create_policygroup(
                constants.L2_DOMAIN,
                vsd_l2_subnet[0]['ID'],
                name='myVSDpg-%s' % i,
                type='SOFTWARE',
                extra_params=None))
        # When I list the policy groups of the VSD-L2-Managed-Subnet
        policy_group_list = \
            self.nuage_network_client.list_nuage_policy_group_for_subnet(
                subnet['id'])
        # I expect the policyGroup in my list
        for i in range(SEVERAL_POLICY_GROUPS):
            pg_present = self._check_policy_group_in_list(
                policy_groups[i][0]['ID'], policy_group_list)
            self.assertTrue(pg_present,
                            "Did not find vsd policy group in "
                            "policy group list")
            # And it has no external ID
            self.assertIsNone(policy_groups[i][0]['externalID'],
                              "Policy Group has an external ID, "
                              "while it should not")
        # When I delete the (first) policy group on the VSD
        self.nuage_client.delete_policygroup(policy_groups[0][0]['ID'])
        # Then I expect this policy group to be gone from my list
        policy_group_list = \
            self.nuage_network_client.list_nuage_policy_group_for_subnet(
                subnet['id'])
        pg_present = self._check_policy_group_in_list(
            policy_groups[0][0]['ID'], policy_group_list)
        self.assertFalse(pg_present,
                         "Deleted policy group(%s) still present in the "
                         "user policy group list" %
                         policy_groups[0][0]['ID'])

    def test_list_l2_policy_groups_subnet_only(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a
        # VSD created policy group
        vsd_l2_subnet_x, l2dom_templ_x = self._create_vsd_l2_managed_subnet()
        network_x, subnet_x = self._create_os_l2_vsd_managed_subnet(
            vsd_l2_subnet_x)
        policy_group_x = self.nuage_client.create_policygroup(
            constants.L2_DOMAIN,
            vsd_l2_subnet_x[0]['ID'],
            name='myVSDpg-X',
            type='SOFTWARE',
            extra_params=None)
        vsd_l2_subnet_y, l2dom_templ_y = self._create_vsd_l2_managed_subnet()
        network_y, subnet_y = self._create_os_l2_vsd_managed_subnet(
            vsd_l2_subnet_y)
        policy_group_y = self.nuage_client.create_policygroup(
            constants.L2_DOMAIN,
            vsd_l2_subnet_y[0]['ID'],
            name='myVSDpg-2',
            type='SOFTWARE',
            extra_params=None)
        # When I retrieve the policy groups of  VSD-L2-Managed-Subnet_x
        policy_group_list_x = \
            self.nuage_network_client.list_nuage_policy_group_for_subnet(
                subnet_x['id'])
        # I expect policyGroup_x in my list
        pg_present = self._check_policy_group_in_list(
            policy_group_x[0]['ID'], policy_group_list_x)
        self.assertTrue(pg_present,
                        "Did not find vsd policy group in policy group list")
        # And I do NOT expect policyGroup_y in my list
        pg_present = self._check_policy_group_in_list(
            policy_group_y[0]['ID'], policy_group_list_x)
        self.assertFalse(pg_present,
                         "Found policgroup (%s) of another subnet (%s) "
                         "in this subnet (%s)" %
                         (policy_group_y[0]['ID'],
                          subnet_y['id'], subnet_x['id']))

        # And vice versa
        # When I retrieve the polic groups of VSD-L2-Managed-Subnet_y
        policy_group_list_y = \
            self.nuage_network_client.list_nuage_policy_group_for_subnet(
                subnet_y['id'])
        # I expect policyGroup_y in my list
        pg_present = self._check_policy_group_in_list(
            policy_group_y[0]['ID'], policy_group_list_y)
        self.assertTrue(pg_present,
                        "Did not find vsd policy group in policy group list")
        # And I do NOT expect policyGroup_x in my list
        pg_present = self._check_policy_group_in_list(
            policy_group_x[0]['ID'], policy_group_list_y)
        self.assertFalse(pg_present,
                         "Found policgroup (%s) of another subnet (%s) "
                         "in this subnet (%s)" %
                         (policy_group_x[0]['ID'],
                          subnet_x['id'], subnet_y['id']))

    def test_l3_associate_port_to_policygroup(self):
        # Given I have a VSD-L3-Managed-Subnet in openstack with a
        # VSD created policy group
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        policy_group = self.nuage_client.create_policygroup(
            constants.DOMAIN,
            vsd_l3_domain[0]['ID'],
            name='myVSDpg-1',
            type='SOFTWARE',
            extra_params=None)
        # When I retrieve the VSD-L2-Managed-Subnet
        policy_group_list = \
            self.nuage_network_client.list_nuage_policy_group_for_subnet(
                subnet['id'])
        # I expect the policyGroup in my list
        pg_present = self._check_policy_group_in_list(
            policy_group[0]['ID'], policy_group_list)
        self.assertTrue(pg_present,
                        "Did not find vsd policy group in policy group list")
        # And it has no external ID
        self.assertIsNone(policy_group[0]['externalID'],
                          "Policy Group has an external ID, "
                          "while it should not")

        self.nuage_network_client.show_nuage_policy_group(
            policy_group[0]['ID'])
        # When I create a port in the subnet
        port = self.create_port(network)
        # And I associate the port with the policy group
        kwargs = {
            'nuage_policy_groups': [policy_group[0]['ID']],
            'name': 'port-with-vsd-pg'
        }
        self.update_port(port, **kwargs)
        # Then I expect the port in the show policy group response
        port_present = self._check_port_in_policy_group(
            port['id'], policy_group[0]['ID'])
        self.assertTrue(port_present,
                        "Port(%s) assiociated to policy group (%s) "
                        "is not present" %
                        (port['id'], policy_group[0]['ID']))
        # When I disassociate the port from the policy group
        kwargs = {
            'nuage_policy_groups': [],
            'name': 'port-without-vsd-pg'
        }
        self.update_port(port, **kwargs)
        # Then I do NOT expect the port in the show policy group response
        port_present = self._check_port_in_policy_group(
            port['id'], policy_group[0]['ID'])
        self.assertFalse(port_present,
                         "Port(%s) disassiociated to policy group (%s) "
                         "is still present" %
                         (port['id'], policy_group[0]['ID']))

    def test_list_l3_policy_groups_subnet_only(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a
        # VSD created policy group
        vsd_l3_subnet_x, vsd_l3_domain_x = self._create_vsd_l3_managed_subnet()
        network_x, subnet_x = self._create_os_l3_vsd_managed_subnet(
            vsd_l3_subnet_x)
        policy_group_x = self.nuage_client.create_policygroup(
            constants.DOMAIN,
            vsd_l3_domain_x[0]['ID'],
            name='myVSD-L3-pg-X',
            type='SOFTWARE',
            extra_params=None)
        vsd_l3_subnet_y, vsd_l3_domain_y = self._create_vsd_l3_managed_subnet()
        network_y, subnet_y = self._create_os_l3_vsd_managed_subnet(
            vsd_l3_subnet_y)
        policy_group_y = self.nuage_client.create_policygroup(
            constants.DOMAIN,
            vsd_l3_domain_y[0]['ID'],
            name='myVSD-L3-pg-Y',
            type='SOFTWARE',
            extra_params=None)
        # When I retrieve the policy groups of  VSD-L2-Managed-Subnet_x
        policy_group_list_x = \
            self.nuage_network_client.list_nuage_policy_group_for_subnet(
                subnet_x['id'])
        # policy_group_list_x = self.client.list_available_nuage_policy_group
        #     (subnet_x['id'])
        # I expect policyGroup_x in my list
        pg_present = self._check_policy_group_in_list(
            policy_group_x[0]['ID'], policy_group_list_x)
        self.assertTrue(pg_present,
                        "Did not find vsd policy group in policy group list")
        # And I do NOT expect policyGroup_y in my list
        pg_present = self._check_policy_group_in_list(
            policy_group_y[0]['ID'], policy_group_list_x)
        self.assertFalse(pg_present,
                         "Found policgroup (%s) of another subnet (%s) "
                         "in this subnet (%s)" %
                         (policy_group_y[0]['ID'],
                          subnet_y['id'], subnet_x['id']))

        # And vice versa
        # When I retrieve the polic groups of VSD-L2-Managed-Subnet_y
        # policy_group_list_y = self.client.list_available_nuage_policy_group
        #     (subnet_y['id'])
        policy_group_list_y = \
            self.nuage_network_client.list_nuage_policy_group_for_subnet(
                subnet_y['id'])
        # I expect policyGroup_y in my list
        pg_present = self._check_policy_group_in_list(
            policy_group_y[0]['ID'], policy_group_list_y)
        self.assertTrue(pg_present,
                        "Did not find vsd policy group in policy group list")
        # And I do NOT expect policyGroup_x in my list
        pg_present = self._check_policy_group_in_list(
            policy_group_x[0]['ID'], policy_group_list_y)
        self.assertFalse(pg_present,
                         "Found policgroup (%s) of another subnet (%s) "
                         "in this subnet (%s)" %
                         (policy_group_x[0]['ID'],
                          subnet_x['id'], subnet_y['id']))

    def test_l3_associate_multiple_ports_to_policygroups(self):
        policy_groups = []
        ports = []
        # Given I have a VSD-L3-Managed-Subnet
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        # And I have multiple policy_groups
        for i in range(SEVERAL_POLICY_GROUPS):
            policy_groups.append(self.nuage_client.create_policygroup(
                constants.DOMAIN,
                vsd_l3_domain[0]['ID'],
                name='my-L3-VSDpg-%s' % i,
                type='SOFTWARE',
                extra_params=None))
        for i in range(SEVERAL_PORTS):
            # When I create multiple ports
            ports.append(self.create_port(network))
        # And associate each port with all these policy groups
        pg_id_list = []
        for i in range(SEVERAL_POLICY_GROUPS):
            pg_id_list.append(policy_groups[i][0]['ID'])
        kwargs = {
            'nuage_policy_groups': pg_id_list,
        }
        for i in range(SEVERAL_PORTS):
            self.update_port(ports[i], **kwargs)
        # When I retrieve each port
        for i in range(SEVERAL_PORTS):
            show_port = self.ports_client.show_port(ports[i]['id'])
            # Then I expect all policy groups in the response

            if not Topology.is_ml2:
                all_pg_present = \
                    self._check_all_policy_groups_in_show_port(
                        pg_id_list, show_port)
                self.assertTrue(all_pg_present,
                                "Port does not contain all associated "
                                "policy groups")

        # When I retrieve each policy group
        for i in range(SEVERAL_POLICY_GROUPS):
            # Then I expect the response to contain all the ports
            for j in range(SEVERAL_PORTS):
                port_present = self._check_port_in_policy_group(
                    ports[j]['id'], policy_groups[i][0]['ID'])
                self.assertTrue(port_present,
                                "Port(%s) not present in policy group(%s)" %
                                (ports[j]['id'], policy_groups[i][0]['ID']))
        # When I disassociate all policy groups from each port
        kwargs = {
            'nuage_policy_groups': []
        }
        for i in range(SEVERAL_PORTS):
            self.update_port(ports[i], **kwargs)
            # Then I do NOT expect the policy Groups in the show port response
            show_port = self.ports_client.show_port(ports[i]['id'])

            if not Topology.is_ml2:
                self.assertEmpty(show_port['port']['nuage_policy_groups'],
                                 "Port-show list disassociated ports")

            # And I do not expect this port in any of the policy groups
            for j in range(SEVERAL_POLICY_GROUPS):
                port_present = self._check_port_in_policy_group(
                    ports[i]['id'], policy_groups[j][0]['ID'])
                self.assertFalse(port_present,
                                 'disassociated port (%s) still present in '
                                 'policy group(%s)' %
                                 (ports[i]['id'], policy_groups[j][0]['ID']))

    def _delete_advfwd_entrytemplate(self, l2domain_id, template_id):
        # Can't use the job BEGIN-APPLY as the ID of the object changes
        # The DRAFT object gets a new ID, with reference to the LIVE object
        # self.nuage_client.begin_l2_policy_changes(l2domain_id)
        self.nuage_client.delete_resource(
            constants.INGRESS_ADV_FWD_TEMPLATE, template_id,
            responseChoice=True)
        # self.nuage_client.apply_l2_policy_changes(l2domain_id)

    def test_l2_list_policy_group_no_security_group_neg(self):
        # Given I have a VSD-L2-Managed-Subnet in openstack with a
        # VSD created policy group
        vsd_l2_subnet, l2_domtmpl = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(
            vsd_l2_subnet)
        policy_group = self.nuage_client.create_policygroup(
            constants.L2_DOMAIN,
            vsd_l2_subnet[0]['ID'],
            name='myVSDpg-1',
            type='SOFTWARE',
            extra_params=None)
        self.addCleanup(self.nuage_client.delete_policygroup,
                        policy_group[0]['ID'])

        # And I have created a security group on the OS subnet
        security_group = self._create_security_group()

        # And I have a redirect target
        os_redirect_target = self._create_redirect_target_in_l2_subnet(subnet)
        self.addCleanup(self.nuage_network_client.delete_redirection_target,
                        os_redirect_target['nuage_redirect_target']['id'])

        advfw_template = self.nuage_client.create_advfwd_entrytemplate(
            constants.L2_DOMAIN,
            vsd_l2_subnet[0]['ID']
        )
        self.addCleanup(self._delete_advfwd_entrytemplate,
                        vsd_l2_subnet[0]['ID'], advfw_template[0]['ID'])

        # When I try to use this security group in a
        # redirect-target-rule-creation
        rt_rule = self._create_redirect_target_rule(
            os_redirect_target['nuage_redirect_target']['id'],
            security_group['id'])
        self.addCleanup(
            self.nuage_network_client.delete_redirection_target_rule,
            rt_rule['nuage_redirect_target_rule']['id'])

        # When I retrieve the VSD-L2-Managed-Subnet
        policy_group_list = \
            self.nuage_network_client.list_nuage_policy_group_for_subnet(
                subnet['id'])
        # I expect the only the policyGroup in my list: length may not
        # be greater than one
        self.assertEqual(1, len(policy_group_list['nuage_policy_groups']),
                         message="Security groups are also in the "
                                 "policy group list")


###############################################################################
###############################################################################
# MultiVIP . allowed address pairsallowable address pairs)
###############################################################################
###############################################################################


class VSDManagedAllowedAddresPairssTest(
        base_vsd_managed_port_attributes.BaseVSDManagedPortAttributes):

    @classmethod
    def resource_setup(cls):
        super(VSDManagedAllowedAddresPairssTest, cls).resource_setup()
        # cls.iacl_template = ''
        # cls.eacl_templace = ''

    def _ensure_nuage_vip_port_vsd_ipam(self, aap_fixed_ip, network):
        if CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed':
            # vsd managed ipam requires nuage:vip port
            self.create_port(network=network,
                             fixed_ips=[{'ip_address': aap_fixed_ip}],
                             device_owner='nuage:vip')

    def test_create_address_pair_l2domain_no_mac(self):
        # Given I have a VSD-L2-Managed subnet
        vsd_l2_subnet, l2_domtmpl = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        # When I create a port in this VSD-L2-Managed-Subnet with
        # - fixed-IP address
        # - allowed-address-pair with
        #     IP@ = fixed-IP+5
        #     no MAC address
        port_fixed_ip = str(IPAddress(
            base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW) + 10)
        aap_fixed_ip = str(IPAddress(port_fixed_ip) + 5)

        self._ensure_nuage_vip_port_vsd_ipam(aap_fixed_ip, network)

        kwargs = {
            'fixed_ips': [{
                'subnet_id': subnet['id'],
                'ip_address': port_fixed_ip
            }],
            'allowed_address_pairs': [{
                'ip_address': aap_fixed_ip
            }]
        }
        addrpair_port = self.create_port(network, **kwargs)
        # Then I expect the allowed-address-pair the port-show response
        # And the allowed-address-pair MACaddress == port MACaddress
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self._verify_port_allowed_address_fields(show_port['port'],
                                                 aap_fixed_ip,
                                                 addrpair_port['mac_address'])
        # And no corresponding MultiVIP on the VSD
        port_ext_id = self.nuage_client.get_vsd_external_id(
            addrpair_port['id'])
        nuage_vport = self.nuage_client.get_vport(constants.L2_DOMAIN,
                                                  vsd_l2_subnet[0]['ID'],
                                                  filters='externalID',
                                                  filter_values=port_ext_id)
        self.assertIsNone(nuage_vport[0]['multiNICVPortID'],
                          "multiNICVPortID is not empty while it should be")
        # And address address spoofing is disabled on vport in VSD
        self.assertEqual(SPOOFING_ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        # When I delete the allowed address  pair from the port
        self._remove_allowed_address_pair_from_port(addrpair_port)
        # I expect it to be gone from the show port response
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self.assertEmpty(show_port['port']['allowed_address_pairs'],
                         "Removed allowed-address-pair stil present in "
                         "port (%s)" % addrpair_port['id'])
        pass

    def test_create_address_pair_l2domain_with_mac(self):
        # Given I have a VSD-L2-Managed subnet
        vsd_l2_subnet, l2_domtmpl = self._create_vsd_l2_managed_subnet()
        network, subnet = self._create_os_l2_vsd_managed_subnet(vsd_l2_subnet)
        # When I create a port in this VSD-L2-Managed-Subnet with
        # - fixed-IP address
        # - allowed-address-pair with
        #     IP@ = fixed-IP+5
        #     valid MAC address (<> port MAC address)
        port_fixed_ip = str(IPAddress(
            base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW) + 100)
        aap_fixed_ip = str(IPAddress(port_fixed_ip) + 5)

        self._ensure_nuage_vip_port_vsd_ipam(aap_fixed_ip, network)

        kwargs = {
            'fixed_ips': [{
                'subnet_id': subnet['id'],
                'ip_address': str(port_fixed_ip)
            }],
            'allowed_address_pairs': [{
                'ip_address': aap_fixed_ip,
                'mac_address': VALID_MAC_ADDRESS
            }]
        }
        addrpair_port = self.create_port(network, **kwargs)
        # Then I expect the allowed-address-pair the port-show response
        # And the allowed-address-pair MACaddress == port MACaddress
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self._verify_port_allowed_address_fields(show_port['port'],
                                                 aap_fixed_ip,
                                                 VALID_MAC_ADDRESS)
        # And no corresponding MultiVIP on the VSD
        port_ext_id = self.nuage_client.get_vsd_external_id(
            addrpair_port['id'])
        nuage_vport = self.nuage_client.get_vport(constants.L2_DOMAIN,
                                                  vsd_l2_subnet[0]['ID'],
                                                  filters='externalID',
                                                  filter_values=port_ext_id)
        self.assertIsNone(nuage_vport[0]['multiNICVPortID'],
                          "multiNICVPortID is not empty while it should be")
        # And address address spoofing is disabled on vport in VSD
        self.assertEqual(SPOOFING_ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        # When I delete the allowed address  pair from the port
        self._remove_allowed_address_pair_from_port(addrpair_port)
        # I expect it to be gone from the show port response
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self.assertEmpty(show_port['port']['allowed_address_pairs'],
                         "Removed allowed-address-pair stil present in "
                         "port (%s)" % addrpair_port['id'])
        pass

    def test_create_address_pair_l3_subnet_no_mac(self):
        # Given I have a VSD-L3-Managed subnet
        vsd_l3_subnet, l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        # When I create a port in this VSD-L3-Managed-Subnet with
        # - fixed-IP address
        # - allowed-address-pair with
        #     IP@ = fixed-IP+5
        #     no MAC address
        port_fixed_ip = str(IPAddress(
            base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW) + 10)
        aap_fixed_ip = str(IPAddress(port_fixed_ip) + 5)

        self._ensure_nuage_vip_port_vsd_ipam(aap_fixed_ip, network)

        kwargs = {
            'fixed_ips': [{
                'subnet_id': subnet['id'],
                'ip_address': str(port_fixed_ip)
            }],
            'allowed_address_pairs': [{
                'ip_address': aap_fixed_ip
            }]
        }
        addrpair_port = self.create_port(network, **kwargs)
        # Then I expect the allowed-address-pair the port-show response
        # And the allowed-address-pair MACaddress == port MACaddress
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self._verify_port_allowed_address_fields(show_port['port'],
                                                 aap_fixed_ip,
                                                 addrpair_port['mac_address'])
        # And no corresponding MultiVIP on the VSD
        port_ext_id = self.nuage_client.get_vsd_external_id(
            addrpair_port['id'])
        nuage_vport = self.nuage_client.get_vport(constants.SUBNETWORK,
                                                  vsd_l3_subnet[0]['ID'],
                                                  filters='externalID',
                                                  filter_values=port_ext_id)
        self.assertIsNone(nuage_vport[0]['multiNICVPortID'],
                          "multiNICVPortID is not empty while it should be")
        # # And address address spoofing is disabled on vport in VSD
        # self.assertEqual(SPOOFING_ENABLED,
        #                  nuage_vport[0]['addressSpoofing'])
        # When I delete the allowed address  pair from the port
        self._remove_allowed_address_pair_from_port(addrpair_port)
        # I expect it to be gone from the show port response
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self.assertEmpty(show_port['port']['allowed_address_pairs'],
                         "Removed allowed-address-pair stil present in "
                         "port (%s)" % addrpair_port['id'])
        pass

    @decorators.attr(type='smoke')
    def test_create_address_pair_l3domain_with_mac(self):
        # Given I have a VSD-L3-Managed subnet
        vsd_l3_subnet, l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        # When I create a port in this VSD-L3-Managed-Subnet with
        # - fixed-IP address
        # - allowed-address-pair with
        #     IP@ = fixed-IP+5
        #     valid MAC address (<> port MAC address)
        port_fixed_ip = str(IPAddress(
            base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW) + 100)
        aap_fixed_ip = str(IPAddress(port_fixed_ip) + 5)

        self._ensure_nuage_vip_port_vsd_ipam(aap_fixed_ip, network)

        kwargs = {
            'fixed_ips': [{
                'subnet_id': subnet['id'],
                'ip_address': str(port_fixed_ip)
            }],
            'allowed_address_pairs': [{
                'ip_address': aap_fixed_ip,
                'mac_address': VALID_MAC_ADDRESS
            }]
        }
        addrpair_port = self.create_port(network, **kwargs)
        # Then I expect the allowed-address-pair the port-show response
        # And the allowed-address-pair MACaddress == port MACaddress
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self._verify_port_allowed_address_fields(show_port['port'],
                                                 aap_fixed_ip,
                                                 VALID_MAC_ADDRESS)
        # And no corresponding MultiVIP on the VSD
        port_ext_id = self.nuage_client.get_vsd_external_id(
            addrpair_port['id'])
        nuage_vport = self.nuage_client.get_vport(
            constants.SUBNETWORK,
            vsd_l3_subnet[0]['ID'],
            filters='externalID',
            filter_values=port_ext_id)
        self.assertIsNone(nuage_vport[0]['multiNICVPortID'],
                          "multiNICVPortID is not empty while it should be")
        # And address address spoofing is disabled on vport in VSD
        self.assertEqual(SPOOFING_DISABLED,
                         nuage_vport[0]['addressSpoofing'])
        # When I delete the allowed address  pair from the port
        self._remove_allowed_address_pair_from_port(addrpair_port)
        # I expect it to be gone from the show port response
        show_port = self.ports_client.show_port(addrpair_port['id'])
        self.assertEmpty(show_port['port']['allowed_address_pairs'],
                         "Removed allowed-address-pair stil present in "
                         "port (%s)" % addrpair_port['id'])
        pass

    ###########################################################################
    ###########################################################################
    # associate FIP testcases
    ###########################################################################
    ###########################################################################


class VSDManagedAssociateFIPTest(
        base_vsd_managed_port_attributes.BaseVSDManagedPortAttributes):

    @classmethod
    def resource_setup(cls):
        super(VSDManagedAssociateFIPTest, cls).resource_setup()
        cls.vsd_fip_pool = cls._create_vsd_floatingip_pool()

    def test_create_port_with_vsd_floatingip(self):
        # Given I have a VSD-FloatingIP-pool
        vsd_fip_pool = self.vsd_fip_pool
        # And VSD-L3-Domain with a VSD-L3-Managed-Subnet
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        # And I have claimed a VSD-FloatingIP in the VSD-L3-Domain
        claimed_fip = self.nuage_client.claim_floatingip(
            vsd_l3_domain[0]['ID'], vsd_fip_pool[0]['ID'])
        # When I retrieve the nuage-floatingIP-list of the
        # VSD-L3-Managed-Subnet
        fip_list = \
            self.nuage_network_client.list_nuage_floatingip_by_subnet(
                subnet['id'])
        # I expect the VSD-floatingIP in my list
        fip_present = self._check_fip_in_list(claimed_fip[0]['ID'], fip_list)
        self.assertTrue(fip_present,
                        msg="nuage floatingip not present in list, "
                            "while expected to be")
        # When I create a port in the subnet
        kwargs = {"nuage_floatingip": {'id': claimed_fip[0]['ID']}}
        port = self.create_port(network, **kwargs)
        # And I associate this port to the claimed floating ip (via update)
        # self._associate_fip_to_port(port, claimed_fip[0]['ID'])

        # Then I expect the claimed floating ip in the port show response
        if not Topology.is_ml2:
            fip_present = self._check_fip_in_port_show(port['id'],
                                                       claimed_fip[0]['ID'])
            self.assertTrue(fip_present,
                            msg="associated VSD claimed FIP (%s) not found "
                                "in port (%s)" %
                                (claimed_fip[0]['ID'], port['id']))

        # When I disassociate the claimed fip from the port
        self._disassociate_fip_from_port(port)
        # Then I no longer expect the claimed floating ip in the port show resp
        if not Topology.is_ml2:
            fip_present = self._check_fip_in_port_show(port['id'],
                                                       claimed_fip[0]['ID'])
            self.assertFalse(fip_present,
                             msg="disassociated VSD claimed FIP (%s) "
                                 "still found in port (%s)" %
                                 (claimed_fip[0]['ID'], port['id']))

    @decorators.attr(type='smoke')
    def test_create_list_associate_vsd_floatingip(self):
        # Given I have a VSD-FloatingIP-pool
        vsd_fip_pool = self.vsd_fip_pool
        # And VSD-L3-Domain with a VSD-L3-Managed-Subnet
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        # And I have claimed a VSD-FloatingIP in the VSD-L3-Domain
        claimed_fip = self.nuage_client.claim_floatingip(
            vsd_l3_domain[0]['ID'], vsd_fip_pool[0]['ID'])
        # When I retrieve the nuage-floatingIP-list of the
        # VSD-L3-Managed-Subnet
        fip_list = self.nuage_network_client.list_nuage_floatingip_by_subnet(
            subnet['id'])
        # I expect the VSD-floatingIP in my list
        fip_present = self._check_fip_in_list(claimed_fip[0]['ID'], fip_list)
        self.assertTrue(fip_present,
                        msg="nuage floatingip not present in list, "
                            "while expected to be")
        # When I create a port in the subnet
        port = self.create_port(network)
        # And I associate this port to the claimed floating ip (via update)
        self._associate_fip_to_port(port, claimed_fip[0]['ID'])

        # Then I expect the claimed floating ip in the port show response
        if not Topology.is_ml2:
            fip_present = self._check_fip_in_port_show(port['id'],
                                                       claimed_fip[0]['ID'])
            self.assertTrue(fip_present,
                            msg="associated VSD claimed FIP (%s) not found "
                                "in port (%s)" %
                                (claimed_fip[0]['ID'], port['id']))

        # When I disassociate the claimed fip from the port
        self._disassociate_fip_from_port(port)
        # Then I no longer expect the claimed floating ip in the port show resp
        if not Topology.is_ml2:
            fip_present = self._check_fip_in_port_show(port['id'],
                                                       claimed_fip[0]['ID'])
            self.assertFalse(fip_present,
                             msg="disassociated VSD claimed FIP (%s) still "
                                 "found in port (%s)" %
                                 (claimed_fip[0]['ID'], port['id']))

    def test_create_list_associate_several_vsd_floatingip(self):
        ports = []
        claimed_fips = []
        # Given I have a several VSD-FloatingIP-pools
        vsd_fip_pool = self.vsd_fip_pool
        # And VSD-L3-Domain with a VSD-L3-Managed-Subnet
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        # And I have claimed several VSD-FloatingIP in the VSD-L3-Domain
        for i in range(SEVERAL_VSD_CLAIMED_FIPS):
            claimed_fip = self.nuage_client.claim_floatingip(
                vsd_l3_domain[0]['ID'], vsd_fip_pool[0]['ID'])
            claimed_fips.append(claimed_fip)
        # When I retrieve the nuage-floatingIP-list of the
        # VSD-L3-Managed-Subnet
        fip_list = self.nuage_network_client.list_nuage_floatingip_by_subnet(
            subnet['id'])
        # I expect all VSD-floatingIP in my list
        for i in range(SEVERAL_VSD_CLAIMED_FIPS):
            fip_present = self._check_fip_in_list(
                claimed_fips[i][0]['ID'], fip_list)
            self.assertTrue(fip_present,
                            msg="nuage floatingip not present in list, "
                                "while expected to be")
        # When I create several ports in the subnet
        for i in range(SEVERAL_VSD_CLAIMED_FIPS):
            port = self.create_port(network)
            ports.append(port)
        # And I associate this port to the claimed floating ip (via update)
        for i in range(SEVERAL_VSD_CLAIMED_FIPS):
            self._associate_fip_to_port(ports[i], claimed_fips[i][0]['ID'])
        for i in range(SEVERAL_VSD_CLAIMED_FIPS):
            # Then I expect the claimed floating ip in the port show response
            if not Topology.is_ml2:
                fip_present = self._check_fip_in_port_show(
                    ports[i]['id'], claimed_fips[i][0]['ID'])
                self.assertTrue(fip_present,
                                msg="associated VSD claimed FIP (%s) not "
                                    "found in port (%s)" %
                                    (claimed_fips[i][0]['ID'], ports[i]['id']))

            # When I disassociate the claimed fip from the port
            self._disassociate_fip_from_port(ports[i])
            # Then I no longer expect the claimed floating ip in the
            # port show response

            if not Topology.is_ml2:
                fip_present = self._check_fip_in_port_show(
                    ports[i]['id'], claimed_fips[i][0]['ID'])
                self.assertFalse(fip_present,
                                 msg="disassociated VSD claimed FIP (%s) "
                                     "still found in port (%s)" %
                                     (claimed_fips[i][0]['ID'],
                                      ports[i]['id']))

    def test_subnets_same_domain_associate_vsd_floatingip(self):
        # Given I have a VSD-FloatingIP-pool
        vsd_fip_pool = self.vsd_fip_pool
        # And I have claimed a VSD-FloatingIp-X in VSD-L3-Managed-Subnet-X
        # And I have claimed a VSD-FloatingIP-Y  in VD-L3-Managed-Subnet-Y
        # And they are in the same  VSD-L3-domain
        vsd_l3_subnet_x, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network_x, subnet_x = self._create_os_l3_vsd_managed_subnet(
            vsd_l3_subnet_x)
        vsd_l3_subnet_y = self._create_vsd_l3_managed_subnet_in_domain(
            vsd_l3_domain[0]['ID'],
            base_vsd_managed_port_attributes.VSD_SECOND_SUBNET_CIDR)
        network_y, subnet_y = self._create_os_l3_vsd_managed_subnet(
            vsd_l3_subnet_y,
            base_vsd_managed_port_attributes.VSD_SECOND_SUBNET_CIDR)
        claimed_fip_x = self.nuage_client.claim_floatingip(
            vsd_l3_domain[0]['ID'], vsd_fip_pool[0]['ID'])
        claimed_fip_y = self.nuage_client.claim_floatingip(
            vsd_l3_domain[0]['ID'], vsd_fip_pool[0]['ID'])

        # When I retrieve the nuage-floatingip-list from
        # VSD-L3-Managed-Subnet-X
        fip_list_x = self.nuage_network_client.list_nuage_floatingip_by_subnet(
            subnet_x['id'])
        # I expect both VSD-FloatingIP's in the list
        fip_present_x = self._check_fip_in_list(claimed_fip_x[0]['ID'],
                                                fip_list_x)
        self.assertTrue(fip_present_x,
                        msg="nuage floatingip not present in list, "
                            "while expected to be")
        fip_present_y = self._check_fip_in_list(claimed_fip_y[0]['ID'],
                                                fip_list_x)
        self.assertTrue(fip_present_y,
                        msg="nuage floatingip not present in list, "
                            "while expected to be")
        # When I retrieve the nuage-floatingip-list from
        # VSD-L3-Managed-Subnet-B
        fip_list_y = self.nuage_network_client.list_nuage_floatingip_by_subnet(
            subnet_y['id'])
        # I expect both VSD-floatingIP's in the list
        fip_present = self._check_fip_in_list(
            claimed_fip_x[0]['ID'], fip_list_y)
        self.assertTrue(fip_present,
                        msg="nuage floatingip not present in list, "
                            "while expected to be")
        fip_present = self._check_fip_in_list(
            claimed_fip_y[0]['ID'], fip_list_y)
        self.assertTrue(fip_present,
                        msg="nuage floatingip not present in list, "
                            "while expected to be")
        # When I associate VSD-FloatingIp-X to port_x
        port_x = self.create_port(network_x)
        self._associate_fip_to_port(port_x, claimed_fip_x[0]['ID'])
        # I expect this VSD-FloatingIp-X to be gone from the lists
        # (no longer available)
        fip_list_x = \
            self.nuage_network_client.list_nuage_floatingip_by_subnet(
                subnet_x['id'])
        fip_present_x = self._check_fip_in_list(
            claimed_fip_x[0]['ID'], fip_list_x)
        self.assertFalse(fip_present_x,
                         msg="associated VSD claimed FIP (%s) still found "
                             "as available in subnet-list (%s)" %
                             (claimed_fip_x[0]['ID'], subnet_x['id']))
        fip_list_y = self.nuage_network_client.list_nuage_floatingip_by_subnet(
            subnet_y['id'])
        fip_present_x = self._check_fip_in_list(
            claimed_fip_x[0]['ID'], fip_list_y)
        self.assertFalse(fip_present_x,
                         msg="associated VSD claimed FIP (%s) still found "
                             "as available in subnet-list (%s)" %
                             (claimed_fip_x[0]['ID'], subnet_y['id']))
        # And VSD-FloatingIp-Y still present in that list
        fip_present_y = self._check_fip_in_list(
            claimed_fip_y[0]['ID'], fip_list_x)
        self.assertTrue(fip_present_y,
                        msg="nuage floatingip not present in list, "
                            "while expected to be")
        # When I associate VSD-FloatingIp-Y to port_y
        port_y = self.create_port(network_y)
        self._associate_fip_to_port(port_y, claimed_fip_y[0]['ID'])
        # Then I expect VSD-FloatingIp-Y to be gone from the list
        # (as no longer available)
        fip_list_y = \
            self.nuage_network_client.list_nuage_floatingip_by_subnet(
                subnet_y['id'])
        fip_present_y = self._check_fip_in_list(
            claimed_fip_y[0]['ID'], fip_list_y)
        self.assertFalse(fip_present_y,
                         msg="associated VSD claimed FIP (%s) still found "
                             "as available in subnet-list (%s)" %
                             (claimed_fip_y[0]['ID'], subnet_y['id']))
        # When I disassociate VSD-FloatingIp-X from port-X
        self._disassociate_fip_from_port(port_x)
        # Then VSD_FloatingIp-X is again available in the list of subnet-X
        fip_list_x = self.nuage_network_client.list_nuage_floatingip_by_subnet(
            subnet_x['id'])
        fip_present_x = self._check_fip_in_list(
            claimed_fip_x[0]['ID'], fip_list_x)
        self.assertTrue(fip_present_x,
                        msg="nuage floatingip not present in list, "
                            "while expected to be")
        # And is is also available in the list of subnet-Y
        fip_list_y = \
            self.nuage_network_client.list_nuage_floatingip_by_subnet(
                subnet_y['id'])
        fip_present_y = self._check_fip_in_list(
            claimed_fip_x[0]['ID'], fip_list_y)
        self.assertTrue(fip_present_y, msg="nuage floatingip not present "
                                           "in list, while expected to be")
        # When I disassociate VSD-FloatingIp-Y from port-Y
        self._disassociate_fip_from_port(port_y)
        # Then VSD_FloatingIp-Y is again available in the list of subnet-X
        fip_list_x = self.nuage_network_client.list_nuage_floatingip_by_subnet(
            subnet_x['id'])
        fip_present_x = self._check_fip_in_list(
            claimed_fip_y[0]['ID'], fip_list_x)
        self.assertTrue(fip_present_x,
                        msg="nuage floatingip not present in list, "
                            "while expected to be")
        # And is is also available in the list of subnet-Y
        fip_list_y = \
            self.nuage_network_client.list_nuage_floatingip_by_subnet(
                subnet_y['id'])
        fip_present_y = self._check_fip_in_list(
            claimed_fip_y[0]['ID'], fip_list_y)
        self.assertTrue(fip_present_y,
                        msg="nuage floatingip not present in list, "
                            "while expected to be")

    def test_subnets_other_domain_associate_vsd_floatingip(self):
        # Given I have a VSD-FloatingIP-pool
        vsd_fip_pool = self.vsd_fip_pool
        # And I have claimed a VSD-FloatingIp-X in VSD-L3-Managed-Subnet-X
        vsd_l3_subnet_x, vsd_l3_domain_x = self._create_vsd_l3_managed_subnet()
        network_x, subnet_x = self._create_os_l3_vsd_managed_subnet(
            vsd_l3_subnet_x)
        claimed_fip_x = self.nuage_client.claim_floatingip(
            vsd_l3_domain_x[0]['ID'], vsd_fip_pool[0]['ID'])
        # And I have claimed a VSD-FloatingIP-Y in VD-L3-Managed-Subnet-Y
        # And they are in different VSD-L3-domains
        vsd_l3_subnet_y, vsd_l3_domain_y = self._create_vsd_l3_managed_subnet()
        network_y, subnet_y = self._create_os_l3_vsd_managed_subnet(
            vsd_l3_subnet_y)
        claimed_fip_y = self.nuage_client.claim_floatingip(
            vsd_l3_domain_y[0]['ID'], vsd_fip_pool[0]['ID'])
        # When I retrieve the nuage-floatingip-list from
        # VSD-L3-Managed-Subnet-X
        fip_list_x = self.nuage_network_client.list_nuage_floatingip_by_subnet(
            subnet_x['id'])
        # I expect only VSD-FloatingIP-X in the list, not VSD-FloatingIP-y
        self.assertTrue(self._check_fip_in_list(
            claimed_fip_x[0]['ID'], fip_list_x),
            msg="nuage floatingip not present in list, while expected to be")
        fip_present = self._check_fip_in_list(
            claimed_fip_y[0]['ID'], fip_list_x)
        self.assertFalse(fip_present,
                         msg="nuage floatingip present in list, "
                             "while expected not to be")
        # When I retrieve the nuage-floatingip-list from
        # VSD-L3-Managed-Subnet-Y
        fip_list_y = \
            self.nuage_network_client.list_nuage_floatingip_by_subnet(
                subnet_y['id'])
        # I expect only VSD-floatingIP-Y in the list
        fip_present = self._check_fip_in_list(
            claimed_fip_x[0]['ID'], fip_list_y)
        self.assertFalse(fip_present,
                         msg="nuage floatingip not present in list, "
                             "while expected to be")
        fip_present = self._check_fip_in_list(
            claimed_fip_y[0]['ID'], fip_list_y)
        self.assertTrue(fip_present,
                        msg="nuage floatingip not present in list, "
                            "while expected to be")
        # When I associate VSD-FloatingIp-x to port-x
        port_x = self.create_port(network_x)
        self._associate_fip_to_port(port_x, claimed_fip_x[0]['ID'])
        # Then VSD-FloatingIp-x is no longer present in the list for subnet-x
        fip_list_x = \
            self.nuage_network_client.list_nuage_floatingip_by_subnet(
                subnet_x['id'])
        self.assertFalse(self._check_fip_in_list(
            claimed_fip_x[0]['ID'], fip_list_x),
            msg="nuage floatingip not present in list, while expected to be")
        # When I associate VSD-FloatingIp-y to port-y
        port_y = self.create_port(network_y)
        self._associate_fip_to_port(port_y, claimed_fip_y[0]['ID'])
        # Then VSD-FloatingIp-y is no longer present in the list for subnet-y
        fip_list_y = \
            self.nuage_network_client.list_nuage_floatingip_by_subnet(
                subnet_y['id'])
        self.assertFalse(self._check_fip_in_list(
            claimed_fip_y[0]['ID'], fip_list_y),
            msg="nuage floatingip not present in list, while expected to be")

    @decorators.attr(type=['negative'])
    def test_create_associate_vsd_floatingip_twice_neg(self):
        # Given I have a VSD-FloatingIP-pool
        vsd_fip_pool = self.vsd_fip_pool
        # And VSD-L3-Domain with a VSD-L3-Managed-Subnet
        vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(vsd_l3_subnet)
        # And I have claimed a VSD-FloatingIP in the VSD-L3-Domain
        claimed_fip = self.nuage_client.claim_floatingip(
            vsd_l3_domain[0]['ID'], vsd_fip_pool[0]['ID'])
        # When I retrieve the nuage-floatingIP-list of the
        # VSD-L3-Managed-Subnet
        fip_list = self.nuage_network_client.list_nuage_floatingip_by_subnet(
            subnet['id'])
        # I expect the VSD-floatingIP in my list
        fip_present = self._check_fip_in_list(claimed_fip[0]['ID'], fip_list)
        self.assertTrue(fip_present,
                        msg="nuage floatingip not present in list, "
                            "while expected to be")
        # When I create a port in the subnet
        port_1 = self.create_port(network)
        # And I associate this port to the claimed floating ip (via update)
        self._associate_fip_to_port(port_1, claimed_fip[0]['ID'])
        self._associate_fip_to_port(port_1, claimed_fip[0]['ID'])
        # kwargs = {"nuage_floatingip": {'id': claimed_fip[0]['ID']}}
        # self.update_port(port_1, **kwargs)

        # Then I expect the claimed floating ip in the port show response
        if not Topology.is_ml2:
            fip_present = self._check_fip_in_port_show(
                port_1['id'], claimed_fip[0]['ID'])
            self.assertTrue(fip_present,
                            msg="associated VSD claimed FIP (%s) not found "
                                "in port (%s)" %
                                (claimed_fip[0]['ID'], port_1['id']))

        # When I try to associate the same claimed floating IP to another port
        port_2 = self.create_port(network)
        # I expect a failure
        expected_exception = exceptions.BadRequest
        msg = self.err_msg_base + 'Floating IP {} is already in use'.format(
            claimed_fip[0]['address'])

        if NUAGE_FEATURES.ml2_limited_exceptions:
            expected_exception = exceptions.ServerFault
            if Topology.at_openstack('kilo'):
                msg = "update_port_postcommit failed"
            else:
                msg = "Got server fault"

        self.assertRaisesRegex(
            expected_exception,
            msg,
            self._associate_fip_to_port,
            port_2,
            claimed_fip[0]['ID'])
