# Copyright 2018 NOKIA
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

from netaddr import IPNetwork

from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.test import tags
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.tests.api.vsd_managed \
    import base_vsd_managed_networks
from nuage_tempest_plugin.tests.api.vsd_managed \
    import base_vsd_public_resources

OS_FULL_CIDR24_RANGE = 254  # .256 -1 (.0) -1 (.255)
VSD_L2_SHARED_MGD_OPT3_CIDR = IPNetwork('21.21.21.0/24')
VSD_L2_SHARED_MGD_OPT3_GW = '21.21.21.1'
VSD_L2_SHARED_MGD_OPT3 = '21.21.21.121'
VSD_L3_SHARED_MGD_OPT3_CIDR = IPNetwork('31.31.31.0/24')
VSD_L3_SHARED_MGD_OPT3_GW = '31.31.31.1'
VSD_L3_SHARED_MGD_OPT3 = '31.31.31.131'
#
VALID_CIDR = IPNetwork('3.22.111.0/24')
VALID_CIDR_GW = '3.22.111.1'
#
EXPECT_DHCP_ENABLE_TRUE = "enable_dhcp in subnet must be True"
EXPECT_DHCP_ENABLE_FALSE = "enable_dhcp in subnet must be False"
EXPECT_CIDRS_DO_NOT_MATCH = "do not match"
EXPECT_GATEWAY_IN_CIDR = "Invalid input for operation: " \
                         "Gateway is not valid on subnet."


@nuage_test.class_header(tags=[tags.ML2, tags.VSD_MANAGED])
class VSDPublicResourcesML2Test(
        base_vsd_public_resources.BaseVSDPublicResources):

    os_shared_network = False

    if Topology.before_openstack('Newton'):
        failure_type = exceptions.ServerFault
        dhcp_port = False
    else:
        failure_type = exceptions.BadRequest
        dhcp_port = True

    @classmethod
    def skip_checks(cls):
        super(VSDPublicResourcesML2Test, cls).skip_checks()
        if not Topology.is_ml2:
            raise cls.skipException('Skipping ml2 tests with '
                                    'nuage-core plugin')

    @nuage_test.header()
    def test_vsd_l2_shared_unmgd_l2_unmgd_without_gw_ip(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L2-Shared-domain without IPAM (i.e. UnManaged)
        # and these are linked
        vsd_l2dom_unmgd = self._given_vsdl2sharedunmgd_lnkd_to_vsdl2domunmgd()

        self._check_vsd_l2_shared_l2_unmgd(
            vsd_l2dom_unmgd=vsd_l2dom_unmgd,

            # When I create an OS subnet with
            #   enable_dhcp == False
            #   a valid CIDR
            #   nuagenet == UUID of VSD-L2-domain
            #   no IP
            os_shared_network=self.os_shared_network,
            enable_dhcp=False,
            cidr=VALID_CIDR,
            gateway_ip='',

            # Then the OS subnet has
            #   an OS allocation pool covering the full CIDR range
            #   gateway_ip equal to None
            expected_gateway_ip=None,
            #   and has no network:dhcp:nuage port
            expect_network_dhcp_nuage_port=False,

            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the valid CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain is empty
            expect_vm_ip_addresses_equal=''
        )

    @nuage_test.header()
    def test_vsd_l2_shared_unmgd_l2_unmgd_with_gw_ip_neg(self):
        # Pass on liberty, fail on kilo
        # Given I have a VSD-L2-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L2-Shared-domain without IPAM (i.e. UnManaged)
        # and these are linked
        vsd_l2dom_unmgd = self._given_vsdl2sharedunmgd_lnkd_to_vsdl2domunmgd()

        self._check_vsd_l2_shared_l2_unmgd(
            vsd_l2dom_unmgd=vsd_l2dom_unmgd,
            # When I create an OS subnet with
            #   enable_dhcp == False
            #   a valid CIDR
            #   nuagenet == UUID of VSD-L2-domain
            os_shared_network=self.os_shared_network,
            enable_dhcp=False,
            gateway_ip=VALID_CIDR_GW,
            cidr=VALID_CIDR,

            # Then the OS subnet has
            #   an OS allocation pool covering the full CIDR range
            #   gateway_ip equal to None
            expected_gateway_ip=None,
            #   and no network:dhcp:nuage port
            expect_network_dhcp_nuage_port=False,

            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the valid CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain is empty
            expect_vm_ip_addresses_equal=''
        )

    @nuage_test.header()
    def test_vsd_l2_shared_unmgd_l2_unmgd_no_gateway(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L2-Shared-domain without IPAM (i.e. UnManaged)
        # And these are linked
        vsd_l2dom_unmgd = self._given_vsdl2sharedunmgd_lnkd_to_vsdl2domunmgd()
        self._check_vsd_l2_shared_l2_unmgd(
            vsd_l2dom_unmgd=vsd_l2dom_unmgd,
            # When I create an OS subnet with
            #     enable_dhcp == False
            #     a valid CIDR
            #     nuagenet == UUID of VSD-L2-domain
            #     no-gateway
            os_shared_network=self.os_shared_network,
            enable_dhcp=False,
            cidr=VALID_CIDR,
            gateway_ip=None,

            # Then the OS subnet has
            # gateway_ip equal to None
            expected_gateway_ip=None,
            #   and no network:dhcp:nuage port
            expect_network_dhcp_nuage_port=False,

            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the valid CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain is empty
            expect_vm_ip_addresses_equal=''
        )

    @nuage_test.header()
    def test_vsd_l2_shared_mgd_l2_unmgd_without_gateway(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L2-Shared-domain without IPAM (i.e. UnManaged)
        # And these are linked
        vsd_l2dom_unmgd = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self._check_vsd_l2_shared_l2_unmgd(
            vsd_l2dom_unmgd=vsd_l2dom_unmgd,
            #  When I create an OS subnet with
            #   enable_dhcp == False
            #   a valid CIDR
            #   nuagenet == UUID of VSD-L2-domain
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip='',

            # Then the OS subnet has
            #   gateway_ip equal to None
            expected_gateway_ip=None,
            #   and network:dhcp:nuage port exist from Newton onwards
            expect_network_dhcp_nuage_port=self.dhcp_port,

            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the valid CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain is empty
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l2_shared_mgd_l2_unmgd_with_gw_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # And these are linked
        vsd_l2dom_unmgd = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        if Topology.at_openstack('kilo'):
            self.assertRaisesRegex(
                exceptions.ServerFault,
                "create_subnet_postcommit failed.",
                self._check_vsd_l2_shared_l2_unmgd,
                vsd_l2dom_unmgd=vsd_l2dom_unmgd,
                os_shared_network=self.os_shared_network,
                enable_dhcp=True,
                cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
                gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
                expect_network_dhcp_nuage_port=False,
                expected_gateway_ip=None,
                expect_vm_ip_addresses_equal=True
            )
        else:
            # In ML2 Liberty this is not a negative test so it should pass
            self._check_vsd_l2_shared_l2_unmgd(
                vsd_l2dom_unmgd=vsd_l2dom_unmgd,
                #  When I create an OS subnet with
                #   enable_dhcp == False
                #   a valid CIDR
                #   nuagenet == UUID of VSD-L2-domain
                os_shared_network=self.os_shared_network,
                enable_dhcp=True,
                cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
                gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,

                # Then the OS subnet has
                #   gateway_ip equal to None
                expected_gateway_ip=None,
                #   and no network:dhcp:nuage port
                expect_network_dhcp_nuage_port=self.dhcp_port,

                # When I spin a VM in this network
                # Then the OS  VM-IP-address is in the valid CIDR range
                # And the VM-interface-IP-address in the VSD-L2-domain is empty
                expect_vm_ip_addresses_equal=True
            )

    @nuage_test.header()
    def test_vsd_l2_shared_mgd_l2_unmgd_no_gateway(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # And these are linked
        vsd_l2dom_unmgd = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self._check_vsd_l2_shared_l2_unmgd(
            vsd_l2dom_unmgd=vsd_l2dom_unmgd,
            # When I create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L2-Shared-domain
            #   nuagenet == UUID of VSD-L2-domain
            #   no-gateway
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip=None,

            # Then the OS subnet has
            #   gateway_ip equal to None
            expected_gateway_ip=None,
            #   and no network:dhcp:nuage port
            expect_network_dhcp_nuage_port=self.dhcp_port,

            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain equals
            # the OS VM-IP-address
            expect_vm_ip_addresses_equal=True
        )

    @nuage_test.header()
    def test_vsd_l2_shared_mgd_opt3_l2_unmgd_without_gw_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom_unmgd = \
            self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
                VSD_L2_SHARED_MGD_OPT3)

        self._create_vsd_mgd_subnet(
            vsd_l2dom_unmgd,
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip='',  # bad, must be VSD_L2_SHARED_MGD_OPT3
            must_fail=True)

    @nuage_test.header()
    def test_vsd_l2_shared_mgd_opt3_l2_unmgd_with_gateway(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # and these are linked
        vsd_l2dom_unmgd = \
            self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
                VSD_L2_SHARED_MGD_OPT3)
        self._check_vsd_l2_shared_l2_unmgd(
            vsd_l2dom_unmgd=vsd_l2dom_unmgd,
            # When I create an OS subnet with
            #  enable_dhcp == True
            #  CIDR == CIDR of VSD-L2-Shared-domain
            #  nuagenet == UUID of VSD-L2-domain
            #  gateway-ip == gateway-ip in DHCP-option-3
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip=VSD_L2_SHARED_MGD_OPT3,

            # Then the OS subnet has
            #   gateway_ip equal to DHCP-options-3 of VSD-L2-Shared-domain
            expected_gateway_ip=VSD_L2_SHARED_MGD_OPT3,
            #   and network:dhcp:nuage port exist from Newton onwards
            expect_network_dhcp_nuage_port=self.dhcp_port,

            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain equals
            # the OS VM-IP-address
            expect_vm_ip_addresses_equal=True
        )

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_opt3_l2_unmgd_no_gateway(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # and these are linked
        # Then I expect a failure from OS
        # Supported only when dhcp_option-3 is NOT set
        vsd_l2dom_unmgd = \
            self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
                VSD_L2_SHARED_MGD_OPT3)

        self._create_vsd_mgd_subnet(
            vsd_l2dom_unmgd,
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip=None,  # bad, must be VSD_L2_SHARED_MGD_OPT3
            must_fail=True)

    @nuage_test.header()
    def test_vsd_l3_shared_mgd_l3_unmgd_without_gateway(self):
        # Given I have a VSD-L3-domain in a public zone
        # (i.e. without IPAM (/ UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()

        self._check_vsd_l3_shared_l2_unmgd(
            # When I create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain-public-zone-subnet
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip='',

            # Then the OS subnet has
            #   gateway_ip equal to gateway-ip of VSD-L3-Shared-domain
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            #   and network:dhcp:nuage port exist from Newton onwards
            expect_network_dhcp_nuage_port=self.dhcp_port,

            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the  CIDR range
            # And the VM-interface-IP-address in the VSD-L3-domain equals
            # the OS VM-IP-address
            # And the VM-interface-IP-address is different from the
            # gateway_ip address
            expect_vm_ip_addresses_equal=True
        )

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_vsd_l3_shared_mgd_l3_unmgd_with_gateway(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()

        self._check_vsd_l3_shared_l2_unmgd(
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=self.os_shared_network,
            # When I create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway-ip == gateway-ip of VSD-L3-Shared-domain
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,

            # Then the OS subnet has
            #   gateway_ip equal to gateway-ip of VSD-L3-Shared-domain
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            #   and network:dhcp:nuage port exist from Newton onwards
            expect_network_dhcp_nuage_port=self.dhcp_port,
            #
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L3-domain equals
            # the OS VM-IP-address
            # And the OS VM-IP-address is different from the gateway-ip
            expect_vm_ip_addresses_equal=True
        )

    @nuage_test.header()
    def test_vsd_l3_shared_mgd_l3_unmgd_no_gateway_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()

        self._create_vsd_mgd_subnet(
            vsd_l3_unmgd_subnet,
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip=None,  # bad, must be <base>.VSD_L3_SHARED_MGD_GW
            must_fail=True)

    @nuage_test.header()
    def test_vsd_l3_shared_mgd_opt3_l2_unmgd_with_gateway(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with DHCP-options-3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgdopt3_linked_to_vsdl3subnetunmgd(
                VSD_L3_SHARED_MGD_OPT3)

        self._check_vsd_l3_shared_l2_unmgd(
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=self.os_shared_network,

            # When I create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway-ip == gateway-ip of VSD-L3-Shared-domain
            enable_dhcp=True,
            cidr=VSD_L3_SHARED_MGD_OPT3_CIDR,
            gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,

            # Then the OS subnet has
            #   an OS allocation pool covering the full CIDR range
            # (except the GW-ip)
            #   gateway_ip equal to gateway-ip of VSD-L3-Shared-domain
            expected_gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            #   and network:dhcp:nuage port exist from Newton onwards
            expect_network_dhcp_nuage_port=self.dhcp_port,

            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L3-domain equals
            # the OS VM-IP-address
            # And the OS VM-IP-address is different from the gateway-ip
            expect_vm_ip_addresses_equal=True
        )

    def test_vsd_l3_shared_mgd_opt3_0000_l2_unmgd_with_gateway(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with DHCP-options-3 0.0.0.0
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgdopt3_linked_to_vsdl3subnetunmgd(
                dhcp_option_3='0.0.0.0')

        self._check_vsd_l3_shared_l2_unmgd(
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=self.os_shared_network,
            # When I create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway-ip == gateway-ip of VSD-L3-Shared-domain
            enable_dhcp=True,
            cidr=VSD_L3_SHARED_MGD_OPT3_CIDR,
            gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,

            # Then the OS subnet has
            #   an OS allocation pool covering the full CIDR range
            # (except the GW-ip)
            #   gateway_ip equal to gateway-ip of VSD-L3-Shared-domain
            expected_gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            #   and network:dhcp:nuage port exist from Newton onwards
            expect_network_dhcp_nuage_port=self.dhcp_port,

            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L3-domain equals
            # the OS VM-IP-address
            # And the OS VM-IP-address is different from the gateway-ip
            expect_vm_ip_addresses_equal=True,
        )

    # #########################################################################
    # # Negative testcases
    # #########################################################################

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l2_shared_unmgd_l2_unmgd_wo_gw_enable_dhcp_neg(
            self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain without IPAM (i.e. UnManaged)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedunmgd_lnkd_to_vsdl2domunmgd()
        self._create_vsd_mgd_subnet(
            vsd_l2dom,
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,  # bad
            cidr=VALID_CIDR,  # any CIDR, doesn't matter
            gateway_ip='',
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l2_shared_mgd_l2_unmgd_wo_gw_no_dhcp_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        #     And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self._create_vsd_mgd_subnet(
            vsd_l2dom,
            os_shared_network=self.os_shared_network,
            enable_dhcp=False,  # bad
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip='',
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l2_shared_mgd_l2_unmgd_with_gw_no_dhcp_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        #     And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self._create_vsd_mgd_subnet(
            vsd_l2dom,
            os_shared_network=self.os_shared_network,
            enable_dhcp=False,  # bad
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l2_shared_mgd_l2_unmgd_no_gw_no_dhcp_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        #     And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self._create_vsd_mgd_subnet(
            vsd_l2dom,
            os_shared_network=self.os_shared_network,
            enable_dhcp=False,  # bad
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip=None,
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l2_shared_mgd_l2_unmgd_wo_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self._create_vsd_mgd_subnet(
            vsd_l2dom,
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=VALID_CIDR,  # bad
            gateway_ip='',
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l2_shared_mgd_l2_unmgd_with_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self._create_vsd_mgd_subnet(
            vsd_l2dom,
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=VALID_CIDR,  # bad
            gateway_ip=VALID_CIDR_GW,
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l2_shared_mgd_l2_no_gw_unmgd_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self._create_vsd_mgd_subnet(
            vsd_l2dom,
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=VALID_CIDR,  # bad
            gateway_ip=None,
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l2_shared_mgd_opt3_l2_unmgd_without_gw_no_dhcp_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self._create_vsd_mgd_subnet(
            vsd_l2dom,
            os_shared_network=self.os_shared_network,
            enable_dhcp=False,  # bad
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip='',
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l2_shared_mgd_opt_3_l2_unmgd_with_gw_no_dhcp_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self._create_vsd_mgd_subnet(
            vsd_l2dom,
            os_shared_network=self.os_shared_network,
            enable_dhcp=False,  # bad
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip=VSD_L2_SHARED_MGD_OPT3_GW,
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l2_shared_mgd_opt_3_l2_unmgd_no_gw_no_dhcp_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self._create_vsd_mgd_subnet(
            vsd_l2dom,
            os_shared_network=self.os_shared_network,
            enable_dhcp=False,  # bad
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip=None,
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l2_shared_mgd_opt_3_l2_unmgd_wo_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self._create_vsd_mgd_subnet(
            vsd_l2dom,
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=VALID_CIDR,  # bad
            gateway_ip='',
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l2_shared_mgd_opt_3_l2_unmgd_with_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self._create_vsd_mgd_subnet(
            vsd_l2dom,
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=VALID_CIDR,  # bad
            gateway_ip=VALID_CIDR_GW,
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l2_shared_mgd_opt_3_l2_unmgd_no_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self._create_vsd_mgd_subnet(
            vsd_l2dom,
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=VALID_CIDR,  # bad
            gateway_ip=None,
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l3_shared_mgd_l3_unmgd_wo_gw_no_dhcp_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self._create_vsd_mgd_subnet(
            vsd_l3_unmgd_subnet,
            os_shared_network=self.os_shared_network,
            enable_dhcp=False,  # bad
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip=None,
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l3_shared_mgd_l3_unmgd_with_gw_no_dhcp_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self._create_vsd_mgd_subnet(
            vsd_l3_unmgd_subnet,
            os_shared_network=self.os_shared_network,
            enable_dhcp=False,  # bad
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l3_shared_mgd_l3_unmgd_no_gw_no_dhcp_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self._create_vsd_mgd_subnet(
            vsd_l3_unmgd_subnet,
            os_shared_network=self.os_shared_network,
            enable_dhcp=False,  # bad
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip=None,
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l3_shared_mgd_l3_unmgd_wo_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self._create_vsd_mgd_subnet(
            vsd_l3_unmgd_subnet,
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=VALID_CIDR,  # bad
            gateway_ip='',
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l3_shared_mgd_l3_unmgd_with_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self._create_vsd_mgd_subnet(
            vsd_l3_unmgd_subnet,
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=VALID_CIDR,  # bad
            gateway_ip=VALID_CIDR_GW,
            must_fail=True)

    @decorators.attr(type=['negative'])
    @nuage_test.header()
    def test_vsd_l3_shared_mgd_l3_unmgd_no_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self._create_vsd_mgd_subnet(
            vsd_l3_unmgd_subnet,
            os_shared_network=self.os_shared_network,
            enable_dhcp=True,
            cidr=VALID_CIDR,  # bad
            gateway_ip=None,
            must_fail=True)


@nuage_test.class_header(tags=[tags.ML2, tags.VSD_MANAGED])
class VSDPublicSharedResourcesML2Test(VSDPublicResourcesML2Test):

    os_shared_network = True
