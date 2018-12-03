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

from netaddr import IPNetwork

from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_lib.topology import Topology

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
EXPECT_GATEWAY_IP_MISMATCH = "Bad subnet request: Provided gateway-ip does " \
                             "not match VSD configuration"
EXPECT_CIDR_IN_RANGE = "Bad request: OSP cidr " + str(VALID_CIDR) + \
                       " and NuageVsd cidr"
EXPECT_GATEWAY_IN_CIDR = "Bad request: Gateway IP outside of the subnet CIDR"
EXPECT_DO_NOT_MATCH = "do not match"


class MonolithicPluginVSDPublicResourcesTest(
        base_vsd_public_resources.BaseVSDPublicResources):

    @classmethod
    def resource_setup(cls):
        super(MonolithicPluginVSDPublicResourcesTest, cls).resource_setup()

    @classmethod
    # As i understand all these tests were written for monolithic plugin
    def skip_checks(cls):
        super(MonolithicPluginVSDPublicResourcesTest, cls).skip_checks()
        if Topology.is_ml2:
            raise cls.skipException('Skipping monolithic tests for ml2')

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
            os_shared_network=False,
            enable_dhcp=False,
            cidr=VALID_CIDR,
            gateway_ip='',
            # Then the OS subnet has
            #   NO neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   gateway_ip equal to None
            expect_network_dhcp_nuage_port=False,
            expected_gateway_ip=None,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the valid CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain is empty
            expect_vm_ip_addresses_equal=''
        )

    def test_vsd_l2_shared_unmgd_l2_unmgd_with_gw_ip(self):
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
            os_shared_network=False,
            enable_dhcp=False,
            gateway_ip=VALID_CIDR_GW,
            cidr=VALID_CIDR,
            # Then the OS subnet has
            #   NO neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   gateway_ip equal to None
            expect_network_dhcp_nuage_port=False,
            expected_gateway_ip=None,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the valid CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain is empty
            expect_vm_ip_addresses_equal=''
        )

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
            os_shared_network=False,
            enable_dhcp=False,
            cidr=VALID_CIDR,
            gateway_ip=None,
            # Then the OS subnet has
            # NO neutron port device_owner:network:dhcp:nuage
            # an OS allocation pool covering the full CIDR range
            # gateway_ip equal to None
            expect_network_dhcp_nuage_port=False,
            expected_gateway_ip=None,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the valid CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain is empty
            expect_vm_ip_addresses_equal=''
        )

    def test_vsd_l2_shared_mgd_l2_unmgd_without_gateway(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L2-Shared-domain without IPAM (i.e. UnManaged)
        # and these are linked
        vsd_l2dom_unmgd = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self._check_vsd_l2_shared_l2_unmgd(
            vsd_l2dom_unmgd=vsd_l2dom_unmgd,
            #  When I create an OS subnet with
            #   enable_dhcp == False
            #   a valid CIDR
            #   nuagenet == UUID of VSD-L2-domain
            os_shared_network=False,
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip='',
            # Then the OS subnet has
            #   NO neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   gateway_ip equal to None
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=None,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the valid CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain is empty
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_l2_unmgd_with_gw_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # And these are linked
        vsd_l2dom_unmgd = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_GATEWAY_IP_MISMATCH,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom_unmgd,
            os_shared_network=False,
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=None,
            expect_vm_ip_addresses_equal=True
        )

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
            os_shared_network=False,
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip=None,
            # Then the OS subnet has
            #   a neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   gateway_ip equal to None
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=None,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain equals
            # the OS VM-IP-address
            expect_vm_ip_addresses_equal=True
        )

    def test_vsd_l2_shared_mgd_opt3_l2_unmgd_without_gateway(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2_dom_unmgd = \
            self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
                VSD_L2_SHARED_MGD_OPT3)
        self._check_vsd_l2_shared_l2_unmgd(
            vsd_l2_dom_unmgd,
            # When I create an OS subnet with
            #     enable_dhcp == True
            #     CIDR == CIDR of VSD-L2-Shared-domain
            #     nuagenet == UUID of VSD-L2-domain
            os_shared_network=False,
            enable_dhcp=True,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip='',
            # Then the OS subnet has
            # a neutron port device_owner:network:dhcp:nuage
            # an OS allocation pool covering the full CIDR range except the
            # gateway_ip
            # gateway_ip equal DHCP-options-3 of VSD-L2-Shared-domain
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L2_SHARED_MGD_OPT3,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain equals the
            # OS VM-IP-address
            expect_vm_ip_addresses_equal=True
        )

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
            os_shared_network=False,
            enable_dhcp=True,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip=VSD_L2_SHARED_MGD_OPT3,
            # Then the OS subnet has
            #   a neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   gateway_ip equal to DHCP-options-3 of VSD-L2-Shared-domain
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L2_SHARED_MGD_OPT3,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain equals the
            # OS VM-IP-address
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_opt3_l2_unmgd_no_gateway_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # and these are linked
        # Then I expect a failure from OS
        # Supported only when dhcp_option-3 is NOT set
        vsd_l2dom_unmgd = \
            self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
                VSD_L2_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_GATEWAY_IP_MISMATCH,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd,
            os_shared_network=False,
            # When I try to create an OS subnet with
            # enable_dhcp == True
            # CIDR == CIDR of VSD-L2-Shared-domain
            # nuagenet == UUID of VSD-L2-domain
            # no-gateway
            enable_dhcp=True,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L2_SHARED_MGD_OPT3,
            expect_vm_ip_addresses_equal=True
            # Then I expect a failure from OS
        )

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
            os_shared_network=False,
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip='',
            # Then the OS subnet has
            #   a neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range, except the
            #   VSD-L3-Shared gateway
            #   gateway_ip equal to gateway-ip of VSD-L3-Shared-domain
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the  CIDR range
            # And the VM-interface-IP-address in the VSD-L3-domain equals the
            # OS VM-IP-address
            # And the VM-interface-IP-address is different from the
            # gateway_ip address
            expect_vm_ip_addresses_equal=True
        )

    def test_vsd_l3_shared_mgd_l3_unmgd_with_gateway(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self._check_vsd_l3_shared_l2_unmgd(
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=False,
            # When I create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway-ip == gateway-ip of VSD-L3-Shared-domain
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            # Then the OS subnet has
            #   a neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   (except the GW-ip)
            #   gateway_ip equal to gateway-ip of VSD-L3-Shared-domain
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L3-domain equals the
            # OS VM-IP-address
            # And the OS VM-IP-address is different from the gateway-ip
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_no_gateway_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_GATEWAY_IP_MISMATCH,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   no-gateway
            # Then I expect a failure
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip=None,
            # Then the OS subnet has
            #   a  neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   (except the GW-ip)
            #   gateway_ip equal to gateway-ip of VSD-L3-Shared-domain
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L3-domain equals the
            # OS VM-IP-address
            # And the OS VM-IP-address is different from the gateway-ip
            expect_vm_ip_addresses_equal=True
        )

    def test_vsd_l3_shared_mgd_opt3_l3_unmgd_without_gateway(self):
        # Given I have a VSD-L3-domain in a public zone
        # (i.e. without IPAM (/ UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM
        # (i.e. Managed) with DHCP option 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgdopt3_linked_to_vsdl3subnetunmgd(
                VSD_L3_SHARED_MGD_OPT3)
        self._check_vsd_l3_shared_l2_unmgd(
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=False,
            # When I create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain-public-zone-subnet
            enable_dhcp=True,
            cidr=VSD_L3_SHARED_MGD_OPT3_CIDR,
            gateway_ip='',
            # Then the OS subnet has
            #   a neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range,
            #   except the VSD-L3-Shared gateway
            #   gateway_ip equal to gateway-ip of VSD-L3-Shared-domain
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the  CIDR range
            # And the VM-interface-IP-address in the VSD-L3-domain equals the
            # OS VM-IP-address
            # And the VM-interface-IP-address is different from the
            # gateway_ip address
            expect_vm_ip_addresses_equal=True
        )

    def test_vsd_l3_shared_mgd_opt3_l3_unmgd_with_gateway(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with DHCP-options-3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgdopt3_linked_to_vsdl3subnetunmgd(
                VSD_L3_SHARED_MGD_OPT3)
        self._check_vsd_l3_shared_l2_unmgd(
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=False,
            # When I create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway-ip == gateway-ip of VSD-L3-Shared-domain
            enable_dhcp=True,
            cidr=VSD_L3_SHARED_MGD_OPT3_CIDR,
            gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            # Then the OS subnet has
            #   a  neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   (except the GW-ip)
            #   gateway_ip equal to gateway-ip of VSD-L3-Shared-domain
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L3-domain equals the
            # OS VM-IP-address
            # And the OS VM-IP-address is different from the gateway-ip
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_opt3_l3_subnet_unmgd_no_gateway_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with DHCP-options-3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgdopt3_linked_to_vsdl3subnetunmgd(
                VSD_L3_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_GATEWAY_IP_MISMATCH,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   no-gateway
            # Then I expect a failure indicating gateway IP mismatch
            enable_dhcp=True,
            cidr=VSD_L3_SHARED_MGD_OPT3_CIDR,
            gateway_ip=None,
            # Then the OS subnet has
            #   a  neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   (except the GW-ip)
            #   gateway_ip equal to gateway-ip of VSD-L3-Shared-domain
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L3-domain equals the
            # OS VM-IP-address
            # And the OS VM-IP-address is different from the gateway-ip
            expect_vm_ip_addresses_equal=True
        )

    ###########################################################################
    ###########################################################################
    # Negative testcases
    ###########################################################################
    ###########################################################################
    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_unmgd_l2_unmgd_wo_gw_enable_dhcp_neg(
            self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain without IPAM (i.e. UnManaged)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedunmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_FALSE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect an OS failure indicating enable_dhcp to be
            # False
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VALID_CIDR_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_unmgd_l2_unmgd_with_gw_enable_dhcp_neg(
            self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain without IPAM (i.e. UnManaged)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedunmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_FALSE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway_ip in CIDR
            # Then I expect an OS failure indicating enable_dhcp to be True
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_unmgd_l2_unmgd_no_gw_enable_dhcp_neg(
            self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain without IPAM (i.e. UnManaged)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedunmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_FALSE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   no gateway
            # Then I expect an OS failure indicating enable_dhcp to be False
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_l2_unmgd_wo_gw_enable_dhcp_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        #     And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect an OS failure indicating enable_dhcp to be True
            enable_dhcp=False,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_l2_unmgd_with_gw_no_dhcp_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        #     And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway_ip in CIDR
            # Then I expect an OS failure indicating enable_dhcp to be True
            enable_dhcp=False,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_l2_unmgd_no_gw_no_dhcp_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        #     And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   no gateway
            # Then I expect an OS failure indicating enable_dhcp to be True
            enable_dhcp=False,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_l2_unmgd_wo_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L2-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect a failure indicating CIDR mismatch
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VALID_CIDR_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_l2_unmgd_with_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L2-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway ip in the wrong CIDR
            # Then I expect a failure indicating CIDR mismatch
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip=VALID_CIDR_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VALID_CIDR_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_l2_no_gw_unmgd_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L2-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   no gateway
            # Then I expect a failure indicating CIDR mismatch
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VALID_CIDR_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_opt3_l2_unmgd_wo_gw_no_dhcp_neg(
            self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect an OS failure indicating enable_dhcp to be True
            enable_dhcp=False,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L2_SHARED_MGD_OPT3_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_opt_3_l2_unmgd_with_gw_no_dhcp_neg(
            self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=False,
            # When I try to create an OS subnet with
            # enable_dhcp == False
            # CIDR == CIDR of VSD-L2-Shared-domain
            # nuagenet == UUID of VSD-L2-domain
            # gateway-ip == gateway-ip in DHCP-option-3
            enable_dhcp=False,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip=VSD_L2_SHARED_MGD_OPT3_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L2_SHARED_MGD_OPT3_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_opt_3_l2_unmgd_no_gw_no_dhcp_neg(
            self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=False,
            # When I try to create an OS subnet with
            # enable_dhcp == False
            # CIDR == CIDR of VSD-L2-Shared-domain
            # nuagenet == UUID of VSD-L2-domain
            # no gateway
            enable_dhcp=False,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L2_SHARED_MGD_OPT3_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_opt_3_l2_unmgd_wo_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L2-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect a failure indicating CIDR mismatch
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VALID_CIDR_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_opt_3_l2_unmgd_with_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L2-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway ip in the wrong CIDR
            # Then I expect a failure indicating CIDR mismatch
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip=VALID_CIDR_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VALID_CIDR_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_opt_3_l2_unmgd_no_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L2-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   no gateway
            # Then I expect a failure indicating CIDR mismatch
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VALID_CIDR_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_wo_gw_no_dhcp_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=False,
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_with_gw_no_dhcp_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway_ip in CIDR
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=False,
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_no_gw_no_dhcp_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   no gateway
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=False,
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_opt3_l3_unmgd_wo_gw_no_dhcp_neg(
            self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgdopt3_linked_to_vsdl3subnetunmgd(
                VSD_L3_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=False,
            cidr=VSD_L3_SHARED_MGD_OPT3_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_opt3_l3_unmgd_with_gw_no_dhcp_neg(
            self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgdopt3_linked_to_vsdl3subnetunmgd(
                VSD_L3_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway_ip in CIDR
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=False,
            cidr=VSD_L3_SHARED_MGD_OPT3_CIDR,
            gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_opt3_l3_unmgd_no_gw_no_dhcp_neg(
            self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgdopt3_linked_to_vsdl3subnetunmgd(
                VSD_L3_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway_ip in CIDR
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=False,
            cidr=VSD_L3_SHARED_MGD_OPT3_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_wo_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_with_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway ip in CIDR
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip=VALID_CIDR_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_no_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   no gateway
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_with_gw_gw_mismatch_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_GATEWAY_IN_CIDR,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=False,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway ip not in  CIDR
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )


class VSDPublicResourcesSharedNetworksTest(
        base_vsd_public_resources.BaseVSDPublicResources):

    @classmethod
    # As i understand all these tests were written for monolithic plugin
    def skip_checks(cls):
        super(VSDPublicResourcesSharedNetworksTest, cls).skip_checks()
        if Topology.is_ml2:
            raise cls.skipException('Skipping monolithic tests for ml2')

    @classmethod
    def resource_setup(cls):
        super(VSDPublicResourcesSharedNetworksTest, cls).resource_setup()

    def test_os_shared_vsd_l2_shared_unmgd_l2_unmgd_without_gw_ip(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L2-Shared-domain without IPAM (i.e. UnManaged)
        # and these are linked
        vsd_l2dom_unmgd = self._given_vsdl2sharedunmgd_lnkd_to_vsdl2domunmgd()
        self._check_vsd_l2_shared_l2_unmgd(
            vsd_l2dom_unmgd=vsd_l2dom_unmgd,
            os_shared_network=True,
            # When I create an OS subnet with
            #   enable_dhcp == False
            #   a valid CIDR
            #   nuagenet == UUID of VSD-L2-domain
            enable_dhcp=False,
            cidr=VALID_CIDR,
            gateway_ip='',
            # Then the OS subnet has
            #   NO neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   gateway_ip equal to None
            expect_network_dhcp_nuage_port=False,
            expected_gateway_ip=None,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the valid CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain is empty
            expect_vm_ip_addresses_equal=''
        )

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
            os_shared_network=True,
            enable_dhcp=False,
            cidr=VALID_CIDR,
            gateway_ip='',
            # Then the OS subnet has
            #   NO neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   gateway_ip equal to None
            expect_network_dhcp_nuage_port=False,
            expected_gateway_ip=None,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the valid CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain is empty
            expect_vm_ip_addresses_equal=''
        )

    def test_vsd_l2_shared_unmgd_l2_unmgd_with_gw_ip(self):
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
            os_shared_network=True,
            enable_dhcp=False,
            gateway_ip=VALID_CIDR_GW,
            cidr=VALID_CIDR,
            # Then the OS subnet has
            #   NO neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   gateway_ip equal to None
            expect_network_dhcp_nuage_port=False,
            expected_gateway_ip=None,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the valid CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain is empty
            expect_vm_ip_addresses_equal=''
        )

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
            os_shared_network=True,
            enable_dhcp=False,
            cidr=VALID_CIDR,
            gateway_ip=None,
            # Then the OS subnet has
            # NO neutron port device_owner:network:dhcp:nuage
            # an OS allocation pool covering the full CIDR range
            # gateway_ip equal to None
            expect_network_dhcp_nuage_port=False,
            expected_gateway_ip=None,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the valid CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain is empty
            expect_vm_ip_addresses_equal=''
        )

    def test_vsd_l2_shared_mgd_l2_unmgd_without_gateway(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L2-Shared-domain without IPAM (i.e. UnManaged)
        # and these are linked
        vsd_l2dom_unmgd = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self._check_vsd_l2_shared_l2_unmgd(
            vsd_l2dom_unmgd=vsd_l2dom_unmgd,
            #  When I create an OS subnet with
            #   enable_dhcp == False
            #   a valid CIDR
            #   nuagenet == UUID of VSD-L2-domain
            os_shared_network=True,
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip='',
            # Then the OS subnet has
            #   NO neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   gateway_ip equal to None
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=None,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the valid CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain is empty
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_l2_unmgd_with_gw_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # And these are linked
        vsd_l2dom_unmgd = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_GATEWAY_IP_MISMATCH,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom_unmgd,
            os_shared_network=True,
            enable_dhcp=True,
            gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=None,
            expect_vm_ip_addresses_equal=True
        )

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
            os_shared_network=True,
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip=None,
            # Then the OS subnet has
            #   a neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   gateway_ip equal to None
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=None,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain equals the
            # OS VM-IP-address
            expect_vm_ip_addresses_equal=True
        )

    def test_vsd_l2_shared_mgd_opt3_l2_unmgd_without_gateway(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2_dom_unmgd = \
            self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
                VSD_L2_SHARED_MGD_OPT3)
        self._check_vsd_l2_shared_l2_unmgd(
            vsd_l2_dom_unmgd,
            # When I create an OS subnet with
            #     enable_dhcp == True
            #     CIDR == CIDR of VSD-L2-Shared-domain
            #     nuagenet == UUID of VSD-L2-domain
            os_shared_network=True,
            enable_dhcp=True,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip='',
            # Then the OS subnet has
            # a neutron port device_owner:network:dhcp:nuage
            # an OS allocation pool covering the full CIDR range except
            # the gateway_ip
            # gateway_ip equal DHCP-options-3 of VSD-L2-Shared-domain
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L2_SHARED_MGD_OPT3,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain equals the
            # OS VM-IP-address
            expect_vm_ip_addresses_equal=True
        )

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
            os_shared_network=True,
            # When I create an OS subnet with
            #  enable_dhcp == True
            #  CIDR == CIDR of VSD-L2-Shared-domain
            #  nuagenet == UUID of VSD-L2-domain
            #  gateway-ip == gateway-ip in DHCP-option-3
            enable_dhcp=True,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip=VSD_L2_SHARED_MGD_OPT3,
            # Then the OS subnet has
            #   a neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   gateway_ip equal to DHCP-options-3 of VSD-L2-Shared-domain
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L2_SHARED_MGD_OPT3,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L2-domain equals
            # the OS VM-IP-address
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_opt3_l2_unmgd_no_gateway_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # and these are linked
        # Then I expect a failure from OS
        # Supported only when dhcp_option-3 is NOT set
        vsd_l2dom_unmgd = \
            self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
                VSD_L2_SHARED_MGD_OPT3)

        # TODO(TEAM) test name does not correspond to what is done

        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_GATEWAY_IP_MISMATCH,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd,
            os_shared_network=True,
            # When I try to create an OS subnet with
            # enable_dhcp == True
            # CIDR == CIDR of VSD-L2-Shared-domain
            # nuagenet == UUID of VSD-L2-domain
            # no-gateway
            enable_dhcp=True,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L2_SHARED_MGD_OPT3,
            expect_vm_ip_addresses_equal=True
            # Then I expect a failure from OS
        )

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
            os_shared_network=True,
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip='',
            # Then the OS subnet has
            #   a neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range,
            #   except the VSD-L3-Shared gateway
            #   gateway_ip equal to gateway-ip of VSD-L3-Shared-domain
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the  CIDR range
            # And the VM-interface-IP-address in the VSD-L3-domain equals the
            # OS VM-IP-address
            # And the VM-interface-IP-address is different from the
            # gateway_ip address
            expect_vm_ip_addresses_equal=True
        )

    def test_vsd_l3_shared_mgd_l3_unmgd_with_gateway(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self._check_vsd_l3_shared_l2_unmgd(
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=True,
            # When I create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway-ip == gateway-ip of VSD-L3-Shared-domain
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            # Then the OS subnet has
            #   a neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   (except the GW-ip)
            #   gateway_ip equal to gateway-ip of VSD-L3-Shared-domain
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L3-domain equals the
            # OS VM-IP-address
            # And the OS VM-IP-address is different from the gateway-ip
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_no_gateway_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_GATEWAY_IP_MISMATCH,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   no-gateway
            # Then I expect a failure
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip=None,
            # Then the OS subnet has
            #   a neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            #   (except the GW-ip)
            #   gateway_ip equal to gateway-ip of VSD-L3-Shared-domain
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L3-domain equals the
            # OS VM-IP-address
            # And the OS VM-IP-address is different from the gateway-ip
            expect_vm_ip_addresses_equal=True
        )

    def test_vsd_l3_shared_mgd_opt3_l3_unmgd_without_gateway(self):
        # Given I have a VSD-L3-domain in a public zone
        # (i.e. without IPAM (/ UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with DHCP option 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgdopt3_linked_to_vsdl3subnetunmgd(
                VSD_L3_SHARED_MGD_OPT3)
        self._check_vsd_l3_shared_l2_unmgd(
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=True,
            # When I create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain-public-zone-subnet
            enable_dhcp=True,
            cidr=VSD_L3_SHARED_MGD_OPT3_CIDR,
            gateway_ip='',
            # Then the OS subnet has
            #   a neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range, except
            #   the VSD-L3-Shared gateway
            #   gateway_ip equal to gateway-ip of VSD-L3-Shared-domain
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the  CIDR range
            # And the VM-interface-IP-address in the VSD-L3-domain equals the
            # OS VM-IP-address
            # And the VM-interface-IP-address is different from the
            # gateway_ip address
            expect_vm_ip_addresses_equal=True
        )

    def test_vsd_l3_shared_mgd_opt3_l3_unmgd_with_gateway(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with DHCP-options-3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgdopt3_linked_to_vsdl3subnetunmgd(
                VSD_L3_SHARED_MGD_OPT3)
        self._check_vsd_l3_shared_l2_unmgd(
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=True,
            # When I create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway-ip == gateway-ip of VSD-L3-Shared-domain
            enable_dhcp=True,
            cidr=VSD_L3_SHARED_MGD_OPT3_CIDR,
            gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            # Then the OS subnet has
            #   a  neutron port device_owner:network:dhcp:nuage
            #   an OS allocation pool covering the full CIDR range
            # (except the GW-ip)
            #   gateway_ip equal to gateway-ip of VSD-L3-Shared-domain
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            # When I spin a VM in this network
            # Then the OS VM-IP-address is in the CIDR range
            # And the VM-interface-IP-address in the VSD-L3-domain equals the
            # OS VM-IP-address
            # And the OS VM-IP-address is different from the gateway-ip
            expect_vm_ip_addresses_equal=True
        )

    ###########################################################################
    ###########################################################################
    # Negative testcases
    ###########################################################################
    ###########################################################################

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_unmgd_l2_unmgd_wo_gw_enable_dhcp_neg(
            self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain without IPAM (i.e. UnManaged)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedunmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_FALSE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect an OS failure indicating enable_dhcp to be
            # False
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VALID_CIDR_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_unmgd_l2_unmgd_with_gw_enable_dhcp_neg(
            self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain without IPAM (i.e. UnManaged)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedunmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_FALSE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway_ip in CIDR
            # Then I expect an OS failure indicating enable_dhcp to be True
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_unmgd_l2_unmgd_no_gw_enable_dhcp_neg(
            self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain without IPAM (i.e. UnManaged)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedunmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_FALSE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   no gateway
            # Then I expect an OS failure indicating enable_dhcp to be
            # False
            enable_dhcp=True,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_l2_unmgd_wo_gw_enable_dhcp_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        #     And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect an OS failure indicating enable_dhcp to be True
            enable_dhcp=False,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_l2_unmgd_with_gw_no_dhcp_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        #     And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway_ip in CIDR
            # Then I expect an OS failure indicating enable_dhcp to be True
            enable_dhcp=False,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_l2_unmgd_no_gw_no_dhcp_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        #     And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   no gateway
            # Then I expect an OS failure indicating enable_dhcp to be True
            enable_dhcp=False,
            cidr=base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_l2_unmgd_wo_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L2-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect a failure indicating CIDR mismatch
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VALID_CIDR_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_l2_unmgd_with_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L2-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway ip in the wrong CIDR
            # Then I expect a failure indicating CIDR mismatch
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip=VALID_CIDR_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VALID_CIDR_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_l2_no_gw_unmgd_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgd_lnkd_to_vsdl2domunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L2-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   no gateway
            # Then I expect a failure indicating CIDR mismatch
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VALID_CIDR_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_opt3_l2_unmgd_wo_gw_no_dhcp_neg(
            self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect an OS failure indicating enable_dhcp to be True
            enable_dhcp=False,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L2_SHARED_MGD_OPT3_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_opt_3_l2_unmgd_with_gw_no_dhcp_neg(
            self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=True,
            # When I try to create an OS subnet with
            # enable_dhcp == False
            # CIDR == CIDR of VSD-L2-Shared-domain
            # nuagenet == UUID of VSD-L2-domain
            # gateway-ip == gateway-ip in DHCP-option-3
            enable_dhcp=False,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip=VSD_L2_SHARED_MGD_OPT3_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L2_SHARED_MGD_OPT3_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_opt_3_l2_unmgd_no_gw_no_dhcp_neg(
            self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=True,
            # When I try to create an OS subnet with
            # enable_dhcp == False
            # CIDR == CIDR of VSD-L2-Shared-domain
            # nuagenet == UUID of VSD-L2-domain
            # no gateway
            enable_dhcp=False,
            cidr=VSD_L2_SHARED_MGD_OPT3_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L2_SHARED_MGD_OPT3_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_opt_3_l2_unmgd_wo_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L2-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect a failure indicating CIDR mismatch
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VALID_CIDR_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_opt_3_l2_unmgd_with_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
            VSD_L2_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L2-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway ip in the wrong CIDR
            # Then I expect a failure indicating CIDR mismatch
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip=VALID_CIDR_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VALID_CIDR_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l2_shared_mgd_opt_3_l2_unmgd_no_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L2-domain without IPAM (i.e. unmanaged)
        # And I have a VSD-L2-Shared-domain with IPAM (i.e. managed)
        # with DHCP-option 3 set
        # And these are linked
        vsd_l2dom = \
            self._given_vsdl2sharedmgdopt3_linked_to_vsdl2domunmgd(
                VSD_L2_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l2_shared_l2_unmgd,
            vsd_l2dom_unmgd=vsd_l2dom,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L2-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   no gateway
            # Then I expect a failure indicating CIDR mismatch
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VALID_CIDR_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_opt3_l3_unmgd_no_gateway_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with DHCP-options-3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgdopt3_linked_to_vsdl3subnetunmgd(
                VSD_L3_SHARED_MGD_OPT3)

        self._create_vsd_mgd_subnet(
            vsd_l3_unmgd_subnet,
            os_shared_network=True,
            enable_dhcp=True,
            cidr=VSD_L3_SHARED_MGD_OPT3_CIDR,
            gateway_ip=None,  # bad : must be VSD_L3_SHARED_MGD_OPT3
            must_fail=True)

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_wo_gw_no_dhcp_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=False,
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_with_gw_no_dhcp_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway_ip in CIDR
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=False,
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_no_gw_no_dhcp_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   no gateway
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=False,
            cidr=base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_opt3_l3_unmgd_wo_gw_no_dhcp_neg(
            self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgdopt3_linked_to_vsdl3subnetunmgd(
                VSD_L3_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=False,
            cidr=VSD_L3_SHARED_MGD_OPT3_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_opt3_l3_unmgd_with_gw_no_dhcp_neg(
            self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgdopt3_linked_to_vsdl3subnetunmgd(
                VSD_L3_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway_ip in CIDR
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=False,
            cidr=VSD_L3_SHARED_MGD_OPT3_CIDR,
            gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_op3_l3_unmgd_no_gw_no_dhcp_neg(
            self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgdopt3_linked_to_vsdl3subnetunmgd(
                VSD_L3_SHARED_MGD_OPT3)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DHCP_ENABLE_TRUE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == False
            #   CIDR == CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway_ip in CIDR
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=False,
            cidr=VSD_L3_SHARED_MGD_OPT3_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=VSD_L3_SHARED_MGD_OPT3_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_wo_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip='',
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_with_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway ip in CIDR
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip=VALID_CIDR_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_no_gw_cidr_mismatch_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_DO_NOT_MATCH,  # EXPECT_CIDR_IN_RANGE,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   no gateway
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip=None,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )

    @decorators.attr(type=['negative'])
    def test_vsd_l3_shared_mgd_l3_unmgd_with_gw_gw_mismatch_neg(self):
        # Given I have a VSD-L3-domain without IPAM (i.e. UnManaged)
        # And I have a VSD-L3-Shared-domain with IPAM (i.e. Managed)
        # with dhcp options 3
        # and these are linked
        vsd_l3_unmgd_subnet = \
            self._given_vsdl3sharedmgd_lnkd_to_vsdl2subnetunmgd()
        self.assertRaisesRegex(
            exceptions.BadRequest,
            EXPECT_GATEWAY_IN_CIDR,
            self._check_vsd_l3_shared_l2_unmgd,
            vsd_l3_dom_subnet=vsd_l3_unmgd_subnet,
            os_shared_network=True,
            # When I try to create an OS subnet with
            #   enable_dhcp == True
            #   CIDR != CIDR of VSD-L3-Shared-domain
            #   nuagenet == UUID of VSD-L3-domain
            #   gateway ip not in  CIDR
            # Then I expect a failure indicating enable dhcp may not be false
            enable_dhcp=True,
            cidr=VALID_CIDR,
            gateway_ip=base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
            expect_network_dhcp_nuage_port=True,
            expected_gateway_ip=base_vsd_managed_networks.VSD_L3_SHARED_MGD_GW,
            expect_vm_ip_addresses_equal=True
        )
