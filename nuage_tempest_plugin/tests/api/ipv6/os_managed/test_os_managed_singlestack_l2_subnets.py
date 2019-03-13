# Copyright 2017 - Nokia
# All Rights Reserved.

from tempest.lib import decorators

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest

from nuage_tempest_plugin.tests.api.upgrade.external_id.external_id \
    import ExternalId


class OsManagedSingleStackV4L2SubnetsTest(NuageBaseTest):

    def _validate_dhcp_flag(self, l2_dom, enable_dhcp):
        if self._ip_version == 4:
            self.assertEqual(l2_dom.enable_dhcpv4, enable_dhcp)
        else:
            self.assertEqual(l2_dom.enable_dhcpv6, enable_dhcp)

    @decorators.attr(type='smoke')
    def test_singlestack_subnet_update(self):
        network = self.create_network()

        # Create a dhcp disabled subnet
        subnet = self.create_subnet(network, enable_dhcp=False)
        # verify dhcp status vith vsd
        vsd_l2_domain = self.vsd.get_l2domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(subnet['network_id']).at_cms_id()))
        self._validate_dhcp_flag(vsd_l2_domain, False)

        # change the name and verify it with vsd
        self.update_subnet(subnet, name="nametest")
        vsd_l2_domain = self.vsd.get_l2domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(subnet['network_id']).at_cms_id()))
        self.assertEqual(vsd_l2_domain.description, "nametest")

        # enable dhcp and verify with vsd
        self.update_subnet(subnet, enable_dhcp=True)
        vsd_l2_domain = self.vsd.get_l2domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(subnet['network_id']).at_cms_id()))
        self._validate_dhcp_flag(vsd_l2_domain, True)
        self.assertEqual(vsd_l2_domain.ip_type, 'IPV{}'.format(
            self._ip_version))

        # disable dhcp and verify with vsd
        self.update_subnet(subnet, enable_dhcp=False)
        vsd_l2_domain = self.vsd.get_l2domain(
            vspk_filter='externalID == "{}"'.format(
                ExternalId(subnet['network_id']).at_cms_id()))
        self._validate_dhcp_flag(vsd_l2_domain, False)


class OsManagedSingleStackV6L2SubnetsTest(OsManagedSingleStackV4L2SubnetsTest):
    _ip_version = 6
