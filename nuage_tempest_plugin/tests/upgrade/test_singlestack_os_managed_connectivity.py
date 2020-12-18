# Copyright 2020 - Nokia
# All Rights Reserved.

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest


class Wrapped(object):
    class UpgradeIcmpConnectivityL2OsManagedBase(NuageBaseTest):
        base_name = 'os_mgd_l2'

        default_prepare_for_connectivity = True
        default_include_private_key_as_metadata = True

        def set_me_up(self):
            raise NotImplementedError  # override me

        def test_icmp_connectivity_l2_os_managed(self):
            network, server1, server2 = self.set_me_up()

            # Test connectivity between peer servers
            self.assert_ping(server1, server2, network)


class PreUpgradeIcmpConnectivityL2OsManagedTest(
        Wrapped.UpgradeIcmpConnectivityL2OsManagedBase):

    """PreUpgradeIcmpConnectivityL2OsManagedTest

    Tests to be run on pre-upgrade system. These tests will NOT cleanup the
    resources set up as part of the tests (!!), as they will be further
    assessed post-upgrade, part of PostUpgradeIcmpConnectivityL2OsManagedTest
    """

    def set_me_up(self):
        # Provision OpenStack network resources
        network = self.create_network(self.base_name, cleanup=False)
        self.create_subnet(network, cleanup=False)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group(cleanup=False)

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            [network],
            name=self.base_name + '_vm2',
            security_groups=[ssh_security_group],
            cleanup=False)

        server1 = self.create_tenant_server(
            [network],
            name=self.base_name + '_vm1',
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True,
            cleanup=False)

        return network, server1, server2


class PostUpgradeIcmpConnectivityL2OsManagedTest(
        Wrapped.UpgradeIcmpConnectivityL2OsManagedBase):

    """PostUpgradeIcmpConnectivityL2OsManagedTest

    Tests to be run on post-upgrade system, continuing at under-test resources
    created as part of PreUpgradeIcmpConnectivityL2OsManagedTest. This test
    will build up the object model in Tempest plugin from OpenStack itself.

    NOTE: Always keep both classes aligned, for proper execution of these test
         (= somewhat guaranteed by inheriting from common base)
    """

    def set_me_up(self):
        # resurrect the SUT
        network = self.sync_network(self.base_name)
        server1 = self.sync_tenant_server(self.base_name + '_vm1')
        server2 = self.sync_tenant_server(self.base_name + '_vm2')

        return network, server1, server2
