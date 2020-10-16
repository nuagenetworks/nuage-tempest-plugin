# Copyright 2020 NOKIA
# All Rights Reserved.

from nuage_tempest_plugin.lib.mixins.l3 import L3Mixin
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.tests.upgrade.test_upgrade_base \
    import NuageUpgradeMixin
from nuage_tempest_plugin.tests.upgrade.test_upgrade_base \
    import NuageUpgradeSubTestMixin

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# CAUTION : THIS SUITE IS HIGHLY INTRUSIVE
#           - it relies heavily on devstack env
#           - it installs new packages in the tox env (like neutron)
#           - it changes the neutron branch out of which neutron runs
#           - it restarts neutron
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

DIRECTIONS_OS_VSD = {'egress': 'ingress',
                     'ingress': 'egress'}


class UpgradeFipMixin(NuageUpgradeSubTestMixin):

    def __init__(self, parent):
        super(UpgradeFipMixin, self).__init__(parent)
        self._resources = {'networks': [],
                           'l3_subnets': [],
                           'fips': []}

    def _create_os_resources(self):
        network = self.parent.create_network()
        self._resources['networks'].append(network)

        subnet4 = self.parent.create_subnet(network)
        subnet6 = self.parent.create_subnet(network, ip_version=6)

        router = self.parent.create_router(
            external_network_id=self._ext_net_id)
        self.parent.router_attach(router, subnet4)
        self.parent.router_attach(router, subnet6)

        self._resources['l3_subnets'].append(subnet4)
        self._resources['l3_subnets'].append(subnet6)

        # A FIP attached to vPort with both default ingress and egress rate
        port = self.parent.create_port(network)
        fip = self.parent.create_floatingip(port_id=port['id'])
        self._resources['fips'].append(fip)

        # A FIP attached to vPort with a non-default ingress rate
        port = self.parent.create_port(network)
        fip = self.parent.create_floatingip(port_id=port['id'],
                                            nuage_ingress_fip_rate_kbps=100)
        self._resources['fips'].append(fip)

        # A FIP attached to vPort with a non-default egress rate
        port = self.parent.create_port(network)
        fip = self.parent.create_floatingip(port_id=port['id'],
                                            nuage_egress_fip_rate_kbps=100)
        self._resources['fips'].append(fip)

        # A FIP attached to vPort with both ingress and egress custom rate
        port = self.parent.create_port(network)
        fip = self.parent.create_floatingip(port_id=port['id'],
                                            nuage_ingress_fip_rate_kbps=200,
                                            nuage_egress_fip_rate_kbps=100)
        self._resources['fips'].append(fip)

        # A FIP not attached to vPort
        fip = self.parent.create_floatingip()
        self._resources['fips'].append(fip)

        # A FIP attached to a VIP attached to a vPort
        # (so no rate limiting expected)
        vip_port = self.parent.create_port(network, device_owner='nuage:vip')
        aap_ip = [ip['ip_address'] for ip in vip_port['fixed_ips'] if
                  ip['subnet_id'] == subnet4['id']][0]
        port = self.parent.create_port(
            network, allowed_address_pairs=[{'ip_address': aap_ip}])
        fip = self.parent.create_floatingip(port_id=port['id'])
        fip['non_vip_port_id'] = port['id']
        self._resources['fips'].append(fip)

    def _verify_os_managed_resources(self):
        vsd_subnet = self._vsd.get_subnet(
            by_subnet=self._resources['l3_subnets'][0])
        for fip in self._resources['fips']:
            if fip['port_id']:
                vport = self._vsd.get_vport(subnet=vsd_subnet,
                                            by_port_id=fip['port_id'])
                ext_id_filter = self._vsd.get_external_id_filter(fip['id'])
                nuage_fip = self._vsd.session().user.floating_ips.get(
                    filter=ext_id_filter)[0]

                if not vport:
                    # FIP2VIP case
                    vport = self._vsd.get_vport(
                        vsd_subnet=vsd_subnet,
                        by_port_id=fip['non_vip_port_id'])
                # Verify no qos object
                qoses = vport.qoss.get()
                self.parent.assertEmpty(qoses)

                # Verify rate
                for os_direction in 'ingress', 'egress':
                    vsd_direction = DIRECTIONS_OS_VSD[os_direction]
                    rate = fip.get(
                        'nuage_{}_fip_rate_kbps'.format(os_direction))
                    ext_id_filter = self._vsd.get_external_id_filter(
                        '{}_{}'.format(vsd_direction, fip['id']))
                    rate_limiters = self._vsd.session().user.rate_limiters.get(
                        filter=ext_id_filter)
                    associated_rl = getattr(
                        nuage_fip, '{}_rate_limiter_id'.format(vsd_direction))

                    if rate == -1 or not rate:
                        # Make sure there is no RateLimiter
                        self.parent.assertEmpty(rate_limiters)
                        self.parent.assertIsNone(associated_rl)
                    else:
                        rate_limiter = rate_limiters[0]
                        expected_rate = float(rate) / 1000.0
                        self.parent.assertEqual(
                            float(rate_limiter.peak_information_rate),
                            expected_rate)
                        self.parent.assertEqual(
                            rate_limiter.peak_burst_size, '100')
                        self.parent.assertEqual(
                            rate_limiter.committed_information_rate, '0')
                        self.parent.assertEqual(
                            rate_limiter.name,
                            '{}_{}'.format(vsd_direction, fip['id']))
                        self.parent.assertEqual(
                            rate_limiter.id, associated_rl)


class UpgradeTo2010Test(NuageBaseTest, L3Mixin, NuageUpgradeMixin):

    _from_release = '6.0'
    _to_release = '20.10'

    @classmethod
    def skip_checks(cls):
        super(UpgradeTo2010Test, cls).skip_checks()
        cls._upgrade_skip_check()

    @classmethod
    def setup_clients(cls):
        super(UpgradeTo2010Test, cls).setup_clients()
        cls.vsd_client = NuageRestClient()

    @classmethod
    def setUpClass(cls):
        super(UpgradeTo2010Test, cls).setUpClass()
        cls._set_up()

    def test_upgrade(self):
        #   ----------------------------------------------------   #
        #
        #   T H I S   I S   T H E   T E S T
        #
        #   Mind : there can be only one upgrade test!
        #   ----------------------------------------------------   #

        # Alembic migration is expected from Ussuri onwards
        self._test_upgrade(alembic_expected=Topology.from_openstack('Ussuri'))

    class UpgradeFipTest(UpgradeFipMixin):

        def setup(self):
            self._create_os_resources()

        def verify(self):
            self._verify_os_managed_resources()
