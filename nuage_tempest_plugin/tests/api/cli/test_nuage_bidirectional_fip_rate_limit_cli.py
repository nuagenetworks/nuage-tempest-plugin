# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

import json

from tempest import config
from tempest.test import decorators

from nuage_tempest_plugin.lib import service_mgmt
from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants

from base_nuage_fip_rate_limit_cli import BaseNuageFipRateLimit

CONF = config.CONF

MSG_NO_INPUT = "neutron floatingip-create: error: argument " \
               "--nuage-ingress-fip-rate-kbps: expected one argument"
MSG_INVALID_INPUT = '\'nuage_ingress_fip_rate_kbps\' should be a number ' \
                    'higher than 0, -1 for unlimited or \'default\' ' \
                    'for the configured default value'
MSG_INVALID_INPUT_FOR_OPERATION = "Invalid input for operation: " \
                                  "'nuage_fip_rate' should be a number " \
                                  "higher than 0, " \
                                  "-1 for unlimited or 'default' for " \
                                  "the configured default value.."


class TestNuageBidiFRLCliWODefault(BaseNuageFipRateLimit):

    """FipRateLimit tests using Neutron CLI client.

    """

    @classmethod
    def read_nuage_fip_rate_limit_configs(cls):
        # TODO(Kris) FIXME.....................................................
        if Topology.assume_default_fip_rate_limits():
            return None, None
        # TODO(Kris) FIXME.....................................................

        fip_eg_rate_limit = cls.service_manager.get_configuration_attribute(
            CONF.nuage_sut.nuage_plugin_configuration,
            constants.FIP_RATE_GROUP,
            constants.BIDIRECTIONAL_FIP_RATE_DEFAULT_EGRESS
        )
        fip_ig_rate_limit = cls.service_manager.get_configuration_attribute(
            CONF.nuage_sut.nuage_plugin_configuration,
            constants.FIP_RATE_GROUP,
            constants.BIDIRECTIONAL_FIP_RATE_DEFAULT_INGRESS
        )
        return fip_eg_rate_limit, fip_ig_rate_limit

    @classmethod
    def nuage_fip_rate_limit_configs_needs_update(cls):
        fip_eg_rate_limit, fip_ig_rate_limit = \
            cls.read_nuage_fip_rate_limit_configs()
        return (not cls.fip_rate_config_value_matches(
            cls.configured_default_fip_rate, fip_eg_rate_limit) or
            not cls.fip_rate_config_value_matches(
                cls.configured_default_fip_rate, fip_ig_rate_limit))

    @classmethod
    def assure_nuage_fip_rate_limit_configs(cls):
        if cls.nuage_fip_rate_limit_configs_needs_update():

            if Topology.neutron_restart_supported():
                cls.service_manager = service_mgmt.ServiceManager()
                cls.service_manager.must_have_configuration_attribute(
                    CONF.nuage_sut.nuage_plugin_configuration,
                    constants.FIP_RATE_GROUP,
                    constants.BIDIRECTIONAL_FIP_RATE_DEFAULT_EGRESS,
                    cls.configured_default_fip_rate)
                cls.service_manager.must_have_configuration_attribute(
                    CONF.nuage_sut.nuage_plugin_configuration,
                    constants.FIP_RATE_GROUP,
                    constants.BIDIRECTIONAL_FIP_RATE_DEFAULT_INGRESS,
                    cls.configured_default_fip_rate)

            else:
                msg = 'Skipping tests that restart neutron ...'
                raise cls.skipException(msg)

    def _verify_fip_openstack(self, port, created_floating_ip,
                              ingress_rate_limit=None, egress_rate_limit=None):
        # Then it should be created
        # for the admin tenant id
        self.assertIsNotNone(created_floating_ip['id'])
        self.assertIsNotNone(created_floating_ip['tenant_id'])
        self.assertIsNotNone(created_floating_ip['floating_ip_address'])
        self.assertEqual(created_floating_ip['port_id'], port['id'])
        self.assertEqual(created_floating_ip['floating_network_id'],
                         self.ext_net_id)
        fixed_ips = port['fixed_ips']
        fixed_ips_dict = json.loads(fixed_ips)

        self.assertEqual(created_floating_ip['fixed_ip_address'],
                         fixed_ips_dict['ip_address'])
        self.LOG.info("Ingress FIP Rate limit %s",
                      created_floating_ip['nuage_ingress_fip_rate_kbps'])
        self.LOG.info("Egress FIP Rate limit %s",
                      created_floating_ip['nuage_egress_fip_rate_kbps'])
        if ingress_rate_limit is not None:
            self.assertEqual(
                float(created_floating_ip['nuage_ingress_fip_rate_kbps']),
                float(ingress_rate_limit))
        if egress_rate_limit is not None:
            self.assertEqual(
                float(created_floating_ip['nuage_egress_fip_rate_kbps']),
                float(egress_rate_limit))

    def _verify_fip_vsd(self, subnet, port, created_floating_ip,
                        ingress_rate_limit=None, egress_rate_limit=None):

        # verifying on Domain level that the floating ip is added
        external_id = self.nuage_vsd_client.get_vsd_external_id(
            created_floating_ip['router_id'])
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID',
            filter_value=external_id)
        nuage_domain_fip = self.nuage_vsd_client.get_floatingip(
            constants.DOMAIN, nuage_domain[0]['ID'])

        # The VSD FIP has same IP address than OpenStack FIP
        self.assertIn(created_floating_ip['floating_ip_address'],
                      [nuage_fip['address'] for nuage_fip in
                       nuage_domain_fip])

        # The VSD externalID for FIP matches the OpenStack ID
        external_id = self.nuage_vsd_client.get_vsd_external_id(
            created_floating_ip['id'])
        self.assertIn(external_id,
                      [nuage_fip['externalID'] for nuage_fip in
                       nuage_domain_fip])

        # Check vsd
        vsd_subnets = self.nuage_vsd_client.get_domain_subnet(
            None, None,
            'externalID',
            self.nuage_vsd_client.get_vsd_external_id(subnet['id']))
        self.assertEqual(1, len(vsd_subnets))
        vports = self.nuage_vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_subnets[0]['ID'],
            'externalID',
            self.nuage_vsd_client.get_vsd_external_id(port['id']))
        self.assertEqual(1, len(vports))
        qos = self.nuage_vsd_client.get_qos(constants.VPORT, vports[0]['ID'])
        self.assertEqual(1, len(qos))
        self.assertEqual(True, qos[0]['FIPRateLimitingActive'])

        self.LOG.info("OpenStack Egress FIP Rate limit %s",
                      qos[0]['FIPPeakInformationRate'])
        self.LOG.info("OpenStack Ingress FIP Rate limit %s",
                      qos[0]['EgressFIPPeakInformationRate'])
        if ingress_rate_limit is not None:
            self.assertEqualFiprate(
                ingress_rate_limit,
                self.convert_mbps_to_kbps(
                    qos[0]['EgressFIPPeakInformationRate']))
        if egress_rate_limit is not None:
            self.assertEqualFiprate(
                egress_rate_limit,
                self.convert_mbps_to_kbps(
                    qos[0]['FIPPeakInformationRate']))

        self.assertEqual(self.nuage_vsd_client.get_vsd_external_id(
            created_floating_ip['id']), qos[0]['externalID'])

    def _update_fip_rate_limit(self, subnet, port, floatingip_id,
                               ingress_rate_limit=None,
                               egress_rate_limit=None):
        if ingress_rate_limit is not None and egress_rate_limit is None:
            self.update_floating_ip_with_args(
                floatingip_id, '--nuage-ingress-fip-rate-kbps',
                str(ingress_rate_limit))
        if egress_rate_limit is not None and ingress_rate_limit is None:
            self.update_floating_ip_with_args(
                floatingip_id, '--nuage-egress-fip-rate-kbps',
                str(egress_rate_limit))
        if egress_rate_limit is not None and ingress_rate_limit is not None:
            self.update_floating_ip_with_args(
                floatingip_id, '--nuage-ingress-fip-rate-kbps',
                str(ingress_rate_limit), '--nuage-egress-fip-rate-kbps',
                str(ingress_rate_limit))
        updated_floating_ip = self.show_floating_ip(floatingip_id)

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, updated_floating_ip,
                                   ingress_rate_limit, egress_rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(subnet, port, updated_floating_ip,
                             ingress_rate_limit, egress_rate_limit)

    @nuage_test.header()
    def test_create_fip_without_rate_limit(self):
        self._as_admin()

        network = self.create_network()
        subnet = self.create_subnet_with_args(network['name'], '10.0.0.0/24')
        router = self.create_router()

        self.set_router_gateway_with_args(router['id'], self.ext_net_id)
        self.add_router_interface_with_args(router['id'], subnet['id'])

        port = self.create_port_with_args(network['name'])

        created_floating_ip = self.create_floating_ip_with_args(
            self.ext_net_id, '--port-id', port['id'])
        self.addCleanup(self._delete_floating_ip,
                        created_floating_ip['id'])
        show_floating_ip = self.show_floating_ip(created_floating_ip['id'])

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, show_floating_ip,
                                   self.expected_default_fip_rate,
                                   self.expected_default_fip_rate)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(
            subnet, port, created_floating_ip,
            self.expected_default_fip_rate, self.expected_default_fip_rate)

    @nuage_test.header()
    def test_create_update_fip_with_rate_limit_normal_value_ingress(self):
        #     """
        #     neutron net-create net1
        #     neutron subnet-create net1 10.0.0.0/24
        #
        #     neutron router-create router1
        #     neutron router-gateway-set router1 <thePublicNetworkID>
        #     neutron router-interface-add router1 <theSubnetID>
        #
        #     port-create net1
        #     floatingip-create public --port-id <thePortID> --nuage-fip-rate
        #         <theRateLimit>
        #     """
        self._as_admin()

        network = self.create_network()
        subnet = self.create_subnet_with_args(network['name'], '10.1.0.0/24')
        router = self.create_router()

        self.set_router_gateway_with_args(router['id'], self.ext_net_id)
        self.add_router_interface_with_args(router['id'], subnet['id'])

        port = self.create_port_with_args(network['name'])

        # Do it on ingress first
        rate_limit = 2000
        created_floating_ip = self.create_floating_ip_with_args(
            self.ext_net_id, '--port-id', port['id'],
            '--nuage-ingress-fip-rate-kbps', str(rate_limit))
        self.addCleanup(self._delete_floating_ip,
                        created_floating_ip['id'])

        show_floating_ip = self.show_floating_ip(created_floating_ip['id'])
        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, show_floating_ip,
                                   ingress_rate_limit=rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(subnet, port, created_floating_ip,
                             ingress_rate_limit=rate_limit)

        # Update value
        updated_rate_limit = 4500
        self._update_fip_rate_limit(subnet, port, created_floating_ip['id'],
                                    ingress_rate_limit=updated_rate_limit,
                                    egress_rate_limit=updated_rate_limit)

    @nuage_test.header()
    def test_create_update_fip_with_rate_limit_normal_value_egress(self):
        #     """
        #     neutron net-create net1
        #     neutron subnet-create net1 10.0.0.0/24
        #
        #     neutron router-create router1
        #     neutron router-gateway-set router1 <thePublicNetworkID>
        #     neutron router-interface-add router1 <theSubnetID>
        #
        #     port-create net1
        #     floatingip-create public --port-id <thePortID> --nuage-fip-rate
        #         <theRateLimit>
        #     """
        self._as_admin()

        network = self.create_network()
        subnet = self.create_subnet_with_args(network['name'], '10.1.0.0/24')
        router = self.create_router()

        self.set_router_gateway_with_args(router['id'], self.ext_net_id)
        self.add_router_interface_with_args(router['id'], subnet['id'])

        port = self.create_port_with_args(network['name'])

        # Do it on egress first
        rate_limit = 2000
        created_floating_ip = self.create_floating_ip_with_args(
            self.ext_net_id, '--port-id', port['id'],
            '--nuage-egress-fip-rate-kbps', str(rate_limit))
        self.addCleanup(self._delete_floating_ip,
                        created_floating_ip['id'])

        show_floating_ip = self.show_floating_ip(created_floating_ip['id'])
        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, show_floating_ip,
                                   egress_rate_limit=rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(subnet, port, created_floating_ip,
                             egress_rate_limit=rate_limit)

        # Update value
        updated_rate_limit = 4500
        self._update_fip_rate_limit(subnet, port, created_floating_ip['id'],
                                    ingress_rate_limit=updated_rate_limit,
                                    egress_rate_limit=updated_rate_limit)


class TestNuageBidiFRLCliWDefUnlimited(TestNuageBidiFRLCliWODefault):
    configured_default_fip_rate = constants.UNLIMITED
    expected_default_fip_rate = constants.UNLIMITED


class TestNuageBidiFRLCliWDef(TestNuageBidiFRLCliWODefault):
    configured_default_fip_rate = 321
    expected_default_fip_rate = configured_default_fip_rate

    @nuage_test.header()
    def test_create_fip_with_default_rate_limit_max_value(self):
        network = self.create_network()
        subnet = self.create_subnet_with_args(network['name'], '10.3.0.0/24')
        router = self.create_router()

        self.set_router_gateway_with_args(router['id'], self.ext_net_id)
        self.add_router_interface_with_args(router['id'], subnet['id'])

        port = self.create_port_with_args(network['name'])

        rate_limit = constants.MAX_INT
        created_floating_ip = self.create_floating_ip_with_args(
            self.ext_net_id, '--port-id', port['id'],
            '--nuage-ingress-fip-rate-kbps', str(rate_limit),
            '--nuage-egress-fip-rate-kbps', str(rate_limit))
        self.addCleanup(self._delete_floating_ip,
                        created_floating_ip['id'])
        show_floating_ip = self.show_floating_ip(created_floating_ip['id'])
        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, show_floating_ip, rate_limit,
                                   rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(subnet, port, created_floating_ip,
                             rate_limit, rate_limit)

    @nuage_test.header()
    def test_create_fip_with_default_rate_limit_unlimited(self):
        network = self.create_network()
        subnet = self.create_subnet_with_args(network['name'], '10.4.0.0/24')
        router = self.create_router()

        self.set_router_gateway_with_args(router['id'], self.ext_net_id)
        self.add_router_interface_with_args(router['id'], subnet['id'])

        port = self.create_port_with_args(network['name'])

        rate_limit = constants.UNLIMITED

        created_floating_ip = self.create_floating_ip_with_args(
            self.ext_net_id, '--port-id', port['id'],
            '--nuage-ingress-fip-rate-kbps', str(rate_limit),
            '--nuage-egress-fip-rate-kbps', str(rate_limit))
        self.addCleanup(self._delete_floating_ip,
                        created_floating_ip['id'])
        show_floating_ip = self.show_floating_ip(created_floating_ip['id'])
        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, show_floating_ip, rate_limit,
                                   rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(
            subnet, port, created_floating_ip, rate_limit, rate_limit)

    @nuage_test.header()
    def test_create_update_fip_rate_limit_with_keyword_default(self):
        network = self.create_network()
        subnet = self.create_subnet_with_args(network['name'], '10.5.0.0/24')
        router = self.create_router()

        self.set_router_gateway_with_args(router['id'], self.ext_net_id)
        self.add_router_interface_with_args(router['id'], subnet['id'])

        port = self.create_port_with_args(network['name'])

        # create using 'default' keyword
        ################################
        created_floating_ip = self.create_floating_ip_with_args(
            self.ext_net_id, '--port-id', port['id'],
            '--nuage-ingress-fip-rate-kbps',
            'default', '--nuage-egress-fip-rate-kbps', 'default')
        show_floating_ip = self.show_floating_ip(created_floating_ip['id'])
        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, show_floating_ip,
                                   self.expected_default_fip_rate,
                                   self.expected_default_fip_rate)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(
            subnet, port, created_floating_ip,
            self.expected_default_fip_rate, self.expected_default_fip_rate)

        # # Update to non-default value
        # ################################
        rate_limit = -1
        self._update_fip_rate_limit(subnet, port, created_floating_ip['id'],
                                    rate_limit, rate_limit)

        # # Update to non-default value
        # ################################
        rate_limit = 568
        self._update_fip_rate_limit(subnet, port, created_floating_ip['id'],
                                    rate_limit, rate_limit)

        # # Update using keyword 'default'
        # ################################
        # rate_limit = 'default'
        self.update_floating_ip_with_args(created_floating_ip['id'],
                                          '--nuage-ingress-fip-rate-kbps',
                                          'default',
                                          '--nuage-egress-fip-rate-kbps',
                                          'default')
        updated_floating_ip = self.show_floating_ip(created_floating_ip['id'])

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, updated_floating_ip,
                                   self.expected_default_fip_rate,
                                   self.expected_default_fip_rate)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(
            subnet, port, updated_floating_ip,
            self.expected_default_fip_rate, self.expected_default_fip_rate)

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_create_fip_without_a_value(self):
        network = self.create_network()
        subnet = self.create_subnet_with_args(network['name'], '10.6.0.0/24')
        router = self.create_router()

        self.set_router_gateway_with_args(router['id'], self.ext_net_id)
        self.add_router_interface_with_args(router['id'], subnet['id'])

        port = self.create_port_with_args(network['name'])

        self.assertCommandFailed(MSG_NO_INPUT,
                                 self.create_floating_ip_with_args,
                                 self.ext_net_id, '--port-id', port['id'],
                                 '--nuage-ingress-fip-rate-kbps')
