# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

import json
from oslo_log import log as logging

from tempest.common import utils
from tempest import config
from tempest.test import decorators

from nuage_tempest.lib.remote_cli import remote_cli_base_testcase
from nuage_tempest.lib import service_mgmt
from nuage_tempest.lib.test import nuage_test
from nuage_tempest.lib.topology import Topology
from nuage_tempest.lib.utils import constants
import nuage_tempest.services.nuage_client as nuage_client

CONF = config.CONF

MSG_INVALID_INPUT = "Invalid input for nuage_fip_rate. " \
                    "Reason: \'nuage_fip_rate\' " + \
                    "should be a number higher than 0, -1 for unlimited " + \
                    "or \'default\' for the configured default value.."

MSG_INVALID_INPUT_FOR_OPERATION = "Invalid input for operation: " \
                                  "'nuage_fip_rate' should be a number " \
                                  "higher than 0, " \
                                  "-1 for unlimited or 'default' for the " \
                                  "configured default value.."


def openstack_to_vsd(value):
    """openstack_to_vsd

    Converts an OpenStack value to the associated VSD value.
     :param value: the OpenStack value
     :type value: integer
     """
    if value == constants.UNLIMITED:
        vsd_value = "INFINITY"
    else:
        vsd_value = str(value)
    return vsd_value


# TODO(waelj) don't want to have a dedicated parent class for CLI
class TestNuageFipRateLimitCliWithoutDefault(
        remote_cli_base_testcase.RemoteCliBaseTestCase):

    """FipRateLimit tests using Neutron CLI client.

    """
    LOG = logging.getLogger(__name__)
    configured_default_fip_rate = None
    expected_default_fip_rate = constants.UNLIMITED

    @classmethod
    def skip_checks(cls):
        super(TestNuageFipRateLimitCliWithoutDefault, cls).skip_checks()
        if not CONF.service_available.neutron:
            msg = "Skipping all Neutron cli tests because it is not available"
            raise cls.skipException(msg)

        if not utils.is_extension_enabled('nuage-floatingip', 'network'):
            msg = "Extension nuage_floatingip not enabled."
            raise cls.skipException(msg)

        if Topology.is_devstack():
            msg = 'Skipping tests that restart neutron ...'
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(TestNuageFipRateLimitCliWithoutDefault, cls).setup_clients()
        cls.nuage_vsd_client = nuage_client.NuageRestClient()

        cls.service_manager = service_mgmt.ServiceManager()
        cls.service_manager.must_have_configuration_attribute(
            CONF.nuage_sut.nuage_plugin_configuration,
            constants.FIP_RATE_GROUP, constants.FIP_RATE_DEFAULT,
            cls.configured_default_fip_rate)

    @classmethod
    def resource_setup(cls):

        super(TestNuageFipRateLimitCliWithoutDefault, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id

    def _verify_fip_openstack(self, port, created_floating_ip,
                              default_rate_limit):
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
        # self.assertIn(created_floating_ip['fixed_ip_address'],
        # [ip['ip_address'] for ip in ip_address)]

        self.LOG.info("FIP Rate limit %s",
                      created_floating_ip['nuage_fip_rate'])

        self.assertEqual(created_floating_ip['nuage_fip_rate'],
                         str(default_rate_limit))

    def _verify_fip_vsd(self, subnet, port, created_floating_ip,
                        default_rate_limit):
        # verifying on Domain level that the floating ip is added
        external_id = self.nuage_vsd_client.get_vsd_external_id(
            created_floating_ip['router_id'])
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID',
            filter_value=external_id)
        nuage_domain_fip = self.nuage_vsd_client.get_floatingip(
            constants.DOMAIN, nuage_domain[0]['ID'])

        # The VSD FIP has same IP address than OpenStack FIP
        self.assertEqual(
            nuage_domain_fip[0]['address'],
            created_floating_ip['floating_ip_address'])

        # The VSD externalID for FIP matches the OpenStack ID
        external_id = self.nuage_vsd_client.get_vsd_external_id(
            created_floating_ip['id'])
        self.assertEqual(
            nuage_domain_fip[0]['externalID'],
            external_id)

        # Check vsd
        vsd_subnets = self.nuage_vsd_client.get_domain_subnet(
            None, None, 'externalID',
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

        self.LOG.info("FIP Rate limit %s", qos[0]['FIPPeakInformationRate'])
        self.assertEqual(default_rate_limit, qos[0]['FIPPeakInformationRate'])

    def _get_attr(self, dictionary, key):
        return dictionary[key]

    def _update_fip_rate_limit(self, subnet, port, floatingip_id,
                               new_fip_rate):
        self.update_floating_ip_with_args(floatingip_id, '--nuage-fip-rate',
                                          str(new_fip_rate))
        updated_floating_ip = self.show_floating_ip(floatingip_id)

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, updated_floating_ip, new_fip_rate)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(subnet, port, updated_floating_ip,
                             openstack_to_vsd(new_fip_rate))

    @nuage_test.header()
    def test_create_fip_without_rate_limit(self):
        self._as_admin()

        network = self.create_network()
        subnet = self.create_subnet_with_args(network['name'], ' 10.0.0.0/24')
        router = self.create_router()

        self.set_router_gateway_with_args(router['id'], self.ext_net_id)
        self.add_router_interface_with_args(router['id'], subnet['id'])

        port = self.create_port_with_args(network['name'])

        created_floating_ip = self.create_floating_ip_with_args(
            self.ext_net_id, '--port-id', port['id'])
        self.addCleanup(self._delete_floating_ip,
                        created_floating_ip['id'])

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, created_floating_ip,
                                   self.expected_default_fip_rate)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(port, created_floating_ip,
                             openstack_to_vsd(self.expected_default_fip_rate))

    @nuage_test.header()
    def test_create_update_fip_with_rate_limit_normal_value(self):
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
        #          <theRateLimit>
        #     """
        self._as_admin()

        network = self.create_network()
        subnet = self.create_subnet_with_args(network['name'], '10.1.0.0/24')
        router = self.create_router()

        self.set_router_gateway_with_args(router['id'], self.ext_net_id)
        self.add_router_interface_with_args(router['id'], subnet['id'])

        port = self.create_port_with_args(network['name'])

        rate_limit = 67
        created_floating_ip = self.create_floating_ip_with_args(
            self.ext_net_id, '--port-id', port['id'],
            '--nuage-fip-rate', str(rate_limit))
        self.addCleanup(self._delete_floating_ip,
                        created_floating_ip['id'])

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, created_floating_ip, rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(subnet, port, created_floating_ip,
                             str(rate_limit))

        # Update value
        updated_rate_limit = 856
        self._update_fip_rate_limit(subnet, port, created_floating_ip['id'],
                                    updated_rate_limit)


class TestNuageFipRateLimitCliWithDefaultUnlimited(
        TestNuageFipRateLimitCliWithoutDefault):

    configured_default_fip_rate = constants.UNLIMITED
    expected_default_fip_rate = constants.UNLIMITED


class TestNuageFipRateLimitCliWithDefault(
        TestNuageFipRateLimitCliWithoutDefault):

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
            '--nuage-fip-rate', str(rate_limit))
        self.addCleanup(self._delete_floating_ip,
                        created_floating_ip['id'])

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, created_floating_ip, rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(subnet, port, created_floating_ip,
                             str(rate_limit))

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
            '--nuage-fip-rate', str(rate_limit))
        self.addCleanup(self._delete_floating_ip,
                        created_floating_ip['id'])

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, created_floating_ip, rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(subnet, port, created_floating_ip, "INFINITY")

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
            '--nuage-fip-rate', 'default')

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, created_floating_ip,
                                   self.expected_default_fip_rate)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(subnet, port, created_floating_ip,
                             openstack_to_vsd(self.expected_default_fip_rate))

        # # Update to non-default value
        # ################################
        rate_limit = -1
        self._update_fip_rate_limit(subnet, port, created_floating_ip['id'],
                                    rate_limit)

        # # Update to non-default value
        # ################################
        rate_limit = 568
        self._update_fip_rate_limit(subnet, port, created_floating_ip['id'],
                                    rate_limit)

        # # Update using keyword 'default'
        # ################################
        rate_limit = 'default'
        self.update_floating_ip_with_args(
            created_floating_ip['id'], '--nuage-fip-rate', str(rate_limit))
        updated_floating_ip = self.show_floating_ip(created_floating_ip['id'])

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, updated_floating_ip,
                                   self.expected_default_fip_rate)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(subnet, port, updated_floating_ip,
                             openstack_to_vsd(self.expected_default_fip_rate))

    @nuage_test.header()
    @decorators.attr(type=['negative'])
    def test_create_fip_without_a_value(self):
        network = self.create_network()
        subnet = self.create_subnet_with_args(network['name'], '10.6.0.0/24')
        router = self.create_router()

        self.set_router_gateway_with_args(router['id'], self.ext_net_id)
        self.add_router_interface_with_args(router['id'], subnet['id'])

        port = self.create_port_with_args(network['name'])

        self.assertCommandFailed(MSG_INVALID_INPUT,
                                 self.create_floating_ip_with_args,
                                 self.ext_net_id, '--port-id', port['id'],
                                 '--nuage-fip-rate')
