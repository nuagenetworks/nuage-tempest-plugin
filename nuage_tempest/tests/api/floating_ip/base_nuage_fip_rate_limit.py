# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from oslo_log import log as logging

from tempest.api.network import base
from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils

from nuage_tempest.lib.utils import constants
from nuage_tempest.services import nuage_client

CONF = config.CONF


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


class NuageFipRateLimitBase(base.BaseNetworkTest):
    _interface = 'json'

    """
    v2.0 of the Neutron API is assumed. It is also assumed that the following
    options are defined in the [network] section of etc/tempest.conf:

        public_network_id which is the id for the external network present
    """

    LOG = logging.getLogger(__name__)

    @classmethod
    def setup_clients(cls):
        super(NuageFipRateLimitBase, cls).setup_clients()
        cls.nuage_vsd_client = nuage_client.NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(NuageFipRateLimitBase, cls).resource_setup()
        if not utils.is_extension_enabled('router', 'network'):
            msg = "router extension not enabled."
            raise cls.skipException(msg)

        if not utils.is_extension_enabled('nuage-floatingip', 'network'):
            msg = "Extension nuage_floatingip not enabled."
            raise cls.skipException(msg)

        cls.ext_net_id = CONF.network.public_network_id

        # Create network, subnet, router and add interface
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.router = cls.create_router(data_utils.rand_name('router-'),
                                       external_network_id=cls.ext_net_id)

        cls.create_router_interface(cls.router['id'], cls.subnet['id'])
        cls.port = list()

        # Create two ports one each for Creation and Updating of floatingIP
        for i in range(2):
            cls.create_port(cls.network)

    @classmethod
    def _create_fip_for_port_with_rate_limit(cls, port_id, rate_limit):
        body = cls.floating_ips_client.create_floatingip(
            floating_network_id=cls.ext_net_id,
            port_id=port_id,
            nuage_fip_rate=rate_limit)

        created_floating_ip = body['floatingip']
        cls.floating_ips.append(created_floating_ip)

        return created_floating_ip

    def _do_create_fip_for_port_with_rate_limit(self, port_id, rate_limit):
        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=port_id,
            nuage_fip_rate=rate_limit)

        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        return created_floating_ip

    def _do_update_fip_to_rate_limit(self, floating_ip_id, rate_limit):
        body = self.floating_ips_client.update_floatingip(
            floating_ip_id,
            nuage_fip_rate=rate_limit)

        updated_floating_ip = body['floatingip']
        return updated_floating_ip

    def _do_get_floating_ip(self, floating_ip_id):
        body = self.floating_ips_client.show_floatingip(
            floating_ip_id)

        floating_ip = body['floatingip']
        return floating_ip

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
        self.assertIn(created_floating_ip['fixed_ip_address'],
                      [ip['ip_address'] for ip in port['fixed_ips']])

        self.LOG.info("FIP Rate limit %s",
                      created_floating_ip['nuage_egress_fip_rate_kbps'])

        cmp_with = str(float(default_rate_limit * 1000)
                       ) if default_rate_limit != -1 else "-1.0"
        self.assertEqual(str(
            float(created_floating_ip['nuage_egress_fip_rate_kbps'])),
            cmp_with)

    def _verify_fip_vsd(self, port, created_floating_ip, default_rate_limit):
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
                      [nuage_fip['address'] for nuage_fip in nuage_domain_fip])

        # The VSD externalID for FIP matches the OpenStack ID
        external_id = self.nuage_vsd_client.get_vsd_external_id(
            created_floating_ip['id'])
        self.assertIn(external_id,
                      [nuage_fip['externalID'] for nuage_fip
                       in nuage_domain_fip])
        # Check vsd
        vsd_subnets = self.nuage_vsd_client.get_domain_subnet(
            None, None, 'externalID',
            self.nuage_vsd_client.get_vsd_external_id(self.subnet['id']))
        self.assertEqual(1, len(vsd_subnets))
        vports = self.nuage_vsd_client.get_vport(
            constants.SUBNETWORK, vsd_subnets[0]['ID'], 'externalID',
            self.nuage_vsd_client.get_vsd_external_id(port['id']))
        self.assertEqual(1, len(vports))
        qos = self.nuage_vsd_client.get_qos(constants.VPORT, vports[0]['ID'])
        self.assertEqual(1, len(qos))
        self.assertEqual(True, qos[0]['FIPRateLimitingActive'])

        self.LOG.info("FIP Rate limit %s", qos[0]['FIPPeakInformationRate'])
        self.assertEqual(default_rate_limit, qos[0]['FIPPeakInformationRate'])
        self.assertEqual(self.nuage_vsd_client.get_vsd_external_id(
            created_floating_ip['id']), qos[0]['externalID'])

    def _create_fip_with_fip_rate_limit(self, port, fip_rate_limit):
        # When I create a fip with default rate limit
        created_floating_ip = self._do_create_fip_for_port_with_rate_limit(
            port['id'], fip_rate_limit)

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, created_floating_ip, fip_rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(port, created_floating_ip,
                             openstack_to_vsd(fip_rate_limit))

        return created_floating_ip

    def _update_fip_with_fip_rate_limit(self, port, floating_ip,
                                        fip_rate_limit):
        # When I create a fip with default rate limit
        updated_floating_ip = self._do_update_fip_to_rate_limit(
            floating_ip['id'], fip_rate_limit)

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, updated_floating_ip, fip_rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(port, updated_floating_ip,
                             openstack_to_vsd(fip_rate_limit))

        return updated_floating_ip

    def _show_fip_with_fip_rate_limit(self, port, floating_ip, fip_rate_limit):
        # When I create a fip with default rate limit
        floating_ip = self._do_get_floating_ip(floating_ip['id'])

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, floating_ip, fip_rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(port, floating_ip,
                             openstack_to_vsd(fip_rate_limit))

        return floating_ip
