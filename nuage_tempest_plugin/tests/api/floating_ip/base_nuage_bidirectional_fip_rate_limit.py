# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from tempest.api.network import base
from tempest.common import utils
from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.services import nuage_client

CONF = Topology.get_conf()


class NuageBidirectionalFipRateLimitBase(base.BaseNetworkTest):
    _interface = 'json'

    """
    v2.0 of the Neutron API is assumed. It is also assumed that the following
    options are defined in the [network] section of etc/tempest.conf:

        public_network_id which is the id for the external network present
    """

    @classmethod
    def setup_clients(cls):
        super(NuageBidirectionalFipRateLimitBase, cls).setup_clients()
        cls.nuage_client = nuage_client.NuageRestClient()

    @classmethod
    def create_port(cls, network, **kwargs):
        if CONF.network.port_vnic_type and 'binding:vnic_type' not in kwargs:
            kwargs['binding:vnic_type'] = CONF.network.port_vnic_type
        if CONF.network.port_profile and 'binding:profile' not in kwargs:
            kwargs['binding:profile'] = CONF.network.port_profile
        return super(
            NuageBidirectionalFipRateLimitBase, cls).create_port(network,
                                                                 **kwargs)

    @classmethod
    def resource_setup(cls):
        super(NuageBidirectionalFipRateLimitBase, cls).resource_setup()
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
        cls.ports = []

        # Create two ports one each for Creation and Updating of floatingIP
        kwargs = {}
        if CONF.network.port_vnic_type and 'binding:vnic_type' not in kwargs:
            kwargs['binding:vnic_type'] = CONF.network.port_vnic_type
        if CONF.network.port_profile and 'binding:profile' not in kwargs:
            kwargs['binding:profile'] = CONF.network.port_profile

        for i in range(2):
            port = cls.create_port(cls.network, **kwargs)
            cls.ports.append(port)

    @staticmethod
    def convert_mbps_to_kbps(value):
        if value == 'INFINITY':
            return value
        else:
            return float(value) * 1000

    def assertEqualFiprate(self, os_fip_rate, expected_fip_rate):
        if expected_fip_rate == 'INFINITY':
            if os_fip_rate == 'INFINITY':  # this is conceptually not ok
                # but it seems some tests pass it on that way
                return True  # we are good
            else:
                self.assertEqual(-1, float(os_fip_rate))
        else:
            self.assertEqual(float(expected_fip_rate), float(os_fip_rate))

    @classmethod
    def _create_fip_for_port_with_rate_limit(cls, port_id,
                                             ingress_rate_limit=None,
                                             egress_rate_limit=None):
        rate_limit_dict = {}
        if ingress_rate_limit is not None:
            rate_limit_dict['nuage_ingress_fip_rate_kbps'] = ingress_rate_limit
        if egress_rate_limit is not None:
            rate_limit_dict['nuage_egress_fip_rate_kbps'] = egress_rate_limit
        body = cls.floating_ips_client.create_floatingip(
            floating_network_id=cls.ext_net_id,
            port_id=port_id, **rate_limit_dict)

        created_floating_ip = body['floatingip']

        return created_floating_ip

    def _do_create_fip_for_port_with_rate_limit(self, port_id,
                                                ingress_rate_limit=None,
                                                egress_rate_limit=None):
        rate_limit_dict = {}
        if ingress_rate_limit is not None:
            rate_limit_dict['nuage_ingress_fip_rate_kbps'] = ingress_rate_limit
        if egress_rate_limit is not None:
            rate_limit_dict['nuage_egress_fip_rate_kbps'] = egress_rate_limit

        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=port_id, **rate_limit_dict)

        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        return created_floating_ip

    def _do_create_fip_for_port_with_rate_limit_backward(self, port_id,
                                                         rate_limit=None):
        rate_limit_dict = {}
        if rate_limit is not None:
            rate_limit_dict['nuage_fip_rate'] = rate_limit

        body = self.floating_ips_client.create_floatingip(
            floating_network_id=self.ext_net_id,
            port_id=port_id, **rate_limit_dict)

        created_floating_ip = body['floatingip']
        self.addCleanup(self.floating_ips_client.delete_floatingip,
                        created_floating_ip['id'])
        return created_floating_ip

    def _do_update_fip_to_rate_limit(self, floating_ip_id,
                                     ingress_rate_limit=None,
                                     egress_rate_limit=None):
        rate_limit_dict = {}
        if ingress_rate_limit is not None:
            rate_limit_dict['nuage_ingress_fip_rate_kbps'] = ingress_rate_limit
        if egress_rate_limit is not None:
            rate_limit_dict['nuage_egress_fip_rate_kbps'] = egress_rate_limit
        body = self.floating_ips_client.update_floatingip(
            floating_ip_id, **rate_limit_dict)

        updated_floating_ip = body['floatingip']
        return updated_floating_ip

    def _do_get_floating_ip(self, floating_ip_id):
        body = self.floating_ips_client.show_floatingip(
            floating_ip_id)

        floating_ip = body['floatingip']
        return floating_ip

    def _verify_fip_openstack(self, port, created_floating_ip,
                              ingress_rate_limit=None,
                              egress_rate_limit=None):
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
        if ingress_rate_limit is not None:
            self.assertEqualFiprate(
                created_floating_ip['nuage_ingress_fip_rate_kbps'],
                ingress_rate_limit)
        if egress_rate_limit is not None:
            self.assertEqualFiprate(
                created_floating_ip['nuage_egress_fip_rate_kbps'],
                egress_rate_limit)
        elif egress_rate_limit is not None:
            self.assertEqualFiprate(
                created_floating_ip['nuage_egress_fip_rate_kbps'],
                egress_rate_limit * 1000)

    def _verify_fip_vsd(self, port, created_floating_ip,
                        ingress_rate_limit=None, egress_rate_limit=None):
        # verifying on Domain level that the floating ip is added
        external_id = self.nuage_client.get_vsd_external_id(
            created_floating_ip['router_id'])
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID',
            filter_values=external_id)
        nuage_domain_fips = self.nuage_client.get_floatingip(
            constants.DOMAIN, nuage_domain[0]['ID'])
        # The VSD FIP has same IP address than OpenStack FIP
        self.assertIn(created_floating_ip['floating_ip_address'],
                      [fip['address'] for fip in nuage_domain_fips])

        # The VSD externalID for FIP matches the OpenStack ID
        external_id = self.nuage_client.get_vsd_external_id(
            created_floating_ip['id'])
        self.assertIn(external_id,
                      [nuage_fip['externalID'] for nuage_fip
                       in nuage_domain_fips])

        # Check vsd
        vsd_subnets = self.nuage_client.get_domain_subnet(
            None, None, by_subnet=self.subnet)
        self.assertEqual(1, len(vsd_subnets))
        vports = self.nuage_client.get_vport(
            constants.SUBNETWORK,
            vsd_subnets[0]['ID'],
            'externalID',
            self.nuage_client.get_vsd_external_id(port['id']))
        self.assertEqual(1, len(vports))
        qos = self.nuage_client.get_qos(constants.VPORT, vports[0]['ID'])

        if Topology.from_nuage('20.10'):
            self.assertEqual(0, len(qos))
            nuage_fip = [fip for fip in nuage_domain_fips
                         if fip['externalID'] == external_id][0]
            associated_ingress_rate_limit = nuage_fip.get(
                'ingressRateLimiterID')
            associated_egress_rate_limit = nuage_fip.get('egressRateLimiterID')
            if ingress_rate_limit is not None:
                # Get Ratelimiter
                external_id = 'egress_{}'.format(created_floating_ip['id'])
                ratelimiter = self.nuage_client.get_ratelimiter(external_id)
                if ingress_rate_limit == constants.UNLIMITED:
                    self.assertIsNone(ratelimiter)
                    self.assertIsNone(associated_egress_rate_limit)
                else:
                    self.assertEqualFiprate(
                        ingress_rate_limit,
                        self.convert_mbps_to_kbps(
                            ratelimiter['peakInformationRate']))
                    self.assertEqual(associated_egress_rate_limit,
                                     ratelimiter['ID'])
            if egress_rate_limit is not None:
                external_id = 'ingress_{}'.format(created_floating_ip['id'])
                ratelimiter = self.nuage_client.get_ratelimiter(external_id)
                if egress_rate_limit == constants.UNLIMITED:
                    self.assertIsNone(ratelimiter)
                    self.assertIsNone(associated_ingress_rate_limit)
                else:
                    self.assertEqualFiprate(
                        egress_rate_limit,
                        self.convert_mbps_to_kbps(
                            ratelimiter['peakInformationRate']))
                    self.assertEqual(associated_ingress_rate_limit,
                                     ratelimiter['ID'])

        else:
            self.assertEqual(1, len(qos))
            self.assertEqual(True, qos[0]['FIPRateLimitingActive'])
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
            self.assertEqual(self.nuage_client.get_vsd_external_id(
                created_floating_ip['id']), qos[0]['externalID'])

    def _create_fip_with_fip_rate_limit(self, port, ingress_rate_limit=None,
                                        egress_rate_limit=None):
        # When I create a fip with default rate limit

        created_floating_ip = self._do_create_fip_for_port_with_rate_limit(
            port['id'], ingress_rate_limit, egress_rate_limit)

        show_floating_ip = self._do_get_floating_ip(created_floating_ip['id'])
        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, show_floating_ip, ingress_rate_limit,
                                   egress_rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(port, created_floating_ip, ingress_rate_limit,
                             egress_rate_limit)

        return created_floating_ip

    def _update_fip_with_fip_rate_limit(self, port, floating_ip,
                                        ingress_rate_limit=None,
                                        egress_rate_limit=None):
        # When I create a fip with default rate limit
        updated_floating_ip = self._do_update_fip_to_rate_limit(
            floating_ip['id'], ingress_rate_limit, egress_rate_limit)

        show_floating_ip = self._do_get_floating_ip(updated_floating_ip['id'])
        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, show_floating_ip, ingress_rate_limit,
                                   egress_rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(port, updated_floating_ip,
                             ingress_rate_limit, egress_rate_limit)

        return updated_floating_ip

    def _show_fip_with_fip_rate_limit(self, port, floating_ip,
                                      ingress_rate_limit=None,
                                      egress_rate_limit=None):
        # When I create a fip with default rate limit
        floating_ip = self._do_get_floating_ip(floating_ip['id'])

        # Then I got a valid OpenStack FIP with the default rate limit
        self._verify_fip_openstack(port, floating_ip,
                                   ingress_rate_limit, egress_rate_limit)

        # Then I got a valid VSD FIP with the default rate limit
        self._verify_fip_vsd(port, floating_ip, ingress_rate_limit,
                             egress_rate_limit)

        return floating_ip
