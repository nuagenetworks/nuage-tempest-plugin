# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPAddress
from netaddr import IPNetwork

from six import iteritems

from tempest.lib.common.utils import data_utils

from testtools.matchers._basic import _FlippedEquals

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils as nuage_data_utils
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

# TODO(TEAM) Make inherit from NuageBaseTest

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class BaseNuageNetworksIpv6TestCase(NuageBaseTest):
    # Default to ipv4.
    _ip_version = 4
    credentials = ['primary', 'admin']
    dhcp_agent_present = None

    @classmethod
    def setup_clients(cls):
        super(BaseNuageNetworksIpv6TestCase, cls).setup_clients()

        cls.nuage_network_client = NuageNetworkClientJSON(
            cls.manager.auth_provider,
            **cls.manager.default_params)

    def expectEqual(self, expected, observed, message=''):
        """Expect that 'expected' is equal to 'observed'.

        Nature of 'expect', opposed to Assert, is that tests don't fail
        immediately. As this is missing in BaseTestCases, added here..
        It can be useful in debugging.

        :param expected: The expected value.
        :param observed: The observed value.
        :param message: An optional message to include in the error.
        """
        matcher = _FlippedEquals(expected)
        self.expectThat(observed, matcher, message)

    def create_and_forget_port(self, network, **kwargs):
        """Wrapper utility that returns a test port."""
        body = self.ports_client.create_port(network_id=network['id'],
                                             **kwargs)
        port = body['port']
        # no cleanup !
        return port

    def _given_network_linked_to_vsd_subnet(self, vsd_subnet, cidr4=None,
                                            cidr6=None, enable_dhcp=True,
                                            net_partition=None):
        # create OpenStack IPv4 subnet on OpenStack based on VSD l3dom subnet
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        if net_partition:
            actual_net_partition = net_partition[0]['name']
        else:
            actual_net_partition = self.net_partition[0]['name']

        subnet4 = self.create_subnet(
            network,
            cidr=cidr4,
            enable_dhcp=enable_dhcp,
            mask_bits=cidr4.prefixlen,
            nuagenet=vsd_subnet.id,
            net_partition=actual_net_partition)

        # create OpenStack IPv6 subnet on OpenStack based on VSD l3dom subnet
        subnet6 = None
        if cidr6:
            subnet6 = self.create_subnet(
                network,
                ip_version=6,
                cidr=cidr6,
                mask_bits=IPNetwork(cidr6).prefixlen,
                enable_dhcp=vsd_subnet.enable_dhcpv6,
                nuagenet=vsd_subnet.id,
                net_partition=actual_net_partition)

        return network, subnet4, subnet6

    def _create_redirect_target_in_l3_subnet(self, l3subnet, name=None):
        if name is None:
            name = data_utils.rand_name('os-l3-rt')
        # parameters for nuage redirection target
        post_body = {
            'insertion_mode': 'L3',
            'redundancy_enabled': 'False',
            'subnet_id': l3subnet['id'],
            'name': name
        }
        redirect_target = self.nuage_network_client.create_redirection_target(
            **post_body)
        return redirect_target


############################################################
# VSD resources
############################################################

class BaseVSDManagedNetworksIPv6Test(BaseNuageNetworksIpv6TestCase):

    @classmethod
    def setup_clients(cls):
        super(BaseVSDManagedNetworksIPv6Test, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(BaseVSDManagedNetworksIPv6Test, cls).resource_setup()

        if Topology.is_ml2:
            # create default net_partition if it is not there
            net_partition_name = cls.nuage_client.def_netpart_name
            cls.net_partition = cls.nuage_client.get_net_partition(
                net_partition_name)
            if not cls.net_partition:
                cls.net_partition = cls.nuage_client.create_net_partition(
                    net_partition_name,
                    fip_quota=100,
                    extra_params=None)

    @classmethod
    def resource_cleanup(cls):
        super(BaseVSDManagedNetworksIPv6Test, cls).resource_cleanup()

    @classmethod
    def link_l2domain_to_shared_domain(cls, domain_id, shared_domain_id):
        update_params = {
            'associatedSharedNetworkResourceID': shared_domain_id
        }
        cls.nuage_client.update_l2domain(
            domain_id, update_params=update_params)

    def _verify_vsd_l2domain_template(self, l2domain_template,
                                      ip_type="IPV4", dhcp_managed=False,
                                      cidr4=None, cidr6=None, **kwargs):

        if dhcp_managed:
            self.assertTrue(l2domain_template.dhcp_managed)

            if ip_type == "IPV4":
                self.assertEqual("IPV4", l2domain_template.ip_type)
                self.assertIsNone(l2domain_template.ipv6_address)
                self.assertIsNone(l2domain_template.ipv6_gateway)
            elif ip_type == "IPV6":
                self.assertEqual("IPV6", l2domain_template.ip_type)
                self.assertIsNone(l2domain_template.address)
                self.assertIsNone(l2domain_template.gateway)
                self.assertIsNone(l2domain_template.netmask)
            elif ip_type == "DUALSTACK":
                self.assertEqual("DUALSTACK", l2domain_template.ip_type)
            else:
                self.assertEqual("IPV6", l2domain_template.ip_type)
                self.assertIsNone(cidr4)

            if cidr4:
                self.assertEqual(str(cidr4.ip), l2domain_template.address)

                if "netmask" not in kwargs:
                    netmask = str(cidr4.netmask)
                    self.assertEqual(netmask, l2domain_template.netmask)

                if "gateway" not in kwargs:
                    gateway_ip = str(IPAddress(cidr4) + 1)
                    if l2domain_template.enable_dhcpv4:
                        self.assertEqual(gateway_ip, l2domain_template.gateway)
                    else:
                        self.assertIsNone(l2domain_template.gateway)

            else:
                self.assertIsNone(l2domain_template.address)
                self.assertIsNone(l2domain_template.gateway)
                self.assertIsNone(l2domain_template.netmask)

            if cidr6:
                self.assertEqual(str(cidr6), l2domain_template.ipv6_address)
                if not kwargs.get('ipv6_gateway'):
                    if kwargs.get('enable_dhcpv6'):
                        gateway_ip = str(IPAddress(cidr6) + 1)
                        self.assertEqual(gateway_ip,
                                         l2domain_template.ipv6_gateway)
                    else:
                        self.assertIsNone(l2domain_template.ipv6_gateway)
        else:
            self.assertFalse(l2domain_template.dhcp_managed)

        # verify all other kwargs as attributes (key,value) pairs
        for key, value in iteritems(kwargs):
            self.assertEqual(value, getattr(l2domain_template, key))

        self.assertIsNone(l2domain_template.external_id)

    def _verify_vsd_l2domain_with_template(self, l2domain, l2domain_template):

        self.assertEqual(l2domain_template.id, l2domain.template_id)
        self.assertIsNone(l2domain_template.external_id)

        # matching values
        matching_attributes = ('ip_type', 'address', 'gateway', 'netmask',
                               'ipv6_address', 'ipv6_gateway')
        for matching_attribute in matching_attributes:
            self.assertEqual(getattr(l2domain_template, matching_attribute),
                             getattr(l2domain, matching_attribute))

    def _given_vsd_l2domain(self, cidr4=None, cidr6=None, dhcp_managed=False,
                            verify_l2domain=True, return_template=False,
                            **kwargs):
        if cidr4 and cidr6:
            ip_type = "DUALSTACK"
        elif cidr6:
            ip_type = "IPV6"
        else:
            ip_type = "IPV4"
        vsd_l2domain_template = self.vsd_create_l2domain_template(
            ip_type=ip_type, dhcp_managed=dhcp_managed,
            cidr4=cidr4,
            cidr6=cidr6,
            **kwargs)

        vsd_l2domain = self.vsd_create_l2domain(template=vsd_l2domain_template)

        if verify_l2domain:
            self._verify_vsd_l2domain_with_template(vsd_l2domain,
                                                    vsd_l2domain_template)

        if return_template:
            return vsd_l2domain_template, vsd_l2domain
        else:
            return vsd_l2domain

    def _given_vsd_l3subnet(self, cidr4=None, cidr6=None,
                            enable_dhcpv4=True, enable_dhcpv6=False):
        name = data_utils.rand_name('l3domain-')
        vsd_l3domain_template = self.vsd_create_l3domain_template(
            name=name)
        vsd_l3domain = self.vsd_create_l3domain(
            name=name, template_id=vsd_l3domain_template.id)

        self.assertEqual(vsd_l3domain.name, name)
        zone_name = data_utils.rand_name('zone-')
        vsd_zone = self.vsd_create_zone(name=zone_name,
                                        domain=vsd_l3domain)

        subnet_name = data_utils.rand_name('l3domain-subnet-')

        if cidr6:
            # ip_type = "DUALSTACK"
            vsd_l3domain_subnet = self.create_vsd_subnet(
                name=subnet_name,
                zone=vsd_zone,
                ip_type="DUALSTACK",
                cidr4=cidr4,
                gateway4=str(IPAddress(cidr4) + 1),
                enable_dhcpv4=enable_dhcpv4,
                cidr6=cidr6,
                gateway6=str(IPAddress(cidr6) + 1),
                enable_dhcpv6=enable_dhcpv6)
        else:
            # ip_type = "IPV4"
            raise NotImplementedError

        return vsd_l3domain, vsd_l3domain_subnet

    def _create_vsd_floatingip_pool(self):
        name = data_utils.rand_name('fip-pool')
        fip_pool_cidr = nuage_data_utils.gimme_a_cidr()
        address = IPAddress(fip_pool_cidr.first)
        netmask = fip_pool_cidr.netmask
        gateway = address + 1
        extra_params = {
            "underlay": True
        }

        vsd_fip_pool = self.nuage_client.create_floatingip_pool(
            name=name,
            address=str(address),
            gateway=str(gateway),
            netmask=str(netmask),
            extra_params=extra_params)

        self.addCleanup(self.nuage_client.delete_vsd_shared_resource,
                        vsd_fip_pool[0]['ID'])

        return vsd_fip_pool[0]

    def _disassociate_fip_from_port(self, port):
        kwargs = {"nuage_floatingip": None}
        self.update_port(port, **kwargs)

    @staticmethod
    def _check_fip_in_list(claimed_fip_id, fip_list):
        fip_found = False
        for fip in fip_list['nuage_floatingips']:
            if fip['id'] == claimed_fip_id:
                fip_found = True
                break
        return fip_found

    def _check_fip_in_port_show(self, port_id, claimed_fip_id):
        fip_found = False
        show_port = self.ports_client.show_port(port_id)
        # first check if 'nuage_floatingip' is not None
        if show_port['port']['nuage_floatingip'] is not None:
            if show_port['port']['nuage_floatingip']['id'] == claimed_fip_id:
                fip_found = True
        return fip_found
