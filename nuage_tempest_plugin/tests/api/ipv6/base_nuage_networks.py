# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPAddress
from netaddr import IPNetwork
from netaddr import IPRange

import random

from tempest import exceptions
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest import test

from testtools.matchers import ContainsDict
from testtools.matchers import Equals

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as nuage_constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

# TODO(TEAM) - make inherit from NuageBaseTest ?


class BaseNuageNetworksTestCase(test.BaseTestCase):
    # Default to ipv4.
    _ip_version = 4

    @classmethod
    def setup_clients(cls):
        super(BaseNuageNetworksTestCase, cls).setup_clients()
        client_manager = cls.get_client_manager()

        cls.networks_client = client_manager.networks_client
        cls.subnets_client = client_manager.subnets_client
        cls.ports_client = client_manager.ports_client

        cls.nuage_network_client = NuageNetworkClientJSON(
            client_manager.auth_provider,
            **client_manager.default_params)

    @classmethod
    def resource_setup(cls):
        NuageBaseTest.setup_network_resources(cls)


############################################################
# VSD resources
############################################################

class VsdTestCaseMixin(test.BaseTestCase):
    VSD_FIP_POOL_CIDR_BASE = '130.%s.%s.0/24'

    @classmethod
    def setup_clients(cls):
        super(VsdTestCaseMixin, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(VsdTestCaseMixin, cls).resource_setup()

        if Topology.is_ml2:
            # create default net_partition if it is not there
            net_partition_name = cls.nuage_vsd_client.def_netpart_name
            cls.net_partition = cls.nuage_vsd_client.get_net_partition(
                net_partition_name)
            if not cls.net_partition:
                cls.net_partition = cls.nuage_vsd_client.create_net_partition(
                    net_partition_name,
                    fip_quota=100,
                    extra_params=None)

    @classmethod
    def resource_cleanup(cls):
        super(VsdTestCaseMixin, cls).resource_cleanup()

    @classmethod
    def link_l2domain_to_shared_domain(cls, domain_id, shared_domain_id):
        update_params = {
            'associatedSharedNetworkResourceID': shared_domain_id
        }
        cls.nuage_vsd_client.update_l2domain(
            domain_id, update_params=update_params)

    def create_vsd_l2domain_template(self, name=None, ip_type=None,
                                     dhcp_managed=None,
                                     cidr4=None, cidr6=None, **kwargs):
        params = {}
        if ip_type == "IPV4":
            params.update({'IPType': "IPV4"})
        elif ip_type == "IPV6":
            params.update({'IPType': "IPV6"})
        elif ip_type == "DUALSTACK":
            params.update({'IPType': "DUALSTACK"})

        if cidr4:
            params.update({'address': str(cidr4.ip)})

            if "netmask" in kwargs:
                netmask = kwargs['netmask']
            else:
                netmask = str(cidr4.netmask)
            params.update({'netmask': netmask})

            if "gateway" in kwargs:
                gateway_ip = kwargs['gateway']
            else:
                gateway_ip = str(IPAddress(cidr4) + 1)
            params.update({'gateway': gateway_ip})

        if cidr6:
            params.update({'IPv6Address': str(cidr6)})

            if "netmask6" in kwargs:
                netmask6 = kwargs['netmask6']
            else:
                netmask6 = str(cidr6.netmask)
            params.update({'netmask6': netmask6})

            if "gateway6" in kwargs:
                gateway6_ip = kwargs['gateway6']
                kwargs.pop('gateway6')
            else:
                gateway6_ip = str(IPAddress(cidr6) + 1)
            params.update({'IPv6Gateway': gateway6_ip})

        if dhcp_managed:
            params.update({'DHCPManaged': dhcp_managed})

        if name is None:
            name = data_utils.rand_name('l2domain-template')

        # add all other kwargs as attributes (key,value) pairs
        for key, value in kwargs.iteritems():
            params.update({key: value})

        body = self.nuage_vsd_client.create_l2domaintemplate(
            name, extra_params=params)
        vsd_l2dom_template = body[0]

        self.addCleanup(
            self.nuage_vsd_client.delete_l2domaintemplate,
            vsd_l2dom_template['ID'])
        return vsd_l2dom_template

    def _verify_vsd_l2domain_template(self, l2domain_template,
                                      ip_type="IPV4", dhcp_managed=False,
                                      cidr4=None, cidr6=None, **kwargs):

        if dhcp_managed:
            self.assertThat(l2domain_template,
                            ContainsDict({'DHCPManaged': Equals(True)}))

            if ip_type == "IPV4":
                self.assertThat(l2domain_template,
                                ContainsDict({'IPType': Equals("IPV4")}))
                self.assertIsNone(l2domain_template['IPv6Address'])
                self.assertIsNone(l2domain_template['IPv6Gateway'])
            elif ip_type == "DUALSTACK":
                self.assertThat(l2domain_template,
                                ContainsDict({'IPType': Equals("DUALSTACK")}))
            else:
                self.fail('Invalid ip_type')

            if cidr4:
                self.assertThat(l2domain_template,
                                ContainsDict({'address':
                                              Equals(str(cidr4.ip))}))
                if "netmask" not in kwargs:
                    netmask = str(cidr4.netmask)
                    self.assertThat(l2domain_template,
                                    ContainsDict({'netmask':
                                                  Equals(netmask)}))

                if "gateway" not in kwargs:
                    gateway_ip = str(IPAddress(cidr4) + 1)
                    self.assertThat(l2domain_template,
                                    ContainsDict({'gateway':
                                                  Equals(gateway_ip)}))
            else:
                self.assertIsNone(l2domain_template['address'])
                self.assertIsNone(l2domain_template['gateway'])
                self.assertIsNone(l2domain_template['netmask'])

            if cidr6:
                self.assertThat(l2domain_template,
                                ContainsDict({'IPv6Address':
                                              Equals(str(cidr6))}))
                if "IPv6Gateway" not in kwargs:
                    gateway_ip = str(IPAddress(cidr6) + 1)
                    self.assertThat(l2domain_template,
                                    ContainsDict({'IPv6Gateway':
                                                  Equals(gateway_ip)}))
        else:
            self.assertThat(l2domain_template,
                            ContainsDict({'DHCPManaged': Equals(False)}))

        # verify all other kwargs as attributes (key,value) pairs
        for key, value in kwargs.iteritems():
            self.assertThat(l2domain_template,
                            ContainsDict({key: Equals(value)}))

        self.assertIsNone(l2domain_template['externalID'])

    def _verify_vsd_l2domain_with_template(self, l2domain, l2domain_template):

        self.assertThat(l2domain,
                        ContainsDict({'templateID':
                                      Equals(l2domain_template['ID'])}))
        self.assertIsNone(l2domain_template['externalID'])

        # matching values
        matching_attributes = ('IPType', 'address', 'gateway', 'netmask',
                               'IPv6Address', 'IPv6Gateway')
        for matching_attribute in matching_attributes:
            self.assertThat(l2domain,
                            ContainsDict({matching_attribute:
                                          Equals(l2domain_template[
                                              matching_attribute])}))

    def create_vsd_l2domain(self, template_id, name=None, **kwargs):
        if name is None:
            name = data_utils.rand_name('l2domain-')

        extra_params = kwargs.get('extra_params')
        vsd_l2domains = self.nuage_vsd_client.create_l2domain(
            name,
            templateId=template_id,
            extra_params=extra_params)
        vsd_l2domain = vsd_l2domains[0]
        self.addCleanup(
            self.nuage_vsd_client.delete_l2domain, vsd_l2domain['ID'])
        return vsd_l2domain

    def _given_vsd_l2domain(self, cidr4=None, cidr6=None, dhcp_managed=False,
                            **kwargs):
        if cidr6:
            ip_type = "DUALSTACK"
        else:
            ip_type = "IPV4"

        vsd_l2domain_template = self.create_vsd_l2domain_template(
            ip_type=ip_type, dhcp_managed=dhcp_managed,
            cidr4=cidr4,
            cidr6=cidr6)

        vsd_l2domain = self.create_vsd_l2domain(vsd_l2domain_template['ID'])

        return vsd_l2domain

    def create_vsd_l3dom_template(self, **kwargs):
        vsd_l3dom_templates = self.nuage_vsd_client.create_l3domaintemplate(
            kwargs['name'] + '-template')
        vsd_l3dom_template = vsd_l3dom_templates[0]
        self.addCleanup(self.nuage_vsd_client.delete_l3domaintemplate,
                        vsd_l3dom_template['ID'])
        return vsd_l3dom_template

    def create_vsd_l3domain(self, **kwargs):
        extra_params = kwargs.get('extra_params')
        vsd_l3domains = self.nuage_vsd_client.create_domain(
            kwargs['name'], kwargs['tid'], extra_params=extra_params)
        vsd_l3domain = vsd_l3domains[0]
        self.addCleanup(
            self.nuage_vsd_client.delete_domain, vsd_l3domain['ID'])
        return vsd_l3domain

    def create_vsd_zone(self, **kwargs):
        extra_params = kwargs.get('extra_params')
        vsd_zones = self.nuage_vsd_client.create_zone(
            kwargs['domain_id'], kwargs['name'], extra_params=extra_params)
        vsd_zone = vsd_zones[0]
        self.addCleanup(self.nuage_vsd_client.delete_zone, vsd_zone['ID'])
        return vsd_zone

    def create_vsd_l3domain_dualstack_subnet(self, zone_id, subnet_name,
                                             cidr, gateway,
                                             cidr6, gateway6):
        extra_params = {'IPType': "DUALSTACK",
                        'IPv6Address': str(cidr6),
                        'IPv6Gateway': gateway6}

        vsd_subnets = self.nuage_vsd_client.create_domain_subnet(
            parent_id=zone_id,
            name=subnet_name,
            net_address=str(cidr.ip),
            netmask=str(cidr.netmask),
            gateway=gateway,
            extra_params=extra_params)

        vsd_subnet = vsd_subnets[0]
        self.addCleanup(
            self.nuage_vsd_client.delete_domain_subnet, vsd_subnet['ID'])
        return vsd_subnet

    def create_vsd_l3domain_subnet(self, zone_id, subnet_name,
                                   cidr, gateway,
                                   cidr6=None,
                                   gateway6=None,
                                   ip_type=None):
        params = {}

        if cidr:
            net_address = str(cidr.ip)
            net_mask = str(cidr.netmask)
        else:
            net_address = None
            net_mask = None

        if ip_type == "IPV4":
            params.update({'IPType': "IPV4"})
        elif ip_type == "DUALSTACK":
            params.update({'IPType': "DUALSTACK"})
            params.update({'IPv6Address': str(cidr6),
                           'IPv6Gateway': gateway6})
        elif ip_type == "IPV6":
            params.update({'IPType': "IPV6"})
            params.update({'IPv6Address': str(cidr6),
                           'IPv6Gateway': gateway6})
        elif ip_type:
            params.update({'IPType': ip_type})

        vsd_subnets = self.nuage_vsd_client.create_domain_subnet(
            parent_id=zone_id,
            name=subnet_name,
            net_address=net_address,
            netmask=net_mask,
            gateway=gateway,
            extra_params=params)

        vsd_subnet = vsd_subnets[0]
        self.addCleanup(
            self.nuage_vsd_client.delete_domain_subnet, vsd_subnet['ID'])
        return vsd_subnet

    def _given_vsd_l3subnet(self, cidr4=None, cidr6=None, dhcp_managed=True,
                            **kwargs):
        name = data_utils.rand_name('l3domain-')
        vsd_l3domain_template = self.create_vsd_l3dom_template(
            name=name)
        vsd_l3domain = self.create_vsd_l3domain(
            name=name, tid=vsd_l3domain_template['ID'])

        self.assertEqual(vsd_l3domain['name'], name)
        zone_name = data_utils.rand_name('zone-')
        extra_params = None
        vsd_zone = self.create_vsd_zone(name=zone_name,
                                        domain_id=vsd_l3domain['ID'],
                                        extra_params=extra_params)

        subnet_name = data_utils.rand_name('l3domain-subnet-')

        if cidr6:
            # ip_type = "DUALSTACK"
            vsd_l3domain_subnet = self.create_vsd_l3domain_dualstack_subnet(
                zone_id=vsd_zone['ID'],
                subnet_name=subnet_name,
                cidr=cidr4,
                gateway=str(IPAddress(cidr4) + 1),
                cidr6=cidr6,
                gateway6=str(IPAddress(cidr6) + 1))
        else:
            # ip_type = "IPV4"
            raise NotImplementedError

        return vsd_l3domain, vsd_l3domain_subnet

    def _verify_vport_in_l2_domain(self, port, vsd_l2domain, **kwargs):
        nuage_vports = self.nuage_vsd_client.get_vport(
            nuage_constants.L2_DOMAIN,
            vsd_l2domain['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(
            len(nuage_vports), 1,
            "Must find one VPort matching port: %s" % port['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport,
                        ContainsDict({'name': Equals(port['id'])}))

        # verify all other kwargs as attributes (key,value) pairs
        for key, value in kwargs.iteritems():
            if isinstance(value, dict):
                # compare dict
                self.fail('Compare with dict is not implemented')
            if isinstance(value, list):
                # self.assertThat(port, ContainsDict({key: Equals(value)}))
                self.assertItemsEqual(port[key], value)
            else:
                self.assertThat(port, ContainsDict({key: Equals(value)}))

    def _verify_vport_in_l3_subnet(self, port, vsd_l3_subnet, **kwargs):
        nuage_vports = self.nuage_vsd_client.get_vport(
            nuage_constants.SUBNETWORK,
            vsd_l3_subnet['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(
            len(nuage_vports), 1,
            "Must find one VPort matching port: %s" % port['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport,
                        ContainsDict({'name': Equals(port['id'])}))

        # verify all other kwargs as attributes (key,value) pairs
        for key, value in kwargs.iteritems():
            if isinstance(value, dict):
                # compare dict
                self.fail('Compare with dict is not implemented')
            if isinstance(value, list):
                # self.assertThat(port, ContainsDict({key: Equals(value)}))
                self.assertItemsEqual(port[key], value)
            else:
                self.assertThat(port, ContainsDict({key: Equals(value)}))

    def _create_vsd_floatingip_pool(
            self, fip_pool_cidr_base=VSD_FIP_POOL_CIDR_BASE):  # mind format!
        name = data_utils.rand_name('fip-pool')

        # randomize fip cidr to avoid parallel runs issues
        fip_pool_cidr = IPNetwork(
            fip_pool_cidr_base % (random.randint(0, 255),
                                  random.randint(0, 255)))
        address = IPAddress(fip_pool_cidr.first)
        netmask = fip_pool_cidr.netmask
        gateway = address + 1
        extra_params = {
            "underlay": True
        }

        vsd_fip_pool = self.nuage_vsd_client.create_floatingip_pool(
            name=name,
            address=str(address),
            gateway=str(gateway),
            netmask=str(netmask),
            extra_params=extra_params)

        self.addCleanup(self.nuage_vsd_client.delete_vsd_shared_resource,
                        vsd_fip_pool[0]['ID'])

        return vsd_fip_pool[0]

    def _claim_vsd_floating_ip(self, l3domain_id, vsd_fip_pool_id):
        claimed_fip = self.nuage_vsd_client.claim_floatingip(l3domain_id,
                                                             vsd_fip_pool_id)
        return claimed_fip

    def _associate_fip_to_port(self, port, fip_id):
        kwargs = {"nuage_floatingip": {'id': fip_id}}
        self.update_port(port, **kwargs)

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


############################################################
# Neutron resources
############################################################
class NetworkTestCaseMixin(BaseNuageNetworksTestCase):

    def create_network(self, network_name=None, **kwargs):
        """Wrapper utility that returns a test network."""
        network_name = network_name or data_utils.rand_name('test-network')

        body = self.networks_client.create_network(name=network_name, **kwargs)
        network = body['network']
        self.addCleanup(self.networks_client.delete_network, network['id'])
        return network

    def create_subnet(self, network, gateway='', cidr=None, mask_bits=None,
                      ip_version=None, client=None, **kwargs):
        """Wrapper utility that returns a test subnet."""
        # allow tests to use admin client
        if not client:
            client = self.subnets_client

        # The cidr and mask_bits depend on the ip version.
        ip_version = ip_version if ip_version is not None else self._ip_version
        gateway_not_set = gateway == ''
        if ip_version == 4:
            cidr = cidr or IPNetwork(self.cidr)
            if mask_bits is None:
                mask_bits = self.mask_bits4
        elif ip_version == 6:
            cidr = (cidr or
                    IPNetwork(self.cidr6))
            if mask_bits is None:
                mask_bits = self.mask_bits6
        # Find a cidr that is not in use yet and create a subnet with it
        for subnet_cidr in cidr.subnet(mask_bits):
            if gateway_not_set:
                gateway_ip = str(IPAddress(subnet_cidr) + 1)
            else:
                gateway_ip = gateway
            try:
                body = client.create_subnet(
                    network_id=network['id'],
                    cidr=str(subnet_cidr),
                    ip_version=ip_version,
                    gateway_ip=gateway_ip,
                    **kwargs)
                break
            except lib_exc.BadRequest as e:
                is_overlapping_cidr = 'overlaps with another subnet' in str(e)
                if not is_overlapping_cidr:
                    raise
        else:
            message = 'Available CIDR for subnet creation could not be found'
            raise exceptions.BuildErrorException(message)
        subnet = body['subnet']

        self.addCleanup(client.delete_subnet, subnet['id'])
        return subnet

    def create_port(self, network, cleanup=True, **kwargs):
        """Wrapper utility that returns a test port."""
        body = self.ports_client.create_port(network_id=network['id'],
                                             **kwargs)
        port = body['port']
        if cleanup:
            self.addCleanup(self.ports_client.delete_port, port['id'])
        return port

    def create_and_forget_port(self, network, **kwargs):
        """Wrapper utility that returns a test port."""
        body = self.ports_client.create_port(network_id=network['id'],
                                             **kwargs)
        port = body['port']
        # no cleanup !
        return port

    def update_port(self, port, **kwargs):
        """Wrapper utility that updates a test port."""
        body = self.ports_client.update_port(port['id'],
                                             **kwargs)
        return body['port']

    def _verify_port(self, port, subnet4=None, subnet6=None, **kwargs):
        has_ipv4_ip = False
        has_ipv6_ip = False

        for fixed_ip in port['fixed_ips']:
            ip_address = fixed_ip['ip_address']
            if subnet4 and fixed_ip['subnet_id'] == subnet4['id']:
                start_ip_address = subnet4['allocation_pools'][0]['start']
                end_ip_address = subnet4['allocation_pools'][0]['end']
                ip_range = IPRange(start_ip_address, end_ip_address)
                self.assertIn(ip_address, ip_range)
                has_ipv4_ip = True

            if subnet6 and fixed_ip['subnet_id'] == subnet6['id']:
                start_ip_address = subnet6['allocation_pools'][0]['start']
                end_ip_address = subnet6['allocation_pools'][0]['end']
                ip_range = IPRange(start_ip_address, end_ip_address)
                self.assertIn(ip_address, ip_range)
                has_ipv6_ip = True

        if subnet4:
            self.assertTrue(
                has_ipv4_ip,
                "Must have an IPv4 ip in subnet: %s" % subnet4['id'])

        if subnet6:
            self.assertTrue(
                has_ipv6_ip,
                "Must have an IPv6 ip in subnet: %s" % subnet6['id'])

        self.assertIsNotNone(port['mac_address'])

        # verify all other kwargs as attributes (key,value) pairs
        for key, value in kwargs.iteritems():
            if isinstance(value, dict):
                # compare dict
                raise NotImplementedError
            if isinstance(value, list):
                # self.assertThat(port, ContainsDict({key: Equals(value)}))
                self.assertItemsEqual(port[key], value)
            else:
                self.assertThat(port, ContainsDict({key: Equals(value)}))

    def _given_network_linked_to_vsd_subnet(self, vsd_subnet, cidr4=None,
                                            cidr6=None, enable_dhcp=True,
                                            net_partition=None):
        # create Openstack IPv4 subnet on Openstack based on VSD l3dom subnet
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        if net_partition:
            actual_net_partition = net_partition
        else:
            actual_net_partition = self.net_partition

        subnet4 = self.create_subnet(
            network,
            cidr=cidr4,
            enable_dhcp=enable_dhcp,
            mask_bits=cidr4.prefixlen,
            nuagenet=vsd_subnet['ID'],
            net_partition=actual_net_partition)

        # create Openstack IPv6 subnet on Openstack based on VSD l3dom subnet
        subnet6 = None
        if cidr6:
            subnet6 = self.create_subnet(
                network,
                ip_version=6,
                cidr=cidr6,
                mask_bits=IPNetwork(cidr6).prefixlen,
                enable_dhcp=False,
                nuagenet=vsd_subnet['ID'],
                net_partition=actual_net_partition)

        return network, subnet4, subnet6

    def _create_redirect_target_in_l3_subnet(self, l3subnet, name=None):
        if name is None:
            name = data_utils.rand_name('os-l3-rt')
        # parameters for nuage redirection target
        post_body = {'insertion_mode': 'L3',
                     'redundancy_enabled': 'False',
                     'subnet_id': l3subnet['id'],
                     'name': name}
        redirect_target = self.nuage_network_client.create_redirection_target(
            **post_body)
        return redirect_target
