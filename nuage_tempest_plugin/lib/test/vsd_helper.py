# Copyright 2017 - Nokia
# All Rights Reserved.

import importlib
from netaddr import IPAddress

import re
from six import iteritems

from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_client import NuageRestClient


def fetch_by_id(fetcher, obj_id):
    return fetcher.fetch(filter='ID is "{}"'.format(obj_id))[2]


def get_by_id(fetcher, obj_id):
    return fetcher.get(filter='ID is "{}"'.format(obj_id))[0]


def fetch_by_name(fetcher, name):
    return fetcher.fetch(filter='name is "{}"'.format(name))[2]


def get_by_name(fetcher, name):
    return fetcher.get(filter='name is "{}"'.format(name))[0]


class VsdHelper(object):
    """VsdHelper

    Base class for VSD interactions.
    This class will have all the common functions to communicate with vsd
    using vspk
    """
    CONST_ETHER_TYPE_IPV4 = "0x0800"
    CONST_ETHER_TYPE_IPV6 = "0x86DD"

    cms_id = Topology.cms_id
    default_netpartition_name = Topology.def_netpartition

    def __init__(self, vsd_server=None, user='csproot', password='csproot',
                 enterprise='csp', version=None):
        self.vsd = vsd_server or Topology.vsd_server
        self.uri = 'https://{}'.format(self.vsd)
        self.user = user
        self.password = password
        self.enterprise = enterprise
        self.vspk = importlib.import_module('vspk.' + str(
            version or self.base_uri_to_version(Topology.base_uri)))
        self._session = None
        self.default_enterprise = None

        # temporarily reusing RESTClient for missing ops
        self.nuage_rest_client = NuageRestClient()

        self.enterprise_name_to_enterprise = {}

    @staticmethod
    def assertIsNotNone(obj, message):
        if obj is None:
            raise AssertionError(message or "{} is None".format(obj))

    @staticmethod
    def base_uri_to_version(base_uri):
        pattern = re.compile(r'(v\d+_?\d*$)')
        match = pattern.search(base_uri)
        version = match.group()
        return str(version)

    def get_enterprise_by_id(self, ent_id):
        return get_by_id(self.session().user.enterprises, ent_id)

    def get_enterprise_by_name(self, ent_name):
        if ent_name in self.enterprise_name_to_enterprise:
            enterprise = self.enterprise_name_to_enterprise[ent_name]
        else:
            enterprise = get_by_name(
                self.session().user.enterprises, ent_name)
            self.enterprise_name_to_enterprise[ent_name] = enterprise

        return enterprise

    def new_session(self):
        """new_session

        Start a new API session via vspk an return the corresponding
        'vspk.NUVSDSession` object.
        Note that this object is also exposed as `self()`
        """
        self._session = self.vspk.NUVSDSession(
            username=self.user,
            password=self.password,
            enterprise=self.enterprise,
            api_url=self.uri)

        self._session.start()
        if not self.default_enterprise:
            self.default_enterprise = self.get_enterprise_by_name(
                self.default_netpartition_name)

        self.assertIsNotNone(self.default_enterprise,
                             "Should have a default "
                             "enterprise for Nuage plugin")

        return self._session

    def session(self):
        if not self._session:
            self._session = self.new_session()
        return self._session

    def get_default_enterprise(self):
        if not self.default_enterprise:
            self.session()
        return self.default_enterprise

    def external_id(self, obj_id):
        return obj_id + '@' + self.cms_id

    @staticmethod
    def filter_str(keys, values):
        filter_str = ""
        if not isinstance(keys, list):
            keys = [keys]
        if not isinstance(values, list):
            values = [values]
        for key, value in zip(keys, values):
            if filter_str:
                filter_str += " AND "
            if isinstance(value, int):
                filter_str += "{} IS {}".format(key, value)
            else:
                filter_str += "{} IS '{}'".format(key, value)
        return filter_str

    def get_external_id_filter(self, object_id):
        return self.filter_str('externalID', self.external_id(object_id))

    def create_l2domain_template(self, name=None, enterprise=None,
                                 dhcp_managed=True, ip_type="IPV4",
                                 cidr4=None, gateway4=None,
                                 cidr6=None, gateway6=None,
                                 enable_dhcpv4=True, enable_dhcpv6=False,
                                 **kwargs):
        if enterprise and not isinstance(enterprise, self.vspk.NUEnterprise):
            # get enterprise by _name_
            enterprise = self.get_enterprise_by_name(enterprise)

        elif not enterprise:
            enterprise = self.get_default_enterprise()

        template_name = name or data_utils.rand_name('test-l2template')

        params = {}
        if not Topology.is_v5:
            params.update({'enable_dhcpv4': enable_dhcpv4})
            params.update({'enable_dhcpv6': enable_dhcpv6})

        if dhcp_managed:
            params['dhcp_managed'] = dhcp_managed

        if ip_type in ("IPV4", "IPV6", "DUALSTACK"):
            params.update({'ip_type': ip_type})

        if cidr4:
            params.update({'address': str(cidr4.ip)})
            if "netmask" in kwargs:
                netmask = kwargs['netmask']
            else:
                netmask = str(cidr4.netmask)
            params.update({'netmask': netmask})

            if not gateway4 and (enable_dhcpv4 or Topology.is_v5):
                # fill in gateway when dhcp is enabled only;
                # or in v5, always fill it when a cidr is set ('managed')
                gateway4 = str(IPAddress(cidr4) + 1)
            if gateway4:
                params.update({'gateway': gateway4})

        if cidr6:
            params.update({'ipv6_address': str(cidr6)})
            if "netmask6" in kwargs:
                netmask6 = kwargs['netmask6']
            else:
                netmask6 = str(cidr6.netmask)
            params.update({'netmask6': netmask6})

            if not gateway6 and (enable_dhcpv6 or Topology.is_v5):
                # fill in gateway when dhcp is enabled only;
                # or in v5, always fill it when a cidr is set ('managed')
                gateway6 = str(IPAddress(cidr6) + 1)
            if gateway6:
                params.update({'ipv6_gateway': gateway6})

        # add all other kwargs as attributes (key,value) pairs
        for key, value in iteritems(kwargs):
            params.update({key: value})

        if kwargs.get('no_gateway'):
            params.update({
                'gateway': None,
                'ipv6_gateway': None})

        template = self.vspk.NUL2DomainTemplate(
            name=template_name,
            **params)

        return enterprise.create_child(template)[0]

    def delete_l2domain_template(self, l2dom_t_id):
        return self.nuage_rest_client.delete_l2domaintemplate(l2dom_t_id)

    def create_l2domain(self, name=None, enterprise=None, template=None,
                        **kwargs):
        if enterprise and not isinstance(enterprise, self.vspk.NUEnterprise):
            # get enterprise by _name_
            enterprise = self.get_enterprise_by_name(enterprise)

        if not enterprise:
            enterprise = self.get_default_enterprise()

        self.assertIsNotNone(template, "Must provide a valid template")

        name = name or data_utils.rand_name('test-l2domain')

        l2domain = self.vspk.NUL2Domain(
            name=name,
            template=template,
            **kwargs)

        return enterprise.instantiate_child(l2domain, template)[0]

    def delete_l2domain(self, l2dom_id):
        return self.nuage_rest_client.delete_l2domain(l2dom_id)

    def _get_enterprise_or_default(self, enterprise):
        if enterprise and not isinstance(enterprise, self.vspk.NUEnterprise):
            # get enterprise by _name_
            enterprise = self.get_enterprise_by_name(enterprise)

        if not enterprise:
            enterprise = self.get_default_enterprise()
        return enterprise

    def _get_vspk_filter_for_subnet(self, by_id=None, by_subnet=None):
        vspk_filter = None
        if by_id:
            vspk_filter = 'ID is "{}"'.format(by_id)
        elif by_subnet:
            if Topology.is_v5:
                vspk_filter = self.get_external_id_filter(by_subnet['id'])
            else:
                if by_subnet['ip_version'] == 6:
                    vspk_filter = self.filter_str(
                        ['externalID', 'IPv6Address'],
                        [self.external_id(by_subnet['network_id']),
                         by_subnet['cidr']])
                else:
                    vspk_filter = self.filter_str(
                        ['externalID', 'address'],
                        [self.external_id(by_subnet['network_id']),
                         by_subnet['cidr'].split('/')[0]])
        return vspk_filter

    def get_l2domain(self, enterprise=None, vspk_filter=None,
                     by_id=None, by_subnet=None):
        """get_l2domain

        @params: enterprise object or enterprise id
                 filter following vspk filter structure
        @return  l2 domain object
        @Example:
        self.vsd.get_l2domain(enterprise=enterprise,
                              vspk_filter='name == "{}"'.format(name))
        self.vsd.get_l2domain(enterprise=enterprise_name,
                              vspk_filter='name == "{}"'.format(name))
        self.vsd.get_l2domain(
            vspk_filter='externalID == "{}"'.format(ext_id))
        """
        enterprise = self._get_enterprise_or_default(enterprise)
        vspk_filter = (vspk_filter or
                       self._get_vspk_filter_for_subnet(by_id=by_id,
                                                        by_subnet=by_subnet))
        return enterprise.l2_domains.get_first(filter=vspk_filter)

    def get_l2domain_template(self, enterprise=None, vspk_filter=None,
                              by_id=None,
                              by_subnet=None):
        """get_l2domain_template

        @params: enterprise object or enterprise id
                 filter following vspk filter structure
        @return  l2 domain template object
        @Example:
        self.vsd.get_l2domain_template(enterprise=enterprise,
                              vspk_filter='name == "{}"'.format(name))
        self.vsd.get_l2domain_template(enterprise=enterprise_name,
                              vspk_filter='name == "{}"'.format(name))
        self.vsd.get_l2domain_template(
            vspk_filter='externalID == "{}"'.format(ext_id))
        """
        enterprise = self._get_enterprise_or_default(enterprise)
        vspk_filter = (vspk_filter or
                       self._get_vspk_filter_for_subnet(by_id=by_id,
                                                        by_subnet=by_subnet))
        return enterprise.l2_domain_templates.get_first(filter=vspk_filter)

    ###
    # l3 domain
    ###

    def create_l3domain_template(self, name=None, enterprise=None):
        if enterprise and not isinstance(enterprise,
                                         self.vspk.NUEnterprise):
            # get enterprise by _name_
            enterprise = self.get_enterprise_by_name(enterprise)

        elif not enterprise:
            enterprise = self.get_default_enterprise()

        template_name = name or data_utils.rand_name('test-l3template')

        template = self.vspk.NUDomainTemplate(
            name=template_name)

        return enterprise.create_child(template)[0]

    def delete_l3domain_template(self, l3dom_t_id):
        return self.nuage_rest_client.delete_l3domaintemplate(l3dom_t_id)

    def create_domain(self, name=None, enterprise=None, template_id=None):
        return self.create_l3domain(name, enterprise, template_id)

    def create_l3domain(self, name=None, enterprise=None, template_id=None,
                        **kwargs):
        if enterprise and not isinstance(enterprise,
                                         self.vspk.NUEnterprise):
            # get enterprise by _name_
            enterprise = self.get_enterprise_by_name(enterprise)

        elif not enterprise:
            enterprise = self.get_default_enterprise()

        self.assertIsNotNone(template_id, "Must provide a valid template ID")

        name = name or data_utils.rand_name('test-l3domain')

        l3domain_data = self.vspk.NUDomain(
            name=name,
            template_id=template_id,
            **kwargs)

        return enterprise.create_child(l3domain_data)[0]

    def delete_domain(self, l3dom_id):
        return self.delete_l3domain(l3dom_id)

    def delete_l3domain(self, l3dom_id):
        return self.nuage_rest_client.delete_domain(l3dom_id)

    def get_l3_domain_by_subnet(self, by_subnet):
        # get the subnet
        subnet = self.get_subnet_from_domain(by_subnet=by_subnet)
        if not subnet:
            return None

        _, domain = self.get_zone_and_domain_parent_of_subnet(subnet)
        return domain

    def get_domain(self, enterprise=None, vspk_filter=None, by_router_id=None):
        return self.get_l3domain(enterprise, vspk_filter, by_router_id)

    def get_l3domain(self, enterprise=None,
                     vspk_filter=None, by_router_id=None):
        """get_l3domain

        @params: enterprise object or enterprise id
                 filter following vspk filter structure
        @return: domain object
        @Example:
        self.vsd.get_l3domain(enterprise=enterprise,
                              vspk_filter='name == "{}"'.format(name))
        self.vsd.get_l3domain(enterprise=enterprise_name,
                              vspk_filter='name == "{}"'.format(name))
        self.vsd.get_l3domain(vspk_filter='externalID == "{}"'.format(ext_id))
        """
        if by_router_id:
            domain = self.get_l3domain(
                enterprise, self.get_external_id_filter(by_router_id))

        else:
            if enterprise and not isinstance(enterprise,
                                             self.vspk.NUEnterprise):
                # get enterprise by _name_
                enterprise = self.get_enterprise_by_name(enterprise)

            elif not enterprise:
                enterprise = self.get_default_enterprise()

            domain = enterprise.domains.get_first(filter=vspk_filter)

        return domain

    def create_zone(self, name=None, domain=None, **kwargs):
        zone_name = name or data_utils.rand_name('test-zone')

        zone_data = self.vspk.NUZone(name=zone_name, **kwargs)

        zone_tuple = domain.create_child(zone_data)
        return zone_tuple[0]

    def create_subnet(self, name=None, zone=None,
                      ip_type="IPV4",
                      cidr4=None,
                      gateway4=None,
                      enable_dhcpv4=True,
                      cidr6=None,
                      gateway6=None,
                      enable_dhcpv6=False,
                      **kwargs):

        self.assertIsNotNone(zone, "Must provide a valid zone")

        subnet_name = name or data_utils.rand_name('test-subnet')

        params = {}

        if not enable_dhcpv4:
            params.update({'enable_dhcpv4': False})
        if not enable_dhcpv6:
            params.update({'enable_dhcpv6': False})

        for key, value in iteritems(kwargs):
            params.update({key: value})

        if cidr4:
            params.update({'address': str(cidr4.ip)})
            if enable_dhcpv4:
                params.update({'enable_dhcpv4': True})
            if "netmask" not in kwargs:
                params.update({'netmask': str(cidr4.netmask)})
            if gateway4:
                params.update({'gateway': gateway4})

        if cidr6:
            params.update({'ipv6_address': str(cidr6)})
            if enable_dhcpv6:
                params.update({'enable_dhcpv6': True})
            if gateway6:
                params.update({'ipv6_gateway': gateway6})

        subnet_data = self.vspk.NUSubnet(
            name=subnet_name,
            ip_type=ip_type,
            **params)

        return zone.create_child(subnet_data)[0]

    def delete_subnet(self, subnet_id):
        return self.nuage_rest_client.delete_domain_subnet(subnet_id)

    ###
    # policy groups
    ###

    def create_policy_group(self, domain, name=None):
        pg = self.vspk.NUPolicyGroup(name=name, type='SOFTWARE')
        domain.create_child(pg)
        return domain.policy_groups.get_first(
            filter='name is "{}"'.format(name))

    def create_ingress_acl_template(self, domain, name='default-acl-template'):
        acl_params = {
            'name': name,
            'active': True,
            'default_allow_ip': True,
            'default_allow_non_ip': False,
            'allow_address_spoof': True}

        ingress_tpl = self.vspk.NUIngressACLTemplate(**acl_params)
        domain.create_child(ingress_tpl)

        return domain.ingress_acl_templates.get_first(
            filter='name is "{}"'.format(name))

    def create_egress_acl_template(self, domain, name='default-acl-template'):
        acl_params = {
            'name': name,
            'active': True,
            'default_allow_ip': True,
            'default_allow_non_ip': False,
            'allow_address_spoof': True}

        egress_tpl = self.vspk.NUEgressACLTemplate(**acl_params)
        domain.create_child(egress_tpl)

        return domain.egress_acl_templates.get_first(
            filter='name is "{}"'.format(name))

    def add_egress_acl_template_rule(self, template, name='default-acl-rule',
                                     protocol='ANY',
                                     location_type='ANY',
                                     network_type='ANY',
                                     stateful=False,
                                     egress="FORWARD"):
        entry = self.vspk.NUIngressACLEntryTemplate(
            name=name,
            protocol=protocol,
            location_type=location_type,
            network_type=network_type,
            stateful=stateful,
            action=egress)

        return template.create_child(entry)[0]

    def create_acl_templates(self, the_domain, allow_spoofing=False):
        acl_params = {
            'name': 'default-acl-template',
            'active': True,
            'default_allow_ip': False,
            'default_allow_non_ip': False,
            'allow_address_spoof': allow_spoofing,
            'default_install_acl_implicit_rules': False
        }
        ingress_template = self.vspk.NUIngressACLTemplate(**acl_params)
        the_domain.create_child(ingress_template)
        egress_template = self.vspk.NUEgressACLTemplate(**acl_params)
        the_domain.create_child(egress_template)
        return ingress_template, egress_template

    def define_ssh_acl(self, ingress_tpl, egress_tpl, stateful=True):
        res = []
        # Add SSH rule for FIP access
        entry = self.vspk.NUIngressACLEntryTemplate(
            ether_type=self.CONST_ETHER_TYPE_IPV4,
            protocol='6',
            location_type='ANY',
            network_type='ANY',
            stateful=stateful,
            destination_port='*',
            source_port='22',
            action='FORWARD')
        obj = ingress_tpl.create_child(entry)[0]
        res.append(obj.stats_id)
        entry = self.vspk.NUEgressACLEntryTemplate(
            ether_type=self.CONST_ETHER_TYPE_IPV4,
            protocol='6',
            location_type='ANY',
            network_type='ANY',
            stateful=stateful,
            destination_port='22',
            source_port='*',
            action='FORWARD')
        obj = egress_tpl.create_child(entry)[0]
        res.append(obj.stats_id)
        return res

    def define_tcp_acl(self, direction, acl_template, ip_version, s_port='*',
                       d_port='80', stateful=True, location_type='ANY',
                       location_id=None):
        res = []
        ether_type = (self.CONST_ETHER_TYPE_IPV4 if ip_version == 4 else
                      self.CONST_ETHER_TYPE_IPV6)
        if direction == 'ingress':
            entry = self.vspk.NUIngressACLEntryTemplate(
                ether_type=ether_type,
                protocol='6',
                location_type=location_type,
                location_id=location_id,
                network_type='ANY',
                stateful=stateful,
                destination_port=d_port,
                source_port=s_port,
                action='FORWARD')
            obj = acl_template.create_child(entry)[0]
            res.append(obj.stats_id)
        elif direction == 'egress':
            entry = self.vspk.NUEgressACLEntryTemplate(
                ether_type=ether_type,
                protocol='6',
                location_type='ANY',
                network_type='ANY',
                stateful=stateful,
                destination_port=d_port,
                source_port=s_port,
                action='FORWARD')
            obj = acl_template.create_child(entry)[0]
            res.append(obj.stats_id)
        return res

    def define_any_to_any_acl(self, domain,
                              ingress='FORWARD', egress='FORWARD',
                              allow_ipv4=True,
                              allow_ipv6=False,
                              stateful=False, spoof=False):
        # always delete first
        for acl in domain.ingress_acl_templates.get():
            acl.delete()
        for acl in domain.egress_acl_templates.get():
            acl.delete()
        # and then create new
        res = []
        ingress_tpl, egress_tpl = self.create_acl_templates(domain, spoof)

        if allow_ipv4:
            entry = self.vspk.NUIngressACLEntryTemplate(
                protocol='ANY',
                location_type='ANY',
                network_type='ANY',
                stateful=stateful,
                action=ingress)
            obj = ingress_tpl.create_child(entry)[0]
            res.append(obj.stats_id)
            entry = self.vspk.NUEgressACLEntryTemplate(
                protocol='ANY',
                location_type='ANY',
                network_type='ANY',
                stateful=stateful,
                action=egress)
            obj = egress_tpl.create_child(entry)[0]
            res.append(obj.stats_id)

        if allow_ipv6:
            entry = self.vspk.NUIngressACLEntryTemplate(
                ether_type=self.CONST_ETHER_TYPE_IPV6,
                protocol='ANY',
                location_type='ANY',
                network_type='ANY',
                stateful=stateful,
                action=ingress)
            obj = ingress_tpl.create_child(entry)[0]
            res.append(obj.stats_id)
            entry = self.vspk.NUEgressACLEntryTemplate(
                ether_type=self.CONST_ETHER_TYPE_IPV6,
                protocol='ANY',
                location_type='ANY',
                network_type='ANY',
                stateful=stateful,
                action=egress)
            obj = egress_tpl.create_child(entry)[0]
            res.append(obj.stats_id)

        if not allow_ipv4:
            # Add SSH rule for FIP access
            entry = self.vspk.NUEgressACLEntryTemplate(
                ether_type=self.CONST_ETHER_TYPE_IPV4,
                protocol='6',
                location_type='ANY',
                network_type='ANY',
                stateful=True,
                destination_port='22',
                source_port='*',
                action=egress)
            obj = egress_tpl.create_child(entry)[0]
            res.append(obj.stats_id)
        return res

    ###
    # Floating ip
    ###

    def get_vport_vip(self, enterprise=None, vport_id=None, router_id=None):
        """get_vport_vip

        @params:
        @return  associated virtual ip
        TODO(team) this only works when there is only one virtual ip associated
        TODO(team) someone have a better idea on how to get down to the virtual
                   ip port?
        """
        if enterprise and not isinstance(enterprise,
                                         self.vspk.NUEnterprise):
            # get enterprise by _name_
            enterprise = self.get_enterprise_by_name(enterprise)

        elif not enterprise:
            enterprise = self.get_default_enterprise()

        self.assertIsNotNone(vport_id, "Must provide a vport id")
        self.assertIsNotNone(router_id, "Must provide a router id")

        domain = enterprise.domains.get_first(
            filter='externalID == "{}"'.format(
                router_id + "@" + Topology.cms_id))
        vport = domain.vports.get_first(
            filter='externalID == "{}"'.format(
                vport_id + "@" + Topology.cms_id))

        return vport.virtual_ips.get_first() if vport else None

    def get_domain_template(self, enterprise=None, vspk_filter=None,
                            by_router_id=None):
        """get_domain_template

        @params: enterprise object or enterprise id
                 filter following vspk filter structure
        @return: domain template object
        @Example:
        self.vsd.get_domain_template(enterprise=enterprise,
                                     filter='name == "{}"'.format(name))
        self.vsd.get_domain_template(enterprise=enterprise_name,
                                     filter='name == "{}"'.format(name))
        self.vsd.get_domain_template(
            filter='externalID == "{}"'.format(ext_id))
        """
        if by_router_id:
            domain_template = self.get_domain_template(
                enterprise, self.get_external_id_filter(by_router_id))

        else:
            if enterprise and not isinstance(enterprise,
                                             self.vspk.NUEnterprise):
                # get enterprise by _name_
                enterprise = self.get_enterprise_by_name(enterprise)

            elif not enterprise:
                enterprise = self.get_default_enterprise()

            domain_template = enterprise.domain_templates.get_first(
                filter=vspk_filter)

        return domain_template

    def get_zone(self, domain=None, vspk_filter=None, by_router_id=None):
        """get_zone

        @params: domain object or domain id
                 filter following vspk filter structure
        @return: zone object
        @Example:
        self.vsd.get_zone(domain=domain,
                         filter='name == "{}"'.format(name))
        self.vsd.get_zone(domain=domain_id,
                         filter='name == "{}"'.format(name))
        self.vsd.get_zone(filter='externalID == "{}"'.format(ext_id))
        """
        if by_router_id:  # this is actually not advised as there will be 2
            zone = self.get_zone(
                domain, self.get_external_id_filter(by_router_id))

        else:
            if domain:
                if not isinstance(domain, self.vspk.NUDomain):
                    domain = self.vspk.NUDomain(id=domain)
                zone = domain.zones.get_first(filter=vspk_filter)
            else:
                zone = self.session().user.zones.get_first(filter=vspk_filter)

        return zone

    def get_subnet(self, zone=None, vspk_filter=None, by_id=None,
                   by_subnet=None):
        """get_subnet

        @params: zone object or zone id
                 filter following vspk filter structure
        @return: subnet object
        @Example:
        self.vsd.get_subnet(zone=zone,
                            filter='name == "{}"'.format(name))
        self.vsd.get_subnet(zone=zone_id,
                            filter='name == "{}"'.format(name))
        self.vsd.get_subnet(filter='externalID == "{}"'.format(ext_id))
        """
        if by_id:
            subnet = self.get_subnet(vspk_filter='ID is "{}"'.format(by_id))

        elif by_subnet:
            vspk_filter = self._get_vspk_filter_for_subnet(by_subnet=by_subnet)
            subnet = self.get_subnet(zone, vspk_filter)

        else:
            if zone:
                if not isinstance(zone, self.vspk.NUZone):
                    zone = self.vspk.NUZone(id=zone)
                subnet = zone.subnets.get_first(filter=vspk_filter)
            else:
                subnet = self.session().user.subnets.get_first(
                    filter=vspk_filter)

        return subnet

    def get_zone_and_domain_parent_of_subnet(self, subnet):
        zone, _ = self.vspk.NUZone(id=subnet.parent_id).fetch()
        domain, _ = self.vspk.NUDomain(id=zone.parent_id).fetch()
        return zone, domain

    def get_subnet_from_domain(self, domain=None, vspk_filter=None,
                               by_subnet=None):
        """get_subnet_from_domain

        @params: domain object or domain id
                 filter following vspk filter structure
        @return: subnet object
        @Example:
        self.vsd.get_subnet(domain=domain,
                            filter='name == "{}"'.format(name))
        self.vsd.get_subnet(domain=domain_id,
                            filter='name == "{}"'.format(name))
        self.vsd.get_subnet(filter='externalID == "{}"'.format(ext_id))
        """
        if by_subnet:
            vspk_filter = self._get_vspk_filter_for_subnet(by_subnet=by_subnet)
            subnet = self.get_subnet_from_domain(domain, vspk_filter)

        else:
            if domain:
                if not isinstance(domain, self.vspk.NUDomain):
                    domain = self.vspk.NUDomain(id=domain)
                subnet = domain.subnets.get_first(filter=vspk_filter)
            else:
                subnet = self.session().user.subnets.get_first(
                    filter=vspk_filter)

        return subnet

    def get_vm(self, subnet=None, vspk_filter=None, by_device_id=None):
        """get_vm

        @params: subnet object or subnet id
                 filter following vspk filter structure
        @return: vm object
        @Example:
        self.vsd.get_vm(subnet=subnet,
                        filter='name == "{}"'.format(name))
        self.vsd.get_vm(subnet=subnet_id,
                        filter='name == "{}"'.format(name))
        self.vsd.get_vm(filter='externalID == "{}"'.format(ext_id))
        """
        if by_device_id:
            vm = self.get_vm(
                subnet, self.get_external_id_filter(by_device_id))

        else:
            if subnet:
                if not isinstance(subnet, self.vspk.NUSubnet):
                    subnet = self.vspk.NUSubnet(id=subnet)
                vm = subnet.vms.get_first(filter=vspk_filter)
            else:
                vm = self.session().user.vms.get_first(filter=vspk_filter)

        return vm

    def get_subnet_dhcp_options(self, subnet=None, vspk_filter=None):
        """get_subnet_dhcp_options

        @params: subnet object or
                 subnet filter following vspk filter structure
        @return: subnet dhcp_options object
        @Example:
        self.vsd.get_subnet_dhcp_options(subnet=subnet)
        self.vsd.get_subnet_dhcp_options(
            filter='externalID == "{}"'.format(subnet_externalID))
        """
        subnet = subnet or self.session().user.subnets.get_first(
            filter=vspk_filter)

        return subnet.dhcp_options.get()

    def get_l2domain_dhcp_options(self, l2domain=None, vspk_filter=None):
        """get_subnet_dhcp_options

        @params: subnet object or
                 subnet filter following vspk filter structure
        @return: subnet dhcp_options object
        @Example:
        self.vsd.get_subnet_dhcp_options(subnet=subnet)
        self.vsd.get_subnet_dhcp_options(
            filter='externalID == "{}"'.format(subnet_externalID))
        """
        l2domain = l2domain or self.session().user.l2domain.get_first(
            filter=vspk_filter)

        return l2domain.dhcp_options.get()

    def get_vport(self, l2domain=None, subnet=None, vspk_filter=None,
                  by_port_id=None):
        """get_vport

        @params: l2domain object
                 subnet object
                 vport filter following vspk filter structure
        @return: vport object
        @Example:
        self.vsd.get_vport(subnet=subnet,
            vspk_filter='externalID == "{}"'.format(ext_id))
        """
        assert l2domain or subnet  # one of both is required
        parent = l2domain if l2domain else subnet

        if by_port_id:
            vport = self.get_vport(
                l2domain, subnet, self.get_external_id_filter(by_port_id))

        else:
            vport = parent.vports.get_first(filter=vspk_filter)

        return vport

    def get_vm_interface(self, vspk_filter):
        """get_vm_interface

        @params: vm interface filter following vspk filter structure
        @return: vm interface object
        @Example:
        self.vsd.get_vm_interface(
            filter='externalID == "{}"'.format(ext_id))
        """
        return self.session().user.vm_interfaces.get_first(
            filter=vspk_filter)

    def get_vm_interface_policy_decisions(self, vm_interface=None,
                                          vspk_filter=None):
        """get_vm_interface_policy_decisions

        @params: vm interface object or
                 vm interface filter following vspk filter structure
        @return: vm interface policy_decisions object
        @Example:
        self.vsd.get_vm_interface_policy_decisions(vm_interface=vm_interface)
        self.vsd.get_vm_interface_policy_decisions(
            filter='externalID == "{}"'.format(vm_interface_externalID))
        """
        vm_interface = (vm_interface or
                        self.session().user.vm_interfaces.get_first(
                            filter=vspk_filter))

        return self.vspk.NUPolicyDecision(
            id=vm_interface.policy_decision_id).fetch()

    def get_vm_interface_dhcp_options(self, vm_interface=None,
                                      vspk_filter=None):
        """get_vm_interface_dhcp_options

        @params: vm interface object or
                 vm interface filter following vspk filter structure
        @return: vm interface dhcp_options object
        @Example:
        self.vsd.get_vm_interface_dhcp_options(vm_interface=vm_interface)
        self.vsd.get_vm_interface_dhcp_options(
            filter='externalID == "{}"'.format(vm_interface_externalID))
        """
        if vm_interface:
            if not isinstance(vm_interface, self.vspk.NUVMInterface):
                vm_interface = self.vspk.NUVMInterfacein(id=vm_interface)

        else:
            vm_interface = self.session().user.vm_interfaces.get_first(
                filter=vspk_filter)

        return vm_interface.dhcp_options.get() if vm_interface else []

    def get_ingress_acl_entries(self, vspk_filter):
        """get_ingress_acl_entries

        @params: ingress acl entry filter following vspk filter structure
        @return: ingress acl entry object list
        @Example:
        self.vsd.get_ingress_acl_entry(
            filter='externalID == "{}"'.format(ext_id))
        """
        return self.session().user.ingress_acl_entry_templates.get(
            filter=vspk_filter)

    def get_egress_acl_entries(self, vspk_filter):
        """get_egress_acl_entry

        @params: egress acl entry filter following vspk filter structure
        @return: egress acl entry object list
        @Example:
        self.vsd.get_egress_acl_entry(
            filter='externalID == "{}"'.format(ext_id))
        """
        return self.session().user.egress_acl_entry_templates.get(
            filter=vspk_filter)

    def get_floating_ip(self, vspk_filter):
        """get_floating_ip

        @params: floating ip filter following vspk filter structure
        @return: floating ip object
        @Example:
        self.vsd.get_floating_ip(
            filter='externalID == "{}"'.format(ext_id))
        """
        return self.session().user.floating_ips.get_first(
            filter=vspk_filter)

    def create_floating_ip(self, domain,
                           shared_network_resource_id, address=None):
        floating_ip_data = self.vspk.NUFloatingIp(
            associated_shared_network_resource_id=shared_network_resource_id,
            address=address)

        return domain.create_child(floating_ip_data)[0]

    def get_ingress_acl_template_entries(self, vspk_filter):
        """get_ingress_acl_template_entries

        @params: ingress template filter following
                 vspk filter structure
        @return: ingress acl entries (objects) list under found template
        @Example:
        self.vsd.get_ingress_acl_entries(
            filter='externalID == "{}"'.format(ext_id))
        """
        acls = []
        templates = self.session().user.ingress_acl_templates.get(
            filter=vspk_filter) or []
        for template in templates:
            tmp = self.vspk.NUIngressACLTemplate(id=template.id)
            acl = tmp.ingress_acl_entry_templates.get()
            acls.append(acl)

        return acls

    def get_egress_acl_template_entries(self, vspk_filter):
        """get_egress_acl_template_entries

        @params: egress template filter following
                 vspk filter structure
        @return: egress acl entries (objects) list under found template
        @Example:
        self.vsd.get_egress_acl_entries(
            filter='externalID == "{}"'.format(ext_id))
        """
        acls = []
        templates = self.session().user.egress_acl_templates.get(
            filter=vspk_filter) or []
        for template in templates:
            tmp = self.vspk.NUEgressACLTemplate(id=template.id)
            acl = tmp.egress_acl_entry_templates.get()
            acls.append(acl)

        return acls

    def get_shared_network_resource(self,
                                    vspk_filter=None, by_fip_subnet_id=None):
        """get_shared_network_resource

        @params: shared network resource filter following
                 vspk filter structure
        @return: shared network resource object
        @Example:
        self.vsd.get_shared_network_resource(
            filter='externalID == "{}"'.format(ext_id))
        """
        if by_fip_subnet_id:
            shared_network_resource = self.get_shared_network_resource(
                self.get_external_id_filter(by_fip_subnet_id))

        else:
            shared_network_resource = \
                self.session().user.shared_network_resources.get_first(
                    filter=vspk_filter)

        return shared_network_resource

    @staticmethod
    def get_virtual_ip(vport, vspk_filter):
        """get_virtual_ip

        @params: vport object
                 vspk_filter following vspk filter structure
        @return: virtual_ip object
        @Example:
        self.vsd.get_virtual_ip(vport=vport,
            filter='externalID == "{}"'.format(ext_id))
        """
        return vport.virtual_ips.get_first(filter=vspk_filter)

    def get_firewall_acl(self, ent=None, vspk_filter=None,
                         by_fw_policy_id=None):
        """get_firewall_acl

        @params: enterprise object
                 vspk_filter following vspk filter structure
        @return: firewall_acl object
        @Example:
        self.vsd.get_firewall_acl(ent=ent1,
            filter='externalID == "{}"'.format(ext_id))
        """
        ent = ent or self.get_default_enterprise()
        if by_fw_policy_id:
            firewall_acl = self.get_firewall_acl(
                ent, self.get_external_id_filter(by_fw_policy_id))

        else:
            firewall_acl = ent.firewall_acls.get_first(filter=vspk_filter)

        return firewall_acl

    def get_firewall_acls(self, ent=None, vspk_filter=None,
                          by_fw_policy_id=None):
        """get_firewall_acls

        @params: enterprise object
                 vspk_filter following vspk filter structure
        @return: firewall_acl object
        @Example:
        self.vsd.get_firewall_acl(ent=ent1,
            filter='externalID == "{}"'.format(ext_id))
        """
        ent = ent or self.get_default_enterprise()
        if by_fw_policy_id:
            firewall_acls = self.get_firewall_acls(
                ent, self.get_external_id_filter(by_fw_policy_id))

        else:
            firewall_acls = ent.firewall_acls.get(filter=vspk_filter)

        return firewall_acls

    def get_firewall_rule(self, ent=None, vspk_filter=None,
                          by_fw_rule_id=None):
        """get_firewall_rule

        @params: enterprise object
                 vspk_filter following vspk filter structure
        @return: get_firewall_rule object
        @Example:
        self.vsd.get_firewall_rule(ent=ent1,
            filter='externalID == "{}"'.format(ext_id))
        """
        ent = ent or self.get_default_enterprise()
        if by_fw_rule_id:
            firewall_rule = self.get_firewall_rule(
                ent, self.get_external_id_filter(by_fw_rule_id))

        else:
            firewall_rule = ent.firewall_rules.get_first(filter=vspk_filter)

        return firewall_rule

    @staticmethod
    def get_firewall_acl_domains(acl):
        """get_firewall_acl_domains

        @params: acl object
                 get_firewall_acl NUFirewallAcl following vspk structure
        @return: get_l3domain(s) object
        @Example:
        self.vsd.get_firewall_acl_domains(acl=acl1)
        """
        return acl.domains.get()
