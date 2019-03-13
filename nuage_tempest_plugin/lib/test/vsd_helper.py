# Copyright 2017 - Nokia
# All Rights Reserved.

import importlib
from netaddr import IPAddress
import re
from six import iteritems

from tempest.lib.common.utils import data_utils

from bambou.exceptions import BambouHTTPError
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

LOG = Topology.get_logger(__name__)


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
    def base_uri_to_version(base_uri):
        pattern = re.compile(r'(v\d+$)')
        match = pattern.search(base_uri)
        version = match.group()
        return str(version)

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

        if not self.default_enterprise:
            assert "Should have a default enterprise for Nuage plugin"

        return self._session

    def session(self):
        if not self._session:
            self._session = self.new_session()
        return self._session

    def get_default_enterprise(self):
        if not self.default_enterprise:
            self.session()
        return self.default_enterprise

    def external_id(self, id):
        return id + '@' + self.cms_id

    @staticmethod
    def filter_str(keys, values):
        filter_str = ""
        if not (isinstance(keys, list) and isinstance(values, list)):
            keys = [keys]
            values = [values]
        for key, value in zip(keys, values):
            if filter_str:
                filter_str += " and "
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

            if not gateway4 and enable_dhcpv4:
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

            if not gateway6 and enable_dhcpv6:
                gateway6 = str(IPAddress(cidr6) + 1)
            if gateway6:
                params.update({'ipv6_gateway': gateway6})

        # add all other kwargs as attributes (key,value) pairs
        for key, value in iteritems(kwargs):
            params.update({key: value})

        template = self.vspk.NUL2DomainTemplate(
            name=template_name,
            **params)

        return enterprise.create_child(template)[0]

    def delete_l2domain_template(self, l2dom_t_id):
        return self.nuage_rest_client.delete_l2domaintemplate(l2dom_t_id)

    def create_l2domain(self, name=None, enterprise=None, template=None):
        if enterprise and not isinstance(enterprise, self.vspk.NUEnterprise):
            # get enterprise by _name_
            enterprise = self.get_enterprise_by_name(enterprise)

        if not enterprise:
            enterprise = self.get_default_enterprise()

        if not template:
            assert "must provide a valid template"

        name = name or data_utils.rand_name('test-l2domain')

        l2domain = self.vspk.NUL2Domain(
            name=name,
            template=template)

        return enterprise.instantiate_child(l2domain, template)[0]

    def delete_l2domain(self, l2dom_id):
        return self.nuage_rest_client.delete_l2domain(l2dom_id)

    def get_l2domain(self, enterprise=None, vspk_filter=None,
                     by_subnet_id=None, by_network_id=None,
                     cidr=None, ip_type=4):
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
        if enterprise and not isinstance(enterprise, self.vspk.NUEnterprise):
            # get enterprise by _name_
            enterprise = self.get_enterprise_by_name(enterprise)

        if not enterprise:
            enterprise = self.get_default_enterprise()

        if vspk_filter:
            l2_domain = enterprise.l2_domains.get_first(filter=vspk_filter)
        elif by_subnet_id:
            l2_domain = self.get_l2domain(
                enterprise, self.get_external_id_filter(by_subnet_id))
        elif by_network_id and cidr:
            if ip_type == 6:
                vspk_filter = self.filter_str(
                    ['externalID', 'IPv6Address'],
                    [self.external_id(by_network_id), cidr])
                l2_domain = self.get_l2domain(enterprise, vspk_filter)
            else:
                vspk_filter = self.filter_str(
                    ['externalID', 'address'],
                    [self.external_id(by_network_id),
                     cidr.split('/')[0]])
                l2_domain = self.get_l2domain(enterprise, vspk_filter)
        else:
            LOG.error('a qualifier is required')
            return None
        if not l2_domain:
            LOG.warning('could not fetch the l2 domain '
                        'matching the filter "{}"'.format(vspk_filter))
        return l2_domain

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

    def create_l3domain(self, name=None, enterprise=None, template_id=None):
        if enterprise and not isinstance(enterprise,
                                         self.vspk.NUEnterprise):
            # get enterprise by _name_
            enterprise = self.get_enterprise_by_name(enterprise)

        elif not enterprise:
            enterprise = self.get_default_enterprise()

        if not template_id:
            assert "Must provide a valid template ID"

        name = name or data_utils.rand_name('test-l3domain')

        l3domain_data = self.vspk.NUDomain(
            name=name,
            template_id=template_id)

        return enterprise.create_child(l3domain_data)[0]

    def delete_domain(self, l3dom_id):
        return self.delete_l3domain(l3dom_id)

    def delete_l3domain(self, l3dom_id):
        return self.nuage_rest_client.delete_domain(l3dom_id)

    def get_l3_domain_by_network_id_and_cidr(self, by_network_id, cidr,
                                             ip_type=4):
        # get the subnet
        subnet = self.get_subnet_from_domain(by_network_id=by_network_id,
                                             cidr=cidr, ip_type=ip_type)
        if not subnet:
            return None

        # get the parent, which is the zone
        try:
            zone, _ = self.vspk.NUZone(id=subnet.parent_id).fetch()
        except BambouHTTPError as exc:
            if exc.connection.response.status_code == 404:
                return None
            else:
                raise

        # get the parent, which is the domain
        try:
            domain, _ = self.vspk.NUDomain(id=zone.parent_id).fetch()
        except BambouHTTPError as exc:
            if exc.connection.response.status_code == 404:
                return None
            else:
                raise

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
        if vspk_filter:
            if enterprise and not isinstance(enterprise,
                                             self.vspk.NUEnterprise):
                # get enterprise by _name_
                enterprise = self.get_enterprise_by_name(enterprise)

            elif not enterprise:
                enterprise = self.get_default_enterprise()

            domain = enterprise.domains.get_first(filter=vspk_filter)

        elif by_router_id:
            domain = self.get_l3domain(
                enterprise, self.get_external_id_filter(by_router_id))
        else:
            LOG.error('a qualifier is required')
            return None
        if not domain:
            LOG.warning('could not fetch the domain matching the filter "{}"'
                        .format(vspk_filter))
        return domain

    def create_zone(self, name=None, domain=None, **kwargs):
        zone_name = name or data_utils.rand_name('test-zone')

        params = {}

        for key, value in iteritems(kwargs):
            params.update({key: value})

        zone_data = self.vspk.NUZone(
            name=zone_name,
            **params)

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

        if not zone:
            assert "Must provide a valid zone"

        subnet_name = name or data_utils.rand_name('test-subnet')

        params = {}
        params.update({'enable_dhcpv4': enable_dhcpv4})
        params.update({'enable_dhcpv6': enable_dhcpv6})

        for key, value in iteritems(kwargs):
            params.update({key: value})

        if cidr4:
            params.update({'address': str(cidr4.ip)})
            if "netmask" not in kwargs:
                params.update({'netmask': str(cidr4.netmask)})

            if gateway4:
                params.update({'gateway': gateway4})

        if cidr6:
            params.update({'ipv6_address': str(cidr6)})

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

    def define_any_to_any_acl(self, domain,
                              ingress='FORWARD', egress='FORWARD',
                              allow_ipv4=True,
                              allow_ipv6=False,
                              stateful=False, spoof=False):
        def create_acl_templates(the_domain, allow_spoofing):
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

        # always delete first
        for acl in domain.ingress_acl_templates.get():
            acl.delete()
        for acl in domain.egress_acl_templates.get():
            acl.delete()
        # and then create new
        res = []
        ingress_tpl, egress_tpl = create_acl_templates(domain, spoof)

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

        if not vport_id:
            assert "must provide a vport id"

        if not router_id:
            assert "must provide a router id"

        domain = enterprise.domains.get_first(
            filter='externalID == "{}"'.format(
                router_id + "@" + Topology.cms_id))
        vport = domain.vports.get_first(
            filter='externalID == "{}"'.format(
                vport_id + "@" + Topology.cms_id))
        if vport:
            vip_port = vport.virtual_ips.get_first()
            return vip_port
        else:
            return None

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
        if vspk_filter:
            if enterprise and not isinstance(enterprise,
                                             self.vspk.NUEnterprise):
                # get enterprise by _name_
                enterprise = self.get_enterprise_by_name(enterprise)

            elif not enterprise:
                enterprise = self.get_default_enterprise()

            domain_template = enterprise.domain_templates.get_first(
                filter=vspk_filter)

        elif by_router_id:
            domain_template = self.get_domain_template(
                enterprise, self.get_external_id_filter(by_router_id))
        else:
            LOG.error('a qualifier is required')
            return None
        if not domain_template:
            LOG.warning('could not fetch the domain template '
                        'matching the filter "{}"'
                        .format(vspk_filter))
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
        if vspk_filter:
            if domain:
                if not isinstance(domain, self.vspk.NUDomain):
                    domain = self.vspk.NUDomain(id=domain)
                zone = domain.zones.get_first(filter=vspk_filter)
            else:
                zone = self.session().user.zones.get_first(filter=vspk_filter)

        elif by_router_id:  # this is actually not advised as there will be 2
            zone = self.get_zone(
                domain, self.get_external_id_filter(by_router_id))
        else:
            LOG.error('a qualifier is required')
            return None
        if not zone:
            LOG.warning('could not fetch the zone matching the filter "{}"'
                        .format(vspk_filter))
        return zone

    def get_subnet(self, zone=None, vspk_filter=None, by_subnet_id=None,
                   by_network_id=None, cidr=None, ip_type=4):
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
        if vspk_filter:
            if zone:
                if not isinstance(zone, self.vspk.NUZone):
                    zone = self.vspk.NUZone(id=zone)
                subnet = zone.subnets.get_first(filter=vspk_filter)
            else:
                subnet = self.session().user.subnets.get_first(
                    filter=vspk_filter)

        elif by_subnet_id:
            subnet = self.get_subnet(
                zone, self.get_external_id_filter(by_subnet_id))
        elif by_network_id and cidr:
            if ip_type == 6:
                vspk_filter = self.filter_str(
                    ['externalID', 'IPv6Address'],
                    [self.external_id(by_network_id), cidr])
                subnet = self.get_subnet(zone, vspk_filter)
            else:
                vspk_filter = self.filter_str(
                    ['externalID', 'address'],
                    [self.external_id(by_network_id),
                     cidr.split('/')[0]])
                subnet = self.get_subnet(zone, vspk_filter)
        else:
            LOG.error('a qualifier is required')
            return None
        if not subnet:
            LOG.warning('could not fetch the subnet matching the filter "{}"'
                        .format(filter))
        return subnet

    def get_subnet_from_domain(self, domain=None, vspk_filter=None,
                               by_subnet_id=None, by_network_id=None,
                               cidr=None, ip_type=4):
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
        if vspk_filter:
            if domain:
                if not isinstance(domain, self.vspk.NUDomain):
                    domain = self.vspk.NUDomain(id=domain)
                subnet = domain.subnets.get_first(filter=vspk_filter)
            else:
                subnet = self.session().user.subnets.get_first(
                    filter=vspk_filter)

        elif by_subnet_id:
            subnet = self.get_subnet_from_domain(
                domain, self.get_external_id_filter(by_subnet_id))
        elif by_network_id and cidr:
            if ip_type == 6:
                vspk_filter = self.filter_str(
                    ['externalID', 'IPv6Address'],
                    [self.external_id(by_network_id), cidr])
                subnet = self.get_subnet_from_domain(domain, vspk_filter)
            else:
                vspk_filter = self.filter_str(
                    ['externalID', 'address'],
                    [self.external_id(by_network_id),
                     cidr.split('/')[0]])
                subnet = self.get_subnet_from_domain(domain, vspk_filter)
        else:
            LOG.error('a qualifier is required')
            return None
        if not subnet:
            LOG.warning('could not fetch the subnet matching the filter "{}"'
                        .format(filter))
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
        if vspk_filter:
            if subnet:
                if not isinstance(subnet, self.vspk.NUSubnet):
                    subnet = self.vspk.NUSubnet(id=subnet)
                vm = subnet.vms.get_first(filter=vspk_filter)
            else:
                vm = self.session().user.vms.get_first(filter=vspk_filter)

        elif by_device_id:
            vm = self.get_vm(
                subnet, self.get_external_id_filter(by_device_id))
        else:
            LOG.error('a qualifier is required')
            return None
        if not vm:
            LOG.warning('could not fetch the vm matching the filter "{}"'
                        .format(vspk_filter))
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
        if not isinstance(subnet, self.vspk.NUSubnet):
            if not vspk_filter:
                LOG.error('a filter is required')
                return None
            subnet = self.session().user.subnets.get_first(filter=vspk_filter)

        dhcp_options = subnet.dhcp_options.get()
        if not dhcp_options:
            if vspk_filter:
                LOG.warning('could not fetch the dhcp options '
                            'on the subnet matching the filter "{}"'
                            .format(vspk_filter))
            else:
                LOG.error('could not fetch the dhcp options on the subnet')

        return dhcp_options

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
        if not isinstance(l2domain, self.vspk.NUL2Domain):
            if not vspk_filter:
                LOG.error('a filter is required')
                return None
            l2domain = self.session().user.l2domain.get_first(
                filter=vspk_filter)

        dhcp_options = l2domain.dhcp_options.get()
        if not dhcp_options:
            if vspk_filter:
                LOG.warning('could not fetch the dhcp options '
                            'on the subnet matching the filter "{}"'
                            .format(vspk_filter))
            else:
                LOG.error('could not fetch the dhcp options on the subnet')

        return dhcp_options

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
        if l2domain and not isinstance(l2domain, self.vspk.NUL2Domain):
            LOG.error('a l2domain is required')
            return None
        if subnet and not isinstance(subnet, self.vspk.NUSubnet):
            LOG.error('a subnet is required')
            return None
        parent = l2domain if l2domain else subnet if subnet else None

        if not parent:
            LOG.error('a parent is required')
            return None

        if vspk_filter:
            vport = parent.vports.get_first(filter=vspk_filter)

        elif by_port_id:
            vport = self.get_vport(
                l2domain, subnet, self.get_external_id_filter(by_port_id))
        else:
            LOG.error('a qualifier is required')
            return None
        if not vport:
            LOG.warning('could not fetch the vport from the l2domain/subnet '
                        'matching the filter "{}"'.format(filter))
        return vport

    def get_vm_interface(self, vspk_filter):
        """get_vm_interface

        @params: vm interface filter following vspk filter structure
        @return: vm interface object
        @Example:
        self.vsd.get_vm_interface(
            filter='externalID == "{}"'.format(ext_id))
        """
        vm_interface = self.session().user.vm_interfaces.get_first(
            filter=vspk_filter)
        if not vm_interface:
            LOG.warning('could not fetch the vm interface '
                        'matching the filter "{}"'.format(vspk_filter))
        return vm_interface

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
        if not isinstance(vm_interface, self.vspk.NUVMInterface):
            if not vspk_filter:
                LOG.error('a filter is required')
                return None
            vm_interface = self.session().user.vm_interfaces.get_first(
                filter=vspk_filter)
        policy_decisions = self.vspk.NUPolicyDecision(
            id=vm_interface.policy_decision_id).fetch()
        if not policy_decisions:
            if vspk_filter:
                LOG.warning('could not fetch the policy decisions '
                            'on the vm interface matching the filter "{}"'
                            .format(vspk_filter))
            else:
                LOG.warning('could not fetch the policy decisions '
                            'on the vm interface')
        return policy_decisions

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
        elif vspk_filter:
            vm_interface = self.session().user.vm_interfaces.get_first(
                filter=vspk_filter)
        else:
            LOG.error('a filter is required')
            return None

        dhcp_options = vm_interface.dhcp_options.get()
        if not dhcp_options:
            if vspk_filter:
                LOG.error('could not fetch the dhcp options on the '
                          'vm interface matching the filter "{}"'
                          .format(vspk_filter))
            else:
                LOG.error('could not fetch the dhcp options '
                          'on the vm interface')
        return dhcp_options

    def get_ingress_acl_entry(self, vspk_filter):
        """get_ingress_acl_entry

        @params: ingress acl entry filter following vspk filter structure
        @return: ingress acl entry object
        @Example:
        self.vsd.get_ingress_acl_entry(
            filter='externalID == "{}"'.format(ext_id))
        """
        acl = self.session().user.ingress_acl_entry_templates.get_first(
            filter=vspk_filter)
        if not acl:
            LOG.warning('could not fetch the ingress acl entry matching '
                        'the filter "{}"'.format(vspk_filter))
        return acl

    def get_egress_acl_entry(self, vspk_filter):
        """get_egress_acl_entry

        @params: egress acl entry filter following vspk filter structure
        @return: egress acl entry object
        @Example:
        self.vsd.get_egress_acl_entry(
            filter='externalID == "{}"'.format(ext_id))
        """
        acl = self.session().user.egress_acl_entry_templates.get_first(
            filter=vspk_filter)
        if not acl:
            LOG.warning('could not fetch the egress acl entry matching '
                        'the filter "{}"'.format(vspk_filter))
        return acl

    def get_floating_ip(self, vspk_filter):
        """get_floating_ip

        @params: floating ip filter following vspk filter structure
        @return: floating ip object
        @Example:
        self.vsd.get_floating_ip(
            filter='externalID == "{}"'.format(ext_id))
        """
        floating_ip = self.session().user.floating_ips.get_first(
            filter=vspk_filter)
        if not floating_ip:
            LOG.warning('could not fetch the floating ip matching '
                        'the filter "{}"'.format(filter))
        return floating_ip

    def create_floating_ip(self, domain,
                           shared_network_resource_id, address=None):
        floating_ip_data = self.vspk.NUFloatingIp(
            associated_shared_network_resource_id=shared_network_resource_id,
            address=address)

        return domain.create_child(floating_ip_data)[0]

    def get_ingress_acl_entries(self, vspk_filter):
        """get_ingress_acl_entries

        @params: ingress acl entries (templates) filter following
                 vspk filter structure
        @return: ingress acl entries (objects) list
        @Example:
        self.vsd.get_ingress_acl_entries(
            filter='externalID == "{}"'.format(ext_id))
        """
        templates = self.session().user.ingress_acl_templates.get(
            filter=vspk_filter)
        if not templates:
            LOG.warning('could not fetch the ingress acl entries (templates) '
                        'matching the filter "{}"'.format(vspk_filter))
            return None
        acls = []
        for template in templates:
            tmp = self.vspk.NUIngressACLTemplate(id=template.id)
            acl = tmp.ingress_acl_entry_templates.get()
            acls.append(acl)
        return acls

    def get_egress_acl_entries(self, vspk_filter):
        """get_egress_acl_entries

        @params: egress acl entries (templates) filter following
                 vspk filter structure
        @return: egress acl entries (objects) list
        @Example:
        self.vsd.get_egress_acl_entries(
            filter='externalID == "{}"'.format(ext_id))
        """
        templates = self.session().user.egress_acl_templates.get(
            filter=vspk_filter)
        if not templates:
            LOG.warning('could not fetch the egress acl entries (templates) '
                        'matching the filter "{}"'.format(vspk_filter))
            return None
        acls = []
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
        if vspk_filter:
            shared_network_resource = \
                self.session().user.shared_network_resources.get_first(
                    filter=vspk_filter)
        elif by_fip_subnet_id:
            shared_network_resource = self.get_shared_network_resource(
                self.get_external_id_filter(by_fip_subnet_id))
        else:
            LOG.error('a qualifier is required')
            return None
        if not shared_network_resource:
            LOG.warning('could not fetch the shared network resource '
                        'matching the filter "{}"'.format(vspk_filter))
        return shared_network_resource

    def get_virtual_ip(self, vport, vspk_filter):
        """get_virtual_ip

        @params: vport object
                 vspk_filter following vspk filter structure
        @return: virtual_ip object
        @Example:
        self.vsd.get_virtual_ip(vport=vport,
            filter='externalID == "{}"'.format(ext_id))
        """
        if not isinstance(vport, self.vspk.NUVPort):
            LOG.error('a vport is required')
            return None
        virtual_ip = vport.virtual_ips.get_first(filter=vspk_filter)

        if not virtual_ip:
            LOG.warning('could not fetch the virtualip matching the '
                        'filter "{}"'.format(vspk_filter))
        return virtual_ip

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
        if vspk_filter:
            if ent and not isinstance(ent, self.vspk.NUEnterprise):
                LOG.error('a enterprise is required')
                return None
            else:
                ent = self.get_default_enterprise()
            firewall_acl = ent.firewall_acls.get_first(filter=vspk_filter)
        elif by_fw_policy_id:
            firewall_acl = self.get_firewall_acl(
                ent, self.get_external_id_filter(by_fw_policy_id))
        else:
            LOG.error('a qualifier is required')
            return None

        if not firewall_acl:
            LOG.warning('could not fetch the firewall_acl matching '
                        'the filter "{}"'.format(vspk_filter))
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
        if not by_fw_policy_id:
            if ent and not isinstance(ent, self.vspk.NUEnterprise):
                LOG.error('a enterprise is required')
                return None
            else:
                ent = self.get_default_enterprise()
            if vspk_filter:
                firewall_acls = ent.firewall_acls.get(filter=vspk_filter)
            else:
                firewall_acls = ent.firewall_acls.get()
        elif by_fw_policy_id:
            firewall_acls = self.get_firewall_acls(
                ent, self.get_external_id_filter(by_fw_policy_id))

        if not firewall_acls:
            LOG.warning('could not fetch the firewall_acls matching '
                        'the filter "{}"'.format(vspk_filter))
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
        if vspk_filter:
            if ent:
                if not isinstance(ent, self.vspk.NUEnterprise):
                    LOG.error('a enterprise is required')
                    return None
            else:
                ent = self.get_default_enterprise()
            firewall_rule = ent.firewall_rules.get_first(filter=vspk_filter)
        elif by_fw_rule_id:
            firewall_rule = self.get_firewall_rule(
                ent, self.get_external_id_filter(by_fw_rule_id))
        else:
            LOG.error('a qualifier is required')
            return None

        if not firewall_rule:
            LOG.warning('could not fetch the firewall_rule matching '
                        'the filter "{}"'.format(vspk_filter))
        return firewall_rule

    def get_firewall_acl_domains(self, acl):
        """get_firewall_acl_domains

        @params: acl object
                 get_firewall_acl NUFirewallAcl following vspk structure
        @return: get_l3domain(s) object
        @Example:
        self.vsd.get_firewall_acl_domains(acl=acl1)
        """
        if not isinstance(acl, self.vspk.NUFirewallAcl):
            LOG.error('a firewall acl is required')
            return None
        domains = acl.domains.get()

        if not domains:
            LOG.error('could not fetch the domains associated to firewall')
        return domains
