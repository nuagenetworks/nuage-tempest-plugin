import importlib
from oslo_log import log as logging

from nuage_tempest.lib.topology import Topology

from tempest import config
from tempest.lib.common.utils import data_utils

CONF = config.CONF

LOG = logging.getLogger(__name__)


def fetch_by_name(fetcher, name):
    return fetcher.fetch(filter='name is "{}"'.format(name))[2]


def get_by_name(fetcher, name):
    return fetcher.get(filter='name is "{}"'.format(name))[0]


class VsdHelper(object):
    """VsdHelper

    Base class for VSD interactions.
    This class will have all the common function to communicate with vsd
    using vspk
    """
    CONST_ETHER_TYPE_IPV4 = "0x0800"
    CONST_ETHER_TYPE_IPV6 = "0x86DD"

    cms_id = CONF.nuage.nuage_cms_id
    default_netpartition_name = CONF.nuage.nuage_default_netpartition

    def __init__(self, base_url, user='csproot', password='csproot',
                 enterprise='csp', version=None):
        self.user = user
        self.password = password
        self.enterprise = enterprise
        self.url = 'https://{}'.format(base_url)
        self.vspk = importlib.import_module("vspk." + str(version))
        self.session = None
        self.default_enterprise = None

    def new_session(self):
        """new_session

        Start a new API session via vspk an return the corresponding
        'vspk.NUVSDSession` object.
        Note that this object is also exposed as `self.session`
        """
        self.session = self.vspk.NUVSDSession(
            username=self.user,
            password=self.password,
            enterprise=self.enterprise,
            api_url=self.url)

        self.session.start()

        self.default_enterprise = get_by_name(self.session.user.enterprises,
                                              self.default_netpartition_name)
        # TODO(team): if not available, than create a default enterprise
        if not self.default_enterprise:
            assert "Should have a default enterprise for " \
                   "OpenStack Nuage plugin"

        return self.session

    def __call__(self):
        if not self.session:
            self.session = self.new_session()
        return self.session

    def _session(self):
        if not self.session:
            self.session = self.new_session()
        return self.session

    def get_default_enterprise(self):
        if not self.default_enterprise:
            self()
        return self.default_enterprise

    def get_external_id_filter(self, object_id):
        ext_id = object_id + "@" + self.cms_id
        return 'externalID is "{}"'.format(ext_id)

    def create_l2domain_template(self, name=None, enterprise=None,
                                 dhcp_managed=True,
                                 ip_type="IPV4",
                                 cidr4=None,
                                 gateway4=None,
                                 cidr6=None,
                                 gateway6=None,
                                 **kwargs):
        if not enterprise:
            enterprise = self.get_default_enterprise()

        template_name = name or data_utils.rand_name('test-l2template')

        params = {}

        if dhcp_managed:
            params['dhcp_managed'] = dhcp_managed

        if ip_type == "IPV4":
            params.update({'ip_type': "IPV4"})
        elif ip_type == "DUALSTACK":
            params.update({'ip_type': "DUALSTACK"})

        if cidr4:
            params.update({'address': str(cidr4.ip)})
            if "netmask" in kwargs:
                netmask = kwargs['netmask']
            else:
                netmask = str(cidr4.netmask)
            params.update({'netmask': netmask})

            if gateway4:
                params.update({'gateway': gateway4})

        if ip_type == self.vspk.NUSubnet.CONST_IP_TYPE_DUALSTACK:
            params.update({'ipv6_address': str(cidr6)})

            if gateway6:
                params.update({'ipv6_gateway': gateway6})

        # add all other kwargs as attributes (key,value) pairs
        for key, value in kwargs.iteritems():
            params.update({key: value})

        template = self.vspk.NUL2DomainTemplate(
            name=template_name,
            **params)

        return enterprise.create_child(template)[0]

    def create_l2domain(self, name=None, enterprise=None, template=None):
        if not enterprise:
            enterprise = self.get_default_enterprise()

        if not template:
            assert "must provide a valid template"

        name = name or data_utils.rand_name('test-l2domain')

        l2domain = self.vspk.NUL2Domain(
            name=name,
            template=template)

        return enterprise.instantiate_child(l2domain, template)[0]

    def get_l2domain(self, enterprise=None, vspk_filter=None):
        """get_l2domain

        @params: enterprise object or enterprise id
                 filter following vspk filter structure
        @return  l2 domain object
        @Example:
        self.vsd.get_l2domain(enterprise=enterprise,
                              vspk_filter='name == "{}"'.format(name))
        self.vsd.get_l2domain(enterprise=enterprise_id,
                              vspk_filter='name == "{}"'.format(name))
        self.vsd.get_l2domain(
            vspk_filter='externalID == "{}"'.format(ext_id))
        """
        l2_domain = None
        if enterprise:
            if not isinstance(enterprise, self.vspk.NUEnterprise):
                enterprise = self.vspk.NUEnterprise(id=enterprise)
            l2_domain = enterprise.l2_domains.get_first(filter=vspk_filter)
        elif filter:
            l2_domain = self._session().user.l2_domains.get_first(
                filter=vspk_filter)
        if not l2_domain:
            LOG.warning('could not fetch the l2 domain '
                        'matching the filter "{}"'.format(vspk_filter))
        return l2_domain

    ###
    # l3 domain
    ###

    def create_l3domain_template(self, name=None, enterprise=None):
        if not enterprise:
            enterprise = self.get_default_enterprise()

        template_name = name or data_utils.rand_name('test-l3template')

        template = self.vspk.NUDomainTemplate(
            name=template_name)

        mytemplate = enterprise.create_child(template)
        return mytemplate[0]

    def create_l3domain(self, enterprise=None, name=None, template_id=None):
        if not enterprise:
            enterprise = self.get_default_enterprise()

        if not template_id:
            assert "Must provide a valid template ID"

        name = name or data_utils.rand_name('test-l3domain')

        l3domain_data = self.vspk.NUDomain(
            name=name,
            template_id=template_id)

        l3domain_tuple = enterprise.create_child(l3domain_data)

        return l3domain_tuple[0]

    def get_l3domain(self, enterprise=None, vspk_filter=None):
        """get_l3domain

        @params: enterprise object or enterprise id
                 filter following vspk filter structure
        @return: domain object
        @Example:
        self.vsd.get_l3domain(enterprise=enterprise,
                              vspk_filter='name == "{}"'.format(name))
        self.vsd.get_l3domain(enterprise=enterprise_id,
                              vspk_filter='name == "{}"'.format(name))
        self.vsd.get_l3domain(vspk_filter='externalID == "{}"'.format(ext_id))
        """
        domain = None
        if enterprise:
            if not isinstance(enterprise, self.vspk.NUEnterprise):
                enterprise = self.vspk.NUEnterprise(id=enterprise)
            domain = enterprise.domains.get_first(filter=filter)
        elif filter:
            domain = self.session.user.domains.get_first(filter=vspk_filter)
        if not domain:
            LOG.warning('could not fetch the domain matching the filter "{}"'
                        .format(vspk_filter))
        return domain

    def create_zone(self, name=None, domain=None):
        zone_name = name or data_utils.rand_name('test-zone')

        zone_data = self.vspk.NUZone(
            name=zone_name),

        zone_tuple = domain.create_child(zone_data[0])
        return zone_tuple[0]

    def create_subnet(self, name=None, zone=None,
                      ip_type="IPV4",
                      cidr4=None,
                      gateway4=None,
                      cidr6=None,
                      gateway6=None,
                      **kwargs):

        if not zone:
            assert "Must provide a valid zone"

        subnet_name = name or data_utils.rand_name('test-subnet')

        params = {}

        if cidr4:
            params.update({'address': str(cidr4.ip)})
            if "netmask" in kwargs:
                netmask = kwargs['netmask']
            else:
                netmask = str(cidr4.netmask)
            params.update({'netmask': netmask})

            if gateway4:
                params.update({'gateway': gateway4})

        if ip_type == self.vspk.NUSubnet.CONST_IP_TYPE_DUALSTACK:
            params.update({'ipv6_address': str(cidr6)})

            if gateway6:
                params.update({'ipv6_gateway': gateway6})

        subnet_data = self.vspk.NUSubnet(
            name=subnet_name,
            ip_type=ip_type,
            **params)

        subnet_tuple = zone.create_child(subnet_data)
        return subnet_tuple[0]

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

        if not allow_ipv4 and Topology.is_devstack():
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

    def get_vport_vip(self, vport_id, router_id):
        """get_vport_vip

        @params:
        @return  associated virtual ip
        TODO(team) this only works when there is only one virtual ip associated
        TODO(team) someone have a better idea on how to get down to the virtual
                   ip port?
        """
        enterprise = self.get_default_enterprise()

        domain = enterprise.domains.get_first(
            filter='externalID == "{}"'.format(
                router_id + "@" + CONF.nuage.nuage_cms_id))
        vport = domain.vports.get_first(
            filter='externalID == "{}"'.format(
                vport_id + "@" + CONF.nuage.nuage_cms_id))
        if vport:
            vip_port = vport.virtual_ips.get_first()
            return vip_port
        else:
            return None

    def get_domain_template(self, enterprise=None, filter=None):
        """get_domain_template

        @params: enterprise object or enterprise id
                 filter following vspk filter structure
        @return: domain template object
        @Example:
        self.vsd.get_domain_template(enterprise=enterprise,
                                     filter='name == "{}"'.format(name))
        self.vsd.get_domain_template(enterprise=enterprise_id,
                                     filter='name == "{}"'.format(name))
        self.vsd.get_domain_template(
            filter='externalID == "{}"'.format(ext_id))
        """
        domain_template = None
        if enterprise:
            if not isinstance(enterprise, self.vspk.NUEnterprise):
                enterprise = self.vspk.NUEnterprise(id=enterprise)
            domain_template = enterprise.domain_templates.get_first(
                filter=filter)
        elif filter:
            domain_template = self.session.user.domain_templates.get_first(
                filter=filter)
        if not domain_template:
            LOG.warning('could not fetch the domain template '
                        'matching the filter "{}"'
                        .format(filter))
        return domain_template

    def get_zone(self, domain=None, filter=None):
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
        zone = None
        if domain:
            if not isinstance(domain, self.vspk.NUDomain):
                domain = self.vspk.NUDomain(id=domain)
            zone = domain.zones.get_first(filter=filter)
        elif filter:
            zone = self.session.user.zones.get_first(filter=filter)
        if not zone:
            LOG.warning('could not fetch the zone matching the filter "{}"'
                        .format(filter))
        return zone

    def get_subnet(self, zone=None, filter=None):
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
        subnet = None
        if zone:
            if not isinstance(zone, self.vspk.NUZone):
                zone = self.vspk.NUZone(id=zone)
            subnet = zone.subnets.get_first(filter=filter)
        elif filter:
            subnet = self.session.user.subnets.get_first(filter=filter)
        if not subnet:
            LOG.warning('could not fetch the subnet matching the filter "{}"'
                        .format(filter))
        return subnet

    def get_subnet_from_domain(self, domain=None, filter=None):
        """get_subnet

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
        subnet = None
        if domain:
            if not isinstance(domain, self.vspk.NUDomain):
                domain = self.vspk.NUDomain(id=domain)
            subnet = domain.subnets.get_first(filter=filter)
        elif filter:
            subnet = self.session.user.subnets.get_first(filter=filter)
        if not subnet:
            LOG.warning('could not fetch the subnet matching the filter "{}"'
                        .format(filter))
        return subnet

    def get_vm(self, subnet=None, filter=None):
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
        vm = None
        if subnet:
            if not isinstance(subnet, self.vspk.NUSubnet):
                subnet = self.vspk.NUSubnet(id=subnet)
            vm = subnet.vms.get_first(filter=filter)
        elif filter:
            vm = self.session.user.vms.get_first(filter=filter)
        if not vm:
            LOG.warning('could not fetch the vm matching the filter "{}"'
                        .format(filter))
        return vm

    def get_subnet_dhcpoptions(self, subnet=None, filter=None):
        """get_subnet_dhcpoptions

        @params: subnet object or
                 subnet filter following vspk filter structure
        @return: subnet dhcpoptions object
        @Example:
        self.vsd.get_subnet_dhcpoptions(subnet=subnet)
        self.vsd.get_subnet_dhcpoptions(
            filter='externalID == "{}"'.format(subnet_externalID))
        """
        if not isinstance(subnet, self.vspk.NUSubnet):
            if not filter:
                LOG.error('a filter is required')
                return None
            subnet = self.session.user.subnets.get_first(filter=filter)
        dhcp_options = subnet.dhcp_options.get()
        if not dhcp_options:
            if filter:
                LOG.warning('could not fetch the dhcp options '
                            'on the subnet matching the filter "{}"'
                            .format(filter))
            else:
                LOG.error('could not fetch the dhcp options on the subnet')
        return dhcp_options

    def get_vport(self, subnet, filter):
        """get_vport

        @params: subnet object
                 vport filter following vspk filter structure
        @return: vport object
        @Example:
        self.vsd.get_vport(subnet=subnet,
            filter='externalID == "{}"'.format(ext_id))
        """
        if not isinstance(subnet, self.vspk.NUSubnet):
            LOG.error('a subnet is required')
            return None
        if not filter:
            LOG.error('a filter is required')
            return None
        vport = subnet.vports.get_first(filter=filter)
        if not vport:
            LOG.warning('could not fetch the vport from the subnet '
                        'matching the filter "{}"'.format(filter))
        return vport

    def get_vm_interface(self, filter):
        """get_vm_interface

        @params: vm interface filter following vspk filter structure
        @return: vm interface object
        @Example:
        self.vsd.get_vm_interface(
            filter='externalID == "{}"'.format(ext_id))
        """
        if not filter:
            LOG.error('a filter is required')
            return None
        vm_interface = self.session.user.vm_interfaces.get_first(
            filter=filter)
        if not vm_interface:
            LOG.warning('could not fetch the vm interface '
                        'matching the filter "{}"'.format(filter))
        return vm_interface

    def get_vm_interface_policydecisions(self, vm_interface=None, filter=None):
        """get_vm_interface_policydecisions

        @params: vm interface object or
                 vm interface filter following vspk filter structure
        @return: vm interface policydecisions object
        @Example:
        self.vsd.get_vm_interface_policydecisions(vm_interface=vm_interface)
        self.vsd.get_vm_interface_policydecisions(
            filter='externalID == "{}"'.format(vm_interface_externalID))
        """
        if not isinstance(vm_interface, self.vspk.NUVMInterface):
            if not filter:
                LOG.error('a filter is required')
                return None
            vm_interface = self.session.user.vm_interfaces.get_first(
                filter=filter)
        policy_decisions = self.vspk.NUPolicyDecision(
            id=vm_interface.policy_decision_id).fetch()
        if not policy_decisions:
            if filter:
                LOG.warning('could not fetch the policy decisions '
                            'on the vm interface matching the filter "{}"'
                            .format(filter))
            else:
                LOG.warning('could not fetch the policy decisions '
                            'on the vm interface')
        return policy_decisions

    def get_vm_interface_dhcpoptions(self, vm_interface=None, filter=None):
        """get_vm_interface_dhcpoptions

        @params: vm interface object or
                 vm interface filter following vspk filter structure
        @return: vm interface dhcpoptions object
        @Example:
        self.vsd.get_vm_interface_dhcpoptions(vm_interface=vm_interface)
        self.vsd.get_vm_interface_dhcpoptions(
            filter='externalID == "{}"'.format(vm_interface_externalID))
        """
        if not isinstance(vm_interface, self.vspk.NUVMInterface):
            if not filter:
                LOG.error('a filter is required')
                return None
            vm_interface = self.session.user.vm_interfaces.get_first(
                filter=filter)
        dhcp_options = vm_interface.dhcp_options.get()
        if not dhcp_options:
            if filter:
                LOG.error('could not fetch the dhcp options on the '
                          'vm interface matching the filter "{}"'
                          .format(filter))
            else:
                LOG.error('could not fetch the dhcp options '
                          'on the vm interface')
        return dhcp_options

    def get_ingress_acl_entry(self, filter):
        """get_ingress_acl_entry

        @params: ingress acl entry filter following vspk filter structure
        @return: ingress acl entry object
        @Example:
        self.vsd.get_ingress_acl_entry(
            filter='externalID == "{}"'.format(ext_id))
        """
        if not filter:
            LOG.error('a filter is required')
            return None
        acl = self.session.user.ingress_acl_entry_templates.get_first(
            filter=filter)
        if not acl:
            LOG.warning('could not fetch the ingress acl entry matching '
                        'the filter "{}"'.format(filter))
        return acl

    def get_egress_acl_entry(self, filter):
        """get_egress_acl_entry

        @params: egress acl entry filter following vspk filter structure
        @return: egress acl entry object
        @Example:
        self.vsd.get_egress_acl_entry(
            filter='externalID == "{}"'.format(ext_id))
        """
        if not filter:
            LOG.error('a filter is required')
            return None
        acl = self.session.user.egress_acl_entry_templates.get_first(
            filter=filter)
        if not acl:
            LOG.warning('could not fetch the egress acl entry matching '
                        'the filter "{}"'.format(filter))
        return acl

    def get_qoss(self, vport):   # TODO(Jan) - qos is with single s
        """get_qoss

        @params: vport object
        @return: qoss object
        @Example:
        self.vsd.get_qoss(vport=vport)
        """
        if not isinstance(vport, self.vspk.NUVPort):
            LOG.error('a vport is required')
            return None
        qoss = vport.qoss.get()
        if not qoss:
            LOG.error('could not fetch the qoss from the vport')
        return qoss

    def get_floating_ip(self, filter):
        """get_floating_ip

        @params: floating ip filter following vspk filter structure
        @return: floating ip object
        @Example:
        self.vsd.get_floating_ip(
            filter='externalID == "{}"'.format(ext_id))
        """
        if not filter:
            LOG.error('a filter is required')
            return None
        floating_ip = self.session.user.floating_ips.get_first(filter=filter)
        if not floating_ip:
            LOG.warning('could not fetch the floating ip matching '
                        'the filter "{}"'.format(filter))
        return floating_ip

    def create_floating_ip(self, domain, shared_network_resource_id):
        floating_ip_data = self.vspk.NUFloatingIp(
            associated_shared_network_resource_id=shared_network_resource_id
        )

        return domain.create_child(floating_ip_data)[0]

    def get_ingress_acl_entries(self, filter):
        """get_ingress_acl_entries

        @params: ingress acl entries (templates) filter following
                 vspk filter structure
        @return: ingress acl entries (objects) list
        @Example:
        self.vsd.get_ingress_acl_entries(
            filter='externalID == "{}"'.format(ext_id))
        """
        if not filter:
            LOG.error('a filter is required')
            return None
        templates = self.session.user.ingress_acl_templates.get(filter=filter)
        if not templates:
            LOG.warning('could not fetch the ingress acl entries (templates) '
                        'matching the filter "{}"'.format(filter))
            return None
        acls = []
        for template in templates:
            tmp = self.vspk.NUIngressACLTemplate(id=template.id)
            acl = tmp.ingress_acl_entry_templates.get()
            acls.append(acl)
        return acls

    def get_egress_acl_entries(self, filter):
        """get_egress_acl_entries

        @params: egress acl entries (templates) filter following
                 vspk filter structure
        @return: egress acl entries (objects) list
        @Example:
        self.vsd.get_egress_acl_entries(
            filter='externalID == "{}"'.format(ext_id))
        """
        if not filter:
            LOG.error('a filter is required')
            return None
        templates = self.session.user.egress_acl_templates.get(filter=filter)
        if not templates:
            LOG.warning('could not fetch the egress acl entries (templates) '
                        'matching the filter "{}"'.format(filter))
            return None
        acls = []
        for template in templates:
            tmp = self.vspk.NUEgressACLTemplate(id=template.id)
            acl = tmp.egress_acl_entry_templates.get()
            acls.append(acl)
        return acls

    def get_shared_network_resource(self, filter):
        """get_shared_network_resource

        @params: shared network resource filter following
                 vspk filter structure
        @return: shared network resource object
        @Example:
        self.vsd.get_shared_network_resource(
            filter='externalID == "{}"'.format(ext_id))
        """
        if not filter:
            LOG.error('a filter is required')
            return None
        shared_network_resource = \
            self.session.user.shared_network_resources.get_first(filter=filter)
        if not shared_network_resource:
            LOG.warning('could not fetch the shared network resource '
                        'matching the filter "{}"'.format(filter))
        return shared_network_resource

    def get_virtualip(self, vport, filter):
        """get_virtualip

        @params: vport object
                 virtualip filter following vspk filter structure
        @return: virtualip object
        @Example:
        self.vsd.get_virtualip(vport=vport,
            filter='externalID == "{}"'.format(ext_id))
        """
        if not isinstance(vport, self.vspk.NUVPort):
            LOG.error('a vport is required')
            return None
        if not filter:
            LOG.error('a filter is required')
            return None
        virtualip = vport.virtual_ips.get_first(filter=filter)

        if not virtualip:
            LOG.warning('could not fetch the virtualip matching the '
                        'filter "{}"'.format(filter))
        return virtualip

    def get_firewallacl(self, ent, filter):
        """get_firewallacl

        @params: enterprise object
                 firewallacl filter following vspk filter structure
        @return: firewallacl object
        @Example:
        self.vsd.get_firewallacl(ent=ent1,
            filter='externalID == "{}"'.format(ext_id))
        """
        if not isinstance(ent, self.vspk.NUEnterprise):
            LOG.error('a enterprise is required')
            return None
        if not filter:
            LOG.error('a filter is required')
            return None
        firewallacl = ent.firewall_acls.get_first(filter=filter)

        if not firewallacl:
            LOG.warning('could not fetch the firewallacl matching '
                        'the filter "{}"'.format(filter))
        return firewallacl

    def get_firewallrule(self, ent, filter):
        """get_firewallrule

        @params: enterprise object
                 get_firewallrule filter following vspk filter structure
        @return: get_firewallrule object
        @Example:
        self.vsd.get_firewallrule(ent=ent1,
            filter='externalID == "{}"'.format(ext_id))
        """
        if not isinstance(ent, self.vspk.NUEnterprise):
            LOG.error('a enterprise is required')
            return None
        if not filter:
            LOG.error('a filter is required')
            return None
        firewallrule = ent.firewall_rules.get_first(filter=filter)

        if not firewallrule:
            LOG.warning('could not fetch the firewallrule matching '
                        'the filter "{}"'.format(filter))
        return firewallrule

    def get_firewallacl_domains(self, acl):
        """get_firewallacl_domains

        @params: acl object
                 get_firewallacl NUFirewallAcl following vspk structure
        @return: get_l3domain(s) object
        @Example:
        self.vsd.get_firewallacl_domains(acl=acl1)
        """
        if not isinstance(acl, self.vspk.NUFirewallAcl):
            LOG.error('a firewall acl is required')
            return None
        domains = acl.domains.get()

        if not domains:
            LOG.error('could not fetch the domains associated to firewall')
        return domains
