# Copyright 2017 - Nokia
# All Rights Reserved.

import logging
from nuage_tempest.lib.openstackData import openstackData
import pickle
import re

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)
LOG.addHandler(logging.StreamHandler())


class CMS(object):

    def __init__(self):
        self.name = 'CMS'
        self.type = "CMS"
        self.parent = 'CMS'
        self.tenantslist = []
        self.enterpriseslist = []
        self.domainslist = []
        self.zoneslist = []
        self.l2domainslist = []
        self.subnetslist = []
        self.endpointslist = []


class UserTenant(object):

    def __init__(self, name):
        self.name = name
        self.type = "Tenant"
        self.parent = 'CMS'
        '''To Do:
        Populate these feilds
        w.r.t the resources'''
        self.domainslist = []
        self.l2domainslist = []
        self.subnetslist = []
        self.endpointslist = []


class UserEnterprise(object):

    def __init__(self, name):
        self.name = name
        self.type = "Enterprise"
        self.parent = 'CMS'
        self.tenant = ''
        self.domainslist = []
        self.l2domainslist = []
        self.subnetslist = []
        self.zoneslist = []
        self.endpointslist = []


class UserDomain(object):

    def __init__(self, name, create_dict=None):
        self.name = name
        self.type = "Domain"
        self.create_dict = create_dict
        self.enterprise = ''
        self.gparent = 'CMS'
        self.tenant = ''
        self.subnetslist = []
        self.zoneslist = []
        self.endpointslist = []


class UserL2Domain(object):

    def __init__(self, name, create_dict=None):
        self.name = name
        self.type = "L2Domain"
        self.create_dict = create_dict
        self.enterprise = ''
        self.gparent = 'CMS'
        self.tenant = ''
        self.endpointslist = []


class UserSubnet(object):

    def __init__(self, name, create_dict=None):
        self.name = name
        self.type = "Subnet"
        self.create_dict = create_dict
        self.zone = ''
        self.domain = ''
        self.enterprise = ''
        self.gggparent = 'CMS'
        self.tenant = ''
        self.endpointslist = []


class UserZone(object):

    def __init__(self, name, create_dict=None):
        self.name = name
        self.type = "Zone"
        self.create_dict = create_dict
        self.domain = ''
        self.enterprise = ''
        self.ggparent = 'CMS'
        self.tenant = ''
        self.subnetslist = []
        self.endpointslist = []


class UserEndPoint(object):

    def __init__(self, name, create_dict=None):
        self.name = name
        self.type = "EndPoint"
        self.create_dict = create_dict
        self.l2domain = ''
        self.subnet = ''
        self.zone = ''
        self.enterprise = ''
        self.ggparent = 'CMS'
        self.tenant = ''
        self.domain = ''
        # Possible values: Vm/Host/Bridge
        self.eptype = ''


class UserResourceData(object):

    def __init__(self, dataStruct):
        self.DS = dataStruct

    def check_init_variables(self, **kwargs):
        available_keys = ['tenants', 'enterprises', 'domPEnt',
                          'zonPDom', 'subPZon', 'l2PEnt']
        for key in available_keys:
            try:
                kwargs[key]
            except KeyError:
                kwargs[key] = 0

    def check_process_root(self, **kwargs):
        if not isinstance(self.DS, openstackData):
            raise Exception("Provided dataStruct is not of type openstackData")
        try:
            self.root = self.DS.get_resource('CMS')
            self.root.user_data = self.root.user_data \
                if self.root.user_data else CMS()
        except Exception:
            raise Exception("Root CMS for this tree not present")

    def return_children_of_type(self, parent, type):
        children = None
        try:
            children = self.DS.get_children_resources(parent)
        except Exception:
            LOG.debug('No {} currently present in tree'.format(type))
        # except NodeIDAbsentError:
        #     raise Exception("Node ID is absent in the tree")
        return_children = []
        if not children:
            raise Exception("Children not p")
        for child in children:
            if child.user_data.type == type:
                return_children.append(child)
        return return_children

    def check_if_type_present(self, parent, type):
        '''check_if_type_present

        Return number of type object children and type of that object
        '''
        children = None
        try:
            children = self.DS.get_children_resources(parent)
        except Exception:
            LOG.debug('No {} currently present in tree'.format(type))
        LOG.debug("{} Children currently present in tree".format(
            len(children)))
        number_of_type_objects = 0
        highest_type_object_offset = 0
        for child in children:
            try:
                child.user_data.type
            except NameError:
                continue
            if child.user_data.type == type:
                number_of_type_objects += 1
                offset = re.compile(r'(\d+)$').search(child.user_data.name).\
                    group(1)
                if offset > highest_type_object_offset:
                    highest_type_object_offset = offset
        return number_of_type_objects, int(highest_type_object_offset)

    def check_return_max_offset_from_list(self, resource_list):
        try:
            offset = re.compile(r'(\d+)$').search(resource_list[-1]).group(1)
            return offset
        except IndexError:
            return 0

    def store_tree_in_file(self, os_data):
        store_file = open('openstackData.txt', 'wb')
        pickle.dump(os_data, store_file)
        store_file.close()

    def restore_tree_frm_file(self):
        restore_file = open('openstackData.txt', 'rb')
        self.DS = pickle.load(restore_file)
        restore_file.close()
        return self.DS

    def check_user_tenant(self):
        num, offset = self.check_if_type_present('CMS', 'Tenant')
        LOG.debug("{} Tenants currently present in tree".format(num))
        return num, offset

    def populate_user_tenant_in_tree(self, offset, **kwargs):
        number_of_user_tenants = kwargs['tenants']
        for i in range(1, number_of_user_tenants + 1):
            name = 't-{}'.format(offset + i)
            tenant = UserTenant(name)
            self.DS.insert_resource(name, parent='CMS', user_data=tenant)
            self.root.user_data.tenantslist.append(name)

    def check_user_enterprise_in_tenant(self):
        num, offset = self.check_if_type_present('CMS', 'Enterprise')
        LOG.debug("{} Enterprises currently present in CMS".format(num))
        return num, offset

    def populate_user_enterprise_in_tree(self, offset, **kwargs):
        number_of_user_ent = kwargs['enterprises']
        for i in range(1, number_of_user_ent + 1):
            name = 'e-{}'.format(offset + i)
            ent = UserEnterprise(name)
            self.DS.insert_resource(name, parent='CMS', user_data=ent)
            self.root.user_data.enterpriseslist.append(name)

    def check_user_domains_in_enterprise(self, enterprise):
        num, offset = self.check_if_type_present(enterprise, 'Domain')
        LOG.debug("{} Domains currently present in Enterprise {}".format(
            num, enterprise))
        return num, offset

    def populate_user_domains_in_tree(self, parent, offset, **kwargs):
        number_of_user_domains = kwargs['domPEnt']
        '''parent is parent name not type'''
        for i in range(1, number_of_user_domains + 1):
            name = '{}-d-{}'.format(parent, offset + i)
            dom = UserDomain(name)
            dom.enterprise = parent
            self.DS.insert_resource(name, parent=parent, user_data=dom)
            self.root.user_data.domainslist.append(name)
            parent_ent = self.DS.get_resource(dom.enterprise)
            parent_ent.user_data.domainslist.append(name)

    def check_user_l2domains_in_enterprise(self, enterprise):
        num, offset = self.check_if_type_present(enterprise, 'L2Domain')
        LOG.debug("{} L2Domains currently present in Enterprise {}".format(
            num, enterprise))
        return num, offset

    def populate_user_l2domains_in_tree(self, parent, offset, **kwargs):
        '''parent is parent name not type'''
        number_of_user_l2domains = kwargs['l2PEnt']
        for i in range(1, number_of_user_l2domains + 1):
            name = '{}-l2d-{}'.format(parent, offset + i)
            l2dom = UserL2Domain(name)
            l2dom.enterprise = parent
            self.DS.insert_resource(name, parent=parent, user_data=l2dom)
            self.root.user_data.l2domainslist.append(name)
            parent_ent = self.DS.get_resource(l2dom.enterprise)
            parent_ent.user_data.l2domainslist.append(name)

    def check_user_zones_in_domain(self, domain):
        num, offset = self.check_if_type_present(domain, 'Zone')
        LOG.debug("{} Zones currently present in Domain {}".format(
            num, domain))
        return num, offset

    def populate_user_zones_in_tree(self, parent, gparent, offset, **kwargs):
        '''parent is parent name not type'''
        '''gparent is parent name not type'''
        number_of_user_zones = kwargs['zonPDom']
        for i in range(1, number_of_user_zones + 1):
            name = '{}-z-{}'.format(parent, offset + i)
            zon = UserZone(name)
            zon.domain = parent
            zon.enterprise = gparent
            self.DS.insert_resource(name, parent=parent, user_data=zon)
            self.root.user_data.zoneslist.append(name)
            parent_dom = self.DS.get_resource(zon.domain)
            parent_dom.user_data.zoneslist.append(name)
            gparent_ent = self.DS.get_resource(zon.enterprise)
            gparent_ent.user_data.zoneslist.append(name)

    def check_user_subnets_in_zone(self, zone):
        num, offset = self.check_if_type_present(zone, 'Subnet')
        LOG.debug("{} Subnets currently present in Zone {}".format(num, zone))
        return num, offset

    def populate_user_subnets_in_tree(self, parent, gparent, ggparent, offset,
                                      **kwargs):
        number_of_user_subnets = kwargs['subPZon']
        for i in range(1, number_of_user_subnets + 1):
            name = '{}-s-{}'.format(parent, offset + i)
            sub = UserSubnet(name)
            sub.zone = parent
            sub.domain = gparent
            sub.enterprise = ggparent
            self.DS.insert_resource(name, parent=parent, user_data=sub)
            self.root.user_data.subnetslist.append(name)
            parent_zon = self.DS.get_resource(sub.zone)
            parent_zon.user_data.subnetslist.append(name)
            gparent_dom = self.DS.get_resource(sub.domain)
            gparent_dom.user_data.subnetslist.append(name)
            ggparent_ent = self.DS.get_resource(sub.enterprise)
            ggparent_ent.user_data.subnetslist.append(name)

    def check_endpoints_in_l2domain(self, l2domain):
        num, offset = self.check_if_type_present(l2domain, 'EndPoint')
        LOG.debug("{} Endpoints currently present in L2domain {}".format(
            num, l2domain))
        return num, offset

    def check_endpoints_in_subnet(self, subnet):
        num, offset = self.check_if_type_present(subnet, 'EndPoint')
        LOG.debug("{} Endpoints currently present in subnet {}".format(
            num, subnet))
        return num, offset

    def populate_user_endpoint_in_subnet_tree(self, parent, gparent, ggparent,
                                              gggparent, offset, **kwargs):
        number_of_endpoints = kwargs['endpPSub']
        for i in range(1, number_of_endpoints + 1):
            name = '{}-ep-{}'.format(parent, offset + i)
            ep = UserEndPoint(name)
            ep.subnet = parent
            ep.zone = gparent
            ep.domain = ggparent
            ep.enterprise = gggparent
            self.DS.insert_resource(name, parent=parent, user_data=ep)
            self.root.user_data.endpointslist.append(name)
            parent_subnet = self.DS.get_resource(ep.subnet)
            parent_subnet.user_data.endpointslist.append(name)
            gparent_zone = self.DS.get_resource(ep.zone)
            gparent_zone.user_data.endpointslist.append(name)
            ggparent_dom = self.DS.get_resource(ep.domain)
            ggparent_dom.user_data.endpointslist.append(name)
            gggparent_ent = self.DS.get_resource(ep.enterprise)
            gggparent_ent.user_data.endpointslist.append(name)

    def populate_user_endpoint_in_l2dom_tree(self, parent, gparent, offset,
                                             **kwargs):
        number_of_endpoints = kwargs['endpPL2Dom']
        for i in range(1, number_of_endpoints + 1):
            name = '{}-ep-{}'.format(parent, offset + i)
            ep = UserEndPoint(name)
            ep.l2domain = parent
            ep.enterprise = gparent
            self.DS.insert_resource(name, parent=parent, user_data=ep)
            self.root.user_data.endpointslist.append(name)
            parent_l2dom = self.DS.get_resource(ep.l2domain)
            parent_l2dom.user_data.endpointslist.append(name)
            gparent_ent = self.DS.get_resource(ep.enterprise)
            gparent_ent.user_data.endpointslist.append(name)

    def trigger_populate_tree(self, dataStruct=None, **kwargs):
        self.DS = dataStruct if dataStruct else self.DS
        self.check_init_variables(**kwargs)
        self.check_process_root(**kwargs)
        num, offset = self.check_user_tenant()
        self.populate_user_tenant_in_tree(offset, **kwargs)
        num, offset = self.check_user_enterprise_in_tenant()
        self.populate_user_enterprise_in_tree(offset, **kwargs)
        for enterprise in self.return_children_of_type('CMS', "Enterprise"):
            num1, offset1 = self.check_user_domains_in_enterprise(
                enterprise.user_data.name)
            self.populate_user_domains_in_tree(
                enterprise.user_data.name, offset1, **kwargs)
            num1, offset1 = self.check_user_l2domains_in_enterprise(
                enterprise.user_data.name)
            self.populate_user_l2domains_in_tree(
                enterprise.user_data.name, offset1, **kwargs)
            for l2domain in self.return_children_of_type(
                    enterprise.user_data.name, "L2Domain"):
                num4, offset4 = self.check_endpoints_in_l2domain(
                    l2domain.user_data.name)
                self.populate_user_endpoint_in_l2dom_tree(
                    l2domain.user_data.name, enterprise.user_data.name,
                    offset4, **kwargs)

            for domain in self.return_children_of_type(
                    enterprise.user_data.name, "Domain"):
                num2, offset2 = self.check_user_zones_in_domain(
                    domain.user_data.name)
                self.populate_user_zones_in_tree(
                    domain.user_data.name, enterprise.user_data.name, offset2,
                    **kwargs)
                for zone in self.return_children_of_type(
                        domain.user_data.name, "Zone"):
                    num3, offset3 = self.check_user_subnets_in_zone(
                        zone.user_data.name)
                    self.populate_user_subnets_in_tree(
                        zone.user_data.name, domain.user_data.name,
                        enterprise.user_data.name, offset3, **kwargs)
                    for subnet in self.return_children_of_type(
                            zone.user_data.name, "Subnet"):
                        num5, offset5 = self.check_endpoints_in_subnet(
                            subnet.user_data.name)
                        self.populate_user_endpoint_in_subnet_tree(
                            subnet.user_data.name, zone.user_data.name,
                            domain.user_data.name, enterprise.user_data.name,
                            offset5, **kwargs)
