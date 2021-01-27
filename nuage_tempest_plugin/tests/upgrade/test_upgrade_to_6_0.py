# Copyright 2017 NOKIA
# All Rights Reserved.

import random

from netaddr import IPAddress
from netaddr import IPNetwork
from oslo_utils import uuidutils

from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.mixins.l3 import L3Mixin
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.lib.utils import data_utils as nuage_data_utils
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.tests.upgrade.test_upgrade_base \
    import NuageUpgradeMixin
from nuage_tempest_plugin.tests.upgrade.test_upgrade_base \
    import NuageUpgradeSubTestMixin

LOG = Topology.get_logger(__name__)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# CAUTION : THIS SUITE IS HIGHLY INTRUSIVE
#           - it relies heavily on devstack env
#           - it installs new packages in the tox env (like neutron)
#           - it changes the neutron branch out of which neutron runs
#           - it restarts neutron
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class UpgradeResourcesMixin(NuageUpgradeSubTestMixin):

    def __init__(self, parent):
        super(UpgradeResourcesMixin, self).__init__(parent)
        self._resources = {
            'networks': [],
            'l2_subnets': [],
            'l3_subnets': [],
            'external_subnets': [],
            'l2_ports': [],
            'l3_ports': [],
            'routers': [],
            'l2_domains': [],
            'sec_groups': [],
            'vms': [],
            'rts': [],
            'nuage_l3_subnets': []}

        self._default_vms = 1
        self._default_vports = 10 if self._is_large_setup else 1

    @staticmethod
    def _pure_v6_subnet_warning(subnet_id):
        return ("Please delete legacy single-stack ipv6 subnet "
                "'{}'".format(subnet_id))

    @staticmethod
    def _invalid_cidr_warning(ip_address, subnet_id):
        return ('IP Address {} is not valid or cannot be in '
                'reserved address space. Please recreate subnet '
                '{} with a valid cidr.'.format(ip_address, subnet_id))

    @staticmethod
    def _inconsistent_dhcp_warning(subnet_id):
        return ("Subnet '{}' is DHCP-enabled on OpenStack but it is "
                "DHCP-disabled on VSD. Please fix this inconsistent "
                "DHCP setting.".format(subnet_id))

    @staticmethod
    def _vsd_managed_subnet_gateway_ip_in_use_warning(
            subnet_id, port_id, fixed_ip, ip_version=4):
        if ip_version == 4:
            return ('For VSD managed dhcp enabled subnet {}, the gateway {}'
                    ' is used by port {}. Please use an available IP as '
                    'gateway.'.format(subnet_id, fixed_ip, port_id))
        else:
            return ('For VSD managed dhcp enabled subnet {}, the IPv6Gateway '
                    '{} is used by port {}. Please use an available IP as '
                    'IPv6Gateway.'.format(subnet_id, fixed_ip, port_id))


class UpgradeOsMgdResourcesMixin(UpgradeResourcesMixin):

    def _create_os_resources(self, topologies):
        LOG.info('{}: _create_os_resources'.format(self.cls_name))
        # network/subnet/port/vm
        # create resources
        for topology in topologies:
            network = self.parent.create_network()
            self._resources['networks'].append(network)

            temp_subnets = []
            for ip_version in topology['ip_versions']:
                subnet = self.parent.create_subnet(
                    network, ip_version=ip_version,
                    mask_bits=24 if ip_version == 4 else 64,
                    enable_dhcp=topology['DHCPv{}'.format(ip_version)])
                temp_subnets.append(subnet)

            # create a security group
            sec_group = self.parent.create_open_ssh_security_group()
            self._resources['sec_groups'].append(sec_group)
            if topology['l3']:
                router = self.parent.create_router(
                    external_network_id=self.parent.ext_net_id
                )
                self._resources['routers'].append(router)
                self.parent.router_attach(router, temp_subnets[0])

                for subnet in temp_subnets:
                    self._resources['l3_subnets'].append(subnet)

                # create ports (not on singlestack v6)
                if not self._is_singlestack_v6(temp_subnets[0]):
                    for _ in range(topology['vports']):
                        port = self.parent.create_port(
                            network, security_groups=[sec_group['id']])
                        self._resources['l3_ports'].append(port)
            else:
                for subnet in temp_subnets:
                    self._resources['l2_subnets'].append(subnet)

                # create ports (not on singlestack v6)
                if not self._is_singlestack_v6(temp_subnets[0]):
                    for _ in range(topology['vports']):
                        port = self.parent.create_port(
                            network, security_groups=[sec_group['id']])
                        self._resources['l2_ports'].append(port)

                # create redirect target/rule for the l2
                # (not for singlestack v6)
                if 4 in topology['ip_versions']:
                    self._create_redirection_target_and_rule(
                        temp_subnets[0], sec_group)

            # create VMs (not on singlestack v6)
            if not self._is_singlestack_v6(temp_subnets[0]):
                for _ in range(topology['vms']):
                    # multi-nic VM upgrade tested.
                    port1 = self.parent.create_port(
                        network, security_groups=[sec_group['id']])
                    port2 = self.parent.create_port(
                        network, security_groups=[sec_group['id']])
                    vm = self.parent.create_tenant_server(
                        ports=[port1, port2])
                    self._resources['vms'].append(vm)

        # external subnet
        params = {'router:external': True}
        ext_network = self.parent.create_network(
            manager=self.parent.admin_manager, **params)
        cidr = nuage_data_utils.gimme_a_cidr_address()
        subnet_params = {
            'network': ext_network,
            'cidr': IPNetwork(cidr),
            'subnet_name': data_utils.rand_name('subnet'),
            'ip_version': self._ip_version
        }
        self._resources['external_subnets'].append(
            self.parent.create_subnet(manager=self.parent.admin_manager,
                                      **subnet_params))

    def _verify_os_managed_resources(self, verify_acl=True,
                                     verify_vm_connectivity=True,
                                     fake_vm_present=False):
        LOG.info('{}: _verify_os_managed_resources'.format(self.cls_name))
        log_data = self._get_log_data()

        # externalID lookup for the L2Domains and add them to self.resources
        for subnet in self._resources['l2_subnets']:
            if self._is_singlestack_v6(subnet):
                self.parent.assertIn(
                    self._pure_v6_subnet_warning(subnet['id']),
                    log_data,
                    "Pure v6 subnet warning haven't logged correctly for: "
                    "{}.".format(subnet['id']))
            else:
                l2dom = self._vsd.get_l2domain(by_subnet=subnet)
                self.parent.assertIsNotNone(l2dom)
                self._verify_l2_dom(l2dom, subnet)
                self._resources['l2_domains'].append(l2dom)

                if verify_acl:
                    # verify the acl templates/entries for the l2 subnets
                    self._verify_acl_templates(subnet['network_id'])
                    self._verify_acl_template_entries(subnet['network_id'])
                    self._verify_ingress_adv_fwd_templates(
                        subnet['network_id'])
                    self._verify_ingress_adv_fwd_entries(subnet['network_id'])

                if subnet.get('enable_dhcp'):
                    # check dhcp port/fixed IP if dhcp is enabled
                    filters = {
                        'device_owner': 'network:dhcp:nuage',
                        'network_id': subnet['network_id']
                    }
                    dhcp_port = self.parent.list_ports(**filters)[0]
                    self.parent.assertTrue(
                        self._is_fixed_ip_address_family_correct(
                            ip_version=subnet['ip_version'],
                            fixed_ips=dhcp_port['fixed_ips']))

        # externalID lookup for the l3 subnets and add them to self.resources
        for subnet in self._resources['l3_subnets']:
            if self._is_singlestack_v6(subnet):
                self.parent.assertIn(
                    self._pure_v6_subnet_warning(subnet['id']),
                    log_data,
                    "Pure v6 subnet warning haven't logged correctly for: "
                    "{}.".format(subnet['id']))
            else:
                nuage_l3_subnet = self._vsd.get_subnet(
                    by_subnet=subnet)
                self.parent.assertIsNotNone(nuage_l3_subnet)
                self._verify_l3_nuage_subnet(nuage_l3_subnet, subnet)
                self._resources['nuage_l3_subnets'].append(nuage_l3_subnet)

        for external_subnet in self._resources['external_subnets']:
            nuage_l3_subnet = self._vsd.get_subnet(
                by_subnet=external_subnet)
            self.parent.assertIsNotNone(nuage_l3_subnet)

        for port in self._resources['l2_ports']:
            l2dom = self._find_l2_dom_in_resources(port['network_id'])
            vport = self._vsd.get_vport(l2domain=l2dom,
                                        by_port_id=port['id'])
            self.parent.assertIsNotNone(vport)

            if fake_vm_present:
                vm_interface = self._vsd.get_vm_interface(
                    vspk_filter='externalID == "{}"'.format
                    (self._get_external_id(port['id'])))
                ipv4s = [ip['ip_address'] for ip in port['fixed_ips']
                         if IPAddress(ip['ip_address']).version == 4]
                ipv6s = [ip['ip_address'] for ip in port['fixed_ips']
                         if IPAddress(ip['ip_address']).version == 6]
                if len(ipv4s) <= 1 and len(ipv6s) <= 1:
                    if ipv4s:
                        self.parent.assertEqual(ipv4s[0],
                                                vm_interface.ip_address)
                    if ipv6s:
                        self.parent.assertEqual(
                            ipv6s[0], vm_interface.ipv6_address.split('/')[0])

        for port in self._resources['l3_ports']:
            l3sub = self._find_l3_nuage_sub_in_resources(port['network_id'])
            vport = self._vsd.get_vport(subnet=l3sub, by_port_id=port['id'])
            self.parent.assertIsNotNone(vport)

        for vm in self._resources['vms']:
            # Verify VM resources -> vm_interface
            for port in vm.ports:
                # find vm_interface through domain
                vm_interface = self._vsd.get_vm_interface(
                    vspk_filter='externalID == "{}"'.format
                    (self._get_external_id(port['id'])))
                ipv4s = [ip['ip_address'] for ip in port['fixed_ips']
                         if IPAddress(ip['ip_address']).version == 4]
                ipv6s = [ip['ip_address'] for ip in port['fixed_ips']
                         if IPAddress(ip['ip_address']).version == 6]
                if len(ipv4s) <= 1 and len(ipv6s) <= 1:
                    if ipv4s:
                        self.parent.assertEqual(
                            ipv4s[0], vm_interface.ip_address)
                    if ipv6s:
                        self.parent.assertEqual(
                            ipv6s[0], vm_interface.ipv6_address.split('/')[0])
                else:
                    pass
                    # TODO(Team) check spoofing is enabled
            # create another vm and test the connectivity for the first vm
            # it will be forced to be deployed on the controller node
            # hypervisor = os.popen('hostname').read()
            vm_network = (vm.networks[0] if vm.networks
                          else vm.ports[0].get('parent_network'))
            if verify_vm_connectivity:
                vm2 = self.parent.create_tenant_server(
                    networks=[vm_network],
                    security_groups=[self._resources['sec_groups'][0]],
                    # availability_zone='nova:{}'.format(hypervisor.strip()),
                    prepare_for_connectivity=True,
                    cleanup=False, cleanup_fip_infra=True)
                self.parent.assert_ping(vm2, vm, vm_network)
                # and destroy it (safe on need for quota)
                self.parent.delete_server(vm2.id)
                verify_vm_connectivity = False

        # cleanup the rts otherwise can't do router attach test.
        for rt in self._resources['rts']:
            self.parent.delete_redirection_target(
                rt['nuage_redirect_target']['id'])

        for subnet in self._resources['l2_subnets']:
            if subnet['ip_version'] == 4:
                # checking for IPv4 is enough because only supported cases
                # singlestack v4 and dualstack
                router = self.parent.create_router(
                    external_network_id=self.parent.ext_net_id,
                    cleanup=False
                )
                self.parent.router_attach(router, subnet, cleanup=False)
                self.parent.router_detach(router, subnet)
                self.parent.delete_router(router)

    # l2/l3 methods are same but might differ when extended.
    def _verify_l2_dom(self, l2dom, subnet):
        if subnet['ip_version'] == 4:
            self.parent.assertEqual(l2dom.enable_dhcpv4, subnet['enable_dhcp'])
            # can't create dns option for the v6 subnets in 5.4
            dhcp_options = l2dom.dhcp_options.get(
                filter='externalID == "{}"'.format(
                    self._get_external_id(subnet['id'])))
            self.parent.assertNotEmpty(dhcp_options)
        else:
            self.parent.assertEqual(l2dom.enable_dhcpv6, subnet['enable_dhcp'])
        self.parent.assertTrue(l2dom.dhcp_managed)

    def _verify_l3_nuage_subnet(self, nuage_sub, subnet):
        if subnet['ip_version'] == 4:
            self.parent.assertEqual(nuage_sub.enable_dhcpv4,
                                    subnet['enable_dhcp'])
        else:
            self.parent.assertEqual(nuage_sub.enable_dhcpv6,
                                    subnet['enable_dhcp'])

    # not to do another lookups for the domains while fetching the vports
    def _find_l2_dom_in_resources(self, network_id):
        for l2dom in self._resources['l2_domains']:
            if network_id in l2dom.external_id:
                return l2dom
        return None

    @staticmethod
    def _is_fixed_ip_address_family_correct(ip_version, fixed_ips):
        for fixed_ip in fixed_ips:
            ip = IPNetwork(fixed_ip['ip_address'])
            if ip.version == ip_version:
                return True
        return False

    def _is_singlestack_v6(self, subnet):
        # determines if the subnet is singlestack v6 or not
        net = self.parent.get_network(subnet['network_id'])
        if subnet['ip_version'] == 6 and len(net['subnets']) == 1:
            return True
        return False

    # not to do another lookups for the domains while fetching the vports
    def _find_l3_nuage_sub_in_resources(self, network_id):
        for l3sub in self._resources['nuage_l3_subnets']:
            if network_id in l3sub.external_id:
                return l3sub
        return None

    def _verify_acl_templates(self, network_id):
        l2dom = self._find_l2_dom_in_resources(network_id)
        ingress_acl_temp = l2dom.ingress_acl_templates.get(
            filter='externalID == "{}"'.format(
                self._get_external_id(network_id)))[0]
        self.parent.assertIsNotNone(ingress_acl_temp)

        egress_acl_temp = l2dom.egress_acl_templates.get(
            filter='externalID == "{}"'.format(
                self._get_external_id(network_id)))[0]
        self.parent.assertIsNotNone(egress_acl_temp)

    def _verify_redirection_targets(self, network_id):
        l2dom = self._find_l2_dom_in_resources(network_id)
        redirection_target = l2dom.redirection_targets.get(
            filter='externalID == "{}"'.format(
                self._get_external_id(network_id)))[0]
        self.parent.assertIsNotNone(redirection_target)

    def _verify_ingress_adv_fwd_templates(self, network_id):
        l2dom = self._find_l2_dom_in_resources(network_id)
        ingress_adv_fwd_temp = l2dom.ingress_adv_fwd_templates.get(
            filter='externalID == "{}"'.format(
                self._get_external_id(network_id)))[0]
        self.parent.assertIsNotNone(ingress_adv_fwd_temp)

    def _verify_acl_template_entries(self, network_id):
        ingress_acl_entries = self._vsd.get_ingress_acl_template_entries(
            vspk_filter='externalID == "{}"'.format(
                self._get_external_id(network_id)))[0]
        self.parent.assertNotEmpty(ingress_acl_entries)

        egress_acl_entries = self._vsd.get_egress_acl_template_entries(
            vspk_filter='externalID == "{}"'.format(
                self._get_external_id(network_id)))[0]
        self.parent.assertNotEmpty(egress_acl_entries)

    def _verify_ingress_adv_fwd_entries(self, network_id):
        ingress_acl_entries = self._get_ingress_adv_fwd_entries(
            network_id=network_id,
            vspk_filter='externalID == "{}"'.format(
                self._get_external_id(network_id)))[0]
        self.parent.assertNotEmpty(ingress_acl_entries)

    def _get_ingress_adv_fwd_entries(self, network_id, vspk_filter):
        l2dom = self._find_l2_dom_in_resources(network_id)
        templates = l2dom.ingress_adv_fwd_templates.get(
            filter=vspk_filter)
        acls = []
        for template in templates:
            tmp = self._vsd.vspk.NUIngressAdvFwdTemplate(id=template.id)
            acl = tmp.ingress_adv_fwd_entry_templates.get()
            acls.append(acl)
        return acls

    def _create_redirection_target_and_rule(self, subnet, sec_group):
        # parameters for nuage redirection target
        post_body = {'insertion_mode': 'VIRTUAL_WIRE',
                     'redundancy_enabled': 'False',
                     'subnet_id': subnet['id'],
                     'name': 'RT_{}'.format(subnet['name'])}

        # Creating redirection Target
        rt = self.parent.create_redirection_target(**post_body)
        self._resources['rts'].append(rt)

        # Creating Redirect Target Rule
        rt_id = str(rt['nuage_redirect_target']['id'])
        rule_body = {'priority': '100',
                     'redirect_target_id': rt_id,
                     'protocol': '6',
                     'origin_group_id': str(sec_group['id']),
                     'remote_ip_prefix': '20.0.0.0/24',
                     'action': 'FORWARD', 'port_range_min': '50',
                     'port_range_max': '120'}

        rtrule = self.parent.create_redirection_target_rule(**rule_body)
        return rt, rtrule


class UpgradeVsdMgdResourcesMixin(UpgradeResourcesMixin):
    _is_l3 = None

    def __init__(self, parent):
        super(UpgradeVsdMgdResourcesMixin, self).__init__(parent)

        self.cidr4_1 = '10.9.8.0/24'
        self.gateway4_1 = '10.9.8.1'
        self.cidr6_1 = 'cafe:babe::/64'
        self.gateway6_1 = 'cafe:babe::1'

        self.cidr4_2 = '10.9.7.0/24'
        self.gateway4_2 = '10.9.7.1'
        self.cidr6_2 = 'cafe:cafe::/64'
        self.gateway6_2 = 'cafe:cafe::1'

        self.cidr4_3 = '10.9.6.0/24'
        self.gateway4_3 = '10.9.6.4'
        self.cidr6_3 = 'cafe:cafa::/64'
        self.gateway6_3 = 'cafe:cafa::4'

        self.l2domain_template_1 = None
        self.l2domain_template_2 = None
        self.l2domain_template_3 = None

        self.vsd_subnet_1 = None
        self.vsd_subnet_2 = None
        self.vsd_subnet_3 = None

        self.sub6_1 = None
        self.sub6_2 = None
        self.sub6_3 = None

        self.port = None

    def _create_vsd_mgd_os_resources(self):
        LOG.info('{}: _create_vsd_mgd_os_resources'.format(self.cls_name))

        if self._is_l3:
            vsd_l3domain_template = self.parent.\
                vsd_create_l3domain_template()
            vsd_l3domain = self.parent.vsd_create_l3domain(
                template_id=vsd_l3domain_template.id)
            vsd_zone = self.parent.vsd_create_zone(domain=vsd_l3domain)
            self.vsd_subnet_1 = self.parent.create_vsd_subnet(
                zone=vsd_zone,
                cidr4=IPNetwork(self.cidr4_1),
                gateway4=self.gateway4_1,
                cidr6=IPNetwork(self.cidr6_1),
                gateway6=self.gateway6_1,
                ip_type='DUALSTACK',
                dhcp_managed=True)

            self.vsd_subnet_2 = self.parent.create_vsd_subnet(
                zone=vsd_zone,
                cidr4=IPNetwork(self.cidr4_2),
                gateway4=self.gateway4_2,
                cidr6=IPNetwork(self.cidr6_2),
                gateway6=self.gateway6_2,
                ip_type='DUALSTACK',
                dhcp_managed=True)

            self.vsd_subnet_3 = self.parent.create_vsd_subnet(
                zone=vsd_zone,
                cidr4=IPNetwork(self.cidr4_3),
                gateway4=self.gateway4_3,
                cidr6=IPNetwork(self.cidr6_3),
                gateway6=self.gateway6_3,
                ip_type='DUALSTACK',
                dhcp_managed=True)

            self._vsd.define_any_to_any_acl(vsd_l3domain)
            network = self.parent.create_network()
            self._resources['l3_subnets'].append(
                self.parent.create_l3_vsd_managed_subnet(
                    network, self.vsd_subnet_1))
            self.sub6_1 = self.parent.create_l3_vsd_managed_subnet(
                network, self.vsd_subnet_1, ip_version=6)
            self._resources['l3_subnets'].append(self.sub6_1)
            self._resources['l3_subnets'].append(
                self.parent.create_l3_vsd_managed_subnet(
                    network, self.vsd_subnet_2))
            self.sub6_2 = self.parent.create_l3_vsd_managed_subnet(
                network, self.vsd_subnet_2, ip_version=6)
            self._resources['l3_subnets'].append(self.sub6_2)
            sub4_3 = self.parent.create_l3_vsd_managed_subnet(
                network, self.vsd_subnet_3)
            self._resources['l3_subnets'].append(sub4_3)
            self.sub6_3 = self.parent.create_l3_vsd_managed_subnet(
                network, self.vsd_subnet_3, ip_version=6)
            self._resources['l3_subnets'].append(self.sub6_3)
        else:
            self.l2domain_template_1 = \
                self.parent.vsd_create_l2domain_template(
                    cidr4=IPNetwork(self.cidr4_1),
                    gateway4=self.gateway4_1,
                    cidr6=IPNetwork(self.cidr6_1),
                    gateway6=self.gateway6_1,
                    ip_type='DUALSTACK',
                    dhcp_managed=True)
            l2domain_1 = self.parent.vsd_create_l2domain(
                template=self.l2domain_template_1)

            self.l2domain_template_2 = \
                self.parent.vsd_create_l2domain_template(
                    cidr4=IPNetwork(self.cidr4_2),
                    gateway4=self.gateway4_2,
                    cidr6=IPNetwork(self.cidr6_2),
                    gateway6=self.gateway6_2,
                    ip_type='DUALSTACK',
                    dhcp_managed=True)
            l2domain_2 = self.parent.vsd_create_l2domain(
                template=self.l2domain_template_2)

            self.l2domain_template_3 = \
                self.parent.vsd_create_l2domain_template(
                    cidr4=IPNetwork(self.cidr4_3),
                    gateway4=self.gateway4_3,
                    cidr6=IPNetwork(self.cidr6_3),
                    gateway6=self.gateway6_3,
                    ip_type='DUALSTACK',
                    dhcp_managed=True)
            l2domain_3 = self.parent.vsd_create_l2domain(
                template=self.l2domain_template_3)

            network = self.parent.create_network()
            self._resources['l2_subnets'].append(
                self.parent.create_l2_vsd_managed_subnet(
                    network, l2domain_1))
            self.sub6_1 = self.parent.create_l2_vsd_managed_subnet(
                network, l2domain_1, ip_version=6)
            self._resources['l2_subnets'].append(self.sub6_1)
            self._resources['l2_subnets'].append(
                self.parent.create_l2_vsd_managed_subnet(
                    network, l2domain_2))
            self.sub6_2 = self.parent.create_l2_vsd_managed_subnet(
                network, l2domain_2, ip_version=6)
            self._resources['l2_subnets'].append(self.sub6_2)
            sub4_3 = self.parent.create_l2_vsd_managed_subnet(
                network, l2domain_3)
            self._resources['l2_subnets'].append(sub4_3)
            self.sub6_3 = self.parent.create_l2_vsd_managed_subnet(
                network, l2domain_3, ip_version=6)
            self._resources['l2_subnets'].append(self.sub6_3)

        # Create a port using IPv6Gateway ip
        fixed_ips = [
            {
                'subnet_id': sub4_3['id']
            }, {
                'ip_address': self.gateway6_3,
                'subnet_id': self.sub6_3['id']
            }
        ]
        self.port = self.parent.create_port(network, fixed_ips=fixed_ips)

    def _verify_vsd_mgd_os_resources(self, dryrun=False):
        if dryrun:

            with open('upgrade_report.json') as report_file:
                report_data = report_file.read()

            # validate inconsistent DHCP setting warnings
            self.parent.assertIn(self._inconsistent_dhcp_warning(
                self.sub6_1['id']), report_data)
            self.parent.assertIn(self._inconsistent_dhcp_warning(
                self.sub6_2['id']), report_data)
            self.parent.assertIn(self._inconsistent_dhcp_warning(
                self.sub6_3['id']), report_data)

            # refetch the resources with v6 API
            if self._is_l3:
                vsd_subnet_1 = self._vspk.NUSubnet(
                    id=self.vsd_subnet_1.id).fetch()[0]
                vsd_subnet_1.enable_dhcpv6 = True
                vsd_subnet_1.ipv6_gateway = self.gateway6_1
                vsd_subnet_1.save()

                vsd_subnet_2 = self._vspk.NUSubnet(
                    id=self.vsd_subnet_2.id).fetch()[0]
                vsd_subnet_2.enable_dhcpv6 = True
                vsd_subnet_2.ipv6_gateway = self.gateway6_2
                vsd_subnet_2.save()

                vsd_subnet_3 = self._vspk.NUSubnet(
                    id=self.vsd_subnet_3.id).fetch()[0]
                vsd_subnet_3.enable_dhcpv6 = True
                vsd_subnet_3.ipv6_gateway = self.gateway6_3
                vsd_subnet_3.save()
            else:
                l2domain_template_1 = self._vspk.NUL2DomainTemplate(
                    id=self.l2domain_template_1.id).fetch()[0]
                l2domain_template_1.enable_dhcpv6 = True
                l2domain_template_1.ipv6_gateway = self.gateway6_1
                l2domain_template_1.save()

                l2domain_template_2 = self._vspk.NUL2DomainTemplate(
                    id=self.l2domain_template_2.id).fetch()[0]
                l2domain_template_2.enable_dhcpv6 = True
                l2domain_template_2.ipv6_gateway = self.gateway6_2
                l2domain_template_2.save()

                l2domain_template_3 = self._vspk.NUL2DomainTemplate(
                    id=self.l2domain_template_3.id).fetch()[0]
                l2domain_template_3.enable_dhcpv6 = True
                l2domain_template_3.ipv6_gateway = self.gateway6_3
                l2domain_template_3.save()

        else:

            # TODO(Kris) FIX THIS
            # with open('upgrade_report.json') as report_file:
            #     report_data = report_file.read()
            # self.assertIn(self._vsd_managed_subnet_gateway_ip_in_use_warning(
            #     self.sub6_3['id'], self.port['id'], self.gateway6_3,
            #     ip_version=6),
            #     report_data)

            if self._is_l3:
                filters = {
                    'device_owner': 'network:dhcp:nuage',
                    'network_id':
                        self._resources['l3_subnets'][0]['network_id']
                }
            else:
                filters = {
                    'device_owner': 'network:dhcp:nuage',
                    'network_id':
                        self._resources['l2_subnets'][0]['network_id']
                }
            dhcp_ports = self.parent.list_ports(**filters)
            for dhcp_port in dhcp_ports:
                if len(dhcp_port['fixed_ips']) == 2:
                    fixed_ip1 = IPAddress(
                        dhcp_port['fixed_ips'][0]['ip_address'])
                    fixed_ip2 = IPAddress(
                        dhcp_port['fixed_ips'][1]['ip_address'])
                    if fixed_ip1.version == 4:
                        if fixed_ip1 in IPNetwork(self.cidr4_1):
                            self.parent.assertTrue(
                                fixed_ip2 in IPNetwork(self.cidr6_1))
                        elif IPAddress(fixed_ip1) in IPNetwork(self.cidr4_2):
                            self.parent.assertTrue(
                                fixed_ip2 in IPNetwork(self.cidr6_2))
                        else:
                            self.parent.fail(
                                "Fixed IP doesn't match with the cidr")
                    else:
                        if fixed_ip1 in IPNetwork(self.cidr6_1):
                            self.parent.assertTrue(
                                fixed_ip2 in IPNetwork(self.cidr4_1))
                        elif IPAddress(fixed_ip1) in IPNetwork(self.cidr6_2):
                            self.parent.assertTrue(
                                fixed_ip2 in IPNetwork(self.cidr4_2))
                        else:
                            self.parent.fail(
                                "Fixed IP doesn't match with the cidr")


class UpgradePgMixin(UpgradeResourcesMixin):

    def _create_sriov_and_baremetal_ports(self):
        kwargs = {'segments': [
            {'provider:network_type': 'vxlan'},
            {'provider:network_type': 'vlan',
             'provider:physical_network': 'physnet1',
             'provider:segmentation_id': str(random.randrange(4095))}
        ]}
        network = self.parent.create_network(
            manager=self.parent.admin_manager, **kwargs)
        cidr = nuage_data_utils.gimme_a_cidr_address()
        subnet_params = {
            'network': network,
            'cidr': IPNetwork(cidr),
            'subnet_name': data_utils.rand_name('subnet'),
            'ip_version': self._ip_version
        }
        subnet1 = self.parent.create_subnet(
            manager=self.parent.admin_manager, mask_bits=24, **subnet_params)

        gateway_vsg = self._vsd_client.create_gateway(
            data_utils.rand_name(name='vsg'),
            data_utils.rand_name(name='sys_id'), 'VSG')[0]
        self.parent.addCleanup(
            self._vsd_client.delete_gateway, gateway_vsg['ID']
        )
        gw_port_sriov = self._vsd_client.create_gateway_port(
            'gw_port_sriov', 'gw_port_sriov', 'ACCESS', gateway_vsg['ID'],
            extra_params={'VLANRange': '0-4095'})[0]

        gw_port_baremetal = self._vsd_client.create_gateway_port(
            'gw_port_baremetal', 'gw_port_baremetal', 'ACCESS',
            gateway_vsg['ID'], extra_params={'VLANRange': '0-4095'})[0]

        pci_slot = '0000:03:{}.6'.format(str(random.randrange(10, 100)))
        mapping = {'switch_id': gateway_vsg['systemID'],
                   'port_id': gw_port_sriov['physicalName'],
                   'host_id': 'host2',
                   'pci_slot': pci_slot
                   }
        create_data = {'binding:vnic_type': 'direct',
                       'binding:host_id': 'host2',
                       'binding:profile': {
                           'pci_slot': pci_slot,
                           'physical_network': 'physnet1',
                           'pci_vendor_info': '8086:10ed'},
                       'network': network
                       }

        with self.parent.switchport_mapping(do_delete=False,
                                            **mapping) as switch_map:
            self.parent.addCleanup(
                self._network_client_admin.delete_switchport_mapping,
                switch_map['id'])
            self.parent.create_port(manager=self.parent.admin_manager,
                                    **create_data)

        baremetal_port_args = {
            'name': 'baremetal-port',
            'network': network,
            'port_security_enabled': False,
            'binding:vnic_type': 'baremetal',
            'binding:host_id': 'dummy',
            'binding:profile': {
                'local_link_information': [
                    {'port_id': gw_port_baremetal['name'],
                     'switch_info': gateway_vsg['systemID']}]
            }}
        self.parent.create_port(manager=self.parent.admin_manager,
                                **baremetal_port_args)
        return subnet1

    def _create_virtio_vrsg_host_bridge_ports(self, bridge_vport=True,
                                              virtio_port_count=3):
        # create VRSG bridge port
        gateway_vrsg = self._vsd_client.create_gateway(
            data_utils.rand_name(name='vrsg'),
            data_utils.rand_name(name='sys_id'), 'VRSG')[0]
        self.parent.addCleanup(
            self._vsd_client.delete_gateway, gateway_vrsg['ID']
        )

        network = self.parent.create_network()
        cidr = nuage_data_utils.gimme_a_cidr(netmask=23)
        subnet = self.parent.create_subnet(network, cidr=cidr,
                                           mask_bits=cidr.prefixlen)
        # we can't test L3 with bridge ports.
        if bridge_vport:
            gw_port_vrsg_bridge = self._vsd_client.create_gateway_port(
                'gw_port_vrsg_bridge', 'gw_port_vrsg_bridge', 'ACCESS',
                gateway_vrsg['ID'], extra_params={'VLANRange': '0-4095'})[0]

            kwargs = {
                'gatewayport': gw_port_vrsg_bridge['ID'],
                'value': str(random.randrange(4095))
            }
            gw_vlan = self._network_client.\
                create_gateway_vlan(**kwargs)

            # Create bridge vport
            kwargs = {
                'gatewayvlan': gw_vlan['nuage_gateway_vlan']['id'],
                'port': None,
                'subnet': subnet['id'],
                'tenant': self._network_client.tenant_id
            }
            gw_port_host = self._network_client.create_gateway_vport(**kwargs)
            self.parent.addCleanup(
                self._network_client.delete_gateway_vport,
                gw_port_host['nuage_gateway_vport']['id']
            )

        # create VRSG host port
        port = self.parent.create_port(network, device_owner='nuage:vip')

        gw_port_vrsg_host = self._vsd_client.create_gateway_port(
            'gw_port_vrsg_host', 'gw_port_vrsg_host', 'ACCESS',
            gateway_vrsg['ID'], extra_params={'VLANRange': '0-4095'})[0]

        kwargs = {
            'gatewayport': gw_port_vrsg_host['ID'],
            'value': str(random.randrange(4095))
        }
        gw_vlan = self._network_client.create_gateway_vlan(**kwargs)

        # Create host vport
        kwargs = {
            'gatewayvlan': gw_vlan['nuage_gateway_vlan']['id'],
            'port': port['id'],
            'subnet': None,
            'tenant': self._network_client.tenant_id
        }
        self._network_client.create_gateway_vport(**kwargs)

        # Create virtio ports
        for _ in range(virtio_port_count):
            self.parent.create_port(network, port_security_enabled=False)

        return subnet


class UpgradePgL2Mixin(UpgradePgMixin):
    def __init__(self, parent):
        super(UpgradePgL2Mixin, self).__init__(parent)
        self.subnet1 = None
        self.subnet2 = None

    def _create_pg_allow_all(self, port_count):
        self.subnet1 = self._create_sriov_and_baremetal_ports()
        self.subnet2 = self._create_virtio_vrsg_host_bridge_ports(
            bridge_vport=True, virtio_port_count=port_count)

    def _verify_pg_allow_all(self):
        l2dom1 = self._vsd.get_l2domain(by_subnet=self.subnet1)

        policy_groups = l2dom1.policy_groups.get()
        self.parent.assertEqual(1, len(policy_groups))
        self.parent.assertEqual('HARDWARE', policy_groups[0].type)
        self.parent.assertEqual(constants.NUAGE_PLCY_GRP_ALLOW_ALL_HW,
                                policy_groups[0].name)
        self.parent.assertEqual(constants.NUAGE_PLCY_GRP_ALLOW_ALL_HW,
                                policy_groups[0].description)
        self.parent.assertEqual('hw:' + self._get_external_id(
            constants.NUAGE_PLCY_GRP_ALLOW_ALL), policy_groups[0].external_id)

        vports = policy_groups[0].vports.get()
        self.parent.assertEqual(2, len(vports))
        l2dom2 = self._vsd.get_l2domain(by_subnet=self.subnet2)

        policy_groups = l2dom2.policy_groups.get()
        self.parent.assertEqual(1, len(policy_groups))
        self.parent.assertEqual('SOFTWARE', policy_groups[0].type)
        self.parent.assertEqual(constants.NUAGE_PLCY_GRP_ALLOW_ALL,
                                policy_groups[0].name)
        self.parent.assertEqual(constants.NUAGE_PLCY_GRP_ALLOW_ALL,
                                policy_groups[0].description)
        self.parent.assertEqual(self._get_external_id(
            constants.NUAGE_PLCY_GRP_ALLOW_ALL),
            policy_groups[0].external_id)
        vports = policy_groups[0].vports.get()
        self.parent.assertEqual(5, len(vports))


class UpgradePgL3Mixin(UpgradePgMixin):

    def __init__(self, parent):
        super(UpgradePgL3Mixin, self).__init__(parent)
        self.l3_domain = None
        self.policy_group = None
        self.vport_num = []

    def _create_pg_allow_all(self, l2_domain_count, vport_num):
        self.vport_num = vport_num

        router = self.parent.create_router()
        subnet = None
        l2_domain = None

        for i in range(l2_domain_count):
            # last subnet and l2domain will have the most port, which will
            # earn to keep it's policy group.
            subnet = self._create_virtio_vrsg_host_bridge_ports(
                bridge_vport=False, virtio_port_count=vport_num[i])

            if i == l2_domain_count - 1:
                # create a port with port security
                network = self.parent.get_network(subnet['network_id'])
                self.parent.create_port(network)
                l2_domain = self._vsd.get_l2domain(by_subnet=subnet)
            self.parent.router_attach(router, subnet)

        self.l3_domain = self._vsd.get_l3_domain_by_subnet(
            by_subnet=subnet)

        # policy group that has the most vports before upgrade
        self.policy_group = self.l3_domain.policy_groups.get(
            filter='externalID == "{}"'.format(self._get_external_id(
                'PG_FOR_LESS_SECURITY_{}_VM'.format(l2_domain.id))))[0]

    def _verify_pg_allow_all(self):
        # fetch all the policy groups under the l3_domain
        policy_groups = self.l3_domain.policy_groups.get()
        self.parent.assertEqual(2, len(policy_groups))
        policy_group_allow_all = self.l3_domain.policy_groups.get(
            filter='externalID == "{}"'.format(
                self._get_external_id(constants.NUAGE_PLCY_GRP_ALLOW_ALL)))[0]
        vports = policy_group_allow_all.vports.get_count()
        self.parent.assertEqual(sum(self.vport_num), vports)
        self.parent.assertEqual(self.policy_group.id,
                                policy_group_allow_all.id)


class UpgradeTo60Test(NuageBaseTest, L3Mixin, NuageUpgradeMixin):

    _from_release = '5.4'
    _to_release = '6.0'

    @classmethod
    def skip_checks(cls):
        super(UpgradeTo60Test, cls).skip_checks()
        cls._upgrade_skip_check()

    @classmethod
    def setup_clients(cls):
        super(UpgradeTo60Test, cls).setup_clients()
        cls.vsd_client = NuageRestClient()

    @classmethod
    def setUpClass(cls):
        super(UpgradeTo60Test, cls).setUpClass()
        cls._set_up()

    def test_upgrade(self):
        #   ----------------------------------------------------   #
        #
        #   T H I S   I S   T H E   T E S T
        #
        #   Mind : there can be only one upgrade test!
        #   ----------------------------------------------------   #
        self._test_upgrade(alembic_expected=True)

    def _test_pre_upgrade_neg(self):
        LOG.info('[{}] _test_pre_upgrade_neg:start'.format(self.cls_tag))
        self._execute_the_upgrade_script(expected_exit_code=1)
        error_message = ("Can't upgrade because plugin doesn't have v6"
                         " API set. Please change it (/nuage/api/v5_0)"
                         " to v6 api (e.g. /nuage/api/v6)"
                         " and run again.")
        self.assertIn(error_message, self._fetch_upgrade_log_data())
        LOG.info('[{}] _test_pre_upgrade_neg:end'.format(self.cls_tag))

    #   --------------------------------------------------------   #
    #
    #   S  U  B    T  E  S  T  S   ( " M I N I - W O R L D S " )
    #
    #   --------------------------------------------------------   #

    class UpgradeUnsupportedCidrL2Test(UpgradeOsMgdResourcesMixin):
        cidr4 = IPNetwork('169.254.32.0/24')
        cidr6 = IPNetwork('fe80::/64')

        def __init__(self, parent):
            super(UpgradeTo60Test.UpgradeUnsupportedCidrL2Test,
                  self).__init__(parent)
            self.sub4 = None
            self.sub6 = None

        def setup(self):
            network = self.parent.create_network()
            self.sub4 = self.parent.create_subnet(
                network, enable_dhcp=False, cidr=self.cidr4)

            network2 = self.parent.create_network()
            self.parent.create_subnet(
                network2, enable_dhcp=False)
            self.sub6 = self.parent.create_subnet(
                network2, enable_dhcp=False, ip_version=6, cidr=self.cidr6)

        def verify(self):
            log_data = self._get_log_data()
            self.parent.assertIn(
                self._invalid_cidr_warning(self.cidr4.ip,
                                           self.sub4['id']), log_data)
            self.parent.assertIn(
                self._invalid_cidr_warning(self.cidr6,
                                           self.sub6['id']), log_data)

    class UpgradeOsMgdSingleStackL2Test(UpgradeOsMgdResourcesMixin):
        _is_l3 = False

        def setup(self):
            topologies = (
                [
                    {'l3': self._is_l3, 'ip_versions': [4], 'DHCPv4': True,
                     'vms': self._default_vms, 'vports': self._default_vports},
                    # {'l3': self.is_l3, 'ip_versions': [4], 'DHCPv4': False,
                    #  'vms': _default_vms, 'vports': _default_vports},
                    {'l3': self._is_l3, 'ip_versions': [6], 'DHCPv6': True,
                     'vms': self._default_vms, 'vports': self._default_vports},
                    # {'l3': self.is_l3, 'ip_versions': [6], 'DHCPv6': False,
                    #  'vms': _default_vms, 'vports': _default_vports}
                ])
            self._create_os_resources(topologies)

        def verify(self):
            self._verify_os_managed_resources()

    class UpgradeOsMgdSingleStackL3Test(UpgradeOsMgdSingleStackL2Test):
        _is_l3 = True

    class UpgradeOsMgdSingleStackBulkSubnetTest(UpgradeOsMgdResourcesMixin):
        def setup(self):
            if self._is_large_setup:

                # Upgrade with 300 l2domain.
                # I couldn't try more than 350 because creation fails without
                # any error.
                # main goal of this test was to test paging, it's not an issue,
                # I tried to lowered the page size and didn't have any problem.

                for i in range(300):
                    network = self.parent.create_network()
                    self._resources['networks'].append(network)

                    for ip_version in [4, 6]:
                        subnet = self.parent.create_subnet(
                            network, ip_version=ip_version,
                            enable_dhcp=True)
                        self._resources['l2_subnets'].append(subnet)

            else:
                LOG.warn('{}: Skipping bulk test in non-large setup'.format(
                    self.parent.cls_tag))

        def verify(self):
            if self._is_large_setup:
                self._verify_os_managed_resources(verify_acl=False)

    class UpgradeOsMgdSingleStackBulkVmTest(UpgradeOsMgdResourcesMixin):
        def setup(self):
            if self._is_large_setup:

                network = self.parent.create_network()
                self._resources['networks'].append(network)

                subnet = self.parent.create_subnet(
                    network, ip_version=4,
                    mask_bits=24,
                    enable_dhcp=False)
                self._resources['l2_subnets'].append(subnet)

                for vport in range(100):
                    kwargs = {
                        'device_owner': 'compute:nova',
                        'device_id': uuidutils.generate_uuid(),
                        'binding:host_id':
                            '11111111-1111-1111-1111-111111111111',
                        'network': network
                    }
                    port = self.parent.create_port(
                        manager=self.parent.admin_manager, **kwargs)
                    self._resources['l2_ports'].append(port)

            else:
                LOG.warn('{}: Skipping bulk test in non-large setup'.format(
                    self.parent.cls_tag))

        def verify(self):
            if self._is_large_setup:
                self._verify_os_managed_resources(verify_acl=False,
                                                  verify_vm_connectivity=False,
                                                  fake_vm_present=True)

    class UpgradeOsMgdDualStackL2Test(UpgradeOsMgdResourcesMixin):
        _is_l3 = False

        def setup(self):
            topologies = (
                [
                    {'l3': self._is_l3, 'ip_versions': [4, 6], 'DHCPv4': True,
                     'DHCPv6': True, 'vms': self._default_vms,
                     'vports': self._default_vports},
                    # {'l3': self.is_l3, 'ip_versions': [4, 6], 'DHCPv4': True,
                    #  'DHCPv6': False, 'vms': _default_vms,
                    #  'vports': _default_vports},
                    {'l3': self._is_l3, 'ip_versions': [4, 6], 'DHCPv4': False,
                     'DHCPv6': True, 'vms': self._default_vms,
                     'vports': self._default_vports},
                    # {'l3': self.is_l3, 'ip_versions': [4, 6],
                    #  'DHCPv4': False,
                    #  'DHCPv6': False, 'vms': _default_vms,
                    #  'vports': _default_vports}
                ])
            self._create_os_resources(topologies)

        def verify(self):
            self._verify_os_managed_resources()

    class UpgradeOsMgdDualStackL3Test(UpgradeOsMgdDualStackL2Test):
        _is_l3 = True

    class UpgradeVsdMgdDualStackL2Test(UpgradeVsdMgdResourcesMixin):
        _is_l3 = False

        def setup(self):
            self._create_vsd_mgd_os_resources()

        def verify(self):
            self._verify_vsd_mgd_os_resources()

    class UpgradeVsdMgdDualStackL3Test(UpgradeVsdMgdDualStackL2Test):
        _is_l3 = True

    class UpgradePgAllowAllL2SkipForNow(UpgradePgL2Mixin):
        def setup(self):
            self._create_pg_allow_all(port_count=3)

        def verify(self):
            self._verify_pg_allow_all()

    class UpgradePgAllowAllL3SkipForNow(UpgradePgL3Mixin):
        def setup(self):
            l2_domain_count = 5
            self._create_pg_allow_all(
                l2_domain_count=l2_domain_count,
                vport_num=list(range(1, l2_domain_count + 1)))

        def verify(self):
            self._verify_pg_allow_all()

    class UpgradePgAllowAllL3LargeScaleTest(UpgradePgL3Mixin):
        def setup(self):
            if self._is_large_setup:
                l2_domain_count = 2
                self._create_pg_allow_all(
                    l2_domain_count=l2_domain_count,
                    vport_num=[251, 252])
            else:
                LOG.warn('{}: Skipping bulk test in non-large setup'.format(
                    self.parent.cls_tag))

        def verify(self):
            if self._is_large_setup:
                self._verify_pg_allow_all()

    class UpgradeWithOrphansTest(UpgradeOsMgdResourcesMixin):
        def setup(self):
            network = self.parent.create_network()
            self._resources['networks'].append(network)

            subnet = self.parent.create_subnet(
                network, ip_version=4,
                enable_dhcp=False)
            self._resources['l2_subnets'].append(subnet)
            l2_dom = self._vsd.get_l2domain(by_subnet=subnet)
            self.parent.assertIsNotNone(l2_dom)

            # create 5 vports with vminterfaces
            for _ in range(5):
                kwargs = {
                    'device_owner': 'compute:nova',
                    'device_id': uuidutils.generate_uuid(),
                    'binding:host_id': '11111111-1111-1111-1111-111111111111',
                    'network': network
                }
                port = self.parent.create_port(
                    manager=self.parent.admin_manager, **kwargs)
                self._resources['l2_ports'].append(port)

            # delete 3 of the vports/vminterfaces from VSD
            for _ in range(3):
                l2_port = self._resources['l2_ports'].pop()
                vm_interface = self._vsd.get_vm_interface(
                    vspk_filter='externalID == "{}"'.format
                    (self._get_external_id(l2_port['id'])))
                vm_interface.delete()
                vport = self._vsd.get_vport(l2domain=l2_dom,
                                            by_port_id=l2_port['id'])
                self.parent.assertIsNotNone(vport)
                vport.delete()

        def verify(self):
            self._verify_os_managed_resources(verify_acl=False,
                                              verify_vm_connectivity=False,
                                              fake_vm_present=True)
