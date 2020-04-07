# Copyright 2017 NOKIA
# All Rights Reserved.

import getpass
import os
import random
import subprocess

from netaddr import IPAddress
from netaddr import IPNetwork
from oslo_utils import uuidutils
from vspk import v5_0 as vspk5
from vspk import v6 as vspk6

from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.mixins.l3 import L3Mixin
from nuage_tempest_plugin.lib.mixins import net_topology as topology_mixin
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.lib.utils import data_utils as nuage_data_utils
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# CAUTION : DO NOT RUN IN CI, AS THIS SUITE IS HIGHLY INTRUSIVE
#           - it relies heavily on devstack env
#           - it installs new packages in the tox env (like neutron)
#           - it changes the neutron branch out of which neutron runs
#           - it restarts neutron
#
# Please only run this suite manually on your custom setup.
# NOTE : this suite will skip tests when being run as 'tempest' user;
#        that will prevent running them in CI.
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class UpgradeTo60Test(NuageBaseTest, L3Mixin,
                      topology_mixin.NetTopologyMixin):
    _ip_version = 4
    _cms_id = Topology.cms_id
    _openstack_version = str(Topology.openstack_version_qualifier)
    _resources = {'networks': [],
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
    _upgrade_script_path = ('/opt/stack/nuage-openstack-upgrade-scripts/'
                            'nuage_upgrade_to_6_0.py')
    _neutron_conf = '/etc/neutron/neutron.conf'
    _plugin_conf = '/etc/neutron/plugins/nuage/plugin.ini'
    _user = getpass.getuser()
    _is_running_in_ci = _user == 'tempest'
    _home = '/home/' + _user
    _log_dir = _home + '/nuageupgrade'

    _is_large_setup = False
    _is_custom_run = False

    _default_vms = 2
    _default_vports = 10 if _is_large_setup else 2

    @classmethod
    def skip_checks(cls):
        super(UpgradeTo60Test, cls).skip_checks()
        if cls._is_running_in_ci:
            msg = ("UpgradeTo60Test tests are to be manually run. "
                   "Skipping in CI.")
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(UpgradeTo60Test, cls).setup_clients()
        cls.vsd_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(UpgradeTo60Test, cls).resource_setup()
        cls.assert_path_exists(cls._upgrade_script_path)
        cls.assert_path_exists(cls._neutron_conf)
        cls.assert_path_exists(cls._plugin_conf)
        cls.assert_path_exists(cls._log_dir, create_if_not=True)

        cls._install_dependencies()

    def setUp(self):
        super(UpgradeTo60Test, self).setUp()

        self.vsd.default_enterprise = None
        self.vsd.enterprise_name_to_enterprise = {}
        self.vsd._session = None
        self.vsd.vspk = vspk5

        self._resources.update((key, []) for key in self._resources)

    @classmethod
    def assert_path_exists(cls, path, create_if_not=False):
        if create_if_not and not os.path.exists(path):
            os.mkdir(path)
            LOG.info('{} created!'.format(path))
        assert os.path.exists(path)

    def test_upgrade_os_managed_dualstack_l3(self):
        topologies = (
            [
                {'l3': True, 'ip_versions': [4, 6], 'DHCPv4': True,
                 'DHCPv6': True, 'vms': self._default_vms,
                 'vports': self._default_vports},
                {'l3': True, 'ip_versions': [4, 6], 'DHCPv4': True,
                 'DHCPv6': False, 'vms': self._default_vms,
                 'vports': self._default_vports},
                {'l3': True, 'ip_versions': [4, 6], 'DHCPv4': False,
                 'DHCPv6': True, 'vms': self._default_vms,
                 'vports': self._default_vports},
                {'l3': True, 'ip_versions': [4, 6], 'DHCPv4': False,
                 'DHCPv6': False, 'vms': self._default_vms,
                 'vports': self._default_vports}
            ])
        self._switch_plugin_branch('5.4/' + self._openstack_version)
        try:
            self._create_os_resource(topologies)
        finally:
            self._switch_plugin_branch('stable/' + self._openstack_version)
        self._execute_the_upgrade_script(dryrun=True)
        self._execute_the_upgrade_script()
        self._verify_os_managed_resources()

    def test_upgrade_os_managed_dualstack_l2(self):
        topologies = (
            [
                {'l3': False, 'ip_versions': [4, 6], 'DHCPv4': True,
                 'DHCPv6': True, 'vms': self._default_vms,
                 'vports': self._default_vports},
                {'l3': False, 'ip_versions': [4, 6], 'DHCPv4': True,
                 'DHCPv6': False, 'vms': self._default_vms,
                 'vports': self._default_vports},
                {'l3': False, 'ip_versions': [4, 6], 'DHCPv4': False,
                 'DHCPv6': True, 'vms': self._default_vms,
                 'vports': self._default_vports},
                {'l3': False, 'ip_versions': [4, 6], 'DHCPv4': False,
                 'DHCPv6': False, 'vms': self._default_vms,
                 'vports': self._default_vports}
            ])
        self._switch_plugin_branch('5.4/' + self._openstack_version)
        try:
            self._create_os_resource(topologies)
        finally:
            self._switch_plugin_branch('stable/' + self._openstack_version)
        self._execute_the_upgrade_script(dryrun=True)
        self._execute_the_upgrade_script()
        self._verify_os_managed_resources()

    def test_upgrade_os_managed_singlestack_l2(self):
        topologies = (
            [
                {'l3': False, 'ip_versions': [4], 'DHCPv4': True,
                 'vms': self._default_vms, 'vports': self._default_vports},
                {'l3': False, 'ip_versions': [4], 'DHCPv4': False,
                 'vms': self._default_vms, 'vports': self._default_vports},
                {'l3': False, 'ip_versions': [6], 'DHCPv6': True,
                 'vms': self._default_vms, 'vports': self._default_vports},
                {'l3': False, 'ip_versions': [6], 'DHCPv6': False,
                 'vms': self._default_vms, 'vports': self._default_vports}
            ])
        self._switch_plugin_branch('5.4/' + self._openstack_version)
        try:
            self._create_os_resource(topologies)
        finally:
            self._switch_plugin_branch('stable/' + self._openstack_version)
        self._execute_the_upgrade_script(dryrun=True)
        self._execute_the_upgrade_script()
        self._verify_os_managed_resources()

    def test_upgrade_os_managed_singlestack_l3(self):
        topologies = (
            [
                {'l3': True, 'ip_versions': [4], 'DHCPv4': True,
                 'vms': self._default_vms, 'vports': self._default_vports},
                {'l3': True, 'ip_versions': [4], 'DHCPv4': False,
                 'vms': self._default_vms, 'vports': self._default_vports},
                {'l3': True, 'ip_versions': [6], 'DHCPv6': True,
                 'vms': self._default_vms, 'vports': self._default_vports},
                {'l3': True, 'ip_versions': [6], 'DHCPv6': False,
                 'vms': self._default_vms, 'vports': self._default_vports}
            ])
        self._switch_plugin_branch('5.4/' + self._openstack_version)
        try:
            self._create_os_resource(topologies)
        finally:
            self._switch_plugin_branch('stable/' + self._openstack_version)
        self._execute_the_upgrade_script(dryrun=True)
        self._execute_the_upgrade_script()
        self._verify_os_managed_resources()

    def test_upgrade_vsd_managed_dualstack_l2(self):
        self._test_upgrade_vsd_managed_dualstack(l3=False)

    def test_upgrade_vsd_managed_dualstack_l3(self):
        self._test_upgrade_vsd_managed_dualstack(l3=True)

    def test_wrong_api_setting_warning(self):
        self._switch_plugin_branch('5.4/' + self._openstack_version)
        try:
            self._execute_the_upgrade_script(expected_exit_code=1)
            log_data = self._fetch_the_latest_log_file()
            error_message = ("Can't upgrade because plugin doesn't have v6"
                             " API set. Please change it (/nuage/api/v5_0)"
                             " to v6 api (e.g. /nuage/api/v6)"
                             " and run again.")

            self.assertIn(error_message, log_data)
        finally:
            self._switch_plugin_branch('stable/' + self._openstack_version)

    def test_unsupported_cidr_l2(self):
        self._switch_plugin_branch('5.4/' + self._openstack_version)
        try:
            cidrv4 = IPNetwork('169.254.32.0/24')
            cidrv6 = IPNetwork('fe80::/64')
            network = self.create_network()
            subv4 = self.create_subnet(
                network, enable_dhcp=False, cidr=cidrv4)

            network2 = self.create_network()
            self.create_subnet(
                network2, enable_dhcp=False)
            subv6 = self.create_subnet(
                network2, enable_dhcp=False, ip_version=6, cidr=cidrv6)
        finally:
            self._switch_plugin_branch('stable/' + self._openstack_version)
        self._execute_the_upgrade_script(dryrun=True)
        self._execute_the_upgrade_script()

        log_data = self._fetch_the_latest_log_file()
        self.assertIn(
            self._invalid_cidr_warning(cidrv4.ip, subv4['id']), log_data)
        self.assertIn(
            self._invalid_cidr_warning(cidrv6, subv6['id']), log_data)

    def _test_upgrade_vsd_managed_dualstack(self, l3=False):
        l2domain_template_1 = l2domain_template_2 = l2domain_template_3 = None
        vsd_subnet_1 = vsd_subnet_2 = vsd_subnet_3 = None

        self._switch_plugin_branch('5.4/' + self._openstack_version)
        try:
            cidrv4_1 = '10.9.8.0/24'
            gatewayv4_1 = '10.9.8.1'
            cidrv6_1 = 'cafe:babe::/64'
            gatewayv6_1 = 'cafe:babe::1'

            cidrv4_2 = '10.9.7.0/24'
            gatewayv4_2 = '10.9.7.1'
            cidrv6_2 = 'cafe:cafe::/64'
            gatewayv6_2 = 'cafe:cafe::1'

            cidrv4_3 = '10.9.6.0/24'
            gatewayv4_3 = '10.9.6.4'
            cidrv6_3 = 'cafe:cafa::/64'
            gatewayv6_3 = 'cafe:cafa::4'

            if l3:
                vsd_l3domain_template = self.vsd_create_l3domain_template()
                vsd_l3domain = self.vsd_create_l3domain(
                    template_id=vsd_l3domain_template.id)
                vsd_zone = self.vsd_create_zone(domain=vsd_l3domain)
                vsd_subnet_1 = self.create_vsd_subnet(
                    zone=vsd_zone,
                    cidr4=IPNetwork(cidrv4_1),
                    gateway4=gatewayv4_1,
                    cidr6=IPNetwork(cidrv6_1),
                    gateway6=gatewayv6_1,
                    ip_type='DUALSTACK',
                    dhcp_managed=True)

                vsd_subnet_2 = self.create_vsd_subnet(
                    zone=vsd_zone,
                    cidr4=IPNetwork(cidrv4_2),
                    gateway4=gatewayv4_2,
                    cidr6=IPNetwork(cidrv6_2),
                    gateway6=gatewayv6_2,
                    ip_type='DUALSTACK',
                    dhcp_managed=True)

                vsd_subnet_3 = self.create_vsd_subnet(
                    zone=vsd_zone,
                    cidr4=IPNetwork(cidrv4_3),
                    gateway4=gatewayv4_3,
                    cidr6=IPNetwork(cidrv6_3),
                    gateway6=gatewayv6_3,
                    ip_type='DUALSTACK',
                    dhcp_managed=True)

                self.vsd.define_any_to_any_acl(vsd_l3domain)
                network = self.create_network()
                self._resources['l3_subnets'].append(
                    self.create_l3_vsd_managed_subnet(
                        network, vsd_subnet_1))
                subv6_1 = self.create_l3_vsd_managed_subnet(
                    network, vsd_subnet_1, ip_version=6)
                self._resources['l3_subnets'].append(subv6_1)
                self._resources['l3_subnets'].append(
                    self.create_l3_vsd_managed_subnet(
                        network, vsd_subnet_2))
                subv6_2 = self.create_l3_vsd_managed_subnet(
                    network, vsd_subnet_2, ip_version=6)
                self._resources['l3_subnets'].append(subv6_2)
                subv4_3 = self.create_l3_vsd_managed_subnet(
                    network, vsd_subnet_3)
                self._resources['l3_subnets'].append(subv4_3)
                subv6_3 = self.create_l3_vsd_managed_subnet(
                    network, vsd_subnet_3, ip_version=6)
                self._resources['l3_subnets'].append(subv6_3)
            else:
                l2domain_template_1 = self.vsd_create_l2domain_template(
                    cidr4=IPNetwork(cidrv4_1),
                    gateway4=gatewayv4_1,
                    cidr6=IPNetwork(cidrv6_1),
                    gateway6=gatewayv6_1,
                    ip_type='DUALSTACK',
                    dhcp_managed=True)
                l2domain_1 = self.vsd_create_l2domain(
                    template=l2domain_template_1)

                l2domain_template_2 = self.vsd_create_l2domain_template(
                    cidr4=IPNetwork(cidrv4_2),
                    gateway4=gatewayv4_2,
                    cidr6=IPNetwork(cidrv6_2),
                    gateway6=gatewayv6_2,
                    ip_type='DUALSTACK',
                    dhcp_managed=True)
                l2domain_2 = self.vsd_create_l2domain(
                    template=l2domain_template_2)

                l2domain_template_3 = self.vsd_create_l2domain_template(
                    cidr4=IPNetwork(cidrv4_3),
                    gateway4=gatewayv4_3,
                    cidr6=IPNetwork(cidrv6_3),
                    gateway6=gatewayv6_3,
                    ip_type='DUALSTACK',
                    dhcp_managed=True)
                l2domain_3 = self.vsd_create_l2domain(
                    template=l2domain_template_3)

                network = self.create_network()
                self._resources['l2_subnets'].append(
                    self.create_l2_vsd_managed_subnet(
                        network, l2domain_1))
                subv6_1 = self.create_l2_vsd_managed_subnet(
                    network, l2domain_1, ip_version=6)
                self._resources['l2_subnets'].append(subv6_1)
                self._resources['l2_subnets'].append(
                    self.create_l2_vsd_managed_subnet(
                        network, l2domain_2))
                subv6_2 = self.create_l2_vsd_managed_subnet(
                    network, l2domain_2, ip_version=6)
                self._resources['l2_subnets'].append(subv6_2)
                subv4_3 = self.create_l2_vsd_managed_subnet(
                    network, l2domain_3)
                self._resources['l2_subnets'].append(subv4_3)
                subv6_3 = self.create_l2_vsd_managed_subnet(
                    network, l2domain_3, ip_version=6)
                self._resources['l2_subnets'].append(subv6_3)

            # Create a port using IPv6Gateway ip
            fixed_ips = [
                {
                    'subnet_id': subv4_3['id']
                }, {
                    'ip_address': gatewayv6_3,
                    'subnet_id': subv6_3['id']
                }
            ]
            port = self.create_port(network, fixed_ips=fixed_ips)

        finally:
            self._switch_plugin_branch('stable/' + self._openstack_version)
        self.vsd.default_enterprise = None
        self.vsd.enterprise_name_to_enterprise = {}
        self.vsd._session = None
        self.vsd.vspk = vspk6
        self.vsd.new_session()
        self._execute_the_upgrade_script(dryrun=True)

        with open('upgrade_report.json') as report_file:
            report_data = report_file.read()

        # validate inconsistent DHCP setting warnings
        self.assertIn(self._inconsistent_dhcp_warning(
            subv6_1['id']), report_data)
        self.assertIn(self._inconsistent_dhcp_warning(
            subv6_2['id']), report_data)
        self.assertIn(self._inconsistent_dhcp_warning(
            subv6_3['id']), report_data)

        # refetch the resources with v6 API
        if l3:
            vsd_subnet_1 = vspk6.NUSubnet(
                id=vsd_subnet_1.id).fetch()[0]
            vsd_subnet_1.enable_dhcpv6 = True
            vsd_subnet_1.ipv6_gateway = gatewayv6_1
            vsd_subnet_1.save()

            vsd_subnet_2 = vspk6.NUSubnet(
                id=vsd_subnet_2.id).fetch()[0]
            vsd_subnet_2.enable_dhcpv6 = True
            vsd_subnet_2.ipv6_gateway = gatewayv6_2
            vsd_subnet_2.save()

            vsd_subnet_3 = vspk6.NUSubnet(
                id=vsd_subnet_3.id).fetch()[0]
            vsd_subnet_3.enable_dhcpv6 = True
            vsd_subnet_3.ipv6_gateway = gatewayv6_3
            vsd_subnet_3.save()
        else:
            l2domain_template_1 = vspk6.NUL2DomainTemplate(
                id=l2domain_template_1.id).fetch()[0]
            l2domain_template_1.enable_dhcpv6 = True
            l2domain_template_1.ipv6_gateway = gatewayv6_1
            l2domain_template_1.save()

            l2domain_template_2 = vspk6.NUL2DomainTemplate(
                id=l2domain_template_2.id).fetch()[0]
            l2domain_template_2.enable_dhcpv6 = True
            l2domain_template_2.ipv6_gateway = gatewayv6_2
            l2domain_template_2.save()

            l2domain_template_3 = vspk6.NUL2DomainTemplate(
                id=l2domain_template_3.id).fetch()[0]
            l2domain_template_3.enable_dhcpv6 = True
            l2domain_template_3.ipv6_gateway = gatewayv6_3
            l2domain_template_3.save()

        self._execute_the_upgrade_script()

        with open('upgrade_report.json') as report_file:
            report_data = report_file.read()
        self.assertIn(self._vsd_managed_subnet_gateway_ip_in_use_warning(
            subv6_3['id'], port['id'], gatewayv6_3, ip_version=6), report_data)

        if l3:
            filters = {
                'device_owner': 'network:dhcp:nuage',
                'network_id': self._resources['l3_subnets'][0]['network_id']
            }
        else:
            filters = {
                'device_owner': 'network:dhcp:nuage',
                'network_id': self._resources['l2_subnets'][0]['network_id']
            }
        dhcp_ports = self.list_ports(**filters)
        for dhcp_port in dhcp_ports:
            if len(dhcp_port['fixed_ips']) == 2:
                fixed_ip1 = IPAddress(dhcp_port['fixed_ips'][0]['ip_address'])
                fixed_ip2 = IPAddress(dhcp_port['fixed_ips'][1]['ip_address'])
                if fixed_ip1.version == 4:
                    if fixed_ip1 in IPNetwork(cidrv4_1):
                        self.assertTrue(fixed_ip2 in IPNetwork(cidrv6_1))
                    elif IPAddress(fixed_ip1) in IPNetwork(cidrv4_2):
                        self.assertTrue(fixed_ip2 in IPNetwork(cidrv6_2))
                    else:
                        self.fail("Fixed IP doesn't match with the cidr")
                else:
                    if fixed_ip1 in IPNetwork(cidrv6_1):
                        self.assertTrue(fixed_ip2 in IPNetwork(cidrv4_1))
                    elif IPAddress(fixed_ip1) in IPNetwork(cidrv6_2):
                        self.assertTrue(fixed_ip2 in IPNetwork(cidrv4_2))
                    else:
                        self.fail("Fixed IP doesn't match with the cidr")

    def test_upgrade_bulk_subnet(self):
        if not self._is_large_setup:
            raise self.skipException('Skipping bulk test in non-large setup')

        # try to upgrade with 300 l2domain
        # couldn't try more than 350 because creation fails without any error.
        # main goal of this test was to tes paging, it's not an issue, I tried
        # to lowered the page size and didn't have any problem.

        self._switch_plugin_branch('5.4/' + self._openstack_version)
        try:
            for i in range(300):
                network = self.create_network()
                self._resources['networks'].append(network)

                for ip_version in [4, 6]:
                    subnet = self.create_subnet(
                        network, ip_version=ip_version,
                        enable_dhcp=True)
                    self._resources['l2_subnets'].append(subnet)
        finally:
            self._switch_plugin_branch('stable/' + self._openstack_version)
        self._execute_the_upgrade_script(dryrun=True)
        self._execute_the_upgrade_script()
        self._verify_os_managed_resources(verify_acl=False)

    def test_upgrade_bulk_vm(self):
        if not self._is_large_setup:
            raise self.skipException('Skipping bulk test in non-large setup')

        self._switch_plugin_branch('5.4/' + self._openstack_version)
        try:
            network = self.create_network()
            self._resources['networks'].append(network)

            subnet = self.create_subnet(
                network, ip_version=4,
                mask_bits=24,
                enable_dhcp=False)
            self._resources['l2_subnets'].append(subnet)

            for vport in range(100):
                kwargs = {
                    'device_owner': 'compute:nova',
                    'device_id': uuidutils.generate_uuid(),
                    'binding:host_id': '11111111-1111-1111-1111-111111111111',
                    'network': network
                }
                port = self.create_port(manager=self.admin_manager, **kwargs)
                self._resources['l2_ports'].append(port)
        finally:
            self._switch_plugin_branch('stable/' + self._openstack_version)
        self._execute_the_upgrade_script(dryrun=True)
        self._execute_the_upgrade_script()
        self._verify_os_managed_resources(verify_acl=False,
                                          verify_vm_connectivity=False,
                                          fake_vm_present=True)

    def test_upgrade_with_orphan_objects(self):
        # unresolved VMs will be also tested with this test
        self._switch_plugin_branch('5.4/' + self._openstack_version)
        try:
            network = self.create_network()
            self._resources['networks'].append(network)

            subnet = self.create_subnet(
                network, ip_version=4,
                enable_dhcp=False)
            self._resources['l2_subnets'].append(subnet)
            l2_dom = self.vsd.get_l2domain(
                by_subnet_id=subnet['id'],
                # by_network_id=network['id'],
                cidr=subnet['cidr'], ip_type=subnet['ip_version'])
            self.assertIsNotNone(l2_dom)

            # create 5 vports with vminterfaces
            for _ in range(5):
                kwargs = {
                    'device_owner': 'compute:nova',
                    'device_id': uuidutils.generate_uuid(),
                    'binding:host_id': '11111111-1111-1111-1111-111111111111',
                    'network': network
                }
                port = self.create_port(manager=self.admin_manager, **kwargs)
                self._resources['l2_ports'].append(port)
            # delete 3 of the vports/vminterfaces from VSD
            for _ in range(3):
                l2_port = self._resources['l2_ports'].pop()
                vm_interface = self.vsd.get_vm_interface(
                    vspk_filter='externalID == "{}"'.format
                    (self._get_external_id(l2_port['id'])))
                vm_interface.delete()
                vport = self.vsd.get_vport(l2domain=l2_dom,
                                           by_port_id=l2_port['id'])
                self.assertIsNotNone(vport)
                vport.delete()
        finally:
            self._switch_plugin_branch('stable/' + self._openstack_version)
        self._execute_the_upgrade_script(dryrun=True)
        self._execute_the_upgrade_script()
        self._verify_os_managed_resources(verify_acl=False,
                                          verify_vm_connectivity=False,
                                          fake_vm_present=True)

    def _create_sriov_and_baremetal_ports(self):
        kwargs = {'segments': [
            {'provider:network_type': 'vxlan'},
            {'provider:network_type': 'vlan',
             'provider:physical_network': 'physnet1',
             'provider:segmentation_id': str(random.randrange(4095))}
        ]}
        network = self.create_network(manager=self.admin_manager, **kwargs)

        cidr = nuage_data_utils.gimme_a_cidr_address()
        subnet_params = {
            'network': network,
            'cidr': IPNetwork(cidr),
            'subnet_name': data_utils.rand_name('subnet'),
            'ip_version': self._ip_version
        }
        subnet1 = self.create_subnet(manager=self.admin_manager,
                                     mask_bits=24,
                                     **subnet_params)

        gateway_vsg = self.vsd_client.create_gateway(
            data_utils.rand_name(name='vsg'),
            data_utils.rand_name(name='sys_id'), 'VSG')[0]
        self.addCleanup(
            self.vsd_client.delete_gateway, gateway_vsg['ID']
        )

        gw_port_sriov = self.vsd_client.create_gateway_port(
            'gw_port_sriov', 'gw_port_sriov', 'ACCESS', gateway_vsg['ID'],
            extra_params={'VLANRange': '0-4095'})[0]

        gw_port_baremetal = self.vsd_client.create_gateway_port(
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

        with self.switchport_mapping(do_delete=False,
                                     **mapping) as switch_map:
            self.addCleanup(
                self.switchport_mapping_client_admin.delete_switchport_mapping,
                switch_map['id'])
            self.create_port(manager=self.admin_manager, **create_data)

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

        self.create_port(manager=self.admin_manager, **baremetal_port_args)

        return subnet1

    def _create_virtio_vrsg_host_bridge_ports(self, bridge_vport=True,
                                              virtio_port_count=3):
        # create VRSG bridge port
        gateway_vrsg = self.vsd_client.create_gateway(
            data_utils.rand_name(name='vrsg'),
            data_utils.rand_name(name='sys_id'), 'VRSG')[0]
        self.addCleanup(
            self.vsd_client.delete_gateway, gateway_vrsg['ID']
        )

        network = self.create_network()
        cidr = nuage_data_utils.gimme_a_cidr(netmask=23)
        subnet = self.create_subnet(network, cidr=cidr,
                                    mask_bits=cidr.prefixlen)

        # we can't test L3 with bridge ports.
        if bridge_vport:
            gw_port_vrsg_bridge = self.vsd_client.create_gateway_port(
                'gw_port_vrsg_bridge', 'gw_port_vrsg_bridge', 'ACCESS',
                gateway_vrsg['ID'], extra_params={'VLANRange': '0-4095'})[0]

            kwargs = {
                'gatewayport': gw_port_vrsg_bridge['ID'],
                'value': str(random.randrange(4095))
            }
            gw_vlan = self.plugin_network_client.create_gateway_vlan(**kwargs)

            # Create bridge vport
            kwargs = {
                'gatewayvlan': gw_vlan['nuage_gateway_vlan']['id'],
                'port': None,
                'subnet': subnet['id'],
                'tenant': self.plugin_network_client.tenant_id
            }
            gw_port_host = self.plugin_network_client.create_gateway_vport(
                **kwargs)
            self.addCleanup(
                self.plugin_network_client.delete_gateway_vport,
                gw_port_host['nuage_gateway_vport']['id']
            )

        # create VRSG host port
        port = self.create_port(network, device_owner='nuage:vip')

        gw_port_vrsg_host = self.vsd_client.create_gateway_port(
            'gw_port_vrsg_host', 'gw_port_vrsg_host', 'ACCESS',
            gateway_vrsg['ID'], extra_params={'VLANRange': '0-4095'})[0]

        kwargs = {
            'gatewayport': gw_port_vrsg_host['ID'],
            'value': str(random.randrange(4095))
        }
        gw_vlan = self.plugin_network_client.create_gateway_vlan(**kwargs)

        # Create host vport
        kwargs = {
            'gatewayvlan': gw_vlan['nuage_gateway_vlan']['id'],
            'port': port['id'],
            'subnet': None,
            'tenant': self.plugin_network_client.tenant_id
        }
        self.plugin_network_client.create_gateway_vport(**kwargs)

        # Create virtio ports
        for _ in range(virtio_port_count):
            self.create_port(network, port_security_enabled=False)

        return subnet

    def _test_upgrade_pg_allow_all_l2(self, branch='5.4/'):
        self.vsd.vspk = vspk5 if branch == '5.4/' else vspk6
        self._switch_plugin_branch(branch + self._openstack_version)
        try:
            subnet1 = self._create_sriov_and_baremetal_ports()
            subnet2 = self._create_virtio_vrsg_host_bridge_ports(
                bridge_vport=True, virtio_port_count=3)
        finally:
            self._switch_plugin_branch('stable/' + self._openstack_version)
        self._execute_the_upgrade_script(dryrun=True)
        self._execute_the_upgrade_script()

        self.vsd.default_enterprise = None
        self.vsd.enterprise_name_to_enterprise = {}
        self.vsd._session = None
        self.vsd.vspk = vspk6

        l2dom1 = self.vsd.get_l2domain(
            by_network_id=subnet1['network_id'],
            cidr=subnet1['cidr'], ip_type=subnet1['ip_version'])

        policy_groups = l2dom1.policy_groups.get()
        self.assertEqual(1, len(policy_groups))
        self.assertEqual('HARDWARE', policy_groups[0].type)
        self.assertEqual(constants.NUAGE_PLCY_GRP_ALLOW_ALL_HW,
                         policy_groups[0].name)
        self.assertEqual(constants.NUAGE_PLCY_GRP_ALLOW_ALL_HW,
                         policy_groups[0].description)
        self.assertEqual('hw:' + self._get_external_id(
            constants.NUAGE_PLCY_GRP_ALLOW_ALL), policy_groups[0].external_id)

        vports = policy_groups[0].vports.get()
        self.assertEqual(2, len(vports))
        l2dom2 = self.vsd.get_l2domain(
            by_network_id=subnet2['network_id'],
            cidr=subnet2['cidr'], ip_type=subnet2['ip_version'])

        policy_groups = l2dom2.policy_groups.get()
        self.assertEqual(1, len(policy_groups))
        self.assertEqual('SOFTWARE', policy_groups[0].type)
        self.assertEqual(constants.NUAGE_PLCY_GRP_ALLOW_ALL,
                         policy_groups[0].name)
        self.assertEqual(constants.NUAGE_PLCY_GRP_ALLOW_ALL,
                         policy_groups[0].description)
        self.assertEqual(self._get_external_id(
            constants.NUAGE_PLCY_GRP_ALLOW_ALL),
            policy_groups[0].external_id)
        vports = policy_groups[0].vports.get()
        self.assertEqual(5, len(vports))

    def test_upgrade_pg_allow_all_l2_601_to_stable(self):
        self._test_upgrade_pg_allow_all_l2(branch='release-6.0.1-')

    def test_upgrade_pg_allow_all_l2_54_to_stable(self):
        self._test_upgrade_pg_allow_all_l2(branch='5.4/')

    def test_upgrade_pg_allow_all_l3_601_to_stable(self):
        l2_domain_count = 5
        self._create_upgrade_pg_allow_all_l3(
            l2_domain_count=l2_domain_count,
            vport_num=list(range(1, l2_domain_count + 1)),
            branch='release-6.0.1-')

    def test_upgrade_pg_allow_all_l3_54_to_stable(self):
        l2_domain_count = 5
        self._create_upgrade_pg_allow_all_l3(
            l2_domain_count=l2_domain_count,
            vport_num=list(range(1, l2_domain_count + 1)),
            branch='5.4/')

    def test_upgrade_pg_allow_all_with_large_scale_vports_l3(self):
        if not self._is_large_setup:
            raise self.skipException('Skipping bulk test in non-large setup')

        self._create_upgrade_pg_allow_all_l3(l2_domain_count=2,
                                             vport_num=[251, 252])

    def _create_upgrade_pg_allow_all_l3(self, l2_domain_count, vport_num,
                                        branch='5.4/'):
        # tests that l3 policy groups are merged together successfully
        # and also the winner takes it all.

        self.vsd.vspk = vspk5 if branch == '5.4/' else vspk6
        self._switch_plugin_branch(branch + self._openstack_version)
        try:
            router = self.create_router()
            subnet = None
            l2_domain = None

            for i in range(l2_domain_count):
                # last subnet and l2domain will have the most port, which will
                # earn to keep it's policy group.
                subnet = self._create_virtio_vrsg_host_bridge_ports(
                    bridge_vport=False, virtio_port_count=vport_num[i])

                if i == l2_domain_count - 1:
                    # create a port with port security
                    network = self.get_network(subnet['network_id'])
                    self.create_port(network)
                    if '5' in branch:
                        l2_domain = self.vsd.get_l2domain(
                            by_network_id=subnet['id'],
                            cidr=subnet['cidr'], ip_type=subnet['ip_version'])
                    else:
                        l2_domain = self.vsd.get_l2domain(
                            by_network_id=subnet['network_id'],
                            cidr=subnet['cidr'], ip_type=subnet['ip_version'])
                self.router_attach(router, subnet)

            if '5' in branch:
                l3_domain = self.vsd.get_l3_domain_by_network_id_and_cidr(
                    by_network_id=subnet['id'],
                    cidr=subnet['cidr'], ip_type=subnet['ip_version'])
            else:
                l3_domain = self.vsd.get_l3_domain_by_network_id_and_cidr(
                    by_network_id=subnet['network_id'],
                    cidr=subnet['cidr'], ip_type=subnet['ip_version'])

            # policy group that has the most vports before upgrade
            assert l3_domain
            policy_group = l3_domain.policy_groups.get(
                filter='externalID == "{}"'.format(self._get_external_id(
                    'PG_FOR_LESS_SECURITY_{}_VM'.format(l2_domain.id))))[0]
        finally:
            self._switch_plugin_branch('stable/' + self._openstack_version)
        self._execute_the_upgrade_script(dryrun=True)
        self._execute_the_upgrade_script()

        self.vsd.default_enterprise = None
        self.vsd.enterprise_name_to_enterprise = {}
        self.vsd._session = None
        self.vsd.vspk = vspk6

        # fetch all the policy groups under the l3_domain
        policy_groups = l3_domain.policy_groups.get()
        self.assertEqual(2, len(policy_groups))
        policy_group_allow_all = l3_domain.policy_groups.get(
            filter='externalID == "{}"'.format(
                self._get_external_id(constants.NUAGE_PLCY_GRP_ALLOW_ALL)))[0]
        vports = policy_group_allow_all.vports.get_count()
        self.assertEqual(sum(vport_num), vports)
        self.assertEqual(policy_group.id, policy_group_allow_all.id)

    def _create_os_resource(self, topologies):
        # network/subnet/port/vm
        # create resources
        for topology in topologies:
            network = self.create_network()
            self._resources['networks'].append(network)

            temp_subnets = []
            for ip_version in topology['ip_versions']:
                subnet = self.create_subnet(
                    network, ip_version=ip_version,
                    mask_bits=24 if ip_version == 4 else 64,
                    enable_dhcp=topology['DHCPv{}'.format(ip_version)])
                temp_subnets.append(subnet)

            # create a security group
            sec_group = self.create_open_ssh_security_group()
            self._resources['sec_groups'].append(sec_group)
            if topology['l3']:
                router = self.create_router(
                    external_network_id=CONF.network.public_network_id
                )
                self._resources['routers'].append(router)
                self.router_attach(router, temp_subnets[0])

                for subnet in temp_subnets:
                    self._resources['l3_subnets'].append(subnet)

                # create ports (not on singlestack v6)
                if not self._is_singlestack_v6(temp_subnets[0]):
                    for _ in range(topology['vports']):
                        port = self.create_port(
                            network, security_groups=[sec_group['id']])
                        self._resources['l3_ports'].append(port)
            else:
                for subnet in temp_subnets:
                    self._resources['l2_subnets'].append(subnet)

                # create ports (not on singlestack v6)
                if not self._is_singlestack_v6(temp_subnets[0]):
                    for _ in range(topology['vports']):
                        port = self.create_port(
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
                    port1 = self.create_port(
                        network, security_groups=[sec_group['id']])
                    port2 = self.create_port(
                        network, security_groups=[sec_group['id']])
                    vm = self.create_tenant_server(
                        ports=[port1, port2])
                    self._resources['vms'].append(vm)

        # external subnet
        params = {'router:external': True}
        ext_network = self.create_network(manager=self.admin_manager, **params)
        cidr = nuage_data_utils.gimme_a_cidr_address()
        subnet_params = {
            'network': ext_network,
            'cidr': IPNetwork(cidr),
            'subnet_name': data_utils.rand_name('subnet'),
            'ip_version': self._ip_version
        }
        self._resources['external_subnets'].append(
            self.create_subnet(manager=self.admin_manager, **subnet_params))

    def _verify_os_managed_resources(self, verify_acl=True,
                                     verify_vm_connectivity=True,
                                     fake_vm_present=False):
        # externalID lookup for the L2Domains and add them to self.resources
        log_data = self._fetch_the_latest_log_file()

        self.vsd.default_enterprise = None
        self.vsd.enterprise_name_to_enterprise = {}
        self.vsd._session = None
        self.vsd.vspk = vspk6

        for subnet in self._resources['l2_subnets']:
            if self._is_singlestack_v6(subnet):
                self.assertIn(
                    self._pure_v6_subnet_warning(subnet['id']),
                    log_data,
                    "Pure v6 subnet warning haven't logged correctly for: "
                    "{}.".format(subnet['id']))
            else:
                l2dom = self.vsd.get_l2domain(
                    by_network_id=subnet['network_id'],
                    cidr=subnet['cidr'], ip_type=subnet['ip_version'])
                self.assertIsNotNone(l2dom)
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
                    dhcp_port = self.list_ports(**filters)[0]
                    self.assertTrue(
                        self._is_fixed_ip_address_family_correct(
                            ip_version=subnet['ip_version'],
                            fixed_ips=dhcp_port['fixed_ips']))

        # externalID lookup for the l3 subnets and add them to self.resources
        for subnet in self._resources['l3_subnets']:
            if self._is_singlestack_v6(subnet):
                self.assertIn(
                    self._pure_v6_subnet_warning(subnet['id']),
                    log_data,
                    "Pure v6 subnet warning haven't logged correctly for: "
                    "{}.".format(subnet['id']))
            else:
                nuage_l3_subnet = self.vsd.get_subnet(
                    by_network_id=subnet['network_id'],
                    cidr=subnet['cidr'])
                self.assertIsNotNone(nuage_l3_subnet)
                self._verify_l3_nuage_subnet(nuage_l3_subnet, subnet)
                self._resources['nuage_l3_subnets'].append(nuage_l3_subnet)

        for external_subnet in self._resources['external_subnets']:
            nuage_l3_subnet = self.vsd.get_subnet(
                by_network_id=external_subnet['network_id'],
                cidr=external_subnet['cidr'])
            self.assertIsNotNone(nuage_l3_subnet)

        for port in self._resources['l2_ports']:
            l2dom = self._find_l2_dom_in_resources(port['network_id'])
            vport = self.vsd.get_vport(l2domain=l2dom,
                                       by_port_id=port['id'])
            self.assertIsNotNone(vport)

            if fake_vm_present:
                vm_interface = self.vsd.get_vm_interface(
                    vspk_filter='externalID == "{}"'.format
                    (self._get_external_id(port['id'])))
                ipv4s = [ip['ip_address'] for ip in port['fixed_ips']
                         if IPAddress(ip['ip_address']).version == 4]
                ipv6s = [ip['ip_address'] for ip in port['fixed_ips']
                         if IPAddress(ip['ip_address']).version == 6]
                if len(ipv4s) <= 1 and len(ipv6s) <= 1:
                    if ipv4s:
                        self.assertEqual(ipv4s[0], vm_interface.ip_address)
                    if ipv6s:
                        self.assertEqual(
                            ipv6s[0], vm_interface.ipv6_address.split('/')[0])

        for port in self._resources['l3_ports']:
            l3sub = self._find_l3_nuage_sub_in_resources(port['network_id'])
            vport = self.vsd.get_vport(subnet=l3sub,
                                       by_port_id=port['id'])
            self.assertIsNotNone(vport)

        for vm in self._resources['vms']:
            # Verify VM resources -> vm_interface
            for port in vm.ports:
                # find vm_interface through domain
                vm_interface = self.vsd.get_vm_interface(
                    vspk_filter='externalID == "{}"'.format
                    (self._get_external_id(port['id'])))
                ipv4s = [ip['ip_address'] for ip in port['fixed_ips']
                         if IPAddress(ip['ip_address']).version == 4]
                ipv6s = [ip['ip_address'] for ip in port['fixed_ips']
                         if IPAddress(ip['ip_address']).version == 6]
                if len(ipv4s) <= 1 and len(ipv6s) <= 1:
                    if ipv4s:
                        self.assertEqual(ipv4s[0], vm_interface.ip_address)
                    if ipv6s:
                        self.assertEqual(
                            ipv6s[0], vm_interface.ipv6_address.split('/')[0])
                else:
                    pass
                    # TODO(Team) check spoofing is enabled
            # create another vm and test the connectivity for the first vm
            # it will be forced to be deployed on the contoller node
            # hypervisor = os.popen('hostname').read()
            vm_network = (vm.networks[0] if vm.networks
                          else vm.ports[0].get('parent_network'))
            if verify_vm_connectivity:
                vm2 = self.create_tenant_server(
                    networks=[vm_network],
                    security_groups=[self._resources['sec_groups'][0]],
                    # availability_zone='nova:{}'.format(hypervisor.strip()),
                    prepare_for_connectivity=True)
                self.assert_ping(vm2, vm, vm_network)
                verify_vm_connectivity = False

        # cleanup the rts otherwise can't do router attach test.
        for rt in self._resources['rts']:
            self.delete_redirection_target(rt['nuage_redirect_target']['id'])

        for subnet in self._resources['l2_subnets']:
            if subnet['ip_version'] == 4:
                # checking for IPv4 is enough because only supported cases
                # singlestack v4 and dualstack
                router = self.create_router(
                    external_network_id=CONF.network.public_network_id,
                    cleanup=False
                )
                self.router_attach(router, subnet, cleanup=False)
                self.router_detach(router, subnet)
                self.delete_router(router)

    # l2/l3 methods are same but might differ when extended.
    def _verify_l2_dom(self, l2dom, subnet):
        if subnet['ip_version'] == 4:
            self.assertEqual(l2dom.enable_dhcpv4, subnet['enable_dhcp'])
            # can't create dns option for the v6 subnets in 5.4
            dhcp_options = l2dom.dhcp_options.get(
                filter='externalID == "{}"'.format(
                    self._get_external_id(subnet['id'])))
            self.assertNotEmpty(dhcp_options)
        else:
            self.assertEqual(l2dom.enable_dhcpv6, subnet['enable_dhcp'])
        self.assertTrue(l2dom.dhcp_managed)

    def _verify_l3_nuage_subnet(self, nuage_sub, subnet):
        if subnet['ip_version'] == 4:
            self.assertEqual(nuage_sub.enable_dhcpv4, subnet['enable_dhcp'])
        else:
            self.assertEqual(nuage_sub.enable_dhcpv6, subnet['enable_dhcp'])

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
        # determines if the subnet is singlestackv6 or not
        net = self.get_network(subnet['network_id'])
        if subnet['ip_version'] == 6 and len(net['subnets']) == 1:
            return True
        return False

    # not to do another lookups for the domains while fetching the vports
    def _find_l3_nuage_sub_in_resources(self, network_id):
        for l3sub in self._resources['nuage_l3_subnets']:
            if network_id in l3sub.external_id:
                return l3sub
        return None

    def _get_external_id(self, neutron_id):
        return neutron_id + '@' + self._cms_id

    def _verify_acl_templates(self, network_id):
        l2dom = self._find_l2_dom_in_resources(network_id)
        ingress_acl_temp = l2dom.ingress_acl_templates.get(
            filter='externalID == "{}"'.format(
                self._get_external_id(network_id)))[0]
        self.assertIsNotNone(ingress_acl_temp)

        egress_acl_temp = l2dom.egress_acl_templates.get(
            filter='externalID == "{}"'.format(
                self._get_external_id(network_id)))[0]
        self.assertIsNotNone(egress_acl_temp)

    def _verify_redirection_targets(self, network_id):
        l2dom = self._find_l2_dom_in_resources(network_id)
        redirection_target = l2dom.redirection_targets.get(
            filter='externalID == "{}"'.format(
                self._get_external_id(network_id)))[0]
        self.assertIsNotNone(redirection_target)

    def _verify_ingress_adv_fwd_templates(self, network_id):
        l2dom = self._find_l2_dom_in_resources(network_id)
        ingress_adv_fwd_temp = l2dom.ingress_adv_fwd_templates.get(
            filter='externalID == "{}"'.format(
                self._get_external_id(network_id)))[0]
        self.assertIsNotNone(ingress_adv_fwd_temp)

    def _verify_acl_template_entries(self, network_id):
        ingress_acl_entries = self.vsd.get_ingress_acl_entries(
            vspk_filter='externalID == "{}"'.format(
                self._get_external_id(network_id)))[0]
        self.assertNotEmpty(ingress_acl_entries)

        egress_acl_entries = self.vsd.get_egress_acl_entries(
            vspk_filter='externalID == "{}"'.format(
                self._get_external_id(network_id)))[0]
        self.assertNotEmpty(egress_acl_entries)

    def _verify_ingress_adv_fwd_entries(self, network_id):
        ingress_acl_entries = self._get_ingress_adv_fwd_entries(
            network_id=network_id,
            vspk_filter='externalID == "{}"'.format(
                self._get_external_id(network_id)))[0]
        self.assertNotEmpty(ingress_acl_entries)

    def _get_ingress_adv_fwd_entries(self, network_id, vspk_filter):
        l2dom = self._find_l2_dom_in_resources(network_id)
        templates = l2dom.ingress_adv_fwd_templates.get(
            filter=vspk_filter)
        acls = []
        for template in templates:
            tmp = self.vsd.vspk.NUIngressAdvFwdTemplate(id=template.id)
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
        rt = self.create_redirection_target(**post_body)
        self._resources['rts'].append(rt)

        # Creating Redirect Target Rule
        rtid = str(rt['nuage_redirect_target']['id'])
        rule_body = {'priority': '100',
                     'redirect_target_id': rtid,
                     'protocol': '6',
                     'origin_group_id': str(sec_group['id']),
                     'remote_ip_prefix': '20.0.0.0/24',
                     'action': 'FORWARD', 'port_range_min': '50',
                     'port_range_max': '120'}

        rtrule = self.create_redirection_target_rule(**rule_body)
        return rt, rtrule

    @classmethod
    def _install_dependencies(cls):
        LOG.info('[{}] _install_dependencies:start'.format(cls.cls_name))
        script_path = os.path.dirname(os.path.abspath(__file__))
        errcode = subprocess.call('{}/bash/install_dependencies.sh'.format(
            script_path), shell=True)
        assert 0 == errcode
        LOG.info('[{}] _install_dependencies:end'.format(cls.cls_name))

    def _switch_plugin_branch(self, branch):
        LOG.info('[{}] _switch_plugin_branch:start ({})'.format(
            self.test_name, branch))
        script_path = os.path.dirname(os.path.abspath(__file__))
        errcode = subprocess.call('{}/bash/set_plugin_version.sh {}'.format(
            script_path, branch), shell=True)
        self.assertEqual(0, errcode)
        LOG.info('[{}] _switch_plugin_branch:end'.format(
            self.test_name))

    def _execute_the_upgrade_script(self, expected_exit_code=0, dryrun=False):
        LOG.info('[{}] _execute_the_upgrade_script:start{}'.format(
            self.test_name, ' (dry-run)' if dryrun else ''))

        # if env variables are not set, default values will be used.
        upgrade_script_path = os.getenv('UPGRADE_SCRIPT_PATH',
                                        self._upgrade_script_path)
        neutron_conf = os.getenv('NEUTRON_CONF', self._neutron_conf)
        plugin_conf = os.getenv('PLUGIN_CONF', self._plugin_conf)

        if dryrun:
            cmd = ('python {} --neutron-conf {} --nuage-conf {}'
                   ' --dry-run'.format(
                       upgrade_script_path, neutron_conf, plugin_conf))
        else:
            cmd = 'python {} --neutron-conf {} --nuage-conf {}'.format(
                upgrade_script_path, neutron_conf, plugin_conf)
        errcode = subprocess.call(cmd, shell=True)
        self.assertEqual(expected_exit_code, errcode)
        log_data = self._fetch_the_latest_log_file()
        self.assertNotIn(' ERROR', log_data)
        LOG.info('[{}] _execute_the_upgrade_script:end'.format(
            self.test_name))

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
        # keep quotes
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

    def _fetch_the_latest_log_file(
            self, log_file_matcher='upgrade_nuage_upgrade_to_6_0.*.log'):
        file_name = subprocess.check_output(
            "ls -lt {}/{}".format(self._log_dir, log_file_matcher) +
            " | (head -1; dd of=/dev/null 2>/dev/null)"  # fix broken pipe
            " | awk '{ print $9 }'", shell=True).strip()
        LOG.info('[{}] _fetch_the_latest_log_file:{}'.format(
            self.test_name, file_name))
        with open(file_name, 'r') as log_file:
            data = log_file.read()
        return data
