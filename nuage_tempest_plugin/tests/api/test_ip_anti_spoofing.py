# Copyright 2016 Nokia
# All Rights Reserved.

from collections import namedtuple
from enum import Enum
from netaddr import IPNetwork
from oslo_log import log as logging

from tempest.api.network import base
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest import test
from tempest.test import decorators

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.test.vsd_helper import VsdHelper

CONF = config.CONF
LOG = logging.getLogger(__name__)


# Enum for the IP MAC anti spoofing or VIP creation actions
class Action(Enum):
    spoofing = 1
    vip = 2
    no_vip = 3


class IpAntiSpoofingTestBase(base.BaseNetworkTest):
    @classmethod
    def resource_setup(cls):
        super(IpAntiSpoofingTestBase, cls).resource_setup()
        cls.def_net_partition = CONF.nuage.nuage_default_netpartition
        cls.vip_action = Action
        cls.vip_param = namedtuple(
            "VIP_Params", ["full_cidr", "diff_mac", "same_ip", "same_subn"])
        cls.vip_action_map = {}
        cls._populate_vip_action_map()
        cls.cur_vip_param = None

    @classmethod
    def setup_clients(cls):
        super(IpAntiSpoofingTestBase, cls).setup_clients()
        cls.vsd = VsdHelper()

    @classmethod
    def _create_subnet(cls, ntw, name=None, cidr=None, net_partition=None):
        if cidr is None:
            cidr = '30.30.30.0/24'
        if name is None:
            name = data_utils.rand_name('subnet-')
        kwargs = {'name': name,
                  'network_id': ntw['id'],
                  'ip_version': 4,
                  'cidr': cidr}
        if net_partition:
            kwargs['net_partition'] = net_partition
        body = cls.subnets_client.create_subnet(**kwargs)
        return body['subnet']

    @classmethod
    def _populate_vip_action_map(cls):
        cls.vip_action_map.update(
            {cls.vip_param('0', '0', '0', '0'): cls.vip_action.spoofing,
             cls.vip_param('0', '0', '0', '1'): cls.vip_action.spoofing,
             cls.vip_param('0', '0', '1', '1'): cls.vip_action.spoofing,
             cls.vip_param('0', '1', '0', '0'): cls.vip_action.spoofing,
             cls.vip_param('0', '1', '0', '1'): cls.vip_action.spoofing,
             cls.vip_param('0', '1', '1', '1'): cls.vip_action.spoofing,
             cls.vip_param('1', '0', '0', '0'): cls.vip_action.no_vip,
             cls.vip_param('1', '0', '0', '1'): cls.vip_action.vip,
             cls.vip_param('1', '0', '1', '1'): cls.vip_action.no_vip,
             cls.vip_param('1', '1', '0', '0'): cls.vip_action.spoofing,
             cls.vip_param('1', '1', '0', '1'): cls.vip_action.vip,
             cls.vip_param('1', '1', '1', '1'): cls.vip_action.spoofing})

    def _create_network_port_l2resources(self, ntw_security=True,
                                         port_security=True,
                                         port_name='port-1',
                                         l2domain_name='l2domain-1',
                                         netpart=None,
                                         allowed_address_pairs=None):
        # Method to create ntw, port and l2domain
        if netpart is None:
            netpart = self.def_net_partition
        kwargs = {'name': data_utils.rand_name('network-')}
        if ntw_security is not None:
            if not ntw_security:
                kwargs.update({'port_security_enabled': 'False'})
            # This is how it should be but was done differently; commenting out
            # else:
            #     kwargs.update({'port_security_enabled': 'True'})
        network = self.networks_client.create_network(**kwargs)['network']
        self.addCleanup(self.networks_client.delete_network, network['id'])
        l2domain = self._create_subnet(network, name=l2domain_name,
                                       net_partition=netpart)
        self.addCleanup(self.subnets_client.delete_subnet, l2domain['id'])
        kwargs = {'name': port_name, 'network_id': network['id']}
        if allowed_address_pairs:
            kwargs.update({'allowed_address_pairs': allowed_address_pairs})
        if port_security is not None:
            if not port_security:
                kwargs.update({'port_security_enabled': 'False'})
            # This is how it should be but was done differently; commenting out
            # else:
            #     kwargs.update({'port_security_enabled': 'True'})
        port = self.ports_client.create_port(**kwargs)['port']
        self.addCleanup(self.ports_client.delete_port, port['id'])
        return network, l2domain, port

    def _create_network_port_l3resources(self, ntw_security=True,
                                         port_security=True,
                                         router_name='router-1',
                                         subnet_name='subnet-1',
                                         port_name='port-1',
                                         netpart=None,
                                         allowed_address_pairs=None):
        # Method to create ntw, router, subnet and port
        if netpart is None:
            netpart = self.def_net_partition
        kwargs = {'name': data_utils.rand_name('network-')}
        if ntw_security is not None:
            if not ntw_security:
                kwargs.update({'port_security_enabled': 'False'})
            # This is how it should be but was done differently; commenting out
            # else:
            #     kwargs.update({'port_security_enabled': 'True'})
        network = self.networks_client.create_network(**kwargs)['network']
        self.addCleanup(self.networks_client.delete_network, network['id'])

        body = self.routers_client.create_router(name=router_name,
                                                 net_partition=netpart)
        router = body['router']
        self.addCleanup(self.routers_client.delete_router, router['id'])

        subnet = self._create_subnet(network, name=subnet_name,
                                     net_partition=netpart)
        self.addCleanup(self.subnets_client.delete_subnet, subnet['id'])

        self.routers_client.add_router_interface(router['id'],
                                                 subnet_id=subnet['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        router['id'], subnet_id=subnet['id'])
        kwargs = {'name': port_name, 'network_id': network['id']}
        if allowed_address_pairs:
            kwargs.update({'allowed_address_pairs': allowed_address_pairs})
        if port_security is not None:
            if not port_security:
                kwargs.update({'port_security_enabled': 'False'})
            # This is how it should be but was done differently; commenting out
            # else:
            #    kwargs.update({'port_security_enabled': 'True'})
        port = self.ports_client.create_port(**kwargs)['port']
        self.addCleanup(self.ports_client.delete_port, port['id'])
        return network, router, subnet, port

    def _create_vsd_managed_l2resources(self, ntw_security=True,
                                        port_security=True,
                                        port_name='port-1',
                                        l2domain_name='l2domain-1',
                                        netpart=None,
                                        allowed_address_pairs=None):
        if netpart is None:
            netpart = self.def_net_partition
        kwargs = {'name': data_utils.rand_name('network-')}
        if ntw_security is not None:
            if not ntw_security:
                kwargs.update({'port_security_enabled': 'False'})
            # This is how it should be but was done differently; commenting out
            # else:
            #     kwargs.update({'port_security_enabled': 'True'})
        network = self.networks_client.create_network(**kwargs)['network']
        self.addCleanup(self.networks_client.delete_network, network['id'])
        cidr = IPNetwork('40.40.40.0/24')
        gateway = '40.40.40.1'
        l2dom_temp_name = data_utils.rand_name('l2dom-template-')
        vsd_l2dom_tmplt = self.vsd.create_l2domain_template(
            name=l2dom_temp_name, enterprise=netpart,
            dhcp_managed=True, cidr4=cidr, gateway4=gateway)
        self.addCleanup(self.vsd.delete_l2domain_template, vsd_l2dom_tmplt.id)
        vsd_l2dom = self.vsd.create_l2domain(
            name=l2domain_name, enterprise=netpart, template=vsd_l2dom_tmplt)
        self.addCleanup(self.vsd.delete_l2domain, vsd_l2dom.id)
        subnet = self.create_subnet(
            network, cidr=cidr,
            mask_bits=24, gateway=None,
            nuagenet=vsd_l2dom.id,
            net_partition=netpart)
        self.addCleanup(self.subnets_client.delete_subnet, subnet['id'])

        kwargs = {'name': port_name, 'network_id': network['id']}
        if allowed_address_pairs:
            kwargs.update({'allowed_address_pairs': allowed_address_pairs})
        if port_security is not None:
            if not port_security:
                kwargs.update({'port_security_enabled': 'False'})
            # This is how it should be but was done differently; commenting out
            # else:
            #     kwargs.update({'port_security_enabled': 'True'})
        port = self.ports_client.create_port(**kwargs)['port']
        self.addCleanup(self.ports_client.delete_port, port['id'])
        return network, subnet, port, vsd_l2dom

    def _create_vsd_managed_l3resources(self, ntw_security=True,
                                        port_security=True,
                                        router_name='router-1',
                                        subnet_name='subnet-1',
                                        port_name='port-1',
                                        netpart=None,
                                        allowed_address_pairs=None):
        if netpart is None:
            netpart = self.def_net_partition
        kwargs = {'name': data_utils.rand_name('network-')}
        if ntw_security is not None:
            if not ntw_security:
                kwargs.update({'port_security_enabled': 'False'})
            # This is how it should be but was done differently; commenting out
            # else:
            #     kwargs.update({'port_security_enabled': 'True'})
        network = self.networks_client.create_network(**kwargs)['network']
        self.addCleanup(self.networks_client.delete_network, network['id'])
        router_temp_name = data_utils.rand_name('l3dom-template-')
        vsd_l3dom_tmplt = self.vsd.create_l3domain_template(
            name=router_temp_name, enterprise=netpart)
        self.addCleanup(self.vsd.delete_l3domain_template,
                        vsd_l3dom_tmplt.id)
        vsd_l3dom = self.vsd.create_domain(
            name=router_name, enterprise=netpart,
            template_id=vsd_l3dom_tmplt.id)
        self.addCleanup(self.vsd.delete_domain, vsd_l3dom.id)
        zone_name = data_utils.rand_name('l3dom-zone-')
        vsd_zone = self.vsd.create_zone(
            name=zone_name, domain=vsd_l3dom)
        cidr = IPNetwork('40.40.40.0/24')
        gateway = '40.40.40.1'
        vsd_subnet = self.vsd.create_subnet(
            name=subnet_name,
            zone=vsd_zone,
            cidr4=cidr,
            gateway=gateway)
        self.addCleanup(self.vsd.delete_subnet, vsd_subnet.id)
        subnet = self.create_subnet(network,
                                    cidr=cidr,
                                    mask_bits=24,
                                    nuagenet=vsd_subnet.id,
                                    net_partition=netpart)
        self.addCleanup(self.subnets_client.delete_subnet, subnet['id'])

        kwargs = {'name': port_name, 'network_id': network['id']}
        if allowed_address_pairs:
            kwargs.update({'allowed_address_pairs': allowed_address_pairs})
        if port_security is not None:
            if not port_security:
                kwargs.update({'port_security_enabled': 'False'})
            # This is how it should be but was done differently; commenting out
            # else:
            #     kwargs.update({'port_security_enabled': 'True'})
        port = self.ports_client.create_port(**kwargs)['port']
        self.addCleanup(self.ports_client.delete_port, port['id'])
        return network, subnet, port, vsd_l3dom, vsd_subnet

    def get_vip_action(self, key):
        return self.vip_action_map.get(key)

    # verification

    def _verify_vip_and_anti_spoofing(self, port, vsd_port, vip_params):
        # Case where only the anti-spoofing is enabled
        if self.get_vip_action(vip_params) == self.vip_action.spoofing:
            self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
            self.assertEqual(vsd_port.name, port['id'])
        # Case where VIP gets created. Verify the ip and mac of VIP
        if self.get_vip_action(vip_params) == self.vip_action.vip:
            self.assertEqual(vsd_port.address_spoofing, 'INHERITED')
            vsd_vips = vsd_port.virtual_ips.get()

            for os_vip in port['allowed_address_pairs']:
                vsd_vip = vsd_vips.pop()
                self.assertEqual(os_vip['ip_address'], vsd_vip.virtual_ip)
                self.assertEqual(os_vip['mac_address'], vsd_vip.mac)

        # Case where no action occurs on VSD for given AAP
        if self.get_vip_action(vip_params) == self.vip_action.no_vip:
            self.assertEqual(vsd_port.address_spoofing, 'INHERITED')

    # vsd getters

    def _get_vsd_l2dom_port(self, subnet, port):
        vsd_l2domain = self.vsd.get_l2domain(by_subnet_id=subnet['id'])
        self.assertIsNotNone(vsd_l2domain)
        vsd_ports = vsd_l2domain.vports.get()
        vsd_port = None
        while len(vsd_ports) > 0:
            vsd_port = vsd_ports.pop()
            if port['id'] == vsd_port.name:
                break
        self.assertIsNotNone(vsd_port)
        return vsd_l2domain, vsd_port

    def _get_vsd_router_subnet_port(self, router, subnet, port):
        vsd_l3dom = self.vsd.get_domain(by_router_id=router['id'])
        self.assertIsNotNone(vsd_l3dom)
        vsd_sub = self.vsd.get_subnet(by_subnet_id=subnet['id'])
        self.assertIsNotNone(vsd_sub)
        vsd_port = self.vsd.get_vport(subnet=vsd_sub, by_port_id=port['id'])
        self.assertIsNotNone(vsd_port)
        return vsd_l3dom, vsd_sub, vsd_port

    def _get_port_for_vsd_managed_l2domain(self, vsd_sub, port):
        vsd_l2domain = self.vsd.get_l2domain(vspk_filter='name == "{}"'.
                                             format(vsd_sub.name))
        self.assertIsNotNone(vsd_l2domain)
        vsd_ports = vsd_l2domain.vports.get()
        vsd_port = None
        while vsd_ports.__len__() > 0:
            vsd_port = vsd_ports.pop()
            if port['id'] == vsd_port.name:
                break
        self.assertIsNotNone(vsd_port)
        return vsd_port

    def _get_port_for_vsd_managed_l3domain(self, vsd_l3dom, vsd_sub, port):
        vsd_l3dom = self.vsd.get_domain(vspk_filter='name == "{}"'.
                                        format(vsd_l3dom.name))
        self.assertIsNotNone(vsd_l3dom)
        vsd_sub = self.vsd.get_subnet_from_domain(
            domain=vsd_l3dom.id,
            vspk_filter='name == "{}"'.format(vsd_sub.name))
        self.assertIsNotNone(vsd_sub)
        vsd_port = self.vsd.get_vport(subnet=vsd_sub, by_port_id=port['id'])
        self.assertIsNotNone(vsd_port)
        return vsd_port

    def _check_pg_for_less_security_set(self, vsd_domain, vsd_port):
        vsd_port_pg = vsd_port.policy_groups.get_first()
        vsd_l3dom_pgs = vsd_domain.policy_groups.get()
        pg_cnt = len(vsd_l3dom_pgs)
        self.assertEqual(1, pg_cnt)
        vsd_l3dom_pg = vsd_l3dom_pgs[0]
        self.assertEqual(vsd_port_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
        self.assertEqual(vsd_port_pg.name, vsd_l3dom_pg.name)
        # Check the two ingress and egress rules
        self._verify_ingress_egress_rules(vsd_port_pg)

    def _verify_ingress_egress_rules(self, vsd_pg, in_rule=None, eg_rule=None):
        # Method to verify the ingress and egress rules created for ports with
        # port-security-enabled set to False

        if in_rule is None:
            LOG.debug('getting ingress rules')
            in_rule = self.vsd.get_ingress_acl_entry(
                vspk_filter='locationID == "{}"'.format(vsd_pg.id))
        if eg_rule is None:
            LOG.debug('getting egress rules')
            eg_rule = self.vsd.get_egress_acl_entry(
                vspk_filter='locationID == "{}"'.format(vsd_pg.id))

        self.assertIsNotNone(in_rule, "in_rule must not be None")

        self.assertEqual(in_rule.network_type, 'ANY')
        self.assertEqual(in_rule.location_type, 'POLICYGROUP')
        self.assertEqual(in_rule.location_id, vsd_pg.id)

        self.assertIsNotNone(eg_rule, "eg_rule must not be None")

        self.assertEqual(eg_rule.network_type, 'ANY')
        self.assertEqual(eg_rule.location_type, 'POLICYGROUP')
        self.assertEqual(eg_rule.location_id, vsd_pg.id)


class IpAntiSpoofingTest(IpAntiSpoofingTestBase):
    @nuage_test.header()
    def test_create_delete_sec_disabled_ntw_port_l2domain(self):
        # L2domain testcase to test network and port creation with
        # port-security-enabled set to False explicitly for both
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security=False, port_security=False,
            l2domain_name='l2dom1-1',
            port_name='port1-1')
        self.assertEqual(network['port_security_enabled'], False)
        self.assertEqual(port['port_security_enabled'], False)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(l2domain, port)
        self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port.name, port['id'])
        self._check_pg_for_less_security_set(vsd_l2domain, vsd_port)

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_create_delete_sec_ntw_port_l2domain(self):
        # L2domain testcase to test network and port creation without
        # specifying security related attributes
        network, l2domain, port = self._create_network_port_l2resources(
            l2domain_name='l2domdefault-1',
            port_name='portdefault-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], True)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(l2domain, port)
        self.assertEqual(vsd_port.address_spoofing, 'INHERITED')
        self.assertEqual(vsd_port.name, port['id'])

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_create_delete_sec_ntw_port_l3domain(self):
        # L3domain testcase to test network and port creation without
        # specifying port-security attributes
        network, router, subnet, port = self._create_network_port_l3resources(
            router_name='routerdefault-1',
            subnet_name='subnetdefault-1',
            port_name='portdefault-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], True)
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        self.assertEqual(vsd_port.address_spoofing, 'INHERITED')
        self.assertEqual(vsd_port.name, port['id'])

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_create_delete_sec_disabled_ntw_l2domain(self):
        # L2domain testcase to test network and port creation with
        # port-security-enabled set to False at network level only
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security=False,
            l2domain_name='l2dom2-1',
            port_name='port2-1')
        self.assertEqual(network['port_security_enabled'], False)
        self.assertEqual(port['port_security_enabled'], False)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(l2domain, port)
        self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port.name, port['id'])
        self._check_pg_for_less_security_set(vsd_l2domain, vsd_port)

    @nuage_test.header()
    def test_create_delete_sec_disabled_port_l2domain(self):
        # L2domain testcase to test network and port creation with
        # port-security-enabled set to False at port level only
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=False,
            l2domain_name='l2dom3-1',
            port_name='port3-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], False)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(l2domain, port)
        self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port.name, port['id'])
        self._check_pg_for_less_security_set(vsd_l2domain, vsd_port)

    @nuage_test.header()
    def test_create_delete_sec_disabled_ntw_port_l3domain(self):
        # L3domain testcase to test the network and port creation with
        # port-security-enabled set to False explicitly for both
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=False,
            port_security=False,
            router_name='router4-1',
            subnet_name='subnet4-1',
            port_name='port4-1')
        self.assertEqual(network['port_security_enabled'], False)
        self.assertEqual(port['port_security_enabled'], False)
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port.name, port['id'])
        self._check_pg_for_less_security_set(vsd_l3dom, vsd_port)

    @nuage_test.header()
    def test_create_delete_sec_disabled_ntw_l3domain(self):
        # L3domain testcase to test the network and port creation with
        # port-security-enabled set to False explicitly for both
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=False,
            port_security=True,
            router_name='router5-1',
            subnet_name='subnet5-1',
            port_name='port5-1')
        self.assertEqual(network['port_security_enabled'], False)
        self.assertEqual(port['port_security_enabled'], False)
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port.name, port['id'])
        self._check_pg_for_less_security_set(vsd_l3dom, vsd_port)

    @nuage_test.header()
    def test_create_delete_sec_disabled_port_l3domain(self):
        # L3domain testcase to test the network and port creation with
        # port-security-enabled set to False explicitly for both
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=False,
            router_name='router6-1',
            subnet_name='subnet6-1',
            port_name='port6-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], False)
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port.name, port['id'])
        self._check_pg_for_less_security_set(vsd_l3dom, vsd_port)

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_update_ntw_from_sec_disabled_to_enabled_l2domain(self):
        # L2domain testcase for updating the port-security-enabled flag
        # from False to True. Ports are created at both the states to check
        # if the network level security is correctly proaogated.
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security=False, port_security=True,
            l2domain_name='l2dom7-1',
            port_name='port7-1')
        self.assertEqual(network['port_security_enabled'], False)
        self.assertEqual(port['port_security_enabled'], False)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(l2domain, port)
        self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port.name, port['id'])
        self._check_pg_for_less_security_set(vsd_l2domain, vsd_port)

        # Update the network and create a new port
        self.networks_client.update_network(network['id'],
                                            port_security_enabled='True')
        kwargs = {'name': 'port7-2', 'network_id': network['id']}
        body = self.ports_client.create_port(**kwargs)
        port_2 = body['port']
        self.addCleanup(self.ports_client.delete_port, port_2['id'])

    @nuage_test.header()
    def test_update_ntw_from_sec_enabled_to_disabled_l2domain(self):
        # L2domain testcase for updating the port-security-enabled flag
        # from True to False. Ports are created at both the states to check
        # if the network level security is correctly propagated.
        network, l2domain, port_1 = self._create_network_port_l2resources(
            ntw_security=True, port_security=True,
            l2domain_name='l2dom8-1',
            port_name='port8-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port_1['port_security_enabled'], True)

        vsd_l2domain, vsd_port_1 = self._get_vsd_l2dom_port(l2domain, port_1)
        self.assertEqual(vsd_port_1.address_spoofing, 'INHERITED')
        self.assertEqual(vsd_port_1.name, port_1['id'])
        port_1_pg = vsd_port_1.policy_groups.get_first()
        self.assertNotEqual(port_1_pg.name[:21], 'PG_FOR_LESS_SECURITY_')

        # Update the network and create a new port
        self.networks_client.update_network(
            network['id'], port_security_enabled='False')
        kwargs = {'name': 'port8-2', 'network_id': network['id']}
        body = self.ports_client.create_port(**kwargs)
        port_2 = body['port']
        self.addCleanup(self.ports_client.delete_port, port_2['id'])
        vsd_l2domain, vsd_port_2 = self._get_vsd_l2dom_port(l2domain, port_2)
        self.assertEqual(vsd_port_1.address_spoofing, 'INHERITED')
        self.assertEqual(vsd_port_2.address_spoofing, 'ENABLED')  # No sure why
        self.assertEqual(vsd_port_1.name, port_1['id'])
        self.assertEqual(vsd_port_2.name, port_2['id'])
        port_2_pg = vsd_port_2.policy_groups.get_first()
        self.assertEqual(port_2_pg.name[:21], 'PG_FOR_LESS_SECURITY_')

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_update_port_from_sec_disabled_to_enabled_l2domain(self):
        # L2domain testcase for updating the port-security-enabled flag
        # from False to True at port level. Network level flag set to
        # True by default
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=False,
            l2domain_name='l2dom9-1',
            port_name='port9-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], False)

        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(l2domain, port)
        self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port.name, port['id'])
        self._check_pg_for_less_security_set(vsd_l2domain, vsd_port)

        # Update the port
        body = self.ports_client.update_port(port['id'],
                                             port_security_enabled='True')
        port = body['port']
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(l2domain, port)
        self.assertEqual(vsd_port.address_spoofing, 'DISABLED')
        self.assertEqual(vsd_port.name, port['id'])

        port_pg = vsd_port.policy_groups.get_first()
        self.assertIsNone(port_pg)

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_update_port_from_sec_enabled_to_disabled_l2domain(self):
        # L2domain testcase for updating the port-security-enabled flag
        # from True to False at port level. Network level flag set to
        # True by default
        network, l2domain, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=True,
            l2domain_name='l2dom10-1',
            port_name='port10-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], True)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(l2domain, port)
        self.assertEqual(vsd_port.address_spoofing, 'INHERITED')
        self.assertEqual(vsd_port.name, port['id'])

        # Update the port
        self.ports_client.update_port(port['id'], security_groups=[])
        body = self.ports_client.update_port(port['id'],
                                             port_security_enabled='False')
        port = body['port']
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(l2domain, port)
        self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port.name, port['id'])
        self._check_pg_for_less_security_set(vsd_l2domain, vsd_port)

    @nuage_test.header()
    def test_update_ntw_from_sec_disabled_to_enabled_l3domain(self):
        # L3domain testcase for updating the port-security-enabled flag
        # from False to True. Ports are created at both the states to check
        # if the network level security is correctly propagated.
        network, router, subnet, port_1 = \
            self._create_network_port_l3resources(
                ntw_security=False,
                port_security=True,
                router_name='router11-1',
                subnet_name='subnet11-1',
                port_name='port11-1')
        self.assertEqual(network['port_security_enabled'], False)
        self.assertEqual(port_1['port_security_enabled'], False)
        vsd_l3dom, vsd_sub, vsd_port_1 = self._get_vsd_router_subnet_port(
            router, subnet, port_1)
        self.assertEqual(vsd_port_1.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port_1.name, port_1['id'])
        self._check_pg_for_less_security_set(vsd_l3dom, vsd_port_1)

        # Update the network and create a new port
        self.networks_client.update_network(network['id'],
                                            port_security_enabled='True')
        kwargs = {'name': 'port11-2', 'network_id': network['id']}
        body = self.ports_client.create_port(**kwargs)
        port_2 = body['port']
        self.addCleanup(self.ports_client.delete_port, port_2['id'])
        vsd_l3dom, vsd_sub, vsd_port_2 = self._get_vsd_router_subnet_port(
            router, subnet, port_2)
        self.assertEqual(vsd_port_1.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port_2.address_spoofing, 'INHERITED')
        self.assertEqual(vsd_port_1.name, port_1['id'])
        self.assertEqual(vsd_port_2.name, port_2['id'])

        port_1_pg = vsd_port_1.policy_groups.get_first()
        port_2_pg = vsd_port_2.policy_groups.get_first()
        self.assertEqual(port_1_pg.name[:21], 'PG_FOR_LESS_SECURITY_')
        self.assertNotEqual(port_2_pg.name[:21], 'PG_FOR_LESS_SECURITY_')

    @nuage_test.header()
    def test_update_ntw_from_sec_enabled_to_disabled_l3domain(self):
        # L3domain testcase for updating the port-security-enabled flag
        # from True to False. Ports are created at both the states to check
        # if the network level security is correctly propagated.
        network, router, subnet, port_1 = \
            self._create_network_port_l3resources(
                ntw_security=True,
                port_security=True,
                router_name='router12-1',
                subnet_name='subnet12-1',
                port_name='port12-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port_1['port_security_enabled'], True)
        vsd_l3dom, vsd_sub, vsd_port_1 = self._get_vsd_router_subnet_port(
            router, subnet, port_1)
        self.assertEqual(vsd_port_1.address_spoofing, 'INHERITED')
        self.assertEqual(vsd_port_1.name, port_1['id'])
        port_1_pg = vsd_port_1.policy_groups.get_first()
        self.assertNotEqual(port_1_pg.name[:21], 'PG_FOR_LESS_SECURITY_')

        # Update the network and create a new port
        self.networks_client.update_network(network['id'],
                                            port_security_enabled='False')
        kwargs = {'name': 'port12-2', 'network_id': network['id']}
        body = self.ports_client.create_port(**kwargs)
        port_2 = body['port']
        self.addCleanup(self.ports_client.delete_port, port_2['id'])
        vsd_l3dom, vsd_sub, vsd_port_2 = self._get_vsd_router_subnet_port(
            router, subnet, port_2)
        self.assertEqual(vsd_port_1.address_spoofing, 'INHERITED')  # ???
        self.assertEqual(vsd_port_2.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port_1.name, port_1['id'])
        self.assertEqual(vsd_port_2.name, port_2['id'])

        port_2_pg = vsd_port_2.policy_groups.get_first()
        self.assertEqual(port_2_pg.name[:21], 'PG_FOR_LESS_SECURITY_')

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_update_port_from_sec_disabled_to_enabled_l3domain(self):
        # L3domain testcase for updating the port-security-enabled flag
        # from False to True at port level. Network level flag set to
        # True by default
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=False,
            router_name='router13-1',
            subnet_name='subnet13-1',
            port_name='port13-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], False)
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port.name, port['id'])
        self._check_pg_for_less_security_set(vsd_l3dom, vsd_port)

        # Update the port
        body = self.ports_client.update_port(port['id'],
                                             port_security_enabled='True')
        updated_port = body['port']
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, updated_port)
        self.assertEqual(vsd_port.address_spoofing, 'DISABLED')
        self.assertEqual(vsd_port.name, port['id'])

        port_pg = vsd_port.policy_groups.get_first()
        self.assertIsNone(port_pg)

    @nuage_test.header()
    @decorators.attr(type='smoke')
    def test_update_port_from_sec_enabled_to_disabled_l3domain(self):
        # L3domain testcase for updating the port-security-enabled flag
        # from True to False at port level. Network level flag set to
        # True by default
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=True,
            router_name='router14-1',
            subnet_name='subnet14-1',
            port_name='port14-1')
        self.assertEqual(network['port_security_enabled'], True)
        self.assertEqual(port['port_security_enabled'], True)
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        self.assertEqual(vsd_port.address_spoofing, 'INHERITED')
        self.assertEqual(vsd_port.name, port['id'])

        # Update the port
        self.ports_client.update_port(port['id'], security_groups=[])
        body = self.ports_client.update_port(port['id'],
                                             port_security_enabled='False')
        port = body['port']
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port.name, port['id'])
        self._check_pg_for_less_security_set(vsd_l3dom, vsd_port)

    @nuage_test.header()
    def test_show_sec_disabled_ntw(self):
        pass

    @nuage_test.header()
    def test_show_sec_disabled_port(self):
        pass

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.0.0/24'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, subnet, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=True,
            l2domain_name='l2dom21-1',
            port_name='port21-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('0', '0', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, same subnet in
        # comparison with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, subnet, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=True,
            l2domain_name='l2dom22-1',
            port_name='port22-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('0', '0', '0', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, subnet, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=True,
            l2domain_name='l2dom23-1',
            port_name='port23-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('0', '0', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.0.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, subnet, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=True,
            l2domain_name='l2dom24-1',
            port_name='port24-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('0', '1', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, same subnet in
        # comparison with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, subnet, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=True,
            l2domain_name='l2dom25-1',
            port_name='port25-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('0', '1', '0', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, subnet, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=True,
            l2domain_name='l2dom26-1',
            port_name='port26-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('0', '1', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.20.100'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, subnet, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=True,
            l2domain_name='l2dom27-1',
            port_name='port27-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('1', '0', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, same ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '30.30.30.100'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, subnet, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=True,
            l2domain_name='l2dom28-1',
            port_name='port28-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port.name, port['id'])

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        network, subnet, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=True,
            l2domain_name='l2dom29-1',
            port_name='port29-1')
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = port['mac_address']
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        body = self.ports_client.update_port(
            port['id'], allowed_address_pairs=allowed_address_pairs)
        port = body['port']
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('1', '0', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.20.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, subnet, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=True,
            l2domain_name='l2dom30-1',
            port_name='port30-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('1', '1', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different ip, different ip,  different subnet in
        # comparison with the corresponding port parameters
        ip_address = '30.30.30.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, subnet, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=True,
            l2domain_name='l2dom31-1',
            port_name='port31-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port.name, port['id'])

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        network, subnet, port = self._create_network_port_l2resources(
            ntw_security=True, port_security=True,
            l2domain_name='l2dom32-1',
            port_name='port32-1')
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        body = self.ports_client.update_port(
            port['id'], allowed_address_pairs=allowed_address_pairs)
        port = body['port']
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('1', '1', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.0.0/24'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=True,
            router_name='router41-1',
            subnet_name='subnet41-1',
            port_name='port41-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('0', '0', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, same subnet in
        # comparison with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=True,
            router_name='router42-1',
            subnet_name='subnet42-1',
            port_name='port42-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('0', '0', '0', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=True,
            router_name='router43-1',
            subnet_name='subnet43-1',
            port_name='port43-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('0', '0', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.0.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=True,
            router_name='router44-1',
            subnet_name='subnet44-1',
            port_name='port44-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('0', '1', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, same subnet in
        # comparison with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=True,
            router_name='router45-1',
            subnet_name='subnet45-1',
            port_name='port45-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('0', '1', '0', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        ip_address = '30.30.30.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=True,
            router_name='router46-1',
            subnet_name='subnet46-1',
            port_name='port46-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('0', '1', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.20.100'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=True,
            router_name='router47-1',
            subnet_name='subnet47-1',
            port_name='port47-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('1', '0', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, same ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '30.30.30.100'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=True,
            router_name='router48-1',
            subnet_name='subnet48-1',
            port_name='port48-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('1', '0', '0', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=True,
            router_name='router49-1',
            subnet_name='subnet49-1',
            port_name='port49-1')
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = port['mac_address']
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        body = self.ports_client.update_port(
            port['id'], allowed_address_pairs=allowed_address_pairs)
        port = body['port']
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('1', '0', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.20.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=True,
            router_name='router50-1',
            subnet_name='subnet50-1',
            port_name='port50-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('1', '1', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different ip, different ip,  different subnet in
        # comparison with the corresponding port parameters
        ip_address = '30.30.30.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=True,
            router_name='router51-1',
            subnet_name='subnet51-1',
            port_name='port51-1',
            netpart=self.def_net_partition,
            allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('1', '1', '0', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        network, router, subnet, port = self._create_network_port_l3resources(
            ntw_security=True,
            port_security=True,
            router_name='router52-1',
            subnet_name='subnet52-1',
            port_name='port52-1')
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        body = self.ports_client.update_port(
            port['id'], allowed_address_pairs=allowed_address_pairs)
        port = body['port']
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('1', '1', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_1_1_vsd_managed_l2domain(self):
        # IP Anti Spoofing tests for vsd managed port having vip parameters:
        # full cidr(/32 IP), different mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        network, subnet, port, vsd_l2dom = \
            self._create_vsd_managed_l2resources(
                ntw_security=True,
                port_security=True,
                l2domain_name='subnet64-1',
                port_name='port64-1')
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        body = self.ports_client.update_port(
            port['id'], allowed_address_pairs=allowed_address_pairs)
        port = body['port']
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        vsd_port = self._get_port_for_vsd_managed_l2domain(vsd_l2dom, port)
        vip_params = ('1', '1', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_1_1_vsd_managed_l3domain(self):
        # IP Anti Spoofing tests for vsd managed port having vip parameters:
        # full cidr(/32 IP), different mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        network, subnet, port, vsd_l3dom, vsd_sub = \
            self._create_vsd_managed_l3resources(
                ntw_security=True,
                port_security=True,
                router_name='router61-1',
                subnet_name='subnet61-1',
                port_name='port61-1')
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_address_pairs = [{'ip_address': ip_address,
                                  'mac_address': mac_address}]
        body = self.ports_client.update_port(
            port['id'], allowed_address_pairs=allowed_address_pairs)
        port = body['port']
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        self.assertEqual(port['allowed_address_pairs'][0]['mac_address'],
                         allowed_address_pairs[0]['mac_address'])
        vsd_port = self._get_port_for_vsd_managed_l3domain(
            vsd_l3dom, vsd_sub, port)
        vip_params = ('1', '1', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_1_vsd_managed_l3domain(self):
        # IP Anti Spoofing tests for vsd managed subnet port with
        # vip parameters having full cidr(/32 IP), same mac, same ip,
        # different subnet in comparison with the corresponding
        # port parameters
        ip_address = '40.40.40.100'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, subnet, port, vsd_l3dom, vsd_sub = \
            self._create_vsd_managed_l3resources(
                ntw_security=True,
                port_security=True,
                router_name='router62-1',
                subnet_name='subnet62-1',
                port_name='port62-1',
                netpart=self.def_net_partition,
                allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        vsd_port = self._get_port_for_vsd_managed_l3domain(
            vsd_l3dom, vsd_sub, port)
        vip_params = ('1', '0', '0', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_0_vsd_managed_l3domain(self):
        # IP Anti Spoofing tests for vsd managed subnet port with
        # vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.20.100'
        allowed_address_pairs = [{'ip_address': ip_address}]
        network, subnet, port, vsd_l3dom, vsd_sub = \
            self._create_vsd_managed_l3resources(
                ntw_security=True,
                port_security=True,
                router_name='router63-1',
                subnet_name='subnet63-1',
                port_name='port63-1',
                netpart=self.def_net_partition,
                allowed_address_pairs=allowed_address_pairs)
        self.assertEqual(port['allowed_address_pairs'][0]['ip_address'],
                         allowed_address_pairs[0]['ip_address'])
        vsd_port = self._get_port_for_vsd_managed_l3domain(
            vsd_l3dom, vsd_sub, port)
        vip_params = ('1', '0', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)


class IpAntiSpoofingCliTests(IpAntiSpoofingTestBase, test.BaseTestCase):

    @classmethod
    def skip_checks(cls):
        # TODO(Kris) NEEDS MORE WORK
        raise cls.skipException(
            'TODO(KRIS) : IpAntiSpoofingCliTests need more work.')

    def_net_partition = CONF.nuage.nuage_default_netpartition

    def _create_and_verify_ntw_port_with_sec_value(self, ntw_name, port_name,
                                                   ntw_security=None,
                                                   port_security=None):
        if ntw_security is None:
            network = self.create_network(ntw_name)
            ntw_security = True
        else:
            kwargs = {'port_security_enabled': ntw_security}
            network = self.create_network(ntw_name, **kwargs)
        self.assertEqual(network['name'], ntw_name)
        self.assertEqual(network['port_security_enabled'], ntw_security)
        port_kwargs = {'name': port_name}
        if port_security is None:
            port = self.create_port(network, **port_kwargs)
            port_security = ntw_security
        else:
            port_kwargs.update({'port_security_enabled': port_security})
            port = self.create_port(network, **port_kwargs)
        self.assertEqual(port['port_security_enabled'], port_security)
        self.assertEqual(port['name'], port_name)
        return port

    def _create_l2resources(self, ntw_name, sub_name, port_name,
                            addr_pr=None, cidr='50.50.50.0/24', mac=None):
        network = self.create_network(ntw_name)
        cidr = IPNetwork(cidr)
        subnet = self.create_subnet(network, cidr=cidr,
                                    mask_bits=cidr.prefixlen,
                                    net_partition=self.def_net_partition)
        if mac:
            raise NotImplemented

        if addr_pr:
            kwargs = {'allowed_address_pairs': addr_pr,
                      'name': port_name}
        else:
            kwargs = {'name': port_name}
        port = self.create_port(network, **kwargs)
        return subnet, port

    def _create_l3resources(self, ntw_name, router_name, sub_name, port_name,
                            addr_pr=None, cidr='50.50.50.0/24', mac=None):
        router = self.create_router(router_name,
                                    net_partition=self.def_net_partition)
        network = self.create_network(ntw_name)
        cidr = IPNetwork(cidr)
        if mac:
            raise NotImplemented

        kwargs = {'name': sub_name, 'net_partition': self.def_net_partition}
        subnet = self.create_subnet(network, cidr=cidr, mask_bits=24, **kwargs)
        self.create_router_interface(router['id'], subnet['id'])
        if addr_pr:
            kwargs = {'allowed_address_pairs': addr_pr,
                      'name': port_name}
            port = self.create_port(network, **kwargs)
        else:
            port = self.create_port(network)
        return router, subnet, port

    @nuage_test.header()
    def test_create_show_update_delete_ntw_with_sec_disabled(self):
        ntw_name = data_utils.rand_name('network-')
        kwargs = {'port_security_enabled': 'False'}
        network = self.create_network(ntw_name, **kwargs)
        self.assertEqual(network['port_security_enabled'], 'False')
        self.assertEqual(network['name'], ntw_name)
        # check the net-show to verify the port_security option
        ntw_show = self.networks_client.show_network(network['id'])
        self.assertEqual(ntw_show['port_security_enabled'], 'False')
        self.assertEqual(ntw_show['name'], ntw_name)

        # update the network to enable port security
        kwargs = {'port_security_enabled': 'True'}
        self.networks_client.update_network(network['id'], **kwargs)
        ntw_show = self.networks_client.show_network(network['id'])
        self.assertEqual(ntw_show['port_security_enabled'], 'True')

    @nuage_test.header()
    def test_create_show_update_delete_port_with_sec_disabled(self):
        ntw_name = data_utils.rand_name('network-')
        port_name = data_utils.rand_name('port-')
        port = self._create_and_verify_ntw_port_with_sec_value(
            ntw_name, port_name,
            port_security=False)

        # Check the port-shows the right port-security value
        port_show = self.ports_client.show_port(port['id'])
        self.assertEqual(port_show['port_security_enabled'], 'False')
        self.assertEqual(port_show['name'], port_name)

        # Update the port to enable port security
        kwargs = {'port_security_enabled': 'True'}
        self.ports_client.update_port(port, **kwargs)
        port_show = self.ports_client.show_port(port['id'])
        self.assertEqual(port_show['port_security_enabled'], 'True')

    @nuage_test.header()
    def test_create_port_in_sec_disabled_ntw(self):
        ntw_name = data_utils.rand_name('network-')
        port_name = data_utils.rand_name('port-')
        port = self._create_and_verify_ntw_port_with_sec_value(
            ntw_name, port_name,
            ntw_security=False)
        self.assertIsNotNone(port)

    @nuage_test.header()
    def test_create_sec_disabled_port_in_sec_disabled_ntw(self):
        ntw_name = data_utils.rand_name('network-')
        port_name = data_utils.rand_name('port-')
        port = self._create_and_verify_ntw_port_with_sec_value(
            ntw_name, port_name,
            ntw_security=False,
            port_security=False)
        self.assertIsNotNone(port)

    @nuage_test.header()
    def test_create_sec_enabled_port_in_sec_disabled_ntw(self):
        ntw_name = data_utils.rand_name('network-')
        port_name = data_utils.rand_name('port-')
        port = self._create_and_verify_ntw_port_with_sec_value(
            ntw_name, port_name,
            ntw_security=False,
            port_security=True)
        self.assertIsNotNone(port)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        allowed_addr_pair = [{'ip_address': '30.30.30.0/24'}]
        ntw_name = 'network70-1'
        sub_name = 'subnet70-1'
        port_name = 'port70-1'
        subnet, port = self._create_l2resources(
            ntw_name, sub_name, port_name, addr_pr=allowed_addr_pair)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('0', '0', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, same subnet in
        # comparison with the corresponding port parameters
        allowed_addr_pair = [{'ip_address': '50.50.50.0/24'}]
        ntw_name = 'network71-1'
        sub_name = 'subnet71-1'
        port_name = 'port71-1'
        subnet, port = self._create_l2resources(
            ntw_name, sub_name, port_name, addr_pr=allowed_addr_pair)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('0', '0', '0', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        # ip_address = '30.30.30.0/24'
        allowed_addr_pair = [{'ip_address': '50.50.50.0/24'}]
        ntw_name = 'network72-1'
        sub_name = 'subnet72-1'
        port_name = 'port72-1'
        subnet, port = self._create_l2resources(
            ntw_name, sub_name, port_name, addr_pr=allowed_addr_pair)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('0', '0', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.0.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = [{'ip_address': ip_address,
                              'mac_address': mac_address}]
        ntw_name = 'network73-1'
        sub_name = 'subnet73-1'
        port_name = 'port73-1'
        subnet, port = self._create_l2resources(
            ntw_name, sub_name, port_name, addr_pr=allowed_addr_pair)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('0', '1', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, same subnet in
        # comparison with the corresponding port parameters
        ip_address = '50.50.50.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = [{'ip_address': ip_address,
                              'mac_address': mac_address}]
        ntw_name = 'network74-1'
        sub_name = 'subnet74-1'
        port_name = 'port74-1'
        subnet, port = self._create_l2resources(
            ntw_name, sub_name, port_name, addr_pr=allowed_addr_pair)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('0', '1', '0', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        ip_address = '50.50.50.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = [{'ip_address': ip_address,
                              'mac_address': mac_address}]
        ntw_name = 'network75-1'
        sub_name = 'subnet75-1'
        port_name = 'port75-1'
        subnet, port = self._create_l2resources(
            ntw_name, sub_name, port_name, addr_pr=allowed_addr_pair)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('0', '1', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.20.100'
        allowed_addr_pair = [{'ip_address': ip_address}]
        ntw_name = 'network76-1'
        sub_name = 'subnet76-1'
        port_name = 'port76-1'
        subnet, port = self._create_l2resources(
            ntw_name, sub_name, port_name, addr_pr=allowed_addr_pair)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('1', '0', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, same ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '50.50.50.100'
        allowed_addr_pair = [{'ip_address': ip_address}]
        ntw_name = 'network77-1'
        sub_name = 'subnet77-1'
        port_name = 'port77-1'
        subnet, port = self._create_l2resources(
            ntw_name, sub_name, port_name, addr_pr=allowed_addr_pair)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port.name, port['id'])

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        ntw_name = 'network78-1'
        sub_name = 'subnet78-1'
        port_name = 'port78-1'
        subnet, port = self._create_l2resources(
            ntw_name, sub_name, port_name)
        ip_address = port['fixed_ips'][0]['ip_address']

        mac_address = port['mac_address']
        allowed_addr_pair = {'ip_address': ip_address,
                             'mac_address': mac_address}
        kwargs = {'allowed_address_pairs': allowed_addr_pair}
        port = self.ports_client.update_port(port, **kwargs)
        self.assertIsNone(port)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('1', '0', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_0_0_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.20.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = [{'ip_address': ip_address,
                              'mac_address': mac_address}]
        ntw_name = 'network79-1'
        sub_name = 'subnet79-1'
        port_name = 'port79-1'
        subnet, port = self._create_l2resources(
            ntw_name, sub_name, port_name, addr_pr=allowed_addr_pair)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('1', '1', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_0_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different ip, different ip,  different subnet in
        # comparison with the corresponding port parameters
        ip_address = '50.50.50.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = [{'ip_address': ip_address,
                              'mac_address': mac_address}]
        ntw_name = 'network80-1'
        sub_name = 'subnet80-1'
        port_name = 'port80-1'
        subnet, port = self._create_l2resources(
            ntw_name, sub_name, port_name, addr_pr=allowed_addr_pair)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        self.assertEqual(vsd_port.address_spoofing, 'ENABLED')
        self.assertEqual(vsd_port.name, port['id'])

    @nuage_test.header()
    # KRIS OK
    def test_anti_spoofing_for_params_1_1_1_1_l2domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        ntw_name = 'network81-1'
        sub_name = 'subnet81-1'
        port_name = 'port81-1'
        subnet, port = self._create_l2resources(ntw_name, sub_name, port_name)
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = [{'ip_address': ip_address,
                              'mac_address': mac_address}]
        kwargs = {'allowed_address_pairs': allowed_addr_pair}
        port = self.ports_client.update_port(port, **kwargs)
        self.assertIsNone(port)
        vsd_l2domain, vsd_port = self._get_vsd_l2dom_port(subnet, port)
        vip_params = ('1', '1', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.0.0/24'
        allowed_addr_pair = [{'ip_address': ip_address}]
        ntw_name = 'network82-1'
        router_name = 'router82-1'
        sub_name = 'subnet82-1'
        port_name = 'port82-1'
        router, subnet, port = self._create_l3resources(
            ntw_name, router_name, sub_name, port_name,
            addr_pr=allowed_addr_pair)
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('0', '0', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, different ip, same subnet in
        # comparison with the corresponding port parameters
        ip_address = '50.50.50.0/24'
        allowed_addr_pair = [{'ip_address': ip_address}]
        ntw_name = 'network83-1'
        router_name = 'router83-1'
        sub_name = 'subnet83-1'
        port_name = 'port83-1'
        router, subnet, port = self._create_l3resources(
            ntw_name, router_name, sub_name, port_name,
            addr_pr=allowed_addr_pair)
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('0', '0', '0', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_0_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        ip_address = '50.50.50.0/24'
        allowed_addr_pair = [{'ip_address': ip_address}]
        ntw_name = 'network84-1'
        router_name = 'router84-1'
        sub_name = 'subnet84-1'
        port_name = 'port84-1'
        router, subnet, port = self._create_l3resources(
            ntw_name, router_name, sub_name, port_name,
            addr_pr=allowed_addr_pair)
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('0', '0', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.0.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = [{'ip_address': ip_address,
                              'mac_address': mac_address}]
        ntw_name = 'network85-1'
        router_name = 'router85-1'
        sub_name = 'subnet85-1'
        port_name = 'port85-1'
        router, subnet, port = self._create_l3resources(
            ntw_name, router_name, sub_name, port_name,
            addr_pr=allowed_addr_pair)
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('0', '1', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_0_1_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, different ip, same subnet in
        # comparison with the corresponding port parameters
        ip_address = '50.50.50.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = [{'ip_address': ip_address,
                              'mac_address': mac_address}]
        ntw_name = 'network86-1'
        router_name = 'router86-1'
        sub_name = 'subnet86-1'
        port_name = 'port86-1'
        router, subnet, port = self._create_l3resources(
            ntw_name, router_name, sub_name, port_name,
            addr_pr=allowed_addr_pair)
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('0', '1', '0', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    def test_anti_spoofing_for_params_0_1_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # different mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        ip_address = '50.50.50.0/24'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = [{'ip_address': ip_address,
                             'mac_address': mac_address}]
        ntw_name = 'network87-1'
        router_name = 'router87-1'
        sub_name = 'subnet87-1'
        port_name = 'port87-1'
        router, subnet, port = self._create_l3resources(
            ntw_name, router_name, sub_name, port_name,
            addr_pr=allowed_addr_pair)
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('0', '1', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.20.100'
        allowed_addr_pair = [{'ip_address': ip_address}]
        ntw_name = 'network88-1'
        router_name = 'router88-1'
        sub_name = 'subnet88-1'
        port_name = 'port88-1'
        router, subnet, port = self._create_l3resources(
            ntw_name, router_name, sub_name, port_name,
            addr_pr=allowed_addr_pair)
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('1', '0', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    def test_anti_spoofing_for_params_1_0_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, same ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '50.50.50.100'
        allowed_addr_pair = [{'ip_address': ip_address}]
        ntw_name = 'network89-1'
        router_name = 'router89-1'
        sub_name = 'subnet89-1'
        port_name = 'port89-1'
        router, subnet, port = self._create_l3resources(
            ntw_name, router_name, sub_name, port_name,
            addr_pr=allowed_addr_pair)
        _, _, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('1', '0', '0', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_0_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having cidr(not /32 IP),
        # same mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        ntw_name = 'network90-1'
        router_name = 'router90-1'
        sub_name = 'subnet90-1'
        port_name = 'port90-1'
        router, subnet, port = self._create_l3resources(ntw_name, router_name,
                                                        sub_name, port_name)
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = port['mac_address']
        allowed_addr_pair = [{'ip_address': ip_address,
                              'mac_address': mac_address}]
        kwargs = {'allowed_address_pairs': allowed_addr_pair}
        port = self.ports_client.update_port(port, **kwargs)
        self.assertIsNone(port)
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('1', '0', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_0_0_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # same mac, different ip, different subnet in
        # comparison with the corresponding port parameters
        ip_address = '20.20.20.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = [{'ip_address': ip_address,
                              'mac_address': mac_address}]
        ntw_name = 'network91-1'
        router_name = 'router91-1'
        sub_name = 'subnet91-1'
        port_name = 'port91-1'
        router, subnet, port = self._create_l3resources(
            ntw_name, router_name, sub_name, port_name,
            addr_pr=allowed_addr_pair)
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('1', '1', '0', '0')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    def test_anti_spoofing_for_params_1_1_0_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different ip, different ip,  different subnet in
        # comparison with the corresponding port parameters
        ip_address = '50.50.50.100'
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = [{'ip_address': ip_address,
                              'mac_address': mac_address}]
        ntw_name = 'network92-1'
        router_name = 'router92-1'
        sub_name = 'subnet92-1'
        port_name = 'port92-1'
        router, subnet, port = self._create_l3resources(
            ntw_name, router_name, sub_name, port_name,
            addr_pr=allowed_addr_pair)
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('1', '1', '0', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)

    @nuage_test.header()
    def test_anti_spoofing_for_params_1_1_1_1_l3domain(self):
        # IP Anti Spoofing tests for vip parameters having full cidr(/32 IP),
        # different mac, same ip, same subnet in
        # comparison with the corresponding port parameters
        ntw_name = 'network93-1'
        router_name = 'router93-1'
        sub_name = 'subnet93-1'
        port_name = 'port93-1'
        router, subnet, port = self._create_l3resources(ntw_name, router_name,
                                                        sub_name, port_name)
        ip_address = port['fixed_ips'][0]['ip_address']
        mac_address = 'fe:a0:36:4b:c8:70'
        allowed_addr_pair = [{'ip_address': ip_address,
                              'mac_address': mac_address}]
        kwargs = {'allowed_address_pairs': allowed_addr_pair}
        port = self.ports_client.update_port(port, **kwargs)
        self.assertIsNone(port)
        router, subnet, port = self._create_l3resources(
            ntw_name, router_name, sub_name, port_name,
            addr_pr=allowed_addr_pair)
        vsd_l3dom, vsd_sub, vsd_port = self._get_vsd_router_subnet_port(
            router, subnet, port)
        vip_params = ('1', '1', '1', '1')
        self._verify_vip_and_anti_spoofing(port, vsd_port, vip_params)
