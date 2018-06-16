# Copyright 2013 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from six import iteritems

import uuid

from tempest.api.network import base_security_groups as base
from tempest.lib.common.utils import data_utils
from tempest.test import decorators

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.tests.api.upgrade.external_id.external_id \
    import ExternalId

CONF = Topology.get_conf()


class SecGroupTestNuageBase(base.BaseSecGroupTest):
    _tenant_network_cidr = CONF.network.project_network_cidr
    nuage_any_domain = None
    nuage_domain_type = None

    @classmethod
    def setup_clients(cls):
        super(SecGroupTestNuageBase, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    def _create_verify_security_group_rule(self, nuage_domains=None, **kwargs):
        sec_group_rule = self.security_group_rules_client \
            .create_security_group_rule(**kwargs)
        if nuage_domains:
            for nuage_domain in nuage_domains:
                self._verify_nuage_acl(
                    sec_group_rule.get('security_group_rule'),
                    nuage_domain)
        else:
            self._verify_nuage_acl(sec_group_rule.get('security_group_rule'))

    def _create_nuage_port_with_security_group(self, sg_id, nw_id):
        post_body = {"network_id": nw_id,
                     "device_owner": "compute:None",
                     "device_id": str(uuid.uuid1()),
                     "security_groups": [sg_id]}
        body = self.ports_client.create_port(**post_body)
        self.addCleanup(self.ports_client.delete_port, body['port']['id'])

    def _verify_vsd_policy_grp(self, remote_group_id, nuage_domain=None,
                               name=None):
        if not nuage_domain:
            nuage_domain = self.nuage_any_domain
        nuage_policy_grps = self.nuage_client.get_policygroup(
            self.nuage_domain_type,
            nuage_domain[0]['ID'])

        self.assertGreater(len(nuage_policy_grps), 0)
        found = False
        for nuage_policy_grp in nuage_policy_grps:
            if ExternalId(remote_group_id).at_cms_id() == \
                    nuage_policy_grp['externalID']:
                found = True
                if name and name != nuage_policy_grp['description']:
                    found = False
                    self.assertTrue(found,
                                    "Must have nuage policy group"
                                    " with matching security group name")
                    break
                break

        self.assertTrue(found,
                        "Must have nuage policy group"
                        " with matching externalID")

        # can retrieve VSD policy group by the externalID
        nuage_policy_grp = self.nuage_client.get_policygroup(
            self.nuage_domain_type,
            nuage_domain[0]['ID'],
            filters='externalID',
            filter_value=remote_group_id)
        self.assertEqual(nuage_policy_grp[0]['name'],
                         remote_group_id)

    def _verify_vsd_network_macro(self, remote_ip_prefix):
        net_addr = remote_ip_prefix.split('/')
        ent_net_macro = self.nuage_client.get_enterprise_net_macro(
            filters='address', filter_value=net_addr[0])
        self.assertNotEqual(ent_net_macro, '', msg='Macro not found')
        if Topology.within_ext_id_release():
            self.assertEqual(ent_net_macro[0]['externalID'],
                             ent_net_macro[0]['parentID'] + '@openstack')

    def _get_nuage_acl_entry_template(self, sec_group_rule, nuage_domain=None):
        if not nuage_domain:
            nuage_domain = self.nuage_any_domain
        if sec_group_rule['direction'] == 'ingress':
            nuage_eacl_template = self.nuage_client. \
                get_egressacl_template(self.nuage_domain_type,
                                       nuage_domain[0]['ID'])
            nuage_eacl_entrytemplate = self.nuage_client. \
                get_egressacl_entytemplate(n_constants.EGRESS_ACL_TEMPLATE,
                                           nuage_eacl_template[0]['ID'],
                                           filters='externalID',
                                           filter_value=sec_group_rule['id'])
            return nuage_eacl_entrytemplate
        else:
            nuage_iacl_template = self.nuage_client. \
                get_ingressacl_template(self.nuage_domain_type,
                                        nuage_domain[0]['ID'])
            nuage_iacl_entrytemplate = self.nuage_client. \
                get_ingressacl_entytemplate(n_constants.INGRESS_ACL_TEMPLATE,
                                            nuage_iacl_template[0]['ID'],
                                            filters='externalID',
                                            filter_value=sec_group_rule['id'])
            return nuage_iacl_entrytemplate

    def _verify_nuage_acl(self, sec_group_rule, nuage_domain=None):

        if sec_group_rule.get('remote_group_id'):
            self._verify_vsd_policy_grp(sec_group_rule['remote_group_id'],
                                        nuage_domain=nuage_domain)

        if sec_group_rule.get('remote_ip_prefix'):
            self._verify_vsd_network_macro(sec_group_rule['remote_ip_prefix'])

        nuage_acl_entry = self._get_nuage_acl_entry_template(
            sec_group_rule, nuage_domain=nuage_domain)
        self.assertNotEmpty(nuage_acl_entry, "Did not find acl entry for sec"
                                             "group rule {} on "
                                             "VSD".format(sec_group_rule))
        self.assertEqual(nuage_acl_entry[0]['externalID'],
                         ExternalId(sec_group_rule['id']).at_cms_id())

        to_verify = ['protocol', 'etherType', 'sourcePort', 'destinationPort']
        expected = {}
        for parameter in to_verify:
            parm_value = nuage_acl_entry[0][parameter]
            if parm_value and parameter == 'etherType':
                expected['ethertype'] = parm_value
            elif parm_value:
                expected[parameter] = parm_value

        for key, value in iteritems(expected):
            if key in ['sourcePort']:
                self.assertEqual(value, '*')
            elif key in ['destinationPort']:
                if not sec_group_rule['port_range_max']:
                    self.assertEqual(value, '*')
                elif sec_group_rule['port_range_max'] == \
                        sec_group_rule['port_range_min']:
                    self.assertEqual(
                        int(value), sec_group_rule['port_range_max'])
                else:
                    self.assertEqual(
                        value,
                        str(sec_group_rule['port_range_min']) + '-' + str(
                            sec_group_rule['port_range_max']))
            else:
                self.assertEqual(value,
                                 n_constants.PROTO_NAME_TO_NUM[
                                     sec_group_rule[key]],
                                 "Field %s of the created security group "
                                 "rule does not match with %s." %
                                 (key, value))

    def _test_create_list_update_show_delete_security_group(self):
        group_create_body, name = self._create_security_group()

        # List security groups and verify if created group is there in response
        list_body = self.security_groups_client.list_security_groups()
        secgroup_list = list()
        for secgroup in list_body['security_groups']:
            secgroup_list.append(secgroup['id'])
        self.assertIn(group_create_body['security_group']['id'], secgroup_list)
        # Update the security group
        # create a nuage port to create sg on VSD.
        self._create_nuage_port_with_security_group(
            group_create_body['security_group']['id'], self.network['id'])
        # Verify vsd.
        self._verify_vsd_policy_grp(
            group_create_body['security_group']['id'],
            name=group_create_body['security_group']['name'])
        new_name = data_utils.rand_name('security-')
        new_description = data_utils.rand_name('security-description')
        update_body = self.security_groups_client.update_security_group(
            group_create_body['security_group']['id'],
            name=new_name,
            description=new_description)
        # Verify if security group is updated
        self.assertEqual(update_body['security_group']['name'], new_name)
        self.assertEqual(update_body['security_group']['description'],
                         new_description)
        # Show details of the updated security group
        show_body = self.security_groups_client.show_security_group(
            group_create_body['security_group']['id'])
        self.assertEqual(show_body['security_group']['name'], new_name)
        self.assertEqual(show_body['security_group']['description'],
                         new_description)
        self._verify_vsd_policy_grp(
            group_create_body['security_group']['id'],
            name=new_name)

    def _test_create_show_delete_security_group_rule(self):
        group_create_body, _ = self._create_security_group()
        # create a nuage port to create sg on VSD.
        self._create_nuage_port_with_security_group(
            group_create_body['security_group']['id'], self.network['id'])
        # Create rules for each protocol
        protocols = ['tcp', 'udp', 'icmp']
        for protocol in protocols:
            rule_create_body = (
                self.security_group_rules_client.create_security_group_rule(
                    security_group_id=group_create_body['security_group']
                    ['id'],
                    protocol=protocol,
                    direction='ingress',
                    ethertype=self.ethertype
                ))
            # Show details of the created security rule
            show_rule_body = (
                self.security_group_rules_client.show_security_group_rule(
                    rule_create_body['security_group_rule']['id']))
            create_dict = rule_create_body['security_group_rule']
            for key, value in iteritems(create_dict):
                self.assertEqual(value,
                                 show_rule_body['security_group_rule'][key],
                                 "%s does not match." % key)
            self._verify_nuage_acl(rule_create_body['security_group_rule'])
            # List rules and verify created rule is in response
            rule_list_body = (self.security_group_rules_client.
                              list_security_group_rules())
            rule_list = [rule['id']
                         for rule in rule_list_body['security_group_rules']]
            self.assertIn(rule_create_body['security_group_rule']['id'],
                          rule_list)

    def _test_create_security_group_rule_with_additional_args(self):
        """Verify security group rule with additional arguments works.

        direction:ingress, ethertype:[IPv4/IPv6],
        protocol:tcp, port_range_min:77, port_range_max:77
        """
        group_create_body, _ = self._create_security_group()
        self._create_nuage_port_with_security_group(
            group_create_body['security_group']['id'], self.network['id'])
        sg_id = group_create_body['security_group']['id']
        direction = 'ingress'
        protocol = 'tcp'
        port_range_min = 77
        port_range_max = 77
        self._create_verify_security_group_rule(
            security_group_id=sg_id, direction=direction,
            ethertype=self.ethertype, protocol=protocol,
            port_range_min=port_range_min,
            port_range_max=port_range_max)

    def _test_create_security_group_rule_with_icmp_type_code(self):
        """Verify security group rule for icmp protocol works.

        Specify icmp type (port_range_min) and icmp code
        (port_range_max) with different values. A seperate testcase
        is added for icmp protocol as icmp validation would be
        different from tcp/udp.
        """
        group_create_body, _ = self._create_security_group()
        self._create_nuage_port_with_security_group(
            group_create_body['security_group']['id'], self.network['id'])
        sg_id = group_create_body['security_group']['id']
        direction = 'ingress'
        protocol = 'icmp'
        icmp_type_codes = [(3, 2), (2, 3), (3, 0), (2, None)]
        for icmp_type, icmp_code in icmp_type_codes:
            self._create_verify_security_group_rule(
                security_group_id=sg_id, direction=direction,
                ethertype=self.ethertype, protocol=protocol,
                port_range_min=icmp_type, port_range_max=icmp_code)

    def _test_create_security_group_rule_with_remote_group_id(self):
        # Verify creating security group rule with remote_group_id works
        sg1_body, _ = self._create_security_group()
        sg2_body, _ = self._create_security_group()
        self._create_nuage_port_with_security_group(
            sg1_body['security_group']['id'], self.network['id'])
        self._create_nuage_port_with_security_group(
            sg2_body['security_group']['id'], self.network['id'])
        sg_id = sg1_body['security_group']['id']
        direction = 'ingress'
        protocol = 'udp'
        port_range_min = 50
        port_range_max = 55
        remote_id = sg2_body['security_group']['id']
        self._create_verify_security_group_rule(
            security_group_id=sg_id, direction=direction,
            ethertype=self.ethertype, protocol=protocol,
            port_range_min=port_range_min,
            port_range_max=port_range_max,
            remote_group_id=remote_id)

    def _test_create_security_group_rule_with_remote_ip_prefix(self):
        # Verify creating security group rule with remote_ip_prefix works
        sg1_body, _ = self._create_security_group()
        self._create_nuage_port_with_security_group(
            sg1_body['security_group']['id'], self.network['id'])
        sg_id = sg1_body['security_group']['id']
        direction = 'ingress'
        protocol = 'tcp'
        port_range_min = 76
        port_range_max = 77
        ip_prefix = self._tenant_network_cidr
        self._create_verify_security_group_rule(
            security_group_id=sg_id, direction=direction,
            ethertype=self.ethertype, protocol=protocol,
            port_range_min=port_range_min,
            port_range_max=port_range_max,
            remote_ip_prefix=ip_prefix)

    def _test_create_security_group_rule_in_multiple_domains(self, l3=False):
        sg1_body, _ = self._create_security_group()
        name = "SG_multiple_domains "
        n1 = self.create_network(network_name=name + '1')
        s1 = self.create_subnet(n1)
        n2 = self.create_network(network_name=name + '2')
        s2 = self.create_subnet(n2)
        if l3:
            r1 = self.create_router(
                router_name=name + '1',
                admin_state_up=False,
                external_network_id=CONF.network.public_network_id,
                enable_snat=None)
            self.create_router_interface(r1['id'], s1['id'])
            r2 = self.create_router(
                router_name=name + '2',
                admin_state_up=False,
                external_network_id=CONF.network.public_network_id,
                enable_snat=None)
            self.create_router_interface(r2['id'], s2['id'])

        self._create_nuage_port_with_security_group(
            sg1_body['security_group']['id'], n1['id'])
        self._create_nuage_port_with_security_group(
            sg1_body['security_group']['id'], n2['id'])
        if l3:
            nuage_d1 = self.nuage_client.get_l3domain(
                filters='externalID',
                filter_value=r1['id'])
            nuage_d2 = self.nuage_client.get_l3domain(
                filters='externalID',
                filter_value=r2['id'])

        else:
            nuage_d1 = self.nuage_client.get_l2domain(
                filters='externalID',
                filter_value=s1['id'])
            nuage_d2 = self.nuage_client.get_l2domain(
                filters='externalID',
                filter_value=s2['id'])

        sg_id = sg1_body['security_group']['id']
        direction = 'ingress'
        protocol = 'tcp'
        port_range_min = 80
        port_range_max = 80
        ip_prefix = self._tenant_network_cidr
        nuage_domains = [nuage_d1, nuage_d2]
        self._create_verify_security_group_rule(
            security_group_id=sg_id, direction=direction,
            ethertype=self.ethertype, protocol=protocol,
            port_range_min=port_range_min,
            port_range_max=port_range_max,
            remote_ip_prefix=ip_prefix, nuage_domains=nuage_domains)


class TestSecGroupTestNuageL2Domain(SecGroupTestNuageBase):
    @classmethod
    def resource_setup(cls):
        super(TestSecGroupTestNuageL2Domain, cls).resource_setup()

        # Nuage specific resource addition
        name = data_utils.rand_name('network-')
        cls.network = cls.create_network(network_name=name)
        cls.subnet = cls.create_subnet(cls.network)
        nuage_l2domain = cls.nuage_client.get_l2domain(
            filters='externalID',
            filter_value=cls.subnet['id'])
        cls.nuage_any_domain = nuage_l2domain
        cls.nuage_domain_type = n_constants.L2_DOMAIN

    @decorators.attr(type='smoke')
    def test_create_list_update_show_delete_security_group(self):
        self._test_create_list_update_show_delete_security_group()

    @decorators.attr(type='smoke')
    def test_create_show_delete_security_group_rule(self):
        self._test_create_show_delete_security_group_rule()

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_additional_args(self):
        self._test_create_security_group_rule_with_additional_args()

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_icmp_type_code(self):
        self._test_create_security_group_rule_with_icmp_type_code()

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_remote_group_id(self):
        self._test_create_security_group_rule_with_remote_group_id()

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_remote_ip_prefix(self):
        self._test_create_security_group_rule_with_remote_ip_prefix()

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_in_multiple_domains(self):
        self._test_create_security_group_rule_in_multiple_domains()


class TestSecGroupTestNuageL3Domain(SecGroupTestNuageBase):
    @classmethod
    def resource_setup(cls):
        super(TestSecGroupTestNuageL3Domain, cls).resource_setup()

        # Create a network
        name = data_utils.rand_name('network-')
        cls.network = cls.create_network(network_name=name)

        # Create a subnet
        cls.subnet = cls.create_subnet(cls.network)

        # Create a router
        name = data_utils.rand_name('router-')
        create_body = cls.routers_client.create_router(
            name=name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=False)
        cls.router = create_body['router']
        cls.routers_client.add_router_interface(
            cls.router['id'], subnet_id=cls.subnet['id'])

        nuage_l3domain = cls.nuage_client.get_l3domain(
            filters='externalID',
            filter_value=cls.router['id'])

        cls.nuage_any_domain = nuage_l3domain
        cls.nuage_domain_type = n_constants.DOMAIN

    @classmethod
    def resource_cleanup(cls):
        try:
            cls.routers_client.remove_router_interface(
                cls.router['id'], subnet_id=cls.subnet['id'])
        finally:
            pass

        super(TestSecGroupTestNuageL3Domain, cls).resource_cleanup()

    @decorators.attr(type='smoke')
    def test_security_group_rule_on_port_in_l3domain(self):
        group_create_body, name = self._create_security_group()
        security_group = group_create_body['security_group']

        # create a nuage port to create the security group on VSD.
        post_body = {"network_id": self.network['id'],
                     "device_owner": "compute:None",
                     "device_id": str(uuid.uuid1()),
                     "security_groups": [security_group['id']]}
        body = self.ports_client.create_port(**post_body)
        self.addCleanup(self.ports_client.delete_port, body['port']['id'])

        self._verify_vsd_policy_grp(security_group['id'])

        new_name = data_utils.rand_name('security-')
        new_description = data_utils.rand_name('security-description')
        update_body = self.security_groups_client.update_security_group(
            security_group['id'],
            name=new_name,
            description=new_description)

        # Verify if security group is updated
        self.assertEqual(update_body['security_group']['name'], new_name)
        self.assertEqual(update_body['security_group']['description'],
                         new_description)

        # Show details of the updated security group
        show_body = self.security_groups_client.show_security_group(
            group_create_body['security_group']['id'])
        self.assertEqual(show_body['security_group']['name'], new_name)
        self.assertEqual(show_body['security_group']['description'],
                         new_description)

        # Create rules for each protocol
        protocols = ['tcp', 'udp', 'icmp']
        for protocol in protocols:
            rule_create_body = (
                self.security_group_rules_client.create_security_group_rule(
                    security_group_id=security_group['id'],
                    protocol=protocol,
                    direction='ingress',
                    ethertype=self.ethertype
                ))
            # Show details of the created security rule
            show_rule_body = (
                self.security_group_rules_client.show_security_group_rule(
                    rule_create_body['security_group_rule']['id']))
            create_dict = rule_create_body['security_group_rule']
            for key, value in iteritems(create_dict):
                self.assertEqual(value,
                                 show_rule_body['security_group_rule'][key],
                                 "%s does not match." % key)
            self._verify_nuage_acl(rule_create_body['security_group_rule'])
            # List rules and verify created rule is in response
            rule_list_body = (self.security_group_rules_client.
                              list_security_group_rules())
            rule_list = [rule['id']
                         for rule in rule_list_body['security_group_rules']]
            self.assertIn(rule_create_body['security_group_rule']['id'],
                          rule_list)

    @decorators.attr(type='smoke')
    def test_create_list_update_show_delete_security_group(self):
        self._test_create_list_update_show_delete_security_group()

    @decorators.attr(type='smoke')
    def test_create_show_delete_security_group_rule(self):
        self._test_create_show_delete_security_group_rule()

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_additional_args(self):
        self._test_create_security_group_rule_with_additional_args()

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_icmp_type_code(self):
        self._test_create_security_group_rule_with_icmp_type_code()

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_remote_group_id(self):
        self._test_create_security_group_rule_with_remote_group_id()

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_remote_ip_prefix(self):
        self._test_create_security_group_rule_with_remote_ip_prefix()

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_in_multiple_domains(self):
        self._test_create_security_group_rule_in_multiple_domains(l3=True)


# NEEDS MORE WORK
# class SecGroupTestNuageL2DomainIPv6Test(SecGroupTestNuageL2Domain):
#     _ip_version = 6
#     _project_network_cidr = CONF.network.project_network_v6_cidr
#
#     # TODO(KRIS) THIS NEEDS TO GO OUT BUT NEED TO FIGURE OUT HOW
#     if IPNetwork(CONF.network.project_network_v6_cidr).prefixlen < 64:
#         _project_network_cidr = IPNetwork('cafe:babe::/64')
