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

import netaddr
import uuid

from tempest.api.network import base_security_groups as base
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.tests.api.external_id.external_id import ExternalId

CONF = Topology.get_conf()


class SecGroupTestNuageBase(base.BaseSecGroupTest):

    _tenant_network_cidr = CONF.network.project_network_cidr

    # ICMP types/codes under test
    # list of tuples of (ICMP type, ICMP code, stateful ACL @ VSD expected)
    _icmp_type_codes = [(None, None, False), (69, 0, False), (8, 0, True)]

    nuage_any_domain = None
    nuage_domain_type = None

    @classmethod
    def setup_clients(cls):
        super(SecGroupTestNuageBase, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    @classmethod
    def create_port(cls, network, **kwargs):
        if CONF.network.port_vnic_type and 'binding:vnic_type' not in kwargs:
            kwargs['binding:vnic_type'] = CONF.network.port_vnic_type
        if CONF.network.port_profile and 'binding:profile' not in kwargs:
            kwargs['binding:profile'] = CONF.network.port_profile
        return super(SecGroupTestNuageBase, cls).create_port(network,
                                                             **kwargs)

    def _create_verify_security_group_rule(self, nuage_domains=None,
                                           expected_stateful=True, **kwargs):
        sec_group_rule = self.security_group_rules_client \
            .create_security_group_rule(**kwargs)
        if nuage_domains:
            for nuage_domain in nuage_domains:
                self._verify_nuage_acl(
                    sec_group_rule.get('security_group_rule'),
                    nuage_domain, expected_stateful=expected_stateful)
        else:
            self._verify_nuage_acl(sec_group_rule.get('security_group_rule'),
                                   expected_stateful=expected_stateful)

    def _create_nuage_port_with_security_group(self, sg_id, nw):
        post_body = {"network": nw,
                     "device_owner": "compute:None",
                     "device_id": str(uuid.uuid1()),
                     "security_groups": [sg_id]}
        port = self.create_port(**post_body)
        self.addCleanup(self.ports_client.delete_port, port['id'])

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

    def _verify_vsd_network_macro(self, remote_ip_prefix, ethertype='IPv4'):
        net_addr = remote_ip_prefix.split('/')
        if ethertype == 'IPv4':
            ent_net_macro = self.nuage_client.get_enterprise_net_macro(
                filters='address', filter_value=net_addr[0])
        else:
            ent_net_macro = self.nuage_client.get_enterprise_net_macro(
                filters='IPv6Address', filter_value=remote_ip_prefix)
        self.assertNotEqual(ent_net_macro, '', msg='Macro not found')
        self.assertEqual(ent_net_macro[0]['externalID'],
                         ent_net_macro[0]['parentID'] + '@openstack')

    def _get_nuage_acl_entry_template(self, sec_group_rule, nuage_domain=None,
                                      reverse=False):
        if not nuage_domain:
            nuage_domain = self.nuage_any_domain

        if reverse:
            # if meant to retrieve the reverse rule (~ some of icmp type)
            # reverse the OS/VSP reverse logic, so egress stays egress
            fetch_egress = sec_group_rule['direction'] == 'egress'
        else:
            # normal condition
            # OS and VSP have reversed logic, so ingress becomes egress
            fetch_egress = sec_group_rule['direction'] == 'ingress'

        if fetch_egress:
            nuage_eacl_template = self.nuage_client. \
                get_egressacl_template(self.nuage_domain_type,
                                       nuage_domain[0]['ID'])
            nuage_eacl_entry_template = self.nuage_client. \
                get_egressacl_entrytemplate(n_constants.EGRESS_ACL_TEMPLATE,
                                            nuage_eacl_template[0]['ID'],
                                            filters='externalID',
                                            filter_value=sec_group_rule['id'])
            return nuage_eacl_entry_template
        else:
            nuage_iacl_template = self.nuage_client. \
                get_ingressacl_template(self.nuage_domain_type,
                                        nuage_domain[0]['ID'])

            nuage_iacl_entry_template = self.nuage_client. \
                get_ingressacl_entrytemplate(n_constants.INGRESS_ACL_TEMPLATE,
                                             nuage_iacl_template[0]['ID'],
                                             filters='externalID',
                                             filter_value=sec_group_rule['id'])
            return nuage_iacl_entry_template

    def _verify_reverse_acl_entry_template(self, sec_group_rule,
                                           stateful=True, nuage_domain=None):
        nuage_reverse_entry_template = self._get_nuage_acl_entry_template(
            sec_group_rule, nuage_domain, reverse=True)

        # for stateful security groups (normal case),
        # if VSP supports the protocol as stateful (normal case), we don't
        # program a reverse rule;
        # if VSP doesn't support stateful (some of icmp), we do.

        if stateful:
            self.assertEqual(0, len(nuage_reverse_entry_template),
                             'Didn\'t expect a reverse acl for stateful '
                             'protocol/ethertype {}/{} [{}-{}] '
                             'but found {}'.format(
                                 sec_group_rule['protocol'],
                                 sec_group_rule['ethertype'],
                                 sec_group_rule['port_range_min'],
                                 sec_group_rule['port_range_max'],
                                 len(nuage_reverse_entry_template)))
        else:
            self.assertEqual(1, len(nuage_reverse_entry_template),
                             'Expected a reverse acl for stateless '
                             'protocol/ethertype {}/{} [{}-{}] '
                             'but found {}'.format(
                                 sec_group_rule['protocol'],
                                 sec_group_rule['ethertype'],
                                 sec_group_rule['port_range_min'],
                                 sec_group_rule['port_range_max'],
                                 len(nuage_reverse_entry_template)))

    def _verify_nuage_acl(self, sec_group_rule, nuage_domain=None,
                          expected_stateful=True):

        if sec_group_rule.get('remote_group_id'):
            self._verify_vsd_policy_grp(sec_group_rule['remote_group_id'],
                                        nuage_domain=nuage_domain)

        if sec_group_rule.get('remote_ip_prefix'):
            self._verify_vsd_network_macro(sec_group_rule['remote_ip_prefix'],
                                           sec_group_rule['ethertype'])

        nuage_acl_entry = self._get_nuage_acl_entry_template(
            sec_group_rule, nuage_domain)
        self.assertNotEmpty(nuage_acl_entry, "Did not find acl entry for sec"
                                             "group rule {} on "
                                             "VSD".format(sec_group_rule))
        self.assertEqual(ExternalId(sec_group_rule['id']).at_cms_id(),
                         nuage_acl_entry[0]['externalID'])
        self.assertEqual(expected_stateful, nuage_acl_entry[0]['stateful'],
                         'Unexpected stateful value {} for protocol/ethertype '
                         '= {}/{} [{}-{}], expected {}'.format(
                             nuage_acl_entry[0]['stateful'],
                             sec_group_rule['protocol'],
                             sec_group_rule['ethertype'],
                             sec_group_rule['port_range_min'],
                             sec_group_rule['port_range_max'],
                             expected_stateful))
        self._verify_reverse_acl_entry_template(
            sec_group_rule, expected_stateful, nuage_domain)

        to_verify = ['etherType', 'protocol', 'sourcePort', 'destinationPort']
        expected = {}
        for parameter in to_verify:
            parm_value = nuage_acl_entry[0][parameter]
            if parm_value and parameter == 'etherType':
                expected['ethertype'] = parm_value
            elif parm_value:
                if (expected['ethertype'] ==
                        n_constants.PROTO_NAME_TO_NUM['IPv6'] and
                        nuage_acl_entry[0][parameter] ==
                        n_constants.PROTO_NAME_TO_NUM['ipv6-icmp']):
                    expected[parameter] = [
                        # neutron can be multiple options, they all map to
                        # 58 in VSD
                        n_constants.PROTO_NAME_TO_NUM['icmp'],
                        n_constants.PROTO_NAME_TO_NUM['ipv6-icmp']]
                else:
                    expected[parameter] = parm_value

        for key, value in iteritems(expected):
            if key == 'sourcePort':
                self.assertEqual(value, '*')
            elif key == 'destinationPort':
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
            elif isinstance(value, list):
                self.assertIn(n_constants.PROTO_NAME_TO_NUM[
                              sec_group_rule[key]],
                              value,
                              "Field %s of the created security group "
                              "rule does not match any of %s." %
                              (key, value))
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
            group_create_body['security_group']['id'], self.network)
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

    def _test_create_show_delete_security_group_rule(self, ipv6=False):
        group_create_body, _ = self._create_security_group()
        security_group_id = group_create_body['security_group']['id']
        # create a nuage port to create sg on VSD.
        self._create_nuage_port_with_security_group(security_group_id,
                                                    self.network)
        if ipv6:
            if Topology.up_to_openstack('stein'):
                protocols = (n_constants.IPV6_PROTO_NAME +
                             [n_constants.IPV6_PROTO_NAME_LEGACY])
            else:
                # Train onwards, legacy is canonicalized
                # https://review.opendev.org/#/c/453346/14
                protocols = n_constants.IPV6_PROTO_NAME
        else:
            protocols = n_constants.IPV4_PROTO_NAME
        # Create rules for each protocol
        for protocol in protocols:
            rule_create_body = (
                self.security_group_rules_client.create_security_group_rule(
                    security_group_id=security_group_id,
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
            self._verify_nuage_acl(
                rule_create_body['security_group_rule'],
                expected_stateful='icmp' not in protocol)

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
            group_create_body['security_group']['id'], self.network)
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

    def _test_create_security_group_rule_with_icmp_type_code(self,
                                                             protocol,
                                                             icmp_type_codes):
        """Verify security group rule for icmp protocol works.

        Specify icmp type (port_range_min) and icmp code
        (port_range_max) with different values. A separate testcase
        is added for icmp protocol as icmp validation would be
        different from tcp/udp.
        """
        group_create_body, _ = self._create_security_group()
        self._create_nuage_port_with_security_group(
            group_create_body['security_group']['id'], self.network)
        sg_id = group_create_body['security_group']['id']
        direction = 'ingress'
        for icmp_type, icmp_code, stateful in icmp_type_codes:
            if icmp_type is not None and icmp_code is not None:
                self._create_verify_security_group_rule(
                    security_group_id=sg_id, direction=direction,
                    ethertype=self.ethertype, protocol=protocol,
                    port_range_min=icmp_type, port_range_max=icmp_code,
                    expected_stateful=stateful)
            else:
                self._create_verify_security_group_rule(
                    security_group_id=sg_id, direction=direction,
                    ethertype=self.ethertype, protocol=protocol,
                    expected_stateful=stateful)

    def _test_create_security_group_rule_with_remote_group_id(self):
        # Verify creating security group rule with remote_group_id works
        sg1_body, _ = self._create_security_group()
        sg2_body, _ = self._create_security_group()
        self._create_nuage_port_with_security_group(
            sg1_body['security_group']['id'], self.network)
        self._create_nuage_port_with_security_group(
            sg2_body['security_group']['id'], self.network)
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
            sg1_body['security_group']['id'], self.network)
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
        r1 = r2 = None  # keep pycharm happy
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
            sg1_body['security_group']['id'], n1)
        self._create_nuage_port_with_security_group(
            sg1_body['security_group']['id'], n2)
        if l3:
            nuage_d1 = self.nuage_client.get_l3domain(
                filters='externalID',
                filter_value=r1['id'])
            nuage_d2 = self.nuage_client.get_l3domain(
                filters='externalID',
                filter_value=r2['id'])
        else:
            nuage_d1 = self.nuage_client.get_l2domain(
                filters=['externalID', 'address'],
                filter_value=[s1['network_id'], s1['cidr']])
            nuage_d2 = self.nuage_client.get_l2domain(
                filters=['externalID', 'address'],
                filter_value=[s2['network_id'], s2['cidr']])
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

    def _delete_security_group(self, secgroup_id):
        self.security_groups_client.delete_security_group(secgroup_id)

    def _delete_security_group_rule(self, rule_id):
        self.security_group_rules_client.delete_security_group_rule(rule_id)


class TestSecGroupTestNuageL2Domain(SecGroupTestNuageBase):

    @classmethod
    def resource_setup(cls):
        super(TestSecGroupTestNuageL2Domain, cls).resource_setup()

        # Nuage specific resource addition
        name = data_utils.rand_name('network-')
        cls.network = cls.create_network(network_name=name)
        cls.subnet = cls.create_subnet(cls.network)
        nuage_l2domain = cls.nuage_client.get_l2domain(
            filters=['externalID', 'address'],
            filter_value=[cls.subnet['network_id'],
                          cls.subnet['cidr']])
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
        self._test_create_security_group_rule_with_icmp_type_code(
            'icmp', icmp_type_codes=self._icmp_type_codes)

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_remote_group_id(self):
        self._test_create_security_group_rule_with_remote_group_id()

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_remote_ip_prefix(self):
        self._test_create_security_group_rule_with_remote_ip_prefix()

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_in_multiple_domains(self):
        self._test_create_security_group_rule_in_multiple_domains()

    def test_create_security_group_rule_invalid_ip_prefix_negative(self):
        sg1_body, _ = self._create_security_group()
        sg_id = sg1_body['security_group']['id']
        direction = 'ingress'
        protocol = 'tcp'
        port_range_min = 76
        port_range_max = 77
        ip_prefix = '192.168.1.0/0'
        self.security_group_rules_client.create_security_group_rule(
            security_group_id=sg_id, direction=direction,
            ethertype=self.ethertype, protocol=protocol,
            port_range_min=port_range_min,
            port_range_max=port_range_max,
            remote_ip_prefix=ip_prefix)
        msg = ('Bad request: Error in REST call to VSD: Non supported remote'
               ' CIDR in security rule: Does not match n.n.n.n where n=1-3'
               ' decimal digits and the mask is not all zeros , address is'
               ' 192.168.1.0 , mask is 0.0.0.0')
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self._create_nuage_port_with_security_group,
                               sg_id, self.network)

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_ipv6_ip_prefix(self):
        sg1_body, _ = self._create_security_group()
        sg_id = sg1_body['security_group']['id']
        sg_rule_list = []
        for prefix in [0, 1, 30, 63, 64, 65, 127, 128]:
            direction = 'ingress'
            protocol = 'tcp'
            port_range_min = 76
            port_range_max = 77
            if prefix == 0:
                ip_prefix = '::/' + str(prefix)
            else:
                ip_prefix = '2001::/' + str(prefix)
            sg_rule = (
                self.security_group_rules_client.create_security_group_rule(
                    security_group_id=sg_id, direction=direction,
                    ethertype="IPv6", protocol=protocol,
                    port_range_min=port_range_min,
                    port_range_max=port_range_max,
                    remote_ip_prefix=ip_prefix))
            sg_rule_list.append(sg_rule)
        self._create_nuage_port_with_security_group(sg_id, self.network)
        self._verify_vsd_policy_grp(
            sg_id,
            name=sg1_body['security_group']['name'])
        for sg_rule in sg_rule_list:
            self._verify_nuage_acl(sg_rule['security_group_rule'])

    def test_create_security_group_rule_invalid_nw_macro_negative(self):
        sg1_body, _ = self._create_security_group()
        sg_id = sg1_body['security_group']['id']
        direction = 'ingress'
        protocol = 'tcp'
        port_range_min = 76
        port_range_max = 77
        ip_prefix = '172.16.50.210/24'
        self.security_group_rules_client.create_security_group_rule(
            security_group_id=sg_id, direction=direction,
            ethertype=self.ethertype, protocol=protocol,
            port_range_min=port_range_min,
            port_range_max=port_range_max,
            remote_ip_prefix=ip_prefix)
        msg = ('Bad request: Error in REST call to VSD: Non supported remote'
               ' CIDR in security rule: Network IP Address 172.16.50.210 must'
               ' have host bits set to 0.')
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self._create_nuage_port_with_security_group,
                               sg_id, self.network)

    def test_security_group_rule_invalid_ip_prefix_update_port_negative(self):
        sg1_body, _ = self._create_security_group()
        sg_id = sg1_body['security_group']['id']
        direction = 'ingress'
        protocol = 'tcp'
        port_range_min = 76
        port_range_max = 77
        ip_prefix = '192.168.1.0/0'
        self.security_group_rules_client.create_security_group_rule(
            security_group_id=sg_id, direction=direction,
            ethertype=self.ethertype, protocol=protocol,
            port_range_min=port_range_min,
            port_range_max=port_range_max,
            remote_ip_prefix=ip_prefix)
        msg = ('Bad request: Error in REST call to VSD: Non supported remote'
               ' CIDR in security rule: Does not match n.n.n.n where n=1-3'
               ' decimal digits and the mask is not all zeros , address is'
               ' 192.168.1.0 , mask is 0.0.0.0')
        post_body = {
            "network": self.network,
            "name": data_utils.rand_name('port-')
        }
        port = self.create_port(**post_body)
        sg_body = {"security_groups": [sg_id]}
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.update_port,
                               port, **sg_body)
        nuage_pg = self.nuage_client.get_policygroup(
            self.nuage_domain_type,
            self.nuage_any_domain[0]['ID'],
            filters='externalID',
            filter_value=sg_id)
        self.assertEqual(len(nuage_pg), 0)
        vport = self.nuage_client.get_vport(
            self.nuage_domain_type,
            self.nuage_any_domain[0]['ID'],
            filters='externalID',
            filter_value=port['id'])
        nuage_policy_grps = self.nuage_client.get_policygroup(
            n_constants.VPORT,
            vport[0]['ID'])
        self.assertEqual(nuage_policy_grps[0]['name'],
                         port['security_groups'][0])

    def test_security_group_rule_invalid_nw_macro_update_port_negative(
            self):
        sg1_body, _ = self._create_security_group()
        sg_id = sg1_body['security_group']['id']
        direction = 'ingress'
        protocol = 'tcp'
        port_range_min = 76
        port_range_max = 77
        ip_prefix = '172.16.50.210/24'
        self.security_group_rules_client.create_security_group_rule(
            security_group_id=sg_id, direction=direction,
            ethertype=self.ethertype, protocol=protocol,
            port_range_min=port_range_min,
            port_range_max=port_range_max,
            remote_ip_prefix=ip_prefix)
        msg = ('Bad request: Error in REST call to VSD: Non supported remote'
               ' CIDR in security rule: Network IP Address 172.16.50.210 must'
               ' have host bits set to 0.')
        post_body = {
            "network": self.network,
            "name": data_utils.rand_name('port-')
        }
        port = self.create_port(**post_body)
        sg_body = {"security_groups": [sg_id]}
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.update_port,
                               port, **sg_body)
        nuage_pg = self.nuage_client.get_policygroup(
            self.nuage_domain_type,
            self.nuage_any_domain[0]['ID'],
            filters='externalID',
            filter_value=sg_id)
        self.assertEqual(len(nuage_pg), 0)
        vport = self.nuage_client.get_vport(
            self.nuage_domain_type,
            self.nuage_any_domain[0]['ID'],
            filters='externalID',
            filter_value=port['id'])
        nuage_policy_grps = self.nuage_client.get_policygroup(
            n_constants.VPORT,
            vport[0]['ID'])
        self.assertEqual(nuage_policy_grps[0]['name'],
                         port['security_groups'][0])


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
        self._test_create_security_group_rule_with_icmp_type_code(
            'icmp', icmp_type_codes=self._icmp_type_codes)

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_remote_group_id(self):
        self._test_create_security_group_rule_with_remote_group_id()

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_remote_ip_prefix(self):
        self._test_create_security_group_rule_with_remote_ip_prefix()

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_in_multiple_domains(self):
        self._test_create_security_group_rule_in_multiple_domains(l3=True)


class SecGroupTestNuageBaseV6(SecGroupTestNuageBase):

    _ip_version = 6
    _project_network_cidr = CONF.network.project_network_v6_cidr

    # ICMP types/codes under test
    # list of tuples of (ICMP type, ICMP code, stateful ACL @ VSD expected)
    _icmp_type_codes = [(None, None, False), (69, 0, False), (128, 0, True)]

    # TODO(KRIS) THIS NEEDS TO GO OUT BUT NEED TO FIGURE OUT HOW
    if netaddr.IPNetwork(CONF.network.project_network_v6_cidr).prefixlen < 64:
        _project_network_cidr = netaddr.IPNetwork('cafe:babe::/64')


class SecGroupTestNuageL2DomainIPv6Test(SecGroupTestNuageBaseV6):

    @classmethod
    def resource_setup(cls):
        super(SecGroupTestNuageL2DomainIPv6Test, cls).resource_setup()

        # Nuage specific resource addition
        name = data_utils.rand_name('network-')
        cls.network = cls.create_network(network_name=name)
        cls.ipv6_subnet = cls.create_subnet(cls.network, enable_dhcp=True)
        nuage_l2domain = cls.nuage_client.get_l2domain(
            filters=['externalID', 'IPv6Address'],  # mind
            filter_value=[cls.ipv6_subnet['network_id'],
                          cls.ipv6_subnet['cidr']])
        cls.nuage_any_domain = nuage_l2domain
        cls.nuage_domain_type = n_constants.L2_DOMAIN

    @decorators.attr(type='smoke')
    def test_create_show_delete_security_group_rule(self):
        self._test_create_show_delete_security_group_rule(ipv6=True)

    def test_create_security_group_rule_with_icmp_type_code_legacy(self):
        self._test_create_security_group_rule_with_icmp_type_code(
            'icmp', icmp_type_codes=self._icmp_type_codes)

    def test_create_security_group_rule_with_icmp_type_code_legacy_v6(self):
        self._test_create_security_group_rule_with_icmp_type_code(
            'icmpv6', icmp_type_codes=self._icmp_type_codes)

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_icmp_type_code(self):
        self._test_create_security_group_rule_with_icmp_type_code(
            'ipv6-icmp', icmp_type_codes=self._icmp_type_codes)


class SecGroupTestNuageL2DomainDualstackTest(SecGroupTestNuageBaseV6):

    @classmethod
    def resource_setup(cls):
        super(SecGroupTestNuageL2DomainDualstackTest, cls).resource_setup()

        # Nuage specific resource addition
        name = data_utils.rand_name('network-')
        cls.network = cls.create_network(network_name=name)
        cls.ipv4_subnet = cls.create_subnet(cls.network, ip_version=4)
        cls.ipv6_subnet = cls.create_subnet(cls.network, enable_dhcp=False)
        nuage_l2domain = cls.nuage_client.get_l2domain(
            filters=['externalID', 'address'],
            filter_value=[cls.ipv4_subnet['network_id'],
                          cls.ipv4_subnet['cidr']])
        cls.nuage_any_domain = nuage_l2domain
        cls.nuage_domain_type = n_constants.L2_DOMAIN

    @decorators.attr(type='smoke')
    def test_create_show_delete_security_group_rule(self):
        self._test_create_show_delete_security_group_rule(ipv6=True)

    def test_create_security_group_rule_with_icmp_type_code_legacy(self):
        self._test_create_security_group_rule_with_icmp_type_code(
            'icmp', icmp_type_codes=self._icmp_type_codes)

    def test_create_security_group_rule_with_icmp_type_code_legacy_v6(self):
        self._test_create_security_group_rule_with_icmp_type_code(
            'icmpv6', icmp_type_codes=self._icmp_type_codes)

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_icmp_type_code(self):
        self._test_create_security_group_rule_with_icmp_type_code(
            'ipv6-icmp', icmp_type_codes=self._icmp_type_codes)


class SecGroupTestNuageL3DomainIPv6Test(SecGroupTestNuageBaseV6):

    @classmethod
    def resource_setup(cls):
        super(SecGroupTestNuageL3DomainIPv6Test, cls).resource_setup()

        # Create a network
        name = data_utils.rand_name('network-')
        cls.network = cls.create_network(network_name=name)

        # Create dualstack subnet
        cls.ipv6_subnet = cls.create_subnet(cls.network)

        # Create a router
        name = data_utils.rand_name('router-')
        create_body = cls.routers_client.create_router(
            name=name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=False)
        cls.router = create_body['router']
        cls.routers_client.add_router_interface(
            cls.router['id'], subnet_id=cls.ipv6_subnet['id'])

        nuage_l3domain = cls.nuage_client.get_l3domain(
            filters='externalID',
            filter_value=cls.router['id'])

        cls.nuage_any_domain = nuage_l3domain
        cls.nuage_domain_type = n_constants.DOMAIN

    @classmethod
    def resource_cleanup(cls):
        try:
            cls.routers_client.remove_router_interface(
                cls.router['id'], subnet_id=cls.ipv6_subnet['id'])
        finally:
            pass
        super(SecGroupTestNuageL3DomainIPv6Test, cls).resource_cleanup()

    @decorators.attr(type='smoke')
    def test_create_show_delete_security_group_rule(self):
        self._test_create_show_delete_security_group_rule(ipv6=True)

    def test_create_security_group_rule_with_icmp_type_code_legacy(self):
        self._test_create_security_group_rule_with_icmp_type_code(
            'icmp', icmp_type_codes=self._icmp_type_codes)

    def test_create_security_group_rule_with_icmp_type_code_legacy_v6(self):
        self._test_create_security_group_rule_with_icmp_type_code(
            'icmpv6', icmp_type_codes=self._icmp_type_codes)

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_icmp_type_code(self):
        self._test_create_security_group_rule_with_icmp_type_code(
            'ipv6-icmp', icmp_type_codes=self._icmp_type_codes)


class SecGroupTestNuageL3DomainDualstackTest(SecGroupTestNuageBaseV6):

    @classmethod
    def resource_setup(cls):
        super(SecGroupTestNuageL3DomainDualstackTest, cls).resource_setup()

        # Create a network
        name = data_utils.rand_name('network-')
        cls.network = cls.create_network(network_name=name)

        # Create dualstack subnet
        cls.ipv4_subnet = cls.create_subnet(cls.network, ip_version=4)
        cls.ipv6_subnet = cls.create_subnet(cls.network, enable_dhcp=False)

        # Create a router
        name = data_utils.rand_name('router-')
        create_body = cls.routers_client.create_router(
            name=name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=False)
        cls.router = create_body['router']
        cls.routers_client.add_router_interface(
            cls.router['id'], subnet_id=cls.ipv4_subnet['id'])

        nuage_l3domain = cls.nuage_client.get_l3domain(
            filters='externalID',
            filter_value=cls.router['id'])

        cls.nuage_any_domain = nuage_l3domain
        cls.nuage_domain_type = n_constants.DOMAIN

    @classmethod
    def resource_cleanup(cls):
        try:
            cls.routers_client.remove_router_interface(
                cls.router['id'], subnet_id=cls.ipv4_subnet['id'])
        finally:
            pass
        super(SecGroupTestNuageL3DomainDualstackTest, cls).resource_cleanup()

    @decorators.attr(type='smoke')
    def test_create_show_delete_security_group_rule(self):
        self._test_create_show_delete_security_group_rule(ipv6=True)

    def test_create_security_group_rule_with_icmp_type_code_legacy(self):
        self._test_create_security_group_rule_with_icmp_type_code(
            'icmp', icmp_type_codes=self._icmp_type_codes)

    def test_create_security_group_rule_with_icmp_type_code_legacy_v6(self):
        self._test_create_security_group_rule_with_icmp_type_code(
            'icmpv6', icmp_type_codes=self._icmp_type_codes)

    @decorators.attr(type='smoke')
    def test_create_security_group_rule_with_icmp_type_code(self):
        self._test_create_security_group_rule_with_icmp_type_code(
            'ipv6-icmp', icmp_type_codes=self._icmp_type_codes)
