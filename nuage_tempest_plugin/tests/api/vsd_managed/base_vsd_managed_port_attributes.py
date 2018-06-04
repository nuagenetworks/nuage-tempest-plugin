# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import collections
import json
from netaddr import IPAddress
from netaddr import IPNetwork
import random

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.tests.api.vsd_managed \
    import base_vsd_managed_networks

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


# Stuff for the inter-connectivity VM
OS_CONNECTING_NW_CIDR = IPNetwork('33.33.33.0/24')
OS_CONNECTING_NW_GW = '33.33.33.1'

# # Constants used in this file
# SEVERAL_REDIRECT_TARGETS = 3
# EXPECT_NO_MULTIPLE_RT_MSG = "Bad request: Multiple redirect targets " \
#     "on a port not supported"
# SEVERAL_POLICY_GROUPS = 3
# SEVERAL_PORTS = 3
# SEVERAL_VSD_FIP_POOLS = 3
# SEVERAL_VSD_CLAIMED_FIPS = 3
#
# VALID_MAC_ADDRESS = 'fa:fa:3e:e8:e8:c0'

VSD_FIP_POOL_CIDR_BASE = '120.%s.%s.0/24'
VSD_SECOND_SUBNET_CIDR = IPNetwork('30.31.32.0/24')

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])


class BaseVSDManagedPortAttributes(
        base_vsd_managed_networks.BaseVSDManagedNetwork):

    def setUp(self):
        super(BaseVSDManagedPortAttributes, self).setUp()
        self.keypairs = {}
        self.servers = []

    @classmethod
    def resource_setup(cls):
        super(BaseVSDManagedPortAttributes, cls).resource_setup()
        cls.conn_router_id = '',
        cls.conn_subnet_id = ''

    def _create_shared_network(self, name=None, shared=False):
        if name is None:
            name = data_utils.rand_name('ext-network')
        if shared:
            name = data_utils.rand_name('SHARED-network')
            post_body = {'name': name, 'shared': True}
            body = self.admin_client.create_network(**post_body)
            self.addCleanup(
                self.admin_client.delete_network, body['network']['id'])
        else:
            post_body = {'name': name}
            body = self.networks_client.create_network(**post_body)
            self.addCleanup(
                self.networks_client.delete_network, body['network']['id'])
        network = body['network']
        return network

    def _verify_redirect_target(self, rt, parent, parentinfo, postinfo):
        redirect_target = self.nuage_vsd_client.get_redirection_target(
            parent, parentinfo['ID'], filters='ID',
            filter_value=rt['nuage_redirect_target']['id'])

        self.assertEqual(
            str(redirect_target[0]['redundancyEnabled']),
            postinfo['redundancy_enabled'])
        self.assertEqual(
            str(redirect_target[0]['endPointType']),
            postinfo['insertion_mode'])
        return redirect_target

    def _verify_redirect_target_rules(self, rtrule,
                                      parent, parentinfo, ruleinfo):
        redirect_target_rule_template = \
            self.nuage_vsd_client.get_advfwd_template(
                parent, parentinfo['ID'])

        redirect_target_rule = self.nuage_vsd_client.get_advfwd_entrytemplate(
            'ingressadvfwdtemplates',
            str(redirect_target_rule_template[0]['ID']))

        self.assertEqual(
            str(redirect_target_rule[0]['protocol']), ruleinfo['protocol'])
        self.assertEqual(
            str(redirect_target_rule[0]['protocol']), ruleinfo['protocol'])
        self.assertEqual(
            str(redirect_target_rule[0]['action']), ruleinfo['action'])
        self.assertEqual(
            str(redirect_target_rule[0]['ID']),
            rtrule['nuage_redirect_target_rule']['id'])
        if not (str(ruleinfo['protocol']) == str(1)):
            pmin = str(ruleinfo['port_range_min'])
            pmax = str(ruleinfo['port_range_max'])
            self.assertEqual(
                str(redirect_target_rule[0]['destinationPort']),
                pmin + "-" + pmax)

    def _associate_rt_port(self, rtport, rt):
        self.ports_client.update_port(
            rtport['id'],
            nuage_redirect_targets=str(rt['nuage_redirect_target']['id']))

    def _associate_multiple_rt_port(self, rtport, rts):
        nuage_rt_id_list = []
        for rt in rts:
            nuage_rt_id_list.append(rt['nuage_redirect_target']['id'])
        # convert into comaa separated string
        rt_string = ",".join(nuage_rt_id_list)
        self.ports_client.update_port(
            rtport['id'],
            nuage_redirect_targets=rt_string)

    def _disassociate_rt_port(self, rtport, rt):
        # Unassigning port to Redirect Target
        self.admin_ports_client.update_port(
            rtport['id'], nuage_redirect_targets='')
        redirect_vport = self.nuage_vsd_client.get_redirection_target_vports(
            'redirectiontargets',
            rt['nuage_redirect_target']['id'])
        self.assertEqual(redirect_vport, '')

    def _verify_vsd_rt_port(self, rtport, rt, parent, parentinfo):
        # Verifying vport has associated RT
        redirect_vport = self.nuage_vsd_client.get_redirection_target_vports(
            'redirectiontargets',
            rt['nuage_redirect_target']['id'])
        port_ext_id = self.nuage_vsd_client.get_vsd_external_id(
            rtport['id'])
        vsd_vport = self.nuage_vsd_client.get_vport(
            parent, parentinfo['ID'], filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(
            redirect_vport[0]['ID'], vsd_vport[0]['ID'])

    def _assign_unassign_rt_port(self, rtport, rt, parent, parentinfo):
        self.ports_client.update_port(
            rtport['id'],
            nuage_redirect_targets=str(rt['nuage_redirect_target']['id']))
        redirect_vport = self.nuage_vsd_client.get_redirection_target_vports(
            'redirectiontargets',
            rt['nuage_redirect_target']['id'])

        # Verifying vport has associated RT
        port_ext_id = self.nuage_vsd_client.get_vsd_external_id(
            rtport['id'])
        vsd_vport = self.nuage_vsd_client.get_vport(
            parent, parentinfo['ID'], filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(
            redirect_vport[0]['ID'], vsd_vport[0]['ID'])

        # Unassigning port to Redirect Target
        self.ports_client.update_port(
            rtport['id'], nuage_redirect_targets='')
        redirect_vport = \
            self.nuage_network_client.get_redirection_target_vports(
                'redirectiontargets',
                rt['nuage_redirect_target']['id'])
        self.assertEqual(redirect_vport, '')

    def _check_port_in_show_redirect_target(self, port, rt):
        present = False
        show_rt_body = self.nuage_network_client.show_redirection_target(
            rt['nuage_redirect_target']['id'])
        for show_port in show_rt_body['nuage_redirect_target']['ports']:
            if port['id'] == show_port:
                present = True
                break
        return present

    def _verify_redirect_target_vip(self, rt, vipinfo):
        # Verifying RT has associated vip
        redirect_vip = self.nuage_network_client.get_redirection_target_vips(
            'redirectiontargets',
            rt['nuage_redirect_target']['id'])
        self.assertEqual(
            redirect_vip[0]['virtualIP'], vipinfo['virtual_ip_address'])

    def _find_id_redirect_target_in_list(self, redirect_target_id, subnet):
        rt_found = False
        list_body = self.nuage_network_client.list_redirection_targets(
            id=subnet['id'])
        for rt in list_body['nuage_redirect_targets']:
            if rt['id'] == redirect_target_id:
                rt_found = True
                break
        return rt_found

    def _find_redirect_target_in_list(self, redirect_target_id, subnet):
        rt_found = False
        list_body = self.nuage_network_client.list_redirection_targets(
            id=subnet['id'])
        for rt in list_body['nuage_redirect_targets']:
            if rt['id'] == redirect_target_id:
                rt_found = True
                break
        return rt_found

    def _create_redirect_target_in_l2_subnet(self, l2subnet, name=None):
        if name is None:
            name = data_utils.rand_name('os-l2-rt')
        # parameters for nuage redirection target
        post_body = {'insertion_mode': 'VIRTUAL_WIRE',
                     'redundancy_enabled': 'False',
                     'subnet_id': l2subnet['id'],
                     'name': name}
        redirect_target = self.nuage_network_client.create_redirection_target(
            **post_body)
        return redirect_target

    def _create_redirect_target_rule(self, redirect_target_id,
                                     security_group_id):
        # Creating Redirect Target Rule
        rule_body = {
            'priority': '300',
            'redirect_target_id': redirect_target_id,
            'protocol': '1',
            'origin_group_id': str(security_group_id),
            'remote_ip_prefix': '10.0.0.0/24',
            'action': 'REDIRECT'
        }
        rt_rule = self.nuage_network_client.create_redirection_target_rule(
            **rule_body)
        return rt_rule

    def _list_redirect_target_rule(self, subnet_id):
        return self.nuage_network_client.list_redirection_target_rule(
            subnet_id)

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

    def associate_port_to_policy_group(self, port, policy_group_id):
        kwargs = {
            'nuage_policy_groups': [policy_group_id],
        }
        self.update_port(port, **kwargs)

    def _disassociate_port_from_policy_group(self, port):
        kwargs = {
            'nuage_policy_groups': [],
        }
        self.admin_ports_client.update_port(port['id'],
                                            **kwargs)
        pass

    def _check_policy_group_in_list(self, pg_id, pg_list):
        pg_present = False
        for pg in pg_list['nuage_policy_groups']:
            if pg['id'] == pg_id:
                pg_present = True
                break
        return pg_present

    def _check_port_in_policy_group(self, port_id, pg_id):
        port_found = False
        show_pg = self.nuage_network_client.show_nuage_policy_group(pg_id)
        for id in show_pg['nuage_policy_group']['ports']:
            if id == port_id:
                port_found = True
                break
        return port_found

    def _check_policy_group_in_show_port(self, pg_id, show_port):
        pg_present = False
        for show_pg_id in show_port['port']['nuage_policy_groups']:
            if pg_id == show_pg_id:
                pg_present = True
                break
        return pg_present

    def _check_all_policy_groups_in_show_port(self, pg_id_list, show_port):
        groups_present = True
        for pg_id in show_port['port']['nuage_policy_groups']:
            if pg_id not in pg_id_list:
                groups_present = False
                break
        return groups_present

    def _create_vsd_l2_managed_subnet(self):
        kwargs = {
            'name': data_utils.rand_name("l2dom_template"),
            'cidr': base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            'gateway': base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
        }
        l2dom_template = self.create_vsd_dhcpmanaged_l2dom_template(**kwargs)
        vsd_l2_subnet = self.create_vsd_l2domain(tid=l2dom_template[0]['ID'])
        # self.iacl_template = self._create_ingress_acl_template(
        #     name=data_utils.rand_name("iacl_tmpl"),
        #     template_id=l2dom_template[0]['ID'])
        # self.eacl_templace = self._create_egress_acl_template(
        #     name=data_utils.rand_name("eacl_tmpl"),
        #     template_id=l2dom_template[0]['ID'])
        return vsd_l2_subnet, l2dom_template

    def _create_vsd_l3_managed_subnet(self):
        # create template
        kwargs = {
            'name': data_utils.rand_name("l3dom_template"),
        }
        l3dom_template = self.create_vsd_l3dom_template(**kwargs)
        # create domain
        vsd_l3_domain = self.create_vsd_l3domain(tid=l3dom_template[0]['ID'])
        # create zone om domain
        zone = self.create_vsd_zone(name='l3-zone',
                                    domain_id=vsd_l3_domain[0]['ID'])
        # create subnet in zone
        kwargs = {
            'name': data_utils.rand_name("vsd-l3-mgd-subnet"),
            'zone_id': zone[0]['ID'],
            'extra_params': ""
        }
        vsd_l3_subnet = self.create_vsd_l3domain_managed_subnet(**kwargs)
        return vsd_l3_subnet, vsd_l3_domain

    def _create_vsd_l3_managed_subnet_in_domain(self, l3domain_id, cidr):
        # create zone om domain
        zone = self.create_vsd_zone(name=data_utils.rand_name('l3-zone'),
                                    domain_id=l3domain_id)
        # create subnet in zone
        kwargs = {
            'name': data_utils.rand_name("vsd-l3-mgd-subnet"),
            'zone_id': zone[0]['ID'],
            'cidr': cidr,
            'gateway': str(IPAddress(cidr.first + 1)),
            'extra_params': ""
        }
        vsd_l3_subnet = self.create_vsd_l3domain_managed_subnet(**kwargs)
        return vsd_l3_subnet

    def _create_pg_vsd_l2_managed_subnet(self):
        kwargs = {
            'name': data_utils.rand_name("l2dom_template"),
            'cidr': base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR,
            'gateway': base_vsd_managed_networks.VSD_L2_SHARED_MGD_GW,
        }
        l2dom_template = self.create_vsd_dhcpmanaged_l2dom_template(**kwargs)
        vsd_l2_subnet = self.create_vsd_l2domain(tid=l2dom_template[0]['ID'])
        # create ingress and egress policy group
        self.iacl_template = self._create_l2_ingress_acl_template(
            name=data_utils.rand_name("iacl_tmpl"),
            domain_id=vsd_l2_subnet[0]['ID'])
        self.eacl_templace = self._create_l2_egress_acl_template(
            name=data_utils.rand_name("eacl_tmpl"),
            domain_id=vsd_l2_subnet[0]['ID'])
        return vsd_l2_subnet, l2dom_template

    def _create_ping_security_group_entries(self, policy_group_id,
                                            iacl_template_id):
        extra_params = {
            "networkType": "POLICYGROUP",
            "networkID": policy_group_id,
            "locationType": "POLICYGROUP",
            "locationID": policy_group_id,
            "stateful": True,
            "protocol": "1",
            "ICMPType": "8",
            "ICMPCode": "0",
            "etherType": "0x0800",
            "DSCP": "*",
            "action": "FORWARD"
        }
        self.nuage_vsd_client.create_ingress_security_group_entry(
            name_description='ping8',
            iacl_template_id=iacl_template_id,
            extra_params=extra_params,
            responseChoice=True)

        # create second entry
        extra_params = {
            "networkType": "POLICYGROUP",
            "networkID": policy_group_id,
            "locationType": "POLICYGROUP",
            "locationID": policy_group_id,
            "stateful": False,
            "protocol": "1",
            "ICMPType": "0",
            "ICMPCode": "0",
            "etherType": "0x0800",
            "DSCP": "*",
            "description": "ping0",
            "action": "FORWARD"
        }
        self.nuage_vsd_client.create_ingress_security_group_entry(
            name_description='ping0',
            iacl_template_id=iacl_template_id,
            extra_params=extra_params,
            responseChoice=True)
        pass

    def _prepare_l2_security_group_entries(self, policy_group_id, l2domain_id):
        # For the given VSD L2 managed subnet:
        # Create ingress policy that default does NOT allow IP traffic
        # Create egress policy that allows all
        # Create ingress security policy entry for ICMP-Type8-Code0
        #    (echo) in pg
        # Create ingress security policy entry for ICMP-Type0-Code0
        #    (echo reply) in pg
        # =? ping works in this pg, can be switched off/on via associating
        #    ports to the pg
        #
        # # start policy group changes
        # self.nuage_vsd_client.begin_l2_policy_changes(l2domain_id)
        # create ingress policy
        self.iacl_template = self._create_l2_ingress_acl_template(
            data_utils.rand_name("iacl_policy"), l2domain_id)
        self._create_ping_security_group_entries(
            policy_group_id, self.iacl_template[0]['ID'])
        self.eacl_templace = self._create_l2_egress_acl_template(
            data_utils.rand_name("eacl_policy"), l2domain_id)
        # # Apply the policy changes
        # self.nuage_vsd_client.apply_l2_policy_changes(l2domain_id)
        pass

    def _prepare_l3_security_group_entries(self, policy_group_id, l3domain_id,
                                           defaultAllowIP=False):
        # For the given VSD L3 managed subnet:
        # Create ingress policy that default does NOT allow IP traffic
        # Create egress policy that allows all
        # Create ingress security policy entry for ICMP-Type8-Code0
        #    (echo) in pg
        # Create ingress security policy entry for ICMP-Type0-Code0
        #    (echo reply) in pg
        # =? ping works in this pg, can be switched off/on via associating
        #    ports to the pg
        #
        # # start policy group changes
        # self.nuage_vsd_client.begin_l3_policy_changes(l3domain_id)
        # create ingress policy
        self.iacl_template = self._create_l3_ingress_acl_template(
            data_utils.rand_name("iacl_policy"),
            l3domain_id,
            defaultAllowIP=defaultAllowIP)
        self._create_ping_security_group_entries(
            policy_group_id, self.iacl_template[0]['ID'])
        self.eacl_templace = self._create_l3_egress_acl_template(
            data_utils.rand_name("eacl_policy"), l3domain_id)
        # # Apply the policy changes
        # self.nuage_vsd_client.apply_l3_policy_changes(l3domain_id)
        pass

    def _create_l2_ingress_acl_template(self, name, domain_id):
        # do not allow deafault IP: will do this via security policy entries
        extra_params = {"allowAddressSpoof": True,
                        "priorityType": "NONE",
                        "statsLoggingEnabled": False,
                        "flowLoggingEnabled": False,
                        "defaultAllowNonIP": True,
                        "defaultAllowIP": False,
                        "active": True}
        iacl_template = self.nuage_vsd_client.create_ingress_acl_template(
            name, constants.L2_DOMAIN, domain_id, extra_params=extra_params)
        return iacl_template
        pass

    def _create_l3_ingress_acl_template(self, name, domain_id,
                                        defaultAllowIP=False):
        # do not allow deafault IP: will do this via security policy entries
        extra_params = {"allowAddressSpoof": True,
                        "priorityType": "NONE",
                        "statsLoggingEnabled": False,
                        "flowLoggingEnabled": False,
                        "defaultAllowNonIP": True,
                        "defaultAllowIP": defaultAllowIP,
                        "active": True}
        iacl_template = self.nuage_vsd_client.create_ingress_acl_template(
            name, constants.DOMAIN, domain_id, extra_params=extra_params)
        return iacl_template
        pass

    def _create_ingress_acl_template(self, name, domain_id):
        iacl_template = self.nuage_vsd_client.create_ingress_acl_template(
            name, domain_id)
        return iacl_template
        pass

    def _create_ingress_security_group_entry(self, name_description,
                                             policy_group_id,
                                             extra_params=None):
        data = {
            "policyState": None,
            "networkType": "POLICYGROUP",
            "networkID": policy_group_id,
            "locationType": "POLICYGROUP",
            "locationID": policy_group_id,
            "associatedApplicationObjectType": None,
            "associatedApplicationObjectID": None,
            "associatedApplicationID": None,
            "addressOverride": None,
            "name": name_description,
            "mirrorDestinationID": None,
            "statsLoggingEnabled": False,
            "statsID": None,
            "stateful": True,
            "sourcePort": None,
            "protocol": "1",
            "priority": None,
            "ICMPType": "8",
            "ICMPCode": "0",
            "flowLoggingEnabled": False,
            "etherType": "0x0800",
            "DSCP": "*",
            "destinationPort": None,
            "action": "FORWARD",
            "entityScope": None,
            "parentType": None,
            "parentID": None,
            "owner": None,
            "lastUpdatedBy": None,
            "ID": None,
            "externalID": None
        }

        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=constants.INGRESS_ACL_TEMPLATE,
            resource_id=policy_group_id,
            child_resource=constants.INGRESS_ACL_ENTRY_TEMPLATE)
        result = self.post(res_path, data)
        return result

    def _create_l2_egress_acl_template(self, name, domain_id):
        extra_params = {"allowAddressSpoof": True,
                        "priorityType": "NONE",
                        "statsLoggingEnabled": False,
                        "flowLoggingEnabled": False,
                        "defaultAllowNonIP": True,
                        "defaultAllowIP": False,
                        "active": True}
        eacl_template = self.nuage_vsd_client.create_egress_acl_template(
            name, constants.L2_DOMAIN, domain_id, extra_params=extra_params)
        return eacl_template
        pass

    def _create_l3_egress_acl_template(self, name, domain_id):
        extra_params = {"allowAddressSpoof": True,
                        "priorityType": "NONE",
                        "statsLoggingEnabled": False,
                        "flowLoggingEnabled": False,
                        "defaultAllowNonIP": True,
                        "defaultAllowIP": True,
                        "active": True}
        eacl_template = self.nuage_vsd_client.create_egress_acl_template(
            name, constants.DOMAIN, domain_id, extra_params=extra_params)
        return eacl_template
        pass

    def _create_egress_acl_template(self, name, template_id):
        eacl_template = self.nuage_vsd_client.create_egress_acl_template(
            name, template_id)
        return eacl_template
        pass

    def _create_os_l2_vsd_managed_subnet(self, vsd_l2_subnet, cidr=None):
        network = self.create_network(network_name=data_utils.rand_name(
            'osl2network-'))
        if not cidr:
            cidr = base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR
        kwargs = {
            'network': network,
            'cidr': cidr,
            'mask_bits': cidr.prefixlen,
            'net_partition': Topology.def_netpartition,
            'nuagenet': vsd_l2_subnet[0]['ID']
        }
        subnet = self.create_subnet(**kwargs)
        return network, subnet

    def _create_os_l3_vsd_managed_subnet(self, vsd_l3_subnet, cidr=None):
        network = self.create_network(network_name=data_utils.rand_name(
            'osl3network-'))
        if not cidr:
            cidr = base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR
        kwargs = {
            'network': network,
            'cidr': cidr,
            'mask_bits': cidr.prefixlen,
            'net_partition': Topology.def_netpartition,
            'nuagenet': vsd_l3_subnet[0]['ID']
        }
        subnet = self.create_subnet(**kwargs)
        return network, subnet

    def _create_server(self, name, network_id, port_id=None):

        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        self.security_group = \
            self._create_security_group()
        security_groups = [{'name': self.security_group['name']}]

        network = {'uuid': network_id}
        if port_id is not None:
            network['port'] = port_id
        server = self.create_server(
            name=name,
            networks=[network],
            key_name=keypair['name'],
            security_groups=security_groups)

        return server

    def _create_2nic_server(self, name, network_id_1, port_1, network_id_2,
                            port_2, policy_group=False):

        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        # create an OS security group in case that no policy_group was created
        # (for VSD managed networks)
        if not policy_group:
            self.security_group = \
                self._create_security_group()
            security_groups = [{'name': self.security_group['name']}]
            # pass this security group to port_id_1, to make ssh work
            port_kwargs = {
                'security_groups': [self.security_group['id']]
            }
            self.update_port(port_1, **port_kwargs)
            create_kwargs = {
                'networks': [
                    {'uuid': network_id_1},
                    {'uuid': network_id_2}
                ],
                'key_name': keypair['name'],
                'security_groups': security_groups,
            }
        else:
            create_kwargs = {
                'networks': [
                    {'uuid': network_id_1},
                    {'uuid': network_id_2}
                ],
                'key_name': keypair['name'],
            }

        create_kwargs['networks'][0]['port'] = port_1['id']
        create_kwargs['networks'][1]['port'] = port_2['id']

        server = self.create_server(name=name, **create_kwargs)
        return server

    def _create_connectivity_vm(self, public_network_id,
                                vsd_l2_subnet, vsd_l2_port):
        # Create an intermediate VM with FIP and a second nic in the VSD
        # network, so that we can ssh into this VM and check ping on the
        # second NIC, which is a port that we associated/disassociate to
        # the policy group
        network = self._create_network()
        router = self._get_router(tenant_id=None,
                                  client=self.admin_routers_client)
        kwargs = {
            'network': network,
            'cidr': OS_CONNECTING_NW_CIDR,
            'mask_bits': OS_CONNECTING_NW_CIDR.prefixlen,
            'gateway': OS_CONNECTING_NW_GW
        }
        subnet = self.create_subnet(**kwargs)
        # subnet_kwargs = dict(network=network, client=None)
        # # use explicit check because empty list is a valid option
        # subnet = self._create_subnet(**subnet_kwargs)
        self.admin_routers_client.add_router_interface(
            router_id=router['id'], subnet_id=subnet['id'])
        # subnet.add_to_router(router.id)
        # Set the router gateway to the public FIP network
        self.admin_routers_client.update_router(
            router_id=router['id'],
            external_gateway_info={
                'network_id': CONF.network.public_network_id,
                'enable_snat': True})
        kwargs = {'name': data_utils.rand_name('osport')}
        # port = self.create_port(network=network,
        #                         namestart='osport-1')
        port = self.create_port(network=network, **kwargs)

        # Create floating IP with FIP rate limiting
        result = self.floating_ips_client.create_floatingip(
            floating_network_id=CONF.network.public_network_id,
            port_id=port['id'],
            nuage_fip_rate='5')
        # Add it to the list so it gets deleted afterwards
        self.floating_ips.append(result['floatingip'])
        floating_ip = result['floatingip']

        # now create the VM with 2 vnics
        server = self._create_2nic_server(
            name=data_utils.rand_name('IC-VM'),
            network_id_1=network['id'], port_1=port,
            network_id_2=vsd_l2_subnet[0]['ID'], port_2=vsd_l2_port)

        self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server)
        # store router, subnet and port id clear gateway and interface before
        # cleanup start
        self.conn_router_id = router['id']
        self.conn_subnet_id = subnet['id']
        self.conn_port_id = port['id']
        return server
        pass

    def _create_vsdmgd_connectivity_VM(self, public_network_id,
                                       vsd_l2_subnet, vsd_l2_port):
        # Create an intermediate VM with FIP and a second nic in the
        # VSD network, so that we can ssh into this VM and check ping on the
        # second NIC, which is a port that we associated/disassociate to
        # the policy group
        #
        # Create L3 VSD managed network
        # create template
        kwargs = {
            'name': data_utils.rand_name("l3dom_template"),
        }
        l3dom_template = self.create_vsd_l3dom_template(**kwargs)
        # create domain
        vsd_l3_domain = self.create_vsd_l3domain(tid=l3dom_template[0]['ID'])
        # create zone om domain
        zone = self.create_vsd_zone(name='l3-zone',
                                    domain_id=vsd_l3_domain[0]['ID'])
        # create subnet in zone, with FIP underlay True
        extra_params = {
            'underlayEnabled': 'ENABLED'
        }
        kwargs = {
            'name': data_utils.rand_name("vsd-l3-mgd-subnet"),
            'zone_id': zone[0]['ID'],
            'cidr': OS_CONNECTING_NW_CIDR,
            'gateway': OS_CONNECTING_NW_GW,
            'extra_params': extra_params
        }
        vsd_l3_subnet = self.create_vsd_l3domain_managed_subnet(**kwargs)
        # vsd_l3_subnet, vsd_l3_domain = self._create_vsd_l3_managed_subnet()
        network, subnet = self._create_os_l3_vsd_managed_subnet(
            vsd_l3_subnet, OS_CONNECTING_NW_CIDR)
        policy_group = self.nuage_vsd_client.create_policygroup(
            constants.DOMAIN,
            vsd_l3_domain[0]['ID'],
            name='myVSD-l3-policygrp',
            type='SOFTWARE',
            extra_params=None)
        # create security group entries that allow all traffic
        self._prepare_l3_security_group_entries(
            policy_group_id=policy_group[0]['ID'],
            l3domain_id=vsd_l3_domain[0]['ID'],
            defaultAllowIP=True)
        # network, subnet = self._create_os_l3_vsd_managed_subnet(
        #     vsd_l3_subnet)
        kwargs = {'name': data_utils.rand_name('osport')}
        # port = self.create_port(network=network,
        #                         namestart='osport-1')
        port = self.create_port(network=network, **kwargs)

        # Fetch the floating ip pool corresponding to the "public"
        # network/subnet
        public_network = self.networks_client.show_network(
            CONF.network.public_network_id)
        public_subnet = self.subnets_client.show_subnet(
            public_network['network']['subnets'][0])
        public_subnet_ext_id = self.nuage_vsd_client.get_vsd_external_id(
            public_subnet['subnet']['id'])
        floating_ip_pool = self.nuage_vsd_client.get_sharedresource(
            filters='externalID', filter_value=public_subnet_ext_id)
        floating_ip = self._claim_vsd_floating_ip(vsd_l3_domain[0]['ID'],
                                                  floating_ip_pool[0]['ID'])
        # associate this floating ip to the port
        self._associate_fip_to_port(port, floating_ip[0]['ID'])
        # Create floating IP with FIP rate limiting
        # result = self.floating_ips_client.create_floatingip(
        #     floating_network_id=CONF.network.public_network_id,
        #     port_id=port['id'],
        #     nuage_fip_rate='5')
        # Add it to the list so it gets deleted afterwards
        # self.floating_ips.append(result['floatingip'])
        # convert to format used throughout this file
        # floating_ip = net_resources.DeletableFloatingIp(
        #     client=self.floating_ips_client,
        #     **result['floatingip'])

        # noew create the VM with 2 vnics
        server = self._create_2nic_server(name=data_utils.rand_name('IC-VM'),
                                          network_id_1=network['id'],
                                          port_1=port,
                                          network_id_2=vsd_l2_subnet[0]['ID'],
                                          port_2=vsd_l2_port,
                                          policy_group=True)

        self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server)
        # store router, subnet and port id clear gateway and interface before
        # cleanup start
        # self.conn_router_id = router['id']
        self.conn_subnet_id = subnet['id']
        self.conn_port_id = port['id']
        return server
        pass

    def _create_connectivity_VM_vsd_floatingip(self, public_network_id,
                                               os_l3_network, os_l3_port,
                                               vsd_l3_subnet, vsd_l3_port,
                                               floatingip):
        # Create an intermediate VM with FIP and a second nic in the
        # VSD network, so that we can ssh into this VM and check ping on the
        # second NIC, which is a port that we associated/disassociate to
        # the policy group
        # network = self._create_network(client=None, tenant_id=None)
        # kwargs = {
        #     'network': network,
        #     'cidr': OS_CONNECTING_NW_CIDR,
        #     'mask_bits': OS_CONNECTING_NW_CIDR.prefixlen,
        #     'gateway': OS_CONNECTING_NW_GW
        # }
        # subnet = self._create_subnet(**kwargs)
        #
        # kwargs= {'name': data_utils.rand_name('osport')}
        # # port = self.create_port(network=network,
        # #                          namestart='osport-1')
        # port = self.create_port(network=network, **kwargs)
        #
        # # associate OS port to VSD floatingip
        # self._associate_fip_to_port(port, floatingip['id'])
        # # convert to format used throughout this file
        # floating_ip = net_resources.DeletableFloatingIp(
        #     client=self.os.network_client,
        #     **result['floatingip'])

        # noew create the VM with 2 vnics
        server = self._create_2nic_server(name=data_utils.rand_name('IC-VM'),
                                          network_id_1=os_l3_network['id'],
                                          port_1=os_l3_port,
                                          network_id_2=vsd_l3_subnet[0]['ID'],
                                          port_2=vsd_l3_port)

        self.floating_ip_tuple = Floating_IP_tuple(floatingip, server)
        # store router, subnet and port id clear gateway and interface before
        # cleanup start
        # self.conn_router_id = router['id']
        # self.conn_subnet_id = subnet['id']
        # self.conn_port_id = port['id']
        return server
        pass

    def _clear_connectivity_vm_interfaces(self, router_id, subnet_id, port_id):
        # Clear router gateway
        self.admin_routers_client.update_router(
            router_id=router_id,
            external_gateway_info={}
        )
        self.ports_client.delete_port(port_id)
        # remove router-interface
        self.admin_routers_client.remove_router_interface(router_id=router_id,
                                                          subnet_id=subnet_id)
        pass

    def _update_ingress_template_block_traffic(self, iacl_template_id):
        # update the ingress acl template to block all traffic
        update_params = {
            "defaultAllowNonIP": False,
            "defaultAllowIP": False
        }
        self.nuage_vsd_client.update_ingress_acl_template(
            iacl_template_id, extra_params=update_params)
        pass

    def _update_ingress_template_allow_traffic(self, iacl_template_id):
        # update the ingress acl template to allow all traffic
        update_params = {
            "defaultAllowNonIP": True,
            "defaultAllowIP": True
        }
        self.nuage_vsd_client.update_ingress_acl_template(
            iacl_template_id, extra_params=update_params)
        pass

    def _update_egress_template_block_traffic(self, eacl_template_id):
        # update the egress acl template to block all traffic
        update_params = {
            "defaultAllowNonIP": False,
            "defaultAllowIP": False
        }
        self.nuage_vsd_client.update_egress_acl_template(
            eacl_template_id, extra_params=update_params)
        pass

    def _update_egress_template_allow_traffic(self, eacl_template_id):
        # update the egress acl template to allow all traffic
        update_params = {
            "defaultAllowNonIP": True,
            "defaultAllowIP": True
        }
        self.nuage_vsd_client.update_egress_acl_template(
            eacl_template_id, extra_params=update_params)
        pass

    def _get_server_key(self, server):
        return self.keypairs[server['key_name']]['private_key']

    def _configure_eth1_server(self, server, floating_ip_address):
        private_key = self._get_server_key(server)
        ssh_client = self.get_remote_client(floating_ip_address,
                                            private_key=private_key)
        command = "sudo sh -c 'echo -e \"\nauto eth1\n" \
                  "iface eth1 inet dhcp\n\" >> /etc/network/interfaces'"
        result = ssh_client.exec_command(command)
        command = 'cat /etc/network/interfaces'
        result = ssh_client.exec_command(command)
        #
        # VERY DIRTY: I know ..
        # trying sudo /sbin/ifup eth1 fails with error message
        # ifup: no dhcp clients found
        # ifup: don't seem to have all the variables for eth1/inet
        # No clue why, so I use the 'hard' way: reboot the server
        #
        command = "sudo /sbin/reboot"
        result = ssh_client.exec_command(command)
        return result

    def _check_vm_policy_group_ping(self, server, floating_ip_address,
                                    ping_vm_ipaddress, wait_time):
        # wait_time for speeding up testing
        #  bigger value in case connectivity is expected
        #  smaller value in case connectivity is NOT expected
        # (this method exits faster)
        private_key = self._get_server_key(server)
        ssh_client = self.get_remote_client(floating_ip_address,
                                            private_key=private_key)
        # the "bl**y client exec command cannot cope with exit status <> 0.
        # So we add an echo $? (always succeeds) and provides the exit status
        # of the ping command
        # command = "ping -c1 -q " + "10.12.14.16  >> /dev/null ; echo $?"
        # result = ssh_client.exec_command(command)
        # command = "ping -c1 -w5 -q " + ping_vm_ipaddress +
        #     " >> /dev/null ; echo $?"
        # command = "ping -c1 -w" + str(wait_time) + " -q " +
        #     ping_vm_ipaddress + " >> /dev/null ; echo $?"

        # result = ssh_client.exec_command(command)
        # if result.__contains__("0"): connectivity = True
        # else: connectivity = False

        # command = "ping -c1 -w" + str(wait_time) + " -q " + ping_vm_ipaddress
        command = "ping -c20 -W" + str(wait_time) + " -v " + ping_vm_ipaddress
        connectivity = False
        result = None

        try:
            result = ssh_client.exec_command(command)
            connectivity = True
        except exceptions.SSHExecCommandFailed as e:
            LOG.warn("Fails to ping with exception %s", e)
        except Exception:
            LOG.warn("Fails to ping with result %s", result)
        else:
            LOG.info("Ping with result %s", result)

        return connectivity

    def _create_port_with_allowed_address_pair(self, allowed_address_pairs,
                                               net_id):
        body = self.ports_client.create_port(
            network_id=net_id,
            allowed_address_pairs=allowed_address_pairs)
        self.addCleanup(self.ports_client.delete_port, body['port']['id'])
        return body

    def _get_port_by_id(self, port_id):
        body = self.ports_client.list_ports()
        ports = body['ports']
        port = [p for p in ports if p['id'] == port_id]
        msg = 'Created port not found in list of ports returned by Neutron'
        self.assertTrue(port, msg)
        return port

    def _verify_port_allowed_address_fields(self, port,
                                            addrpair_ip, addrpair_mac):
        ip_address = port['allowed_address_pairs'][0]['ip_address']
        mac_address = port['allowed_address_pairs'][0]['mac_address']
        self.assertEqual(ip_address, addrpair_ip)
        self.assertEqual(mac_address, addrpair_mac)

    def _remove_allowed_address_pair_from_port(self, port):
        # kwargs = {'name': data_utils.rand_name('network-'),
        #           'port_security_enabled': 'False'}
        # body = cls.networks_client.create_network(**kwargs)
        aap_list = []
        kwargs = {'allowed_address_pairs': aap_list}
        self.update_port(port, **kwargs)

    @classmethod
    def _create_vsd_floatingip_pool(
            cls, fip_pool_cidr_base=VSD_FIP_POOL_CIDR_BASE):  # mind its format
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
        vsd_fip_pool = cls.nuage_vsd_client.create_floatingip_pool(
            name=name,
            address=str(address),
            gateway=str(gateway),
            netmask=str(netmask),
            extra_params=extra_params)
        cls.vsd_shared_domains.append(vsd_fip_pool)
        return vsd_fip_pool

    def _claim_vsd_floating_ip(self, l3domain_id, vsd_fip_pool_id):
        claimed_fip = self.nuage_vsd_client.claim_floatingip(
            l3domain_id, vsd_fip_pool_id)
        return claimed_fip

    def _associate_fip_to_port(self, port, fip_id):
        kwargs = {"nuage_floatingip": {'id': fip_id}}
        self.update_port(port, **kwargs)

    def _disassociate_fip_from_port(self, port):
        kwargs = {"nuage_floatingip": None}
        body = self.admin_ports_client.update_port(port['id'],
                                                   **kwargs)
        return body['port']

    def _check_fip_in_list(self, claimed_fip_id, fip_list):
        fip_found = False
        for fip in fip_list['nuage_floatingips']:
            if fip['id'] == claimed_fip_id:
                fip_found = True
        return fip_found

    def _check_fip_in_port_show(self, port_id, claimed_fip_id):
        fip_found = False
        show_port = self.ports_client.show_port(port_id)
        # first check if 'nuage_flaotingip' is not None
        if show_port['port']['nuage_floatingip'] is not None:
            if show_port['port']['nuage_floatingip']['id'] == claimed_fip_id:
                fip_found = True
        return fip_found


###############################################################################
#
# CLI
#
###############################################################################
    def _cli_create_os_l2_vsd_managed_subnet(self, vsd_l2_subnet):
        network_name = data_utils.rand_name('cli_network')
        network = self.create_network_with_args(network_name)
        subnet_name = data_utils.rand_name('cli-subnet')
        cidr = str(base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR.cidr)
        net_partition = Topology.def_netpartition
        nuagenet = vsd_l2_subnet[0]['ID']
        subnet = self.create_subnet_with_args(network['name'],
                                              cidr,
                                              "--name ",
                                              subnet_name,
                                              "--net-partition ",
                                              net_partition,
                                              "--nuagenet ",
                                              nuagenet)
        return network, subnet

    def _cli_create_os_l3_vsd_managed_subnet(self, vsd_l3_subnet, cidr=None):
        # network = self.create_network(network_name=data_utils.rand_name(
        #    'osl3network'))
        network = self.create_network_with_args(data_utils.rand_name(
            'cli-osl3network'))
        if cidr is None:
            cidr = base_vsd_managed_networks.VSD_L3_SHARED_MGD_CIDR
        else:
            cidr = cidr
        subnet = self.create_subnet_with_args(
            network['name'],
            str(cidr.cidr),
            "--name", data_utils.rand_name('cli-osl3subnet'),
            "--net-partition ", Topology.def_netpartition,
            "--nuagenet ", vsd_l3_subnet[0]['ID'])
        return network, subnet

    # def _cli_create_redirect_target_in_l2_subnet(self, l2subnet, name=None):
    #     if name is None:
    #         name = data_utils.rand_name('os-l2-rt')
    #     # parameters for nuage redirection target
    #     post_body = { 'insertion_mode': 'VIRTUAL_WIRE',
    #                   'redundancy_enabled': 'False',
    #                   'subnet_id': l2subnet['id'],
    #                   'name': name}
    #     redirect_target = \
    #         self.nuage_network_client.create_redirection_target(**post_body)
    #     return redirect_target

    # def _create_redirect_target_in_l3_subnet(self, l3subnet, name=None):
    #     if name is None:
    #         name = data_utils.rand_name('os-l3-rt')
    #     # parameters for nuage redirection target
    #     post_body = { 'insertion_mode': 'L3',
    #                   'redundancy_enabled': 'False',
    #                   'subnet_id': l3subnet['id'],
    #                   'name': name}
    #     redirect_target = \
    #         self.nuage_network_client.create_redirection_target(**post_body)
    #     return redirect_target

    def _cli_find_redirect_target_in_list(self, redirect_target_id, subnet):
        rt_found = False
        rt_list = self.list_nuage_redirect_target_for_l2_subnet(subnet)
        # list_body = self.nuage_network_client.list_redirection_targets(
        #     id=subnet['id'])
        for rt in rt_list:
            if rt['id'] == redirect_target_id:
                rt_found = True
                break
        return rt_found

    def _cli_check_port_in_show_redirect_target(self, port, rt):
        present = False
        # show_port = self.show_port(port['id'])
        show_redirect_target = self.show_nuage_redirect_target(rt['id'])
        # show_rt_body = self.nuage_network_client.show_redirection_target(
        #     rt['nuage_redirect_target']['id'])
        if show_redirect_target['ports'] == port['id']:
            # for port_id in show_redirect_target['ports']:
            #     if port_id == port['id']:
            present = True
            # break
        return present

    def _cli_associate_rt_port(self, rtport, rt):
        self.update_port_with_args(rtport['id'],
                                   "--nuage-redirect-targets", rt['id'])

    def _cli_disassociate_rt_port(self, rtport, rt):
        self.update_port_with_args(rtport['id'],
                                   "--nuage-redirect-targets None")

    def _cli_associate_multiple_rt_port(self, rtport, rts):
        nuage_rt_id_list = []
        for rt in rts:
            nuage_rt_id_list.append(rt['nuage_redirect_target']['id'])
        # convert into comma separated string
        rt_string = ",".join(nuage_rt_id_list)
        self.update_port_with_args(rtport['id'],
                                   "--nuage-redirect-targets", rt_string)

    def _cli_check_policy_group_in_list(self, pg_id, pg_list):
        pg_present = False
        for pg in pg_list:
            if pg['id'] == pg_id:
                pg_present = True
                break
        return pg_present

    def cli_associate_port_with_policy_group(self, port, policy_group):
        self.update_port_with_args(port['id'],
                                   "--nuage-policy-groups",
                                   policy_group[0]['ID'],
                                   "--name port-with-vsd-pg")

    def cli_associate_port_with_multiple_policy_group(
            self, port, policy_group_id_list):
        cli_args = ''
        for pg_id in policy_group_id_list:
            cli_args += "--nuage-policy-groups " + pg_id + " "
        self.update_port_with_args(port['id'],
                                   cli_args,
                                   "--name port-with-multiple-vsd-pg")

    def cli_disassociate_port_from_policy_group(self, port_id):
        self.update_port_with_args(port_id,
                                   "--no-nuage-policy-groups")

    def cli_check_port_in_show_policy_group(self, port_id, policy_group_id):
        port_present = False
        show_pg = self.show_nuage_policy_group(policy_group_id)
        for id in show_pg['ports'].split(","):
            if port_id in id:
                    port_present = True
        return port_present

    def _cli_check_all_policy_groups_in_show_port(self, pg_id_list, show_port):
        groups_present = True
        pg_id_list = show_port['nuage_policy_groups'].split(",")
        for pg_id in pg_id_list:
            if pg_id not in pg_id_list:
                groups_present = False
                break
        return groups_present

    def cli_check_show_port_allowed_address_fields(self, show_port,
                                                   addrpair_ip, addrpair_mac):
        ip_addr_present = addrpair_ip in show_port['allowed_address_pairs']
        mac_addr_present = addrpair_mac in show_port['allowed_address_pairs']
        self.assertTrue(ip_addr_present and mac_addr_present)

    def cli_check_fip_in_list(self, fip_id, fip_list):
        fip_present = False
        for fip in fip_list:
            if fip['id'] == fip_id:
                fip_present = True
                break
        return fip_present

    def cli_check_fip_in_port_show(self, fip_id, port_id):
        fip_present = False
        nuage_floatingip = self.show_port(port_id)['nuage_floatingip']
        # Check the is only when the item is present
        if nuage_floatingip:
            # there is a nuage_floatingip present: check the id
            if fip_id == json.loads(nuage_floatingip)['id']:
                fip_present = True
        return fip_present

    def cli_associate_fip_to_port(self, fip_id, port_id):
        self.update_port_with_args(port_id,
                                   "--nuage-floatingip", fip_id)

    def cli_disassociate_fip_from_port(self, port_id):
        self.update_port_with_args(port_id,
                                   "--no-nuage-floatingip")
