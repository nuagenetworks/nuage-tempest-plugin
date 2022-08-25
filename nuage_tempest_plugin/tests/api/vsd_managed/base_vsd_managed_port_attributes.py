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

from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils as nuage_data_utils

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
        redirect_vport = self.nuage_client.get_redirection_target_vports(
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

    @staticmethod
    def _check_policy_group_in_list(pg_id, pg_list):
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

    @staticmethod
    def _check_policy_group_in_show_port(pg_id, show_port):
        pg_present = False
        for show_pg_id in show_port['port']['nuage_policy_groups']:
            if pg_id == show_pg_id:
                pg_present = True
                break
        return pg_present

    @staticmethod
    def _check_all_policy_groups_in_show_port(pg_id_list, show_port):
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
            'nuagenet': vsd_l2_subnet[0]['ID'],
            'gateway': None
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
    def _create_vsd_floatingip_pool(cls):
        name = data_utils.rand_name('fip-pool')

        # randomize fip cidr to avoid parallel runs issues
        fip_pool_cidr = nuage_data_utils.gimme_a_cidr()
        address = IPAddress(fip_pool_cidr.first)
        netmask = fip_pool_cidr.netmask
        gateway = address + 1
        extra_params = {
            "underlay": True
        }
        vsd_fip_pool = cls.nuage_client.create_floatingip_pool(
            name=name,
            address=str(address),
            gateway=str(gateway),
            netmask=str(netmask),
            extra_params=extra_params)
        cls.vsd_shared_domains.append(vsd_fip_pool)
        return vsd_fip_pool

    def _associate_fip_to_port(self, port, fip_id):
        kwargs = {"nuage_floatingip": {'id': fip_id}}
        self.update_port(port, **kwargs)

    def _disassociate_fip_from_port(self, port):
        kwargs = {"nuage_floatingip": None}
        body = self.admin_ports_client.update_port(port['id'],
                                                   **kwargs)
        return body['port']

    @staticmethod
    def _check_fip_in_list(claimed_fip_id, fip_list):
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
                                              "--no-gateway ",
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
