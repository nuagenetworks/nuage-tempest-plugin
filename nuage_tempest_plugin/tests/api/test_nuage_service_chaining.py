# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
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

import netaddr

from tempest.api.network import base
from tempest.lib.common.utils import data_utils
from tempest.test import decorators

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON
from nuage_tempest_plugin.tests.api.external_id.external_id import ExternalId

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class NuageServiceChaining(base.BaseNetworkTest):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(NuageServiceChaining, cls).setup_clients()
        cls.nuage_client = NuageRestClient()
        cls.client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)

    @classmethod
    def resource_setup(cls):
        super(NuageServiceChaining, cls).resource_setup()
        # Nuage specific resource addition
        name = data_utils.rand_name('network-')
        cls.network_l2 = cls.create_network(network_name=name)
        cls.subnet_l2 = cls.create_subnet(cls.network_l2)

        name = data_utils.rand_name('network-')
        cls.network_l3 = cls.create_network(network_name=name)
        cls.subnet_l3 = cls.create_subnet(cls.network_l3)
        cls.router = cls.create_router(data_utils.rand_name('router-'))
        cls.create_router_interface(cls.router['id'], cls.subnet_l3['id'])

    @classmethod
    def create_port(cls, network, **kwargs):
        if CONF.network.port_vnic_type and 'binding:vnic_type' not in kwargs:
            kwargs['binding:vnic_type'] = CONF.network.port_vnic_type
        if CONF.network.port_profile and 'binding:profile' not in kwargs:
            kwargs['binding:profile'] = CONF.network.port_profile
        return super(NuageServiceChaining, cls).create_port(network,
                                                            **kwargs)

    def _verify_redirect_target(self, rt, parent, parentinfo, postinfo):
        redirect_target = self.nuage_client.get_redirection_target(
            parent, parentinfo['ID'], filters='ID',
            filter_values=rt['nuage_redirect_target']['id'])

        self.assertEqual(
            str(redirect_target[0]['redundancyEnabled']),
            postinfo['redundancy_enabled'])
        self.assertEqual(
            str(redirect_target[0]['endPointType']),
            postinfo['insertion_mode'])
        return redirect_target

    def _verify_redirect_target_rules(self, rtrule, parent,
                                      parentinfo, ruleinfo,
                                      with_external_id=None):
        redirect_target_rule_template = (
            self.nuage_client.get_advfwd_template(
                parent, parentinfo['ID'])
        )

        redirect_target_rule = (
            self.nuage_client.get_advfwd_entrytemplate(
                'ingressadvfwdtemplates',
                str(redirect_target_rule_template[0]['ID']))
        )
        self.assertEqual(
            str(redirect_target_rule[0]['protocol']), ruleinfo['protocol'])
        self.assertEqual(
            str(redirect_target_rule[0]['action']), ruleinfo['action'])
        self.assertEqual(
            str(redirect_target_rule[0]['ID']),
            rtrule['nuage_redirect_target_rule']['id'])

        if with_external_id is None:
            self.assertIsNone(redirect_target_rule[0]['externalID'])
        else:
            self.assertEqual(with_external_id,
                             str(redirect_target_rule[0]['externalID']))

        if not (str(ruleinfo['protocol']) == str(1)):
            pmin = str(ruleinfo['port_range_min'])
            pmax = str(ruleinfo['port_range_max'])
            self.assertEqual(
                str(redirect_target_rule[0]['destinationPort']),
                pmin + "-" + pmax)

    def _assign_unassign_rt_port(self, rtport, rt, parent, parentinfo):
        port_body = self.ports_client.update_port(
            rtport['id'],
            nuage_redirect_targets=str(rt['nuage_redirect_target']['id']))
        self.assertEqual(
            port_body['port']['status'], 'DOWN')
        redirect_vport = self.nuage_client.get_redirection_target_vports(
            'redirectiontargets',
            rt['nuage_redirect_target']['id'])

        # Verifying vport has associated RT
        port_ext_id = (
            self.nuage_client.get_vsd_external_id(
                rtport['id'])
        )
        vsd_vport = self.nuage_client.get_vport(
            parent, parentinfo['ID'], filters='externalID',
            filter_values=port_ext_id)
        self.assertEqual(
            redirect_vport[0]['ID'], vsd_vport[0]['ID'])

        # Unassigning port to Redirect Target
        port_body = (
            self.ports_client.update_port(
                rtport['id'], nuage_redirect_targets='')
        )
        self.assertEqual(
            port_body['port']['status'], 'DOWN')
        redirect_vport = self.nuage_client.get_redirection_target_vports(
            'redirectiontargets',
            rt['nuage_redirect_target']['id'])
        self.assertEqual(redirect_vport, '')

    def _verify_redirect_target_vip(self, rt, vipinfo):
        # Verifying RT has associated vip
        redirect_vip = (
            self.nuage_client.get_redirection_target_vips(
                'redirectiontargets',
                rt['nuage_redirect_target']['id'])
        )
        self.assertEqual(
            redirect_vip[0]['virtualIP'], vipinfo['virtual_ip_address'])
        self.assertIsNotNone(redirect_vip[0]['externalID'],
                             message="External ID is not set for"
                                     " Redirect VIP")
        external_id = str(redirect_vip[0]['externalID']).split("@")
        vip_port = self.ports_client.show_port(
            port_id=external_id[0]).get('port')
        self.assertIsNotNone(vip_port, message="Cannot find nuage:vip port"
                                               " for Redirect VIP")
        self.assertEqual(vip_port['device_owner'], 'nuage:vip',
                         message="Port was not created with device_owner"
                                 " as nuage:vip for Redirect VIP")

    @decorators.attr(type='smoke')
    def test_create_delete_redirection_target_l2domain(self):
        # parameters for nuage redirection target
        post_body = {'insertion_mode': 'VIRTUAL_WIRE',
                     'redundancy_enabled': 'False',
                     'subnet_id': self.subnet_l2['id'],
                     'name': 'RT1'}

        # Creating redirection Target
        rt = self.client.create_redirection_target(**post_body)

        vsd_subnet = self.nuage_client.get_l2domain(by_subnet=self.subnet_l2)

        # Verifying Redirect Target on VSD
        redirect_target = self._verify_redirect_target(
            rt, 'l2domains', vsd_subnet[0], post_body)
        subnet_ext_id = self.nuage_client.get_subnet_external_id(
            self.subnet_l2)
        self.assertEqual(redirect_target[0]['externalID'], subnet_ext_id)
        body = self.security_groups_client.list_security_groups()
        security_group_id = body['security_groups'][0]['id']

        # Creating Redirect Target Rule
        rtid = str(rt['nuage_redirect_target']['id'])
        rule_body = {'priority': '100',
                     'redirect_target_id': rtid,
                     'protocol': '6',
                     'origin_group_id': str(security_group_id),
                     'remote_ip_prefix': '20.0.0.0/24',
                     'action': 'FORWARD', 'port_range_min': '50',
                     'port_range_max': '120'}

        rtrule = self.client.create_redirection_target_rule(**rule_body)

        # Verifying Redirect Target Rule on VSD
        external_id = ExternalId(self.subnet_l2['id'] if Topology.is_v5
                                 else self.subnet_l2['network_id']).at_cms_id()

        self._verify_redirect_target_rules(
            rtrule, 'l2domains', vsd_subnet[0], rule_body,
            with_external_id=external_id)
        kwargs = {}
        # Associating port to Redirect Target
        rtport = self.create_port(self.network_l2, **kwargs)
        self.addCleanup(self.ports_client.delete_port, rtport['id'])

        self._assign_unassign_rt_port(
            rtport, rt, 'l2domains', vsd_subnet[0])

        # Deleting RT
        self.client.delete_redirection_target(
            redirect_target[0]['ID'])

        # Verifying RT is deleted from VSD
        redirect_target = self.nuage_client.get_redirection_target(
            'l2domains', vsd_subnet[0]['ID'], filters='ID',
            filter_values=rt['nuage_redirect_target']['id'])
        self.assertEqual(redirect_target, '')

    @decorators.attr(type='smoke')
    def test_create_virtualwire_redirection_target_l3domain(self):
        # parameters for nuage redirection target
        post_body = {'insertion_mode': 'VIRTUAL_WIRE',
                     'redundancy_enabled': 'False',
                     'router_id': self.router['id'],
                     'name': 'RT2'}

        # Creating redirection Target
        rt = self.client.create_redirection_target(**post_body)

        router_ext_id = (
            self.nuage_client.get_vsd_external_id(
                self.router['id'])
        )
        domain = (
            self.nuage_client.get_l3domain(
                filters='externalID', filter_values=router_ext_id)
        )
        vsd_subnet = (
            self.nuage_client.get_domain_subnet(
                'domains', domain[0]['ID'], by_subnet=self.subnet_l3)
        )

        # Verifying Redirect Target on VSD
        redirect_target = self._verify_redirect_target(
            rt, 'domains', domain[0], post_body)
        self.assertEqual(redirect_target[0]['externalID'], router_ext_id)

        body = self.security_groups_client.list_security_groups()
        security_group_id = body['security_groups'][0]['id']

        # Creating Redirect Target Rule
        rtid = str(rt['nuage_redirect_target']['id'])
        rule_body = {'priority': '200',
                     'redirect_target_id': rtid,
                     'protocol': '17',
                     'origin_group_id': str(security_group_id),
                     'remote_ip_prefix': '10.0.0.0/24',
                     'action': 'REDIRECT',
                     'port_range_min': '50',
                     'port_range_max': '120'}

        rtrule = self.client.create_redirection_target_rule(**rule_body)

        # Verifying Redirect Target Rule on VSD
        external_id = ExternalId(self.router['id']).at_cms_id()

        self._verify_redirect_target_rules(rtrule, 'domains',
                                           domain[0], rule_body,
                                           with_external_id=external_id)
        kwargs = {}
        # Associating port to Redirect Target
        rtport = self.create_port(self.network_l3, **kwargs)
        self.addCleanup(self.ports_client.delete_port, rtport['id'])
        self._assign_unassign_rt_port(rtport, rt, 'subnets', vsd_subnet[0])

        # Put in lines to delete the RT from the l3domain and verify on VSD
        self.client.delete_redirection_target(
            redirect_target[0]['ID'])
        redirect_target = self.nuage_client.get_redirection_target(
            'domains', domain[0]['ID'], filters='ID',
            filter_values=rt['nuage_redirect_target']['id'])
        self.assertEqual(redirect_target, '')

    @decorators.attr(type='smoke')
    def test_create_virtualwire_redirection_target_on_subnet_in_l3domain(self):
        # parameters for nuage redirection target
        post_body = {'insertion_mode': 'VIRTUAL_WIRE',
                     'redundancy_enabled': 'False',
                     'subnet_id': self.subnet_l3['id'],
                     'name': 'RT2'}

        # Creating redirection Target
        rt = self.client.create_redirection_target(**post_body)

        router_ext_id = (
            self.nuage_client.get_vsd_external_id(
                self.router['id'])
        )
        domain = (
            self.nuage_client.get_l3domain(
                filters='externalID', filter_values=router_ext_id)
        )
        vsd_subnet = (
            self.nuage_client.get_domain_subnet(
                'domains', domain[0]['ID'], by_subnet=self.subnet_l3)
        )

        # Verifying Redirect Target on VSD
        redirect_target = self._verify_redirect_target(
            rt, 'domains', domain[0], post_body)
        subnet_ext_id = self.nuage_client.get_subnet_external_id(
            self.subnet_l3)
        self.assertEqual(redirect_target[0]['externalID'], subnet_ext_id)

        body = self.security_groups_client.list_security_groups()
        security_group_id = body['security_groups'][0]['id']

        # Creating Redirect Target Rule
        rtid = str(rt['nuage_redirect_target']['id'])
        rule_body = {'priority': '200',
                     'redirect_target_id': rtid,
                     'protocol': '17',
                     'origin_group_id': str(security_group_id),
                     'remote_ip_prefix': '10.0.0.0/24',
                     'action': 'REDIRECT',
                     'port_range_min': '50',
                     'port_range_max': '120'}

        rtrule = self.client.create_redirection_target_rule(**rule_body)

        # Verifying Redirect Target Rule on VSD
        subnet_ext_id = self.nuage_client.get_subnet_external_id(
            self.subnet_l3)
        self._verify_redirect_target_rules(rtrule, 'domains',
                                           domain[0], rule_body,
                                           with_external_id=subnet_ext_id)

        # Associating port to Redirect Target
        rtport = self.create_port(self.network_l3)
        self.addCleanup(self.ports_client.delete_port, rtport['id'])
        self._assign_unassign_rt_port(rtport, rt, 'subnets', vsd_subnet[0])

        # Put in lines to delete the RT from the l3domain and verify on VSD
        self.client.delete_redirection_target(
            redirect_target[0]['ID'])
        redirect_target = self.nuage_client.get_redirection_target(
            'domains', domain[0]['ID'], filters='ID',
            filter_values=rt['nuage_redirect_target']['id'])
        self.assertEqual(redirect_target, '')

    ###
    @decorators.attr(type='smoke')
    def test_create_l3_redirection_target_l3domain(self):
        # parameters for nuage redirection target
        post_body = {'insertion_mode': 'L3',
                     'redundancy_enabled': 'False',
                     'router_id': self.router['id'],
                     'name': 'RT3'}

        # Creating redirection Target
        rt = self.client.create_redirection_target(**post_body)

        router_ext_id = (
            self.nuage_client.get_vsd_external_id(
                self.router['id'])
        )
        domain = (
            self.nuage_client.get_l3domain(
                filters='externalID', filter_values=router_ext_id)
        )
        vsd_subnet = (
            self.nuage_client.get_domain_subnet(
                'domains', domain[0]['ID'], by_subnet=self.subnet_l3)
        )

        # Verifying Redirect Target on VSD
        redirect_target = self._verify_redirect_target(
            rt, 'domains', domain[0], post_body)
        self.assertEqual(redirect_target[0]['externalID'], router_ext_id)
        body = self.security_groups_client.list_security_groups()
        security_group_id = body['security_groups'][0]['id']

        # Creating Redirect Target Rule
        rtid = str(rt['nuage_redirect_target']['id'])
        rule_body = {'priority': '300',
                     'redirect_target_id': rtid,
                     'protocol': '1',
                     'origin_group_id': str(security_group_id),
                     'remote_ip_prefix': '10.0.0.0/24',
                     'action': 'REDIRECT'}

        rtrule = self.client.create_redirection_target_rule(**rule_body)

        # Verifying Redirect Target Rule on VSD
        external_id = ExternalId(self.router['id']).at_cms_id()

        self._verify_redirect_target_rules(rtrule, 'domains',
                                           domain[0], rule_body,
                                           with_external_id=external_id)
        kwargs = {}
        # Associating port to Redirect Target
        rtport = self.create_port(self.network_l3, **kwargs)
        self.addCleanup(self.ports_client.delete_port, rtport['id'])
        self._assign_unassign_rt_port(rtport, rt, 'subnets', vsd_subnet[0])

        # Delete the RT from the l3domain and verify on VSD

        self.client.delete_redirection_target(
            redirect_target[0]['ID'])

        redirect_target = self.nuage_client.get_redirection_target(
            'domains', domain[0]['ID'], filters='ID',
            filter_values=rt['nuage_redirect_target']['id'])
        self.assertEqual(redirect_target, '')

    @decorators.attr(type='smoke')
    def test_create_l3_redirection_target_l3domain_redundancyvip(self):
        # parameters for nuage redirection target
        post_body = {'insertion_mode': 'L3', 'redundancy_enabled': 'True',
                     'router_id': self.router['id'], 'name': 'RT4'}

        # Creating redirection Target
        rt = self.client.create_redirection_target(**post_body)

        router_ext_id = (
            self.nuage_client.get_vsd_external_id(
                self.router['id'])
        )
        domain = (
            self.nuage_client.get_l3domain(
                filters='externalID', filter_values=router_ext_id)
        )
        vsd_subnet = (
            self.nuage_client.get_domain_subnet(
                'domains', domain[0]['ID'], by_subnet=self.subnet_l3)
        )

        # Verifying Redirect Target on VSD
        redirect_target = self._verify_redirect_target(rt, 'domains',
                                                       domain[0], post_body)
        body = self.security_groups_client.list_security_groups()
        security_group_id = body['security_groups'][0]['id']

        # Take address <>.6 from the project_network_cidr
        vip_ip_address = (
            netaddr.IPNetwork(CONF.network.project_network_cidr)[6]
        )
        vip_body = {"virtual_ip_address": str(vip_ip_address),
                    "subnet_id": self.subnet_l3['id'],
                    "redirect_target_id": rt['nuage_redirect_target']['id']}

        self.client.create_redirection_target_vip(**vip_body)
        self._verify_redirect_target_vip(rt, vip_body)

        # Creating Redirect Target Rule
        rule_body = {
            'priority': '300',
            'redirect_target_id': str(rt['nuage_redirect_target']['id']),
            'protocol': '1',
            'origin_group_id': str(security_group_id),
            'remote_ip_prefix': '10.0.0.0/24',
            'action': 'REDIRECT'
        }

        rtrule = self.client.create_redirection_target_rule(**rule_body)

        # Verifying Redirect Target Rule on VSD
        external_id = ExternalId(self.router['id']).at_cms_id()

        self._verify_redirect_target_rules(rtrule, 'domains',
                                           domain[0], rule_body,
                                           with_external_id=external_id)
        kwargs = {}
        # Associating port to Redirect Target
        rtport = self.create_port(self.network_l3, **kwargs)
        self.addCleanup(self.ports_client.delete_port, rtport['id'])
        self._assign_unassign_rt_port(rtport, rt, 'subnets', vsd_subnet[0])

        # Delete the RT from the l3domain and verify on VSD
        self.client.delete_redirection_target(
            redirect_target[0]['ID'])

        redirect_target = self.nuage_client.get_redirection_target(
            'domains', domain[0]['ID'], filters='ID',
            filter_values=rt['nuage_redirect_target']['id'])
        self.assertEqual(redirect_target, '')
