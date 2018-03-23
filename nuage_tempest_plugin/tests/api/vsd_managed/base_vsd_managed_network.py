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

from tempest.api.network import base

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.services.nuage_client import NuageRestClient


class BaseVSDManagedNetworksTest(base.BaseNetworkTest):

    credentials = ['primary', 'admin']

    @classmethod
    def setup_clients(cls):
        super(BaseVSDManagedNetworksTest, cls).setup_clients()
        cls.admin_agents_client = cls.os_adm.network_agents_client
        cls.nuageclient = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        if Topology.is_ml2:
            # create default netpartition if it is not there
            netpartition_name = cls.nuageclient.def_netpart_name
            net_partition = cls.nuageclient.get_net_partition(
                netpartition_name)
            if not net_partition:
                net_partition = cls.nuageclient.create_net_partition(
                    netpartition_name, fip_quota=100, extra_params=None)
        super(BaseVSDManagedNetworksTest, cls).resource_setup()
        cls.vsd_l2dom_template = []
        cls.vsd_l2domain = []
        cls.vsd_l3dom_template = []
        cls.vsd_l3domain = []
        cls.vsd_zone = []
        cls.vsd_subnet = []
        cls.vsd_shared_subnet = []

    @classmethod
    def resource_cleanup(cls):
        super(BaseVSDManagedNetworksTest, cls).resource_cleanup()
        for vsd_l2domain in cls.vsd_l2domain:
            cls.nuageclient.delete_l2domain(vsd_l2domain[0]['ID'])

        for vsd_l2dom_template in cls.vsd_l2dom_template:
            cls.nuageclient.delete_l2domaintemplate(
                vsd_l2dom_template[0]['ID'])

        for vsd_subnet in cls.vsd_subnet:
            cls.nuageclient.delete_domain_subnet(vsd_subnet[0]['ID'])

        for vsd_zone in cls.vsd_zone:
            cls.nuageclient.delete_zone(vsd_zone[0]['ID'])

        for vsd_l3domain in cls.vsd_l3domain:
            cls.nuageclient.delete_domain(vsd_l3domain[0]['ID'])

        for vsd_l3dom_template in cls.vsd_l3dom_template:
            cls.nuageclient.delete_l3domaintemplate(
                vsd_l3dom_template[0]['ID'])

        for vsd_shared_subnet in cls.vsd_shared_subnet:
            resource = ('/sharednetworkresources/%s?responseChoice=1' %
                        vsd_shared_subnet[0]['ID'])
            cls.nuageclient.restproxy.rest_call('DELETE', resource, '')

    @classmethod
    def create_vsd_dhcpmanaged_l2dom_template(cls, **kwargs):
        params = {
            'DHCPManaged': True,
            'address': str(kwargs['cidr'].ip),
            'netmask': str(kwargs['cidr'].netmask),
            'gateway': kwargs['gateway']
        }
        vsd_l2dom_tmplt = cls.nuageclient.create_l2domaintemplate(
            kwargs['name'] + '-template', extra_params=params)
        cls.vsd_l2dom_template.append(vsd_l2dom_tmplt)
        return vsd_l2dom_tmplt

    @classmethod
    def create_vsd_dhcpunmanaged_l2dom_template(cls, **kwargs):
        vsd_l2dom_tmplt = cls.nuageclient.create_l2domaintemplate(
            kwargs['name'] + '-template')
        cls.vsd_l2dom_template.append(vsd_l2dom_tmplt)
        return vsd_l2dom_tmplt

    @classmethod
    def create_vsd_l2domain(cls, **kwargs):
        extra_params = kwargs.get('extra_params')
        vsd_l2dom = cls.nuageclient.create_l2domain(
            kwargs['name'],
            templateId=kwargs['tid'],
            extra_params=extra_params)
        cls.vsd_l2domain.append(vsd_l2dom)
        return vsd_l2dom

    @classmethod
    def create_vsd_l3dom_template(cls, **kwargs):
        vsd_l3dom_tmplt = cls.nuageclient.create_l3domaintemplate(
            kwargs['name'] + '-template')
        cls.vsd_l3dom_template.append(vsd_l3dom_tmplt)
        return vsd_l3dom_tmplt

    @classmethod
    def create_vsd_l3domain(cls, **kwargs):
        extra_params = kwargs.get('extra_params')
        vsd_l3dom = cls.nuageclient.create_domain(kwargs['name'],
                                                  kwargs['tid'],
                                                  extra_params=extra_params)
        cls.vsd_l3domain.append(vsd_l3dom)
        return vsd_l3dom

    @classmethod
    def create_vsd_zone(cls, **kwargs):
        extra_params = kwargs.get('extra_params')
        vsd_zone = cls.nuageclient.create_zone(kwargs['domain_id'],
                                               kwargs['name'],
                                               extra_params=extra_params)
        cls.vsd_zone.append(vsd_zone)
        return vsd_zone

    @classmethod
    def create_vsd_l3domain_subnet(cls, **kwargs):
        vsd_subnet = cls.nuageclient.create_domain_subnet(
            kwargs['zone_id'],
            kwargs['name'],
            str(kwargs['cidr'].ip),
            str(kwargs['cidr'].netmask),
            kwargs['gateway'])
        cls.vsd_subnet.append(vsd_subnet)
        return vsd_subnet

    @classmethod
    def create_vsd_managed_shared_resource(cls, **kwargs):
        data = {}
        data.update(kwargs)
        vsd_shared_subnet = cls.nuageclient.restproxy.rest_call(
            'POST', '/sharednetworkresources', data)
        cls.vsd_shared_subnet.append(vsd_shared_subnet.data)
        return vsd_shared_subnet.data[0]

    dhcp_agent_present = None

    def is_dhcp_agent_present(self):
        if self.dhcp_agent_present is None:
            agents = self.admin_agents_client.list_agents().get('agents')
            if agents:
                self.dhcp_agent_present = any(
                    agent for agent in agents if agent['alive'] and
                    agent['binary'] == 'neutron-dhcp-agent')
            else:
                self.dhcp_agent_present = False

        return self.dhcp_agent_present
