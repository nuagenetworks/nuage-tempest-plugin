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
from netaddr import IPNetwork

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants

from nuage_tempest_plugin.services.nuage_client import NuageRestClient

LOG = Topology.get_logger(__name__)

# default values for shared L2/L3 networks
VSD_L2_SHARED_MGD_CIDR = IPNetwork('20.20.20.0/24')
VSD_L2_SHARED_MGD_GW = '20.20.20.1'

VSD_L3_SHARED_MGD_CIDR = IPNetwork('30.30.30.0/24')
VSD_L3_SHARED_MGD_GW = '30.30.30.1'


class BaseVSDManagedNetworksTest(NuageBaseTest):

    @classmethod
    def setup_clients(cls):
        super(BaseVSDManagedNetworksTest, cls).setup_clients()
        cls.nuageclient = NuageRestClient()

    @classmethod
    def resource_setup(cls):
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

    def get_server_ip_from_vsd(self, vm_id):
        vm_details = self.nuageclient.get_resource(
            constants.VM,
            filters='externalID',
            filter_value=self.nuageclient.get_vsd_external_id(vm_id),
            flat_rest_path=True)[0]
        return vm_details.get('interfaces')[0]['IPAddress']

    @classmethod
    def create_vsd_dhcpmanaged_l2dom_template(cls, netpart_name=None,
                                              **kwargs):
        params = {
            'DHCPManaged': True,
            'address': str(kwargs['cidr'].ip),
            'netmask': str(kwargs['cidr'].netmask),
            'gateway': kwargs['gateway']
        }
        vsd_l2dom_tmplt = cls.nuageclient.create_l2domaintemplate(
            kwargs['name'] + '-template', params, netpart_name)
        cls.vsd_l2dom_template.append(vsd_l2dom_tmplt)
        return vsd_l2dom_tmplt

    @classmethod
    def create_vsd_dhcpunmanaged_l2dom_template(cls, **kwargs):
        vsd_l2dom_tmplt = cls.nuageclient.create_l2domaintemplate(
            kwargs['name'] + '-template')
        cls.vsd_l2dom_template.append(vsd_l2dom_tmplt)
        return vsd_l2dom_tmplt

    @classmethod
    def create_vsd_l2domain(cls, netpart_name=None, **kwargs):
        extra_params = kwargs.get('extra_params')
        vsd_l2dom = cls.nuageclient.create_l2domain(
            kwargs['name'],
            templateId=kwargs['tid'],
            extra_params=extra_params,
            netpart_name=netpart_name)
        cls.vsd_l2domain.append(vsd_l2dom)
        return vsd_l2dom

    @classmethod
    def create_vsd_l3dom_template(cls, netpart_name=None, **kwargs):
        vsd_l3dom_tmplt = cls.nuageclient.create_l3domaintemplate(
            kwargs['name'] + '-template', netpart_name=netpart_name)
        cls.vsd_l3dom_template.append(vsd_l3dom_tmplt)
        return vsd_l3dom_tmplt

    @classmethod
    def create_vsd_l3domain(cls, netpart_name=None, **kwargs):
        extra_params = kwargs.get('extra_params')
        vsd_l3dom = cls.nuageclient.create_domain(kwargs['name'],
                                                  kwargs['tid'],
                                                  netpart_name=netpart_name,
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
