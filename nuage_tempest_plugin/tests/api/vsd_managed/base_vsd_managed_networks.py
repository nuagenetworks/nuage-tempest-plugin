# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.services import nuage_client
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

# default values for shared L2/L3 networks
VSD_L2_SHARED_MGD_CIDR = IPNetwork('20.20.20.0/24')
VSD_L2_SHARED_MGD_GW = '20.20.20.1'

VSD_L3_SHARED_MGD_CIDR = IPNetwork('30.30.30.0/24')
VSD_L3_SHARED_MGD_GW = '30.30.30.1'

LOG = Topology.get_logger(__name__)
CONF = Topology.get_conf()


class BaseVSDManagedNetwork(NuageBaseTest):

    @classmethod
    def setup_clients(cls):
        super(BaseVSDManagedNetwork, cls).setup_clients()
        cls.admin_networks_client = cls.os_admin.networks_client
        cls.admin_subnets_client = cls.os_admin.subnets_client
        cls.admin_ports_client = cls.os_admin.ports_client

        cls.nuage_client = nuage_client.NuageRestClient()
        cls.nuage_network_client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)

    @classmethod
    def resource_setup(cls):
        super(BaseVSDManagedNetwork, cls).resource_setup()

        cls.vsd_l2dom_templates = []
        cls.vsd_l2domains = []
        cls.vsd_l3dom_templates = []
        cls.vsd_l3domains = []
        cls.vsd_zones = []
        cls.vsd_subnets = []
        cls.vsd_shared_domains = []
        cls.vsd_policy_groups = []

    @classmethod
    def resource_cleanup(cls):
        # cleanup the OpenStack managed objects first
        super(BaseVSDManagedNetwork, cls).resource_cleanup()

        for vsd_policy_group in reversed(cls.vsd_policy_groups):
            cls.nuage_client.delete_policygroup(vsd_policy_group[0]['id'])

        for vsd_l2domain in reversed(cls.vsd_l2domains):
            cls.nuage_client.delete_l2domain(vsd_l2domain[0]['ID'])

        for vsd_l2dom_template in reversed(cls.vsd_l2dom_templates):
            cls.nuage_client.delete_l2domaintemplate(
                vsd_l2dom_template[0]['ID'])

        for vsd_subnet in reversed(cls.vsd_subnets):
            cls.nuage_client.delete_domain_subnet(vsd_subnet[0]['ID'])

        for vsd_zone in reversed(cls.vsd_zones):
            cls.nuage_client.delete_zone(vsd_zone[0]['ID'])

        for vsd_l3domain in reversed(cls.vsd_l3domains):
            cls.nuage_client.delete_domain(vsd_l3domain[0]['ID'])

        for vsd_l3dom_template in reversed(cls.vsd_l3dom_templates):
            cls.nuage_client.delete_l3domaintemplate(
                vsd_l3dom_template[0]['ID'])

        for vsd_shared_domain in reversed(cls.vsd_shared_domains):
            cls.nuage_client.delete_vsd_shared_resource(
                vsd_shared_domain[0]['ID'])

    @classmethod
    def create_vsd_dhcpmanaged_l2dom_template(cls, **kwargs):
        name = kwargs.get('name') or data_utils.rand_name('l2domain-IPAM')
        params = {
            'DHCPManaged': True,
            'address': str(kwargs['cidr'].ip),
            'netmask': str(kwargs['cidr'].netmask),
            'gateway': kwargs.get('gateway'),
            'IPv6Address': str(kwargs.get('cidrv6')),
            'IPv6Gateway': kwargs.get('gatewayv6'),
            'enableDHCPv4': kwargs.get('enableDHCPv4', True),
            'enableDHCPv6': kwargs.get('enableDHCPv6', False),
            'IPType': kwargs.get('IPType')
        }
        vsd_l2dom_tmplt = cls.nuage_client.create_l2domaintemplate(
            name + '-template', params, kwargs.get('netpart_name'))
        cls.vsd_l2dom_templates.append(vsd_l2dom_tmplt)
        return vsd_l2dom_tmplt

    @classmethod
    def create_vsd_dhcpunmanaged_l2dom_template(cls, **kwargs):
        name = kwargs.get('name') or data_utils.rand_name('l2domain-noIPAM')
        vsd_l2dom_tmplt = cls.nuage_client.create_l2domaintemplate(
            name + '-template',
            netpart_name=kwargs.get('netpart_name'))
        cls.vsd_l2dom_templates.append(vsd_l2dom_tmplt)
        return vsd_l2dom_tmplt

    @classmethod
    def create_vsd_l2domain(cls, **kwargs):
        name = kwargs.get('name') or data_utils.rand_name('l2domain')
        extra_params = kwargs.get('extra_params')
        vsd_l2dom = cls.nuage_client.create_l2domain(
            name,
            templateId=kwargs['tid'],
            extra_params=extra_params,
            netpart_name=kwargs.get('netpart_name'))
        cls.vsd_l2domains.append(vsd_l2dom)
        return vsd_l2dom

    @classmethod
    def create_vsd_l3dom_template(cls, **kwargs):
        name = kwargs.get('name') or data_utils.rand_name('l3domain')
        vsd_l3dom_tmplt = cls.nuage_client.create_l3domaintemplate(
            name + '-template', netpart_name=kwargs.get('netpart_name'))
        cls.vsd_l3dom_templates.append(vsd_l3dom_tmplt)
        return vsd_l3dom_tmplt

    @classmethod
    def create_vsd_l3domain(cls, **kwargs):
        name = kwargs.get('name') or data_utils.rand_name('l3domain')
        extra_params = kwargs.get('extra_params')
        vsd_l3dom = cls.nuage_client.create_domain(
            name, kwargs['tid'], netpart_name=kwargs.get('netpart_name'),
            extra_params=extra_params)
        cls.vsd_l3domains.append(vsd_l3dom)
        return vsd_l3dom

    @classmethod
    def create_vsd_zone(cls, **kwargs):
        name = kwargs.get('name') or data_utils.rand_name('zone')
        extra_params = kwargs.get('extra_params')
        vsd_zone = cls.nuage_client.create_zone(kwargs['domain_id'], name,
                                                extra_params=extra_params)
        cls.vsd_zones.append(vsd_zone)
        return vsd_zone

    @classmethod
    def create_vsd_l3domain_subnet(cls, **kwargs):
        name = kwargs.get('name') or data_utils.rand_name('subnet')
        vsd_subnet = cls.nuage_client.create_domain_subnet(
            kwargs['zone_id'],
            name,
            str(kwargs['cidr'].ip),
            str(kwargs['cidr'].netmask),
            kwargs['gateway'])
        cls.vsd_subnets.append(vsd_subnet)
        return vsd_subnet

    @classmethod
    def create_vsd_l3domain_managed_subnet(cls, **kwargs):
        name = kwargs.get('name') or data_utils.rand_name('l3-managed-subnet')
        if 'cidr' not in kwargs:
            address = VSD_L3_SHARED_MGD_CIDR.ip
            netmask = VSD_L3_SHARED_MGD_CIDR.netmask
        else:
            address = kwargs['cidr'].ip
            netmask = kwargs['cidr'].netmask
        if 'gateway' not in kwargs:
            gateway = VSD_L3_SHARED_MGD_GW
        else:
            gateway = kwargs['gateway']
        if 'extra_params' not in kwargs:
            extra_params = None
        else:
            extra_params = kwargs['extra_params']
        vsd_subnet = cls.nuage_client.create_domain_subnet(
            kwargs['zone_id'],
            name,
            str(address),
            str(netmask),
            gateway,
            None,
            extra_params)
        cls.vsd_subnets.append(vsd_subnet)
        return vsd_subnet

    @classmethod
    def create_vsd_l3domain_unmanaged_subnet(cls, **kwargs):
        name = kwargs.get('name') or data_utils.rand_name(
            'l3-unmanaged-subnet')
        vsd_subnet = cls.nuage_client.create_domain_unmanaged_subnet(
            kwargs['zone_id'],
            name,
            kwargs['extra_params'])
        cls.vsd_subnets.append(vsd_subnet)
        return vsd_subnet

    @classmethod
    def create_vsd_shared_l2domain_unmanaged(cls, **kwargs):
        name = kwargs.get('name') or data_utils.rand_name(
            'vsd-l2domain-shared-unmgd')
        vsd_l2_shared_domain = cls.nuage_client.create_vsd_shared_resource(
            name=name,
            type='L2DOMAIN')
        cls.vsd_shared_domains.append(vsd_l2_shared_domain)
        return vsd_l2_shared_domain

    @classmethod
    def create_vsd_shared_l2domain_managed(cls, **kwargs):
        name = kwargs.get('name') or data_utils.rand_name(
            'vsd-l2domain-shared-mgd')
        if 'cidr' in kwargs:
            cidr = kwargs['cidr']
        else:
            cidr = VSD_L2_SHARED_MGD_CIDR
        #
        if "gateway" in kwargs:
            gateway = kwargs['gateway']
        else:
            gateway = VSD_L2_SHARED_MGD_GW
        extra_params = {
            'DHCPManaged': True,
            'address': str(cidr.ip),
            'netmask': str(cidr.netmask),
            'gateway': gateway
        }
        vsd_l2_shared_domain = cls.nuage_client.create_vsd_shared_resource(
            name=name,
            type='L2DOMAIN',
            extra_params=extra_params)
        cls.vsd_shared_domains.append(vsd_l2_shared_domain)
        return vsd_l2_shared_domain

    @classmethod
    def create_vsd_shared_l3domain_managed(cls, **kwargs):
        name = kwargs.get('name') or data_utils.rand_name(
            'vsd-l3domain-mgd')
        #
        if 'cidr' in kwargs:
            cidr = kwargs['cidr']
        else:
            cidr = VSD_L3_SHARED_MGD_CIDR
        #
        if "gateway" in kwargs:
            gateway = kwargs['gateway']
        else:
            gateway = VSD_L3_SHARED_MGD_GW
        extra_params = {
            'DHCPManaged': True,
            'address': str(cidr.ip),
            'netmask': str(cidr.netmask),
            'gateway': gateway
        }
        vsd_l3_shared_domain = cls.nuage_client.create_vsd_shared_resource(
            name=name,
            type='PUBLIC',
            extra_params=extra_params)
        cls.vsd_shared_domains.append(vsd_l3_shared_domain)
        return vsd_l3_shared_domain

    @classmethod
    def link_l2domain_to_shared_domain(cls, domain_id, shared_domain_id):
        update_params = {
            'associatedSharedNetworkResourceID': shared_domain_id
        }
        cls.nuage_client.update_l2domain(domain_id,
                                         update_params=update_params)

    @classmethod
    def create_vsd_l2_policy_group(cls, vsd_l2_subnet_id, name=None, type=None,
                                   extra_params=None):
        if name is None:
            name = data_utils.rand_name('vsd-policy-group')
        policy_group = cls.nuage_client.create_policygroup(
            constants.L2_DOMAIN,
            vsd_l2_subnet_id,
            name=name,
            type=type,
            extra_params=extra_params)
        cls.vsd_policy_groups.append(policy_group)
        return policy_group

    def get_server_ip_from_vsd(self, vm_id, type='IPV4'):
        vm_details = self.nuage_client.get_resource(
            constants.VM,
            filters='externalID',
            filter_value=self.nuage_client.get_vsd_external_id(vm_id),
            flat_rest_path=True)[0]
        if type == 'DUALSTACK':
            return (vm_details.get('interfaces')[0]['IPAddress'],
                    vm_details.get('interfaces')[0]['IPv6Address'])
        elif type == 'IPV4':
            return vm_details.get('interfaces')[0]['IPAddress']
        else:
            return vm_details.get('interfaces')[0]['IPv6Address']
