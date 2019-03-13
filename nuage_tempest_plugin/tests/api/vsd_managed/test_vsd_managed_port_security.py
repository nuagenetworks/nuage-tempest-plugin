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
from oslo_log import log as logging

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.test import decorators

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.test import tags
from nuage_tempest_plugin.lib.utils import constants

from nuage_tempest_plugin.tests.api.vsd_managed \
    import base_vsd_managed_networks

CONF = config.CONF
LOG = logging.getLogger(__name__)


@nuage_test.class_header(tags=tags.VSD_MANAGED)
class VSDManagedPortSecurity(
        base_vsd_managed_networks.BaseVSDManagedNetwork):

    @decorators.attr(type='smoke')
    def test_create_port_security_disabled_l3(self):
        name = data_utils.rand_name('l3domain-')
        vsd_l3dom_tmplt = self.create_vsd_l3dom_template(
            name=name)
        vsd_l3dom = self.create_vsd_l3domain(name=name,
                                             tid=vsd_l3dom_tmplt[0]['ID'])
        zonename = data_utils.rand_name('l3dom-zone-')
        vsd_zone = self.create_vsd_zone(name=zonename,
                                        domain_id=vsd_l3dom[0]['ID'])
        subname = data_utils.rand_name('l3dom-sub-')
        cidr = IPNetwork('10.10.100.0/24')
        extra_params = {}
        vsd_subnet = self.create_vsd_l3domain_subnet(
            name=subname,
            zone_id=vsd_zone[0]['ID'],
            cidr=cidr,
            gateway='10.10.100.1',
            extra_params=extra_params)
        net_name = data_utils.rand_name('network-vsd-managed-')
        net = self.create_network(network_name=net_name)
        np = CONF.nuage.nuage_default_netpartition
        self.create_subnet(net,
                           cidr=cidr,
                           mask_bits=24,
                           nuagenet=vsd_subnet[0]['ID'],
                           net_partition=np)

        post_body = {'network_id': net['id'],
                     'port_security_enabled': 'False'}
        self._configure_smart_nic_attributes(post_body)
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        nuage_vport = self.nuage_client.get_vport(
            constants.SUBNETWORK,
            vsd_subnet[0]['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])

    @decorators.attr(type='smoke')
    def test_create_port_security_managed_l2(self):
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name, cidr=cidr, gateway='10.10.100.1')
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        net = self.create_network(network_name=net_name)
        self.create_subnet(
            net, gateway=None,
            cidr=cidr, mask_bits=24, nuagenet=vsd_l2dom[0]['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition,
            enable_dhcp=True)
        post_body = {'network_id': net['id'],
                     'port_security_enabled': 'False'}
        self._configure_smart_nic_attributes(post_body)
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        nuage_vport = self.nuage_client.get_vport(
            constants.L2_DOMAIN,
            vsd_l2dom[0]['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])

    @decorators.attr(type='smoke')
    def test_create_port_security_vsd_managed_no_dhcp_l2(self):
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name, cidr=cidr, enableDHCPv4=False)
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l2dom[0]['name'], name)
        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        net = self.create_network(network_name=net_name)
        self.create_subnet(
            net,
            cidr=IPNetwork('10.10.100.0/24'),
            mask_bits=24, nuagenet=vsd_l2dom[0]['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition,
            enable_dhcp=False)
        post_body = {'network_id': net['id'],
                     'port_security_enabled': 'False'}
        self._configure_smart_nic_attributes(post_body)
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        nuage_vport = self.nuage_client.get_vport(
            constants.L2_DOMAIN,
            vsd_l2dom[0]['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])

    @decorators.attr(type='smoke')
    def test_update_port_security_l3(self):
        name = data_utils.rand_name('l3domain-')
        vsd_l3dom_tmplt = self.create_vsd_l3dom_template(
            name=name)
        vsd_l3dom = self.create_vsd_l3domain(name=name,
                                             tid=vsd_l3dom_tmplt[0]['ID'])
        zonename = data_utils.rand_name('l3dom-zone-')
        vsd_zone = self.create_vsd_zone(name=zonename,
                                        domain_id=vsd_l3dom[0]['ID'])
        subname = data_utils.rand_name('l3dom-sub-')
        cidr = IPNetwork('10.10.100.0/24')
        extra_params = {}
        vsd_subnet = self.create_vsd_l3domain_subnet(
            name=subname,
            zone_id=vsd_zone[0]['ID'],
            cidr=cidr,
            gateway='10.10.100.1',
            extra_params=extra_params)
        net_name = data_utils.rand_name('network-vsd-managed-')
        net = self.create_network(network_name=net_name)
        np = CONF.nuage.nuage_default_netpartition
        self.create_subnet(net,
                           cidr=cidr,
                           mask_bits=24,
                           nuagenet=vsd_subnet[0]['ID'],
                           net_partition=np)

        post_body = {'network_id': net['id']}
        self._configure_smart_nic_attributes(post_body)
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        nuage_vport = self.nuage_client.get_vport(
            constants.SUBNETWORK,
            vsd_subnet[0]['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])
        update_body = {'security_groups': [],
                       'port_security_enabled': 'False'}
        self.ports_client.update_port(port['id'], **update_body)

        nuage_vport = self.nuage_client.get_vport(
            constants.SUBNETWORK,
            vsd_subnet[0]['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        update_body = {'port_security_enabled': 'True'}
        self.ports_client.update_port(port['id'], **update_body)

        nuage_vport = self.nuage_client.get_vport(
            constants.SUBNETWORK,
            vsd_subnet[0]['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.DISABLED,
                         nuage_vport[0]['addressSpoofing'])

    @decorators.attr(type='smoke')
    def test_update_port_security_managed_l2(self):
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name, cidr=cidr, gateway='10.10.100.1')
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        net = self.create_network(network_name=net_name)
        self.create_subnet(
            net, gateway=None,
            cidr=cidr, mask_bits=24, nuagenet=vsd_l2dom[0]['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition,
            enable_dhcp=True)

        post_body = {'network_id': net['id']}
        self._configure_smart_nic_attributes(post_body)
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        nuage_vport = self.nuage_client.get_vport(
            constants.L2_DOMAIN,
            vsd_l2dom[0]['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])
        update_body = {'security_groups': [],
                       'port_security_enabled': 'False'}
        self.ports_client.update_port(port['id'], **update_body)

        nuage_vport = self.nuage_client.get_vport(
            constants.L2_DOMAIN,
            vsd_l2dom[0]['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        update_body = {'port_security_enabled': 'True'}
        self.ports_client.update_port(port['id'], **update_body)

        nuage_vport = self.nuage_client.get_vport(
            constants.L2_DOMAIN,
            vsd_l2dom[0]['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.DISABLED,
                         nuage_vport[0]['addressSpoofing'])

    @decorators.attr(type='smoke')
    def test_update_port_security_vsd_managed_no_dhcp_l2(self):
        name = data_utils.rand_name('l2domain-')
        cidr = IPNetwork('10.10.100.0/24')
        vsd_l2dom_tmplt = self.create_vsd_dhcpmanaged_l2dom_template(
            name=name, cidr=cidr, enableDHCPv4=False)
        vsd_l2dom = self.create_vsd_l2domain(name=name,
                                             tid=vsd_l2dom_tmplt[0]['ID'])

        self.assertEqual(vsd_l2dom[0]['name'], name)
        # create subnet on OS with nuagenet param set to l2domain UUID
        net_name = data_utils.rand_name('network-')
        net = self.create_network(network_name=net_name)
        self.create_subnet(
            net,
            cidr=IPNetwork('10.10.100.0/24'),
            mask_bits=24, nuagenet=vsd_l2dom[0]['ID'],
            net_partition=CONF.nuage.nuage_default_netpartition,
            enable_dhcp=False)
        post_body = {'network_id': net['id']}
        self._configure_smart_nic_attributes(post_body)
        body = self.ports_client.create_port(**post_body)
        port = body['port']

        self.addCleanup(self.ports_client.delete_port, port['id'])
        nuage_vport = self.nuage_client.get_vport(
            constants.L2_DOMAIN,
            vsd_l2dom[0]['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])
        update_body = {'security_groups': [],
                       'port_security_enabled': 'False'}
        self.ports_client.update_port(port['id'], **update_body)

        nuage_vport = self.nuage_client.get_vport(
            constants.L2_DOMAIN,
            vsd_l2dom[0]['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        update_body = {'port_security_enabled': 'True'}
        self.ports_client.update_port(port['id'], **update_body)

        nuage_vport = self.nuage_client.get_vport(
            constants.L2_DOMAIN,
            vsd_l2dom[0]['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.DISABLED,
                         nuage_vport[0]['addressSpoofing'])
