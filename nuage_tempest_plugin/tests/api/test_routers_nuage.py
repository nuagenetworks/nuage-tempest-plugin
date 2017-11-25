# Copyright 2013 OpenStack Foundation
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

import netaddr
from random import randint
import uuid

from tempest.api.network.admin import test_routers as admin_test_routers
from tempest.api.network import test_routers
from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.release import Release
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON
from nuage_tempest_plugin.tests.api.upgrade.external_id.external_id \
    import ExternalId

CONF = config.CONF
external_id_release = Release(n_constants.EXTERNALID_RELEASE)
current_release = Release(Topology.nuage_release)
NUAGE_PAT_ENABLED = 'ENABLED'
NUAGE_PAT_DISABLED = 'DISABLED'


class RoutersTestNuage(test_routers.RoutersTest):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(RoutersTestNuage, cls).setup_clients()
        cls.client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os_primary.default_params)
        cls.nuage_vsd_client = NuageRestClient()

    @classmethod
    def resource_setup(cls):
        super(RoutersTestNuage, cls).resource_setup()

    @decorators.attr(type='smoke')
    def test_create_show_list_update_delete_router(self):
        # Create a router
        name = data_utils.rand_name('router-')
        create_body = self.routers_client.create_router(
            name=name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=False)
        self.addCleanup(self.routers_client.delete_router,
                        create_body['router']['id'])
        self.assertEqual(create_body['router']['name'], name)
        # VSD validation
        rtr_id = create_body['router']['id']
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=rtr_id)
        self.assertEqual(nuage_domain[0][u'description'], name)
        if external_id_release <= current_release:
            nuage_zones = self.nuage_vsd_client.get_zone(
                parent_id=nuage_domain[0]['ID'])
            self.assertEqual(len(nuage_zones), 2, "Zones for the corresponding"
                                                  " Domain are not found")
            for zone in nuage_zones:
                self.assertEqual(zone['externalID'],
                                 self.nuage_vsd_client.get_vsd_external_id(
                                     rtr_id))
                permissions = self.nuage_vsd_client.get_permissions(
                    parent=n_constants.ZONE,
                    parent_id=zone['ID'])
                self.assertEqual(len(permissions), 1)
                self.assertEqual(permissions[0]['externalID'],
                                 self.nuage_vsd_client.get_vsd_external_id(
                                     create_body['router']['tenant_id']))
                if zone['name'].split('-')[1] == 'pub':
                    self.assertEqual(permissions[0]['permittedEntityName'],
                                     "Everybody")
                else:
                    self.assertEqual(permissions[0]['permittedEntityName'],
                                     self.routers_client.tenant_id)
                    group_resp = self.nuage_vsd_client.get_resource(
                        resource=n_constants.GROUP,
                        filters='externalID',
                        filter_value=(self.routers_client.tenant_id +
                                      '@openstack'),
                        netpart_name=self.nuage_vsd_client.def_netpart_name)
                    self.assertIsNot(group_resp, "",
                                     "User Group on VSD for the user who "
                                     "created the Router was not Found")
                    self.assertEqual(group_resp[0]['name'],
                                     self.routers_client.tenant_id)
                user_resp = self.nuage_vsd_client.get_user(
                    filters='externalID',
                    filter_value=(self.routers_client.tenant_id +
                                  '@openstack'),
                    netpart_name=self.nuage_vsd_client.def_netpart_name)
                self.assertIsNot(user_resp, "",
                                 "User on VSD for the user who created the "
                                 "Router was not Found")
                self.assertEqual(user_resp[0]['userName'],
                                 self.routers_client.tenant_id)
            default_egress_tmpl = self.nuage_vsd_client.get_child_resource(
                resource=n_constants.DOMAIN,
                resource_id=nuage_domain[0]['ID'],
                child_resource=n_constants.EGRESS_ACL_TEMPLATE,
                filters='externalID',
                filter_value=self.nuage_vsd_client.get_vsd_external_id(
                    rtr_id))
            self.assertIsNot(default_egress_tmpl,
                             "",
                             "Could not Find Default EGRESS Template on VSD "
                             "For Router")
            default_ingress_tmpl = self.nuage_vsd_client.get_child_resource(
                resource=n_constants.DOMAIN,
                resource_id=nuage_domain[0]['ID'],
                child_resource=n_constants.INGRESS_ACL_TEMPLATE,
                filters='externalID',
                filter_value=self.nuage_vsd_client.get_vsd_external_id(
                    rtr_id))
            self.assertIsNot(default_ingress_tmpl,
                             "",
                             "Could not Find Default INGRESS Template on VSD"
                             " For Router")
            default_ingress_awd_tmpl = \
                self.nuage_vsd_client.get_child_resource(
                    resource=n_constants.DOMAIN,
                    resource_id=nuage_domain[0]['ID'],
                    child_resource=n_constants.INGRESS_ADV_FWD_TEMPLATE,
                    filters='externalID',
                    filter_value=self.nuage_vsd_client.get_vsd_external_id(
                        rtr_id))
            self.assertIsNot(default_ingress_awd_tmpl,
                             "",
                             "Could not Find Default Forwarding INGRESS"
                             " Template on VSD For Router")
        self.assertEqual(
            create_body['router']['external_gateway_info']['network_id'],
            CONF.network.public_network_id)
        self.assertEqual(create_body['router']['admin_state_up'], False)
        # Show details of the created router
        show_body = self.routers_client.show_router(
            create_body['router']['id'])
        self.assertEqual(show_body['router']['name'], name)
        self.assertEqual(
            show_body['router']['external_gateway_info']['network_id'],
            CONF.network.public_network_id)
        self.assertEqual(show_body['router']['admin_state_up'], False)
        # List routers and verify if created router is there in response
        list_body = self.routers_client.list_routers()
        routers_list = list()
        for router in list_body['routers']:
            routers_list.append(router['id'])
        self.assertIn(create_body['router']['id'], routers_list)
        # Update the name of router and verify if it is updated
        updated_name = 'updated ' + name
        update_body = self.routers_client.update_router(
            create_body['router']['id'], name=updated_name)
        self.assertEqual(update_body['router']['name'], updated_name)
        show_body = self.routers_client.show_router(
            create_body['router']['id'])
        self.assertEqual(show_body['router']['name'], updated_name)

    @decorators.attr(type='smoke')
    def test_add_remove_router_interface_with_subnet_id(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        # Validate that an L2Domain is created on VSD for the subnet creation
        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID',
            filter_value=subnet['id'])
        self.assertEqual(nuage_l2dom[0][u'name'], subnet['id'])

        router = self._create_router(data_utils.rand_name('router-'))
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=router['id'])
        # Add router interface with subnet id
        interface = self.routers_client.add_router_interface(
            router['id'], subnet_id=subnet['id'])
        self.addCleanup(self._remove_router_interface_with_subnet_id,
                        router['id'], subnet['id'])
        self.assertIn('subnet_id', interface.keys())
        self.assertIn('port_id', interface.keys())
        # Verify router id is equal to device id in port details
        show_port_body = self.ports_client.show_port(
            interface['port_id'])
        self.assertEqual(show_port_body['port']['device_id'],
                         router['id'])
        # Validate VSD L2 Domain created above is deleted and added as a
        # L3Domain subnet
        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID',
            filter_value=subnet['id'])
        self.assertEqual(nuage_l2dom, '', "L2 domain is not deleted")
        nuage_domain_subnet = self.nuage_vsd_client.get_domain_subnet(
            parent=n_constants.DOMAIN, parent_id=nuage_domain[0]['ID'])

        self.assertEqual(nuage_domain_subnet[0][u'name'], subnet['id'])

    @decorators.attr(type='smoke')
    def test_add_remove_router_interface_with_port_id(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        # Validate that an L2Domain is created on VSD for the subnet creation
        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID',
            filter_value=subnet['id'])
        self.assertEqual(nuage_l2dom[0][u'name'], subnet['id'])

        router = self._create_router(data_utils.rand_name('router-'))
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=router['id'])
        port_body = self.ports_client.create_port(
            network_id=network['id'])
        # add router interface to port created above
        interface = self.routers_client.add_router_interface(
            router['id'], port_id=port_body['port']['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        router['id'], port_id=port_body['port']['id'])
        self.assertIn('subnet_id', interface.keys())
        self.assertIn('port_id', interface.keys())
        # Verify router id is equal to device id in port details
        show_port_body = self.ports_client.show_port(
            interface['port_id'])
        self.assertEqual(show_port_body['port']['device_id'],
                         router['id'])
        # Validate L2 Domain created above is deleted and added as a L3Domain
        # subnet
        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID', filter_value=subnet['id'])
        self.assertEqual(
            nuage_l2dom, '', "L2 domain is not deleted in VSD")
        nuage_domain_subnet = self.nuage_vsd_client.get_domain_subnet(
            n_constants.DOMAIN, nuage_domain[0]['ID'])
        self.assertEqual(nuage_domain_subnet[0][u'name'], subnet['id'])

    @utils.requires_ext(extension='extraroute', service='network')
    @decorators.attr(type='smoke')
    def test_update_extra_route(self):
        self.network = self.create_network()
        self.name = self.network['name']
        self.subnet = self.create_subnet(self.network)
        # Add router interface with subnet id
        self.router = self._create_router(
            data_utils.rand_name('router-'), True)
        # VSD validation
        # Verify Router is created in VSD
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=self.router['id'])
        self.assertEqual(
            nuage_domain[0][u'description'], self.router['name'])

        self.create_router_interface(self.router['id'], self.subnet['id'])
        self.addCleanup(
            self._delete_extra_routes,
            self.router['id'])
        # Update router extra route, second ip of the range is used as next hop
        cidr = netaddr.IPNetwork(self.subnet['cidr'])
        next_hop = str(cidr[2])
        destination = str(self.subnet['cidr'])
        extra_route = self.client.update_extra_routes(
            self.router['id'],
            next_hop, destination)
        self.assertEqual(1, len(extra_route['router']['routes']))
        self.assertEqual(destination,
                         extra_route['router']['routes'][0]['destination'])
        self.assertEqual(next_hop,
                         extra_route['router']['routes'][0]['nexthop'])
        show_body = self.routers_client.show_router(self.router['id'])
        self.assertEqual(destination,
                         show_body['router']['routes'][0]['destination'])
        self.assertEqual(next_hop,
                         show_body['router']['routes'][0]['nexthop'])

        # VSD validation
        nuage_static_route = self.nuage_vsd_client.get_staticroute(
            parent=n_constants.DOMAIN, parent_id=nuage_domain[0]['ID'])
        self.assertEqual(
            nuage_static_route[0][u'nextHopIp'], next_hop, "wrong nexthop")

        if Release(Topology.nuage_release) >= Release('4.0R5'):
            self.assertEqual(nuage_static_route[0]['externalID'],
                             ExternalId(self.router['id']).at_cms_id())

    @decorators.attr(type='smoke')
    def test_add_router_interface_different_netpart(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        # Validate that L2Domain is created on VSD
        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID', filter_value=subnet['id'])
        self.assertEqual(nuage_l2dom[0]['name'], subnet['id'])

        # Create net-partition
        netpart_name = data_utils.rand_name('netpart')
        netpart = {
            'net_partition': netpart_name
        }
        netpart_body = self.client.create_netpartition(netpart_name)
        self.addCleanup(self.client.delete_netpartition,
                        netpart_body['net_partition']['id'])

        # Create router in new net-partition
        rtr_body = self.routers_client.create_router(
            name=data_utils.rand_name('router'), admin_state_up=True,
            **netpart)
        self.addCleanup(self.routers_client.delete_router,
                        rtr_body['router']['id'])

        # Verify Router is created in correct net-partition
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=rtr_body['router']['id'],
            netpart_name=netpart_name)
        self.assertEqual(rtr_body['router']['name'], nuage_domain[0][
            'description'])
        self.assertEqual(netpart_body['net_partition']['id'],
                         nuage_domain[0]['parentID'])

        # Add router interface with subnet id
        # Since subnet and router are in different net-partitions,
        # VSD should throw an exception
        self.assertRaises(
            exceptions.BadRequest,
            self.routers_client.add_router_interface,
            rtr_body['router']['id'], subnet_id=subnet['id'])

    @decorators.attr(type='smoke')
    def test_router_create_with_template(self):
        # Create a router template in VSD
        template_name = data_utils.rand_name('rtr-template')
        nuage_template = self.nuage_vsd_client.create_l3domaintemplate(
            template_name)
        args = [n_constants.DOMAIN_TEMPLATE, nuage_template[0]['ID'],
                True]
        self.addCleanup(self.nuage_vsd_client.delete_resource, *args)

        # Create zones under the template
        nuage_isolated_zone = self.nuage_vsd_client.create_zonetemplate(
            nuage_template[0]['ID'], 'openstack-isolated')

        nuage_public_zone = self.nuage_vsd_client.create_zonetemplate(
            nuage_template[0]['ID'], 'openstack-shared')

        # Verify template and zones are created correctly
        self.assertEqual(template_name, nuage_template[0]['name'])
        self.assertEqual('openstack-isolated',
                         nuage_isolated_zone[0]['name'])
        self.assertEqual('openstack-shared',
                         nuage_public_zone[0]['name'])

        rtr_template = {
            'nuage_router_template': nuage_template[0]['ID']
        }
        # Create a router using new template
        rtr_body = self.routers_client.create_router(
            name=data_utils.rand_name('router'), admin_state_up=True,
            **rtr_template)
        self.addCleanup(self.routers_client.delete_router,
                        rtr_body['router']['id'])

        # Verify router is created with correct template
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=rtr_body['router']['id'])
        self.assertEqual(rtr_body['router']['name'], nuage_domain[0][
            'description'])
        self.assertEqual(nuage_template[0]['ID'],
                         nuage_domain[0]['templateID'])

    @decorators.attr(type='smoke')
    def test_router_create_with_incorrect_template(self):
        template_id = str(uuid.uuid1())
        rtr_template = {
            'nuage_router_template': template_id
        }
        # Create a router using new template and verify correct exception is
        # raised
        self.assertRaises(exceptions.ServerFault,
                          self.routers_client.create_router,
                          name=data_utils.rand_name('router'),
                          admin_state_up=True,
                          **rtr_template)

    @decorators.attr(type='smoke')
    def test_router_create_with_template_no_zones(self):
        # Create a router template in VSD
        template_name = data_utils.rand_name('rtr-template')
        nuage_template = self.nuage_vsd_client.create_l3domaintemplate(
            template_name)
        args = [n_constants.DOMAIN_TEMPLATE, nuage_template[0]['ID'],
                True]
        self.addCleanup(self.nuage_vsd_client.delete_resource, *args)

        # Verify template and zones are created correctly
        self.assertEqual(template_name, nuage_template[0]['name'])

        rtr_template = {
            'nuage_router_template': nuage_template[0]['ID']
        }

        self.assertRaises(exceptions.ServerFault,
                          self.routers_client.create_router,
                          name=data_utils.rand_name('router'),
                          admin_state_up=True,
                          **rtr_template)

    def test_router_create_with_netpart(self):
        netpart_name = data_utils.rand_name('netpart')
        netpart = {
            'net_partition': netpart_name
        }

        # Create net-partition
        netpart_body = self.client.create_netpartition(netpart_name)
        self.addCleanup(self.client.delete_netpartition,
                        netpart_body['net_partition']['id'])

        # Create router in that net-partition
        rtr_body = self.routers_client.create_router(
            name=data_utils.rand_name('router'), admin_state_up=True,
            **netpart)
        self.addCleanup(self.routers_client.delete_router,
                        rtr_body['router']['id'])

        # Verify Router is created in correct net-partition
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=rtr_body['router']['id'],
            netpart_name=netpart_name)
        self.assertEqual(rtr_body['router']['name'], nuage_domain[0][
            'description'])
        self.assertEqual(netpart_body['net_partition']['id'],
                         nuage_domain[0]['parentID'])

    @decorators.attr(type='smoke')
    def test_router_create_with_rt_rd(self):
        # Create a router with specific rt/rd values
        rtrd = {
            'rt': '64435:' + str(randint(0, 1000)),
            'rd': '64435:' + str(randint(0, 1000)),
        }
        create_body = self.routers_client.create_router(
            name=data_utils.rand_name('router'), admin_state_up=True, **rtrd)
        self.addCleanup(self.routers_client.delete_router,
                        create_body['router']['id'])

        # Verify router is created in VSD with correct rt/rd values
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['name'], nuage_domain[0][
            'description'])
        self.assertEqual(rtrd['rd'], nuage_domain[0]['routeDistinguisher'])
        self.assertEqual(rtrd['rt'], nuage_domain[0]['routeTarget'])

    @decorators.attr(type='smoke')
    def test_router_update_rt_rd(self):
        # Create a router
        create_body = self.routers_client.create_router(
            name=data_utils.rand_name('router'), external_gateway_info=None,
            admin_state_up=True)
        self.addCleanup(self.routers_client.delete_router,
                        create_body['router']['id'])

        # Verify router is created in VSD
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['name'],
                         nuage_domain[0]['description'])

        # Update rt/rd
        rt = '64435:' + str(randint(0, 1000))
        rd = '64435:' + str(randint(0, 1000))
        self.routers_client.update_router(create_body['router']['id'],
                                          rt=rt, rd=rd)

        # Get the domain from VSD and verify that rt/rd are updated
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(rd, nuage_domain[0]['routeDistinguisher'])
        self.assertEqual(rt, nuage_domain[0]['routeTarget'])

    @decorators.attr(type='smoke')
    def test_router_update_no_rt_rd(self):
        # Create a router
        create_body = self.routers_client.create_router(
            name=data_utils.rand_name('router'), external_gateway_info=None,
            admin_state_up=True)
        self.addCleanup(self.routers_client.delete_router,
                        create_body['router']['id'])

        # Verify router is created in VSD
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['name'],
                         nuage_domain[0]['description'])

        update_dict = dict()
        self.routers_client.update_router(
            create_body['router']['id'], **update_dict)

        # Get the domain from VSD and verify that rt/rd is not updated
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['rd'],
                         nuage_domain[0]['routeDistinguisher'])
        self.assertEqual(create_body['router']['rt'],
                         nuage_domain[0]['routeTarget'])

    @decorators.attr(type='smoke')
    def test_router_update_rt(self):
        # Create a router
        create_body = self.routers_client.create_router(
            name=data_utils.rand_name('router'), external_gateway_info=None,
            admin_state_up=True)
        self.addCleanup(self.routers_client.delete_router,
                        create_body['router']['id'])

        # Verify router is created in VSD
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['name'],
                         nuage_domain[0]['description'])

        # Update rt
        rt = '64435:' + str(randint(0, 1000))
        self.routers_client.update_router(create_body['router']['id'], rt=rt)

        # Get the domain from VSD and verify that rt is updated
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(rt, nuage_domain[0]['routeTarget'])

    @decorators.attr(type='smoke')
    def test_router_update_rd(self):
        # Create a router
        create_body = self.routers_client.create_router(
            name=data_utils.rand_name('router'), external_gateway_info=None,
            admin_state_up=True)
        self.addCleanup(self.routers_client.delete_router,
                        create_body['router']['id'])

        # Verify router is created in VSD
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['name'],
                         nuage_domain[0]['description'])

        # Update rd
        rd = '64435:' + str(randint(0, 1000))
        self.routers_client.update_router(create_body['router']['id'], rd=rd)

        # Get the domain from VSD and verify that rd is updated
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(rd, nuage_domain[0]['routeDistinguisher'])

    # TODO(TEAM) Overruling from upstream test class is not good practice
    # This particular below test fails upstream - temp. overrule as for now
    def test_create_router_set_gateway_with_fixed_ip(self):
        self.skipTest('Skipping test as not Nuage supported.')


class RoutersAdminTestNuage(admin_test_routers.RoutersAdminTest):

    @classmethod
    def setup_clients(cls):
        super(RoutersAdminTestNuage, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()

    @utils.requires_ext(extension='ext-gw-mode', service='network')
    @decorators.attr(type='smoke')
    def test_create_router_with_default_snat_value(self):
        (super(RoutersAdminTestNuage, self).
         test_create_router_with_default_snat_value())
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=self.routers[-1]['id'])
        self.assertEqual(nuage_domain[0]['PATEnabled'], NUAGE_PAT_DISABLED)

    @utils.requires_ext(extension='ext-gw-mode', service='network')
    @decorators.attr(type='smoke')
    def test_update_router_set_gateway_with_snat_explicit(self):
        super(RoutersAdminTestNuage,
              self).test_update_router_set_gateway_with_snat_explicit()
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=self.routers[-1]['id'])
        self.assertEqual(nuage_domain[0]['PATEnabled'], NUAGE_PAT_ENABLED)

    @utils.requires_ext(extension='ext-gw-mode', service='network')
    @decorators.attr(type='smoke')
    def test_update_router_set_gateway_without_snat(self):
        super(RoutersAdminTestNuage,
              self).test_update_router_set_gateway_without_snat()
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=self.routers[-1]['id'])
        self.assertEqual(nuage_domain[0]['PATEnabled'], NUAGE_PAT_DISABLED)

    @utils.requires_ext(extension='ext-gw-mode', service='network')
    @decorators.attr(type='smoke')
    def test_update_router_reset_gateway_without_snat(self):
        router = self._create_router(
            data_utils.rand_name('router-'),
            external_network_id=CONF.network.public_network_id)
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=router['id'])
        self.assertEqual(nuage_domain[0]['PATEnabled'], NUAGE_PAT_DISABLED)
        self.admin_routers_client.update_router(
            router['id'],
            external_gateway_info={
                'network_id': CONF.network.public_network_id,
                'enable_snat': False})
        self._verify_router_gateway(
            router['id'],
            {'network_id': CONF.network.public_network_id,
             'enable_snat': False})
        self._verify_gateway_port(router['id'])
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=router['id'])
        self.assertEqual(nuage_domain[0]['PATEnabled'], NUAGE_PAT_DISABLED)

    @utils.requires_ext(extension='ext-gw-mode', service='network')
    @decorators.attr(type='smoke')
    def test_create_router_with_snat_explicit(self):
        name = data_utils.rand_name('snat-router')
        # Create a router enabling snat attributes
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            external_gateway_info = {
                'network_id': CONF.network.public_network_id,
                'enable_snat': enable_snat}
            create_body = self.admin_routers_client.create_router(
                name=name, external_gateway_info=external_gateway_info)
            self.addCleanup(self.admin_routers_client.delete_router,
                            create_body['router']['id'])
            # Verify snat attributes after router creation
            self._verify_router_gateway(create_body['router']['id'],
                                        exp_ext_gw_info=external_gateway_info)
            nuage_domain = self.nuage_vsd_client.get_l3domain(
                filters='externalID',
                filter_value=create_body['router']['id'])
            self.assertEqual(
                nuage_domain[0]['PATEnabled'],
                NUAGE_PAT_ENABLED if enable_snat else NUAGE_PAT_DISABLED)

    @decorators.attr(type='smoke')
    def test_add_router_interface_shared_network(self):
        # Create a shared network
        network = {
            'name': data_utils.rand_name('network'),
            'shared': True
        }
        net_body = self.admin_networks_client.create_network(**network)
        self.addCleanup(self.admin_networks_client.delete_network,
                        net_body['network']['id'])
        subnet = {
            'network_id': net_body['network']['id'],
            'cidr': '21.21.21.0/24',
            'name': data_utils.rand_name('subnet'),
            'ip_version': 4
        }
        subn_body = self.admin_subnets_client.create_subnet(**subnet)
        self.addCleanup(self.admin_subnets_client.delete_subnet,
                        subn_body['subnet']['id'])

        # Add router interface with subnet id
        router = {
            'name': data_utils.rand_name('router'),
            'admin_state_up': True
        }

        rtr_body = self.admin_routers_client.create_router(**router)
        self.addCleanup(self.admin_routers_client.delete_router,
                        rtr_body['router']['id'])

        # Verify Router is created in VSD
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=rtr_body['router']['id'])
        self.assertEqual(nuage_domain[0]['description'],
                         rtr_body['router']['name'])

        self.admin_routers_client.add_router_interface(
            rtr_body['router']['id'],
            subnet_id=subn_body['subnet']['id'])

        # Verify that the subnet is attached to public zone in VSD
        nuage_zones = self.nuage_vsd_client.get_zone(nuage_domain[0]['ID'])
        shared_zone_id = None
        for zone in nuage_zones:
            if '-pub-' in zone['name']:
                shared_zone_id = zone['ID']

        nuage_domain_subn = self.nuage_vsd_client.get_domain_subnet(
            n_constants.ZONE, shared_zone_id,
            filters='externalID', filter_value=subn_body['subnet']['id'])
        self.assertIsNotNone(nuage_domain_subn[0])

        # Delete the router interface
        self.admin_routers_client.remove_router_interface(
            rtr_body['router']['id'],
            subnet_id=subn_body['subnet']['id'])

        # Verify that the subnet is created with everybody permissions
        nuage_l2dom = self.nuage_vsd_client.get_l2domain(
            filters='externalID', filter_value=subn_body['subnet']['id'])
        nuage_perm = self.nuage_vsd_client.get_permissions(
            n_constants.L2_DOMAIN, nuage_l2dom[0]['ID'])
        self.assertIsNotNone(nuage_perm[0])
        self.assertEqual(nuage_perm[0]['permittedEntityName'], u'Everybody')

    @decorators.attr(type='smoke')
    def test_router_create_update_show_delete_with_backhaul_vnid_rt_rd(
            self):
        name = data_utils.rand_name('router-')
        bkhaul_vnid = data_utils.rand_int_id(start=0,
                                             end=n_constants.MAX_VNID)
        rt = data_utils.rand_int_id(start=0, end=n_constants.MAX_RT)
        rd = data_utils.rand_int_id(start=0, end=n_constants.MAX_RD)
        bkhaul_rt = "%s:%s" % (rt, rt)
        bkhaul_rd = "%s:%s" % (rd, rd)
        create_body = self.admin_routers_client.create_router(
            name=name, nuage_backhaul_vnid=str(bkhaul_vnid),
            nuage_backhaul_rt=bkhaul_rt,
            nuage_backhaul_rd=bkhaul_rd,
            tunnel_type="VXLAN")
        self.addCleanup(self.admin_routers_client.delete_router,
                        create_body['router']['id'])
        self.assertEqual(create_body['router']['name'], name)
        self.assertEqual(create_body['router']['nuage_backhaul_vnid'],
                         bkhaul_vnid)
        self.assertEqual(create_body['router']['nuage_backhaul_rt'],
                         bkhaul_rt)
        self.assertEqual(create_body['router']['nuage_backhaul_rd'],
                         bkhaul_rd)
        # VSD validation
        rtr_id = create_body['router']['id']
        l3dom_ext_id = self.nuage_vsd_client.get_vsd_external_id(
            rtr_id)
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=l3dom_ext_id)
        self.assertEqual(nuage_domain[0][u'description'], name)
        self.assertEqual(nuage_domain[0][u'backHaulVNID'], bkhaul_vnid)
        self.assertEqual(nuage_domain[0][u'backHaulRouteTarget'],
                         bkhaul_rt)
        self.assertEqual(nuage_domain[0][u'backHaulRouteDistinguisher'],
                         bkhaul_rd)
        # Show details of the created router
        show_body = self.admin_routers_client.show_router(
            create_body['router']['id'])
        self.assertEqual(show_body['router']['name'], name)
        self.assertEqual(show_body['router']['nuage_backhaul_vnid'],
                         bkhaul_vnid)
        self.assertEqual(show_body['router']['nuage_backhaul_rt'],
                         bkhaul_rt)
        self.assertEqual(show_body['router']['nuage_backhaul_rd'],
                         bkhaul_rd)

        # Update the backhaul rt:rd to new values
        updated_bkhaul_vnid = data_utils.rand_int_id(
            start=0,
            end=n_constants.MAX_VNID)
        updated_rt = data_utils.rand_int_id(start=0,
                                            end=n_constants.MAX_RT)
        updated_rd = data_utils.rand_int_id(start=0,
                                            end=n_constants.MAX_RD)
        updated_bkhaul_rt = "%s:%s" % (updated_rt, updated_rt)
        updated_bkhaul_rd = "%s:%s" % (updated_rd, updated_rd)
        self.admin_routers_client.update_router(
            create_body['router']['id'],
            nuage_backhaul_vnid=str(updated_bkhaul_vnid),
            nuage_backhaul_rt=updated_bkhaul_rt,
            nuage_backhaul_rd=updated_bkhaul_rd)
        show_body = self.admin_routers_client.show_router(
            create_body['router']['id'])
        self.assertEqual(show_body['router']['nuage_backhaul_vnid'],
                         updated_bkhaul_vnid)
        self.assertEqual(show_body['router']['nuage_backhaul_rt'],
                         updated_bkhaul_rt)
        self.assertEqual(show_body['router']['nuage_backhaul_rd'],
                         updated_bkhaul_rd)
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID', filter_value=l3dom_ext_id)
        self.assertEqual(nuage_domain[0][u'backHaulVNID'],
                         updated_bkhaul_vnid)
        self.assertEqual(nuage_domain[0][u'backHaulRouteTarget'],
                         updated_bkhaul_rt)
        self.assertEqual(nuage_domain[0][u'backHaulRouteDistinguisher'],
                         updated_bkhaul_rd)

    @decorators.attr(type='smoke')
    def test_router_backhaul_vnid_rt_rd_negative(self):
        # Incorrect backhaul-vnid value
        self.assertRaises(exceptions.ServerFault,
                          self.admin_routers_client.create_router,
                          name=data_utils.rand_name('router-'),
                          nuage_backhaul_vnid="0xb")
        self.assertRaises(exceptions.ServerFault,
                          self.admin_routers_client.create_router,
                          name=data_utils.rand_name('router-'),
                          nuage_backhaul_rt="-1:1")
        self.assertRaises(exceptions.ServerFault,
                          self.admin_routers_client.create_router,
                          name=data_utils.rand_name('router-'),
                          nuage_backhaul_rd="2:-3")
