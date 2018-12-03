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

from future.utils import listitems

import netaddr
from oslo_log import log as logging
from random import randint
import testtools
import time
import uuid

from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_commons import constants as n_constants
from nuage_commons import data_utils as nuage_data_utils

from nuage_tempest_lib.features import NUAGE_FEATURES
from nuage_tempest_lib.tests.nuage_test import NuageAdminNetworkTest
from nuage_tempest_lib.tests.nuage_test import NuageBaseNetworkTest
from nuage_tempest_lib.topology import Topology
from nuage_tempest_lib.vsdclient.nuage_client import NuageRestClient
from nuage_tempest_lib.vsdclient.nuage_network_client \
    import NuageNetworkClientJSON

from nuage_tempest_plugin.tests.api.upgrade.external_id.external_id \
    import ExternalId

NUAGE_PAT_ENABLED = 'ENABLED'
NUAGE_PAT_DISABLED = 'DISABLED'

LOG = logging.getLogger(__name__)


class NuageRoutersTest(NuageBaseNetworkTest):

    @classmethod
    def skip_checks(cls):
        super(NuageRoutersTest, cls).skip_checks()
        if not utils.is_extension_enabled('router', 'network'):
            msg = "router extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(NuageRoutersTest, cls).setup_clients()
        cls.client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)
        cls.nuage_client = NuageRestClient()

    # copy of RoutersTest - start

    def _create_router(self, name=None, admin_state_up=False,
                       external_network_id=None, enable_snat=None):
        # associate a cleanup with created routers to avoid quota limits
        router = self.create_router(name, admin_state_up,
                                    external_network_id, enable_snat)
        self.addCleanup(self.delete_router, router)
        return router

    def _delete_extra_routes(self, router_id):
        self.routers_client.update_router(router_id, routes=None)

    def _add_router_interface_with_subnet_id(self, router_id, subnet_id):
        interface = self.routers_client.add_router_interface(
            router_id, subnet_id=subnet_id)
        self.addCleanup(self._remove_router_interface_with_subnet_id,
                        router_id, subnet_id)
        self.assertEqual(subnet_id, interface['subnet_id'])
        return interface

    def _remove_router_interface_with_subnet_id(self, router_id, subnet_id):
        body = self.routers_client.remove_router_interface(router_id,
                                                           subnet_id=subnet_id)
        self.assertEqual(subnet_id, body['subnet_id'])

    # copy of RoutersTest - end

    @classmethod
    def delete_router(cls, router):
        # TODO(TEAM: FOLLOW UP ON THIS) - VSD-21337
        for attempt in range(cls.nbr_retries_for_test_robustness):
            try:
                super(NuageRoutersTest, cls).delete_router(router)
                return
            except Exception as e:
                if 'Nuage API: vPort has VMInterface network interfaces ' \
                   'associated with it.' not in str(e):
                    raise
                cls.error('VSD-21337: Domain deletion failed! (%d)',
                          attempt + 1)
                time.sleep(1)

        super(NuageRoutersTest, cls).delete_router(router)

    @decorators.attr(type='smoke')
    def test_create_show_list_update_delete_router(self):
        # Create a router
        name = data_utils.rand_name('router-')
        create_body = self.routers_client.create_router(
            name=name, external_gateway_info={
                "network_id": self.public_network_id},
            admin_state_up=False)
        self.addCleanup(self.routers_client.delete_router,
                        create_body['router']['id'])
        self.assertEqual(create_body['router']['name'], name)
        # VSD validation
        rtr_id = create_body['router']['id']
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=rtr_id)
        self.assertEqual(nuage_domain[0]['description'], name)
        nuage_zones = self.nuage_client.get_zone(
            parent_id=nuage_domain[0]['ID'])
        self.assertEqual(len(nuage_zones), 2, "Zones for the corresponding"
                                              " Domain are not found")
        for zone in nuage_zones:
            self.assertEqual(zone['externalID'],
                             self.nuage_client.get_vsd_external_id(
                                 rtr_id))
            permissions = self.nuage_client.get_permissions(
                parent=n_constants.ZONE,
                parent_id=zone['ID'])
            self.assertEqual(len(permissions), 1)
            self.assertEqual(permissions[0]['externalID'],
                             self.nuage_client.get_vsd_external_id(
                                 create_body['router']['tenant_id']))
            if zone['name'].split('-')[1] == 'pub':
                self.assertEqual(permissions[0]['permittedEntityName'],
                                 "Everybody")
            else:
                self.assertEqual(permissions[0]['permittedEntityName'],
                                 self.routers_client.tenant_id)
                group_resp = self.nuage_client.get_resource(
                    resource=n_constants.GROUP,
                    filters='externalID',
                    filter_value=(self.routers_client.tenant_id +
                                  '@openstack'),
                    netpart_name=self.nuage_client.def_netpartition)
                self.assertIsNot(group_resp, "",
                                 "User Group on VSD for the user who "
                                 "created the Router was not Found")
                self.assertEqual(group_resp[0]['name'],
                                 self.routers_client.tenant_id)
            user_resp = self.nuage_client.get_user(
                filters='externalID',
                filter_value=(self.routers_client.tenant_id +
                              '@openstack'),
                netpart_name=self.nuage_client.def_netpartition)
            self.assertIsNot(user_resp, "",
                             "User on VSD for the user who created the "
                             "Router was not Found")
            self.assertEqual(user_resp[0]['userName'],
                             self.routers_client.tenant_id)
        default_egress_tmpl = self.nuage_client.get_child_resource(
            resource=n_constants.DOMAIN,
            resource_id=nuage_domain[0]['ID'],
            child_resource=n_constants.EGRESS_ACL_TEMPLATE,
            filters='externalID',
            filter_value=self.nuage_client.get_vsd_external_id(
                rtr_id))
        self.assertIsNot(default_egress_tmpl,
                         "",
                         "Could not Find Default EGRESS Template on VSD "
                         "For Router")
        default_ingress_tmpl = self.nuage_client.get_child_resource(
            resource=n_constants.DOMAIN,
            resource_id=nuage_domain[0]['ID'],
            child_resource=n_constants.INGRESS_ACL_TEMPLATE,
            filters='externalID',
            filter_value=self.nuage_client.get_vsd_external_id(
                rtr_id))
        self.assertIsNot(default_ingress_tmpl,
                         "",
                         "Could not Find Default INGRESS Template on VSD"
                         " For Router")
        default_ingress_awd_tmpl = \
            self.nuage_client.get_child_resource(
                resource=n_constants.DOMAIN,
                resource_id=nuage_domain[0]['ID'],
                child_resource=n_constants.INGRESS_ADV_FWD_TEMPLATE,
                filters='externalID',
                filter_value=self.nuage_client.get_vsd_external_id(
                    rtr_id))
        self.assertIsNot(default_ingress_awd_tmpl,
                         "",
                         "Could not Find Default Forwarding INGRESS"
                         " Template on VSD For Router")
        self.assertEqual(
            create_body['router']['external_gateway_info']['network_id'],
            self.public_network_id)
        self.assertEqual(create_body['router']['admin_state_up'], False)
        # Show details of the created router
        show_body = self.routers_client.show_router(
            create_body['router']['id'])
        self.assertEqual(show_body['router']['name'], name)
        self.assertEqual(
            show_body['router']['external_gateway_info']['network_id'],
            self.public_network_id)
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
        nuage_l2dom = self.nuage_client.get_l2domain(
            filters='externalID',
            filter_value=subnet['id'])
        self.assertEqual(nuage_l2dom[0]['name'], subnet['id'])

        router = self._create_router(data_utils.rand_name('router-'))
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=router['id'])
        # Add router interface with subnet id
        interface = self.routers_client.add_router_interface(
            router['id'], subnet_id=subnet['id'])
        self.addCleanup(self._remove_router_interface_with_subnet_id,
                        router['id'], subnet['id'])
        self.assertIn('subnet_id', interface)
        self.assertIn('port_id', interface)
        # Verify router id is equal to device id in port details
        show_port_body = self.ports_client.show_port(
            interface['port_id'])
        self.assertEqual(show_port_body['port']['device_id'],
                         router['id'])
        # Validate VSD L2 Domain created above is deleted and added as a
        # L3Domain subnet
        nuage_l2dom = self.nuage_client.get_l2domain(
            filters='externalID',
            filter_value=subnet['id'])
        self.assertEqual(nuage_l2dom, '', "L2 domain is not deleted")
        nuage_domain_subnet = self.nuage_client.get_domain_subnet(
            parent=n_constants.DOMAIN, parent_id=nuage_domain[0]['ID'])

        self.assertEqual(nuage_domain_subnet[0]['name'], subnet['id'])

    @decorators.attr(type='smoke')
    def test_add_remove_router_interface_with_port_id(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        # Validate that an L2Domain is created on VSD for the subnet creation
        nuage_l2dom = self.nuage_client.get_l2domain(
            filters='externalID',
            filter_value=subnet['id'])
        self.assertEqual(nuage_l2dom[0]['name'], subnet['id'])

        router = self._create_router(data_utils.rand_name('router-'))
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=router['id'])
        port_body = self.ports_client.create_port(
            network_id=network['id'])
        # add router interface to port created above
        interface = self.routers_client.add_router_interface(
            router['id'], port_id=port_body['port']['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        router['id'], port_id=port_body['port']['id'])
        self.assertIn('subnet_id', interface)
        self.assertIn('port_id', interface)
        # Verify router id is equal to device id in port details
        show_port_body = self.ports_client.show_port(
            interface['port_id'])
        self.assertEqual(show_port_body['port']['device_id'],
                         router['id'])
        # Validate L2 Domain created above is deleted and added as a L3Domain
        # subnet
        nuage_l2dom = self.nuage_client.get_l2domain(
            filters='externalID', filter_value=subnet['id'])
        self.assertEqual(
            nuage_l2dom, '', "L2 domain is not deleted in VSD")
        nuage_domain_subnet = self.nuage_client.get_domain_subnet(
            n_constants.DOMAIN, nuage_domain[0]['ID'])
        self.assertEqual(nuage_domain_subnet[0]['name'], subnet['id'])

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
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=self.router['id'])
        self.assertEqual(
            nuage_domain[0]['description'], self.router['name'])

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
        nuage_static_route = self.nuage_client.get_staticroute(
            parent=n_constants.DOMAIN, parent_id=nuage_domain[0]['ID'])
        self.assertEqual(
            nuage_static_route[0]['nextHopIp'], next_hop, "wrong nexthop")
        self.assertEqual(nuage_static_route[0]['externalID'],
                         ExternalId(self.router['id']).at_cms_id())

    @decorators.attr(type='smoke')
    def test_add_router_interface_different_netpart(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        # Validate that L2Domain is created on VSD
        nuage_l2dom = self.nuage_client.get_l2domain(
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
        nuage_domain = self.nuage_client.get_l3domain(
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
        nuage_template = self.nuage_client.create_l3domaintemplate(
            template_name)
        args = [n_constants.DOMAIN_TEMPLATE, nuage_template[0]['ID'], True]
        self.addCleanup(self.nuage_client.delete_resource, *args)

        # Create zones under the template
        nuage_isolated_zone = self.nuage_client.create_zonetemplate(
            nuage_template[0]['ID'], 'openstack-isolated')

        nuage_public_zone = self.nuage_client.create_zonetemplate(
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
        nuage_domain = self.nuage_client.get_l3domain(
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
        nuage_template = self.nuage_client.create_l3domaintemplate(
            template_name)
        args = [n_constants.DOMAIN_TEMPLATE, nuage_template[0]['ID'],
                True]
        self.addCleanup(self.nuage_client.delete_resource, *args)

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
        nuage_domain = self.nuage_client.get_l3domain(
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
        nuage_domain = self.nuage_client.get_l3domain(
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
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['name'],
                         nuage_domain[0]['description'])

        # Update rt/rd
        rt = '64435:' + str(randint(0, 1000))
        rd = '64435:' + str(randint(0, 1000))
        self.routers_client.update_router(create_body['router']['id'],
                                          rt=rt, rd=rd)

        # Get the domain from VSD and verify that rt/rd are updated
        nuage_domain = self.nuage_client.get_l3domain(
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
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['name'],
                         nuage_domain[0]['description'])

        update_dict = dict()
        self.routers_client.update_router(
            create_body['router']['id'], **update_dict)

        # Get the domain from VSD and verify that rt/rd is not updated
        nuage_domain = self.nuage_client.get_l3domain(
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
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['name'],
                         nuage_domain[0]['description'])

        # Update rt
        rt = '64435:' + str(randint(0, 1000))
        self.routers_client.update_router(create_body['router']['id'], rt=rt)

        # Get the domain from VSD and verify that rt is updated
        nuage_domain = self.nuage_client.get_l3domain(
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
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(create_body['router']['name'],
                         nuage_domain[0]['description'])

        # Update rd
        rd = '64435:' + str(randint(0, 1000))
        self.routers_client.update_router(create_body['router']['id'], rd=rd)

        # Get the domain from VSD and verify that rd is updated
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=create_body['router']['id'])
        self.assertEqual(rd, nuage_domain[0]['routeDistinguisher'])


class NuageRoutersAdminTest(NuageAdminNetworkTest):

    @classmethod
    def setup_clients(cls):
        super(NuageRoutersAdminTest, cls).setup_clients()
        cls.nuage_client = NuageRestClient()

    @classmethod
    def delete_router(cls, router):
        if cls.is_dhcp_agent_present():
            for attempt in range(cls.nbr_retries_for_test_robustness):
                try:
                    super(NuageRoutersAdminTest, cls).delete_router(router)
                    return
                except Exception as e:
                    if 'Nuage API: vPort has VMInterface network interfaces ' \
                       'associated with it.' not in str(e):
                        raise
                    cls.error('VSD-21337: Domain deletion failed! (%d)',
                              attempt + 1)
                    time.sleep(1)

            cls.error('=== ROBUSTNESS AIDS DID NOT WORK!!! GIVING UP ===')

        super(NuageRoutersAdminTest, cls).delete_router(router)

    def delete_router_from_client(self, client, router_id):
        for attempt in range(self.nbr_retries_for_test_robustness):
            try:
                client.delete_router(router_id)
                return
            except Exception as e:
                if 'Nuage API: vPort has VMInterface network interfaces ' \
                   'associated with it.' not in str(e):
                    raise
                LOG.error('VSD-21337: Domain deletion failed! (%d)',
                          attempt + 1)
                time.sleep(1)

        client.delete_router(router_id)

    def _create_router(self, name=None, admin_state_up=False,
                       external_network_id=None, enable_snat=None):
        # associate a cleanup with created routers to avoid quota limits
        router = self.create_router(name, admin_state_up,
                                    external_network_id, enable_snat)
        self.addCleanup(self.delete_router, router)
        return router

    # Start of copy from upstream
    def _verify_router_gateway(self, router_id, exp_ext_gw_info=None):
        show_body = self.admin_routers_client.show_router(router_id)
        actual_ext_gw_info = show_body['router']['external_gateway_info']
        if exp_ext_gw_info is None:
            self.assertIsNone(actual_ext_gw_info)
            return
        # Verify only keys passed in exp_ext_gw_info
        for k, v in listitems(exp_ext_gw_info):
            self.assertEqual(v, actual_ext_gw_info[k])

    def _verify_gateway_port(self, router_id):
        list_body = self.admin_ports_client.list_ports(
            network_id=self.public_network_id,
            device_id=router_id)
        self.assertEqual(len(list_body['ports']), 1)
        gw_port = list_body['ports'][0]
        fixed_ips = gw_port['fixed_ips']
        self.assertNotEmpty(fixed_ips)
        # Assert that all of the IPs from the router gateway port
        # are allocated from a valid public subnet.
        public_net_body = self.admin_networks_client.show_network(
            self.public_network_id)
        public_subnet_ids = public_net_body['network']['subnets']
        for fixed_ip in fixed_ips:
            subnet_id = fixed_ip['subnet_id']
            self.assertIn(subnet_id, public_subnet_ids)
    # End of copy from upstream

    @utils.requires_ext(extension='ext-gw-mode', service='network')
    @testtools.skipIf(Topology.new_route_to_underlay_model_enabled(),
                      'Skipping test as new route-to-UL model is enabled')
    @testtools.skipIf(NUAGE_FEATURES.route_to_underlay,
                      'Skipping test as relying on OS-911 bug')
    @decorators.attr(type='smoke')
    def test_create_router_with_default_snat_value(self):
        # Start of copy from upstream
        # Create a router with default snat rule
        router = self._create_router(
            external_network_id=self.public_network_id)
        self._verify_router_gateway(
            router['id'], {'network_id': self.public_network_id,
                           'enable_snat': True})
        # End of copy from upstream

        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=router[-1]['id'])
        self.assertEqual(nuage_domain[0]['PATEnabled'], NUAGE_PAT_DISABLED)

    @utils.requires_ext(extension='ext-gw-mode', service='network')
    @testtools.skipIf(Topology.new_route_to_underlay_model_enabled(),
                      'Skipping test as new route-to-UL model is enabled')
    @decorators.attr(type='smoke')
    def test_update_router_set_gateway_with_snat_explicit(self):
        # Start of copy from upstream
        router = self._create_router()
        self.admin_routers_client.update_router(
            router['id'],
            external_gateway_info={
                'network_id': self.public_network_id,
                'enable_snat': True})
        self._verify_router_gateway(
            router['id'],
            {'network_id': self.public_network_id,
             'enable_snat': True})
        self._verify_gateway_port(router['id'])
        # End of copy from upstream

        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=router['id'])
        self.assertEqual(nuage_domain[0]['PATEnabled'], NUAGE_PAT_ENABLED)

    @utils.requires_ext(extension='ext-gw-mode', service='network')
    @decorators.attr(type='smoke')
    def test_update_router_set_gateway_without_snat(self):
        # Start of copy from upstream
        router = self._create_router()
        self.admin_routers_client.update_router(
            router['id'],
            external_gateway_info={
                'network_id': self.public_network_id,
                'enable_snat': False})
        self._verify_router_gateway(
            router['id'],
            {'network_id': self.public_network_id,
             'enable_snat': False})
        self._verify_gateway_port(router['id'])
        # End of copy from upstream

        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=router['id'])
        self.assertEqual(nuage_domain[0]['PATEnabled'], NUAGE_PAT_DISABLED)

    @utils.requires_ext(extension='ext-gw-mode', service='network')
    @decorators.attr(type='smoke')
    def test_update_router_reset_gateway_without_snat(self):
        router = self._create_router(
            data_utils.rand_name('router-'),
            external_network_id=self.public_network_id)
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=router['id'])
        self.assertEqual(nuage_domain[0]['PATEnabled'], NUAGE_PAT_DISABLED)
        self.admin_routers_client.update_router(
            router['id'],
            external_gateway_info={
                'network_id': self.public_network_id,
                'enable_snat': False})
        self._verify_router_gateway(
            router['id'],
            {'network_id': self.public_network_id,
             'enable_snat': False})
        self._verify_gateway_port(router['id'])
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=router['id'])
        self.assertEqual(nuage_domain[0]['PATEnabled'], NUAGE_PAT_DISABLED)

    @utils.requires_ext(extension='ext-gw-mode', service='network')
    @decorators.attr(type='smoke')
    def test_create_router_with_snat_explicit(self):
        name = data_utils.rand_name('snat-router')
        # Create a router enabling snat attributes
        if Topology.new_route_to_underlay_model_enabled():
            enable_snat_states = [False]
        else:
            enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            external_gateway_info = {
                'network_id': self.public_network_id,
                'enable_snat': enable_snat}
            create_body = self.admin_routers_client.create_router(
                name=name, external_gateway_info=external_gateway_info)
            self.addCleanup(self.admin_routers_client.delete_router,
                            create_body['router']['id'])
            # Verify snat attributes after router creation
            self._verify_router_gateway(create_body['router']['id'],
                                        exp_ext_gw_info=external_gateway_info)
            nuage_domain = self.nuage_client.get_l3domain(
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
        cidr = nuage_data_utils.gimme_a_cidr_address()
        subnet = {
            'network_id': net_body['network']['id'],
            'cidr': cidr,
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

        # i know this is dirty ...... better idea's?
        if self.is_dhcp_agent_present():
            self.addCleanup(self.delete_router_from_client,
                            self.admin_routers_client,
                            rtr_body['router']['id'])
        else:
            self.addCleanup(self.admin_routers_client.delete_router,
                            rtr_body['router']['id'])

        # Verify Router is created in VSD
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=rtr_body['router']['id'])
        self.assertEqual(nuage_domain[0]['description'],
                         rtr_body['router']['name'])

        self.admin_routers_client.add_router_interface(
            rtr_body['router']['id'],
            subnet_id=subn_body['subnet']['id'])

        # Verify that the subnet is attached to public zone in VSD
        nuage_zones = self.nuage_client.get_zone(nuage_domain[0]['ID'])
        shared_zone_id = None
        for zone in nuage_zones:
            if '-pub-' in zone['name']:
                shared_zone_id = zone['ID']

        nuage_domain_subn = self.nuage_client.get_domain_subnet(
            n_constants.ZONE, shared_zone_id,
            filters='externalID', filter_value=subn_body['subnet']['id'])
        self.assertIsNotNone(nuage_domain_subn[0])

        # Delete the router interface
        self.admin_routers_client.remove_router_interface(
            rtr_body['router']['id'],
            subnet_id=subn_body['subnet']['id'])

        # Verify that the subnet is created with everybody permissions
        nuage_l2dom = self.nuage_client.get_l2domain(
            filters='externalID', filter_value=subn_body['subnet']['id'])
        nuage_perm = self.nuage_client.get_permissions(
            n_constants.L2_DOMAIN, nuage_l2dom[0]['ID'])
        self.assertIsNotNone(nuage_perm[0])
        self.assertEqual(nuage_perm[0]['permittedEntityName'], 'Everybody')

    # @decorators.attr(type='smoke')
    def test_add_router_interface_to_external_subnet(self):
        network = {
            'name': data_utils.rand_name('external-network'),
            'router:external': True
        }
        net_body = self.admin_networks_client.create_network(**network)
        self.addCleanup(self.admin_networks_client.delete_network,
                        net_body['network']['id'])
        cidr = nuage_data_utils.gimme_a_cidr_address()
        subnet = {
            'network_id': net_body['network']['id'],
            'cidr': cidr,
            'name': data_utils.rand_name('subnet'),
            'ip_version': 4
        }
        subn_body = self.admin_subnets_client.create_subnet(**subnet)
        self.addCleanup(self.admin_subnets_client.delete_subnet,
                        subn_body['subnet']['id'])

        router = self._create_router(admin_state_up=True)

        # Add router interface with external subnet id
        msg = 'Subnet in external network cannot be an interface of a router'
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.admin_routers_client.add_router_interface,
                               router['id'],
                               subnet_id=subn_body['subnet']['id'])

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
        l3dom_ext_id = self.nuage_client.get_vsd_external_id(
            rtr_id)
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=l3dom_ext_id)
        self.assertEqual(nuage_domain[0]['description'], name)
        self.assertEqual(nuage_domain[0]['backHaulVNID'], bkhaul_vnid)
        self.assertEqual(nuage_domain[0]['backHaulRouteTarget'],
                         bkhaul_rt)
        self.assertEqual(nuage_domain[0]['backHaulRouteDistinguisher'],
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
        nuage_domain = self.nuage_client.get_l3domain(
            filters='externalID', filter_value=l3dom_ext_id)
        self.assertEqual(nuage_domain[0]['backHaulVNID'],
                         updated_bkhaul_vnid)
        self.assertEqual(nuage_domain[0]['backHaulRouteTarget'],
                         updated_bkhaul_rt)
        self.assertEqual(nuage_domain[0]['backHaulRouteDistinguisher'],
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


class NuageRoutersV6Test(NuageRoutersTest):

    _ip_version = 6

    def _verify_router_interface(self, router_id, subnet_id, port_id):
        show_port_body = self.ports_client.show_port(port_id)
        interface_port = show_port_body['port']
        self.assertEqual(router_id, interface_port['device_id'])
        self.assertEqual(subnet_id,
                         interface_port['fixed_ips'][0]['subnet_id'])

    @classmethod
    def create_subnet(cls, network, gateway='', cidr=None, mask_bits=None,
                      ip_version=None, client=None, **kwargs):

        if "enable_dhcp" not in kwargs:
            # NUAGE non-compliance: enforce enable_dhcp = False as
            # the default option
            return super(NuageRoutersV6Test, cls).create_subnet(
                network, gateway, cidr, mask_bits,
                ip_version, client, enable_dhcp=False, **kwargs)
        else:
            return super(NuageRoutersV6Test, cls).create_subnet(
                network, gateway, cidr, mask_bits,
                ip_version, client, **kwargs)

    @decorators.attr(type='smoke')
    # OPENSTACK-1886: fails to remove router with only IPv6 subnet interface
    def test_add_remove_router_interface_with_subnet_id(self):
        network = self.create_network()

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet4 = self.create_subnet(network, ip_version=4, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet4['id'])

        subnet = self.create_subnet(network)
        router = self._create_router()

        # Add router interface with subnet id
        interface = self.routers_client.add_router_interface(
            router['id'], subnet_id=subnet['id'])
        self.addCleanup(self._remove_router_interface_with_subnet_id,
                        router['id'], subnet['id'])
        self.assertIn('subnet_id', interface)
        self.assertIn('port_id', interface)
        # Verify router id is equal to device id in port details
        show_port_body = self.ports_client.show_port(
            interface['port_id'])
        self.assertEqual(show_port_body['port']['device_id'],
                         router['id'])

    @decorators.attr(type='smoke')
    def test_add_remove_router_interface_with_port_id(self):
        network = self.create_network()

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet4 = self.create_subnet(network, ip_version=4, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet4['id'])

        self.create_subnet(network)
        router = self._create_router()
        port_body = self.ports_client.create_port(
            network_id=network['id'])
        # add router interface to port created above
        interface = self.routers_client.add_router_interface(
            router['id'],
            port_id=port_body['port']['id'])
        self.addCleanup(self.routers_client.remove_router_interface,
                        router['id'], port_id=port_body['port']['id'])
        self.assertIn('subnet_id', interface)
        self.assertIn('port_id', interface)
        # Verify router id is equal to device id in port details
        show_port_body = self.ports_client.show_port(
            interface['port_id'])
        self.assertEqual(show_port_body['port']['device_id'],
                         router['id'])

    @utils.requires_ext(extension='extraroute', service='network')
    # OPENSTACK-1887
    def test_update_delete_extra_route(self):
        # Create different cidr for each subnet to avoid cidr duplicate
        # The cidr starts from project_cidr
        next_cidr = netaddr.IPNetwork(self.cidr)
        # Prepare to build several routes
        test_routes = []
        routes_num = 4
        # Create a router
        router = self._create_router(admin_state_up=True)
        self.addCleanup(
            self._delete_extra_routes,
            router['id'])
        # Update router extra route, second ip of the range is
        # used as next hop
        for i in range(routes_num):
            network = self.create_network()
            subnet = self.create_subnet(network, cidr=next_cidr)
            next_cidr = next_cidr.next()

            # Add router interface with subnet id
            self.create_router_interface(router['id'], subnet['id'])

            cidr = netaddr.IPNetwork(subnet['cidr'])
            next_hop = str(cidr[2])
            destination = str(subnet['cidr'])
            test_routes.append(
                {'nexthop': next_hop, 'destination': destination}
            )

        test_routes.sort(key=lambda x: x['destination'])
        extra_route = self.routers_client.update_router(
            router['id'], routes=test_routes)
        show_body = self.routers_client.show_router(router['id'])
        # Assert the number of routes
        self.assertEqual(routes_num, len(extra_route['router']['routes']))
        self.assertEqual(routes_num, len(show_body['router']['routes']))

        routes = extra_route['router']['routes']
        routes.sort(key=lambda x: x['destination'])
        # Assert the nexthops & destination
        for i in range(routes_num):
            self.assertEqual(test_routes[i]['destination'],
                             routes[i]['destination'])
            self.assertEqual(test_routes[i]['nexthop'], routes[i]['nexthop'])

        routes = show_body['router']['routes']
        routes.sort(key=lambda x: x['destination'])
        for i in range(routes_num):
            self.assertEqual(test_routes[i]['destination'],
                             routes[i]['destination'])
            self.assertEqual(test_routes[i]['nexthop'], routes[i]['nexthop'])

        self._delete_extra_routes(router['id'])
        show_body_after_deletion = self.routers_client.show_router(
            router['id'])
        self.assertEmpty(show_body_after_deletion['router']['routes'])

    def test_add_router_interface_different_netpart(self):
        self.skipTest('Test skipped for v6')

    @decorators.attr(type='smoke')
    # OPENSTACK-1886: fails to remove router with only IPv6 subnet interface
    def test_add_multiple_router_interfaces(self):
        network01 = self.create_network(
            network_name=data_utils.rand_name('router-network01-'))

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet01_ipv4 = self.create_subnet(
            network01, ip_version=4, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet01_ipv4['id'])

        network02 = self.create_network(
            network_name=data_utils.rand_name('router-network02-'))

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet02_ipv4_cidr = netaddr.IPNetwork(subnet01_ipv4['cidr']).next()
        subnet02_ipv4 = self.create_subnet(
            network02, ip_version=4, cidr=subnet02_ipv4_cidr, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet02_ipv4['id'])

        subnet01 = self.create_subnet(network01)
        sub02_cidr = netaddr.IPNetwork(self.cidr).next()
        subnet02 = self.create_subnet(network02, cidr=sub02_cidr)
        router = self._create_router()
        interface01 = self._add_router_interface_with_subnet_id(router['id'],
                                                                subnet01['id'])
        self._verify_router_interface(router['id'], subnet01['id'],
                                      interface01['port_id'])
        interface02 = self._add_router_interface_with_subnet_id(router['id'],
                                                                subnet02['id'])
        self._verify_router_interface(router['id'], subnet02['id'],
                                      interface02['port_id'])

    # OPENSTACK-1886: fails to remove router with only IPv6 subnet interface
    def test_router_interface_port_update_with_fixed_ip(self):
        network = self.create_network()

        # NUAGE non-compliance: Must have IPv4 subnet
        subnet_ipv4 = self.create_subnet(
            network, ip_version=4, enable_dhcp=True)
        self.addCleanup(self.subnets_client.delete_subnet, subnet_ipv4['id'])

        subnet = self.create_subnet(network)
        router = self._create_router()
        fixed_ip = [{'subnet_id': subnet['id']}]
        interface = self._add_router_interface_with_subnet_id(router['id'],
                                                              subnet['id'])
        self.assertIn('port_id', interface)
        self.assertIn('subnet_id', interface)
        port = self.ports_client.show_port(interface['port_id'])
        self.assertEqual(port['port']['id'], interface['port_id'])
        router_port = self.ports_client.update_port(port['port']['id'],
                                                    fixed_ips=fixed_ip)
        self.assertEqual(subnet['id'],
                         router_port['port']['fixed_ips'][0]['subnet_id'])
