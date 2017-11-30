# Copyright 2013 OpenStack Foundation
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
import re

from tempest.api.network import base
from tempest.common import utils
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.nuage_tempest_test_loader import Release
from nuage_tempest_plugin.lib import service_mgmt
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.services import nuage_client

CONF = config.CONF


class NuagePatUnderlayBase(base.BaseAdminNetworkTest):
    service_manager = None
    _interface = 'json'

    LOG = logging.getLogger(__name__)
    PAT_NEEDS_EXT_NETWORK = "Invalid input for external_gateway_info. " \
                            "Reason: Validation of dictionary's keys failed."
    PAT_NOTAVAILABLE_EXT_GW_INFO = "nuage_pat config is set to " \
                                   "'not_available'." \
                                   " Can't set external_gateway_info"

    @classmethod
    def setup_clients(cls):
        super(NuagePatUnderlayBase, cls).setup_clients()
        cls.nuage_vsd_client = nuage_client.NuageRestClient()
        cls.service_manager = service_mgmt.ServiceManager()

        if not cls.service_manager.is_service_running(
                constants.NEUTRON_SERVICE):
            cls.service_manager.start_service(constants.NEUTRON_SERVICE)

    @classmethod
    def skip_checks(cls):
        super(NuagePatUnderlayBase, cls).skip_checks()
        if not utils.is_extension_enabled('router', 'network'):
            msg = "router extension not enabled."
            raise cls.skipException(msg)

        if not CONF.service_available.neutron:
            msg = "Skipping all Neutron cli tests because it is not available"
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(NuagePatUnderlayBase, cls).resource_setup()

        cls.ext_net_id = CONF.network.public_network_id
        # Fetch current nuage_pat value of of the plugin.ini file
        nuage_pat_ini = cls.read_nuage_pat_value_ini()
        if nuage_pat_ini == '':
            nuage_pat_ini = None
        cls.nuage_pat_ini = nuage_pat_ini

    @classmethod
    def needs_ini_nuage_pat(cls, pat_value):
        if Topology.is_devstack():
            raise cls.skipException('Skipping tests that restart neutron ...')

        # check and set (if different) the nuage_pat setting in the .ini file
        cls.service_manager.must_have_configuration_attribute(
            CONF.nuage_sut.nuage_plugin_configuration,
            constants.NUAGE_PAT_GROUP, constants.NUAGE_PAT, pat_value)
        # Store value
        cls.nuage_pat_ini = pat_value

    @classmethod
    def read_nuage_pat_value_ini(cls):
        # TODO(Kris) FIXME.....................................................
        if Topology.is_devstack():
            return constants.NUAGE_PAT_DEFAULTDISABLED
        # TODO(Kris) FIXME.....................................................

        pat_from_ini = cls.service_manager.get_configuration_attribute(
            CONF.nuage_sut.nuage_plugin_configuration,
            constants.NUAGE_PAT_GROUP, constants.NUAGE_PAT
        )
        return pat_from_ini

    # TODO(Kris) this shd not be duplicated - class inheritance to be fixed
    def assertCommandFailed(self, message, fun, *args, **kwds):
        if Topology.is_devstack():
            self.assertRaisesRegex(exceptions.CommandFailed, message,
                                   fun, *args, **kwds)
        else:
            self.assertRaisesRegex(exceptions.SSHExecCommandFailed, message,
                                   fun, *args, **kwds)

    # Taken from test_external_network_extensions.py,trying to avoid issues
    # with the cli client
    def _create_ext_network(self):
        post_body = {'name': data_utils.rand_name('ext-network'),
                     'router:external': True}
        body = self.admin_networks_client.create_network(**post_body)
        network = body['network']
        self.addCleanup(
            self.admin_networks_client.delete_network, network['id'])
        return network

    def _verify_create_router_without_ext_gw(self):
        """_verify_create_router_without_ext_gw

           Create router without external gateway,
           nuage_pat = self.nuage_pat_ini

           No external_gateway_info section present in the response
           VSD patEnabled flag must be DISABLED
           """
        name = data_utils.rand_name('router-without-ext-gw-without-snat-' +
                                    str(self.nuage_pat_ini))
        create_body = self.admin_routers_client.create_router(name=name)
        self.addCleanup(self.admin_routers_client.delete_router,
                        create_body['router']['id'])
        # Verify snat attributes after router creation
        self._verify_router_gateway(create_body['router']['id'])
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID',
            filter_value=self.nuage_vsd_client.get_vsd_external_id(
                create_body['router']['id']))
        self.assertEqual(
            nuage_domain[0]['PATEnabled'],
            constants.NUAGE_PAT_VSD_DISABLED)

    def _verify_create_router_with_ext_gw_without_snat(self):
        """_verify_create_router_with_ext_gw_without_snat

        Create router with external gateway, without specifying enable_snat

        Response must include enable_snat:
            True when default_pat = default_enabled
            False when default_pat = default_disable
            False when default_pat = not_available
            True when not specified -> see OPENSTACK-981)
        VSD patEnabled flag must be ENABLED/DISABLED accordingly
        """
        name = data_utils.rand_name('router-with-ext-gw-without-snat-') + \
            str(self.nuage_pat_ini)
        if self.nuage_pat_ini == constants.NUAGE_PAT_DEFAULTENABLED:
            pat_value = True
            expected_vsd_pat = constants.NUAGE_PAT_VSD_ENABLED
        else:
            # OPENSTACK-981: mismatch between OS and VSD; OK for PLM in dev ?
            # This is an Schwarzenegger solution: I'll be back
            pat_value = True
            expected_vsd_pat = constants.NUAGE_PAT_VSD_DISABLED
        ext_network = self._create_ext_network()
        external_gateway_info = {
            'network_id': ext_network['id']}
        # Create the router
        create_body = self.admin_routers_client.create_router(
            name=name, external_gateway_info=external_gateway_info)
        self.addCleanup(self.admin_routers_client.delete_router,
                        create_body['router']['id'])
        # enable_snat should be set to pat_value
        external_gateway_info = {
            'network_id': ext_network['id'],
            'enable_snat': pat_value}
        self._verify_router_gateway(create_body['router']['id'],
                                    exp_ext_gw_info=external_gateway_info)
        # Do a show of this router, and enable_snat must also be false
        show_body = self.admin_routers_client.show_router(
            create_body['router']['id'])
        self.assertEqual(
            show_body['router']['external_gateway_info']['enable_snat'],
            pat_value)
        # VSD patEnabled flag should be = ENABLED (True) / DISABLED (False)
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID',
            filter_value=self.nuage_vsd_client.get_vsd_external_id(
                create_body['router']['id']))
        self.assertEqual(
            nuage_domain[0]['PATEnabled'],
            expected_vsd_pat)

    def _verify_create_router_without_ext_gw_with_snat_neg(self):
        """_verify_create_router_without_ext_gw_with_snat_neg

        Create router without external gateway, but specify enable_snat
        (True/False)

        Must fail with 'BadRequest', as enable_snat is only for external
        gateway routers
        """
        name = data_utils.rand_name('router-without-ext-gw-with-snat-' +
                                    str(self.nuage_pat_ini))
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            external_gateway_info = {
                'enable_snat': enable_snat}
            # Create the router: must fail
            kwargs = {
                'name': name,
                'external_gateway_info': external_gateway_info
            }
            self.assertRaises(exceptions.BadRequest,
                              self.admin_routers_client.create_router,
                              **kwargs)

    def _verify_create_router_with_ext_gw_with_snat(self):
        """_verify_create_router_with_ext_gw_with_snat

        Create router with external gateway and specifying enable_snat
        explicitly

        Response must include the same enable_snat value as in the request
        VSD patEnabled flag must be Dis/Enabled according enable_snat value
        This test must succeed for nuage_pat = DefaultDisabled and
        DefaultEnabled
        """
        name = data_utils.rand_name('router-with-ext-gw-with-snat-' +
                                    str(self.nuage_pat_ini))
        ext_network = self._create_ext_network()
        # Create a router enabling snat attributes
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            external_gateway_info = {
                'network_id': ext_network['id'],
                'enable_snat': enable_snat}
            create_body = self.admin_routers_client.create_router(
                name=name, external_gateway_info=external_gateway_info)
            self.addCleanup(self.admin_routers_client.delete_router,
                            create_body['router']['id'])
            # Verify snat attributes after router creation
            self._verify_router_gateway(create_body['router']['id'],
                                        exp_ext_gw_info=external_gateway_info)
            # Showing this router also return the proper value of snat
            show_body = self.admin_routers_client.show_router(
                create_body['router']['id'])
            self.assertEqual(
                show_body['router']['external_gateway_info']['enable_snat'],
                enable_snat)
            # Check patEnabled flag on VSD: should be accordingly
            nuage_domain = self.nuage_vsd_client.get_l3domain(
                filters='externalID',
                filter_value=self.nuage_vsd_client.get_vsd_external_id(
                    create_body['router']['id']))
            self.assertEqual(
                nuage_domain[0]['PATEnabled'],
                constants.NUAGE_PAT_VSD_ENABLED if enable_snat else
                constants.NUAGE_PAT_VSD_DISABLED)

    def _verify_update_router_with_gw_with_snat(self):
        """_verify_update_router_with_gateway_with_snat

        Update router with external gateway: change enable_snat value

        Response must include the new enable_snat value
        VSD patEnabled flag changed accordingly
        """
        name = data_utils.rand_name('update-router-with-ext-gw-with-snat-' +
                                    str(self.nuage_pat_ini))
        ext_network = self._create_ext_network()
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            external_gateway_info = {
                'network_id': ext_network['id'],
                'enable_snat': enable_snat}
            # Create router
            create_body = self.admin_client.create_router(
                name, external_gateway_info=external_gateway_info)
            self.addCleanup(self.admin_client.delete_router,
                            create_body['router']['id'])
            # Update this router with the opposite value of enable_snat
            updated_ext_gw_info = {
                'network_id': ext_network['id'],
                'enable_snat': False if enable_snat else True}
            self.admin_client.update_router_with_snat_gw_info(
                create_body['router']['id'],
                external_gateway_info=updated_ext_gw_info)
            self._verify_router_gateway(
                create_body['router']['id'],
                {'network_id': ext_network['id'],
                 'enable_snat': False if enable_snat else True})
            # check whether the VSD flag is update
            nuage_domain = self.nuage_vsd_client.get_l3domain(
                filters='externalID',
                filter_value=self.nuage_vsd_client.get_vsd_external_id(
                    create_body['router']['id']))
            self.assertEqual(
                nuage_domain[0]['PATEnabled'],
                constants.NUAGE_PAT_VSD_DISABLED if enable_snat else
                constants.NUAGE_PAT_VSD_ENABLED)

    def _verify_update_router_with_ext_gw_with_snat(self):
        """_verify_update_router_with_ext_gw_with_snat

        Update router with external gateway: change enable_snat value

        Response must include the new enable_snat value
        VSD patEnabled flag changed accordingly
        """
        name = data_utils.rand_name('update-router-with-ext-gw-with-snat-' +
                                    str(self.nuage_pat_ini))
        ext_network = self._create_ext_network()
        # Create a router enabling snat attributes
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            external_gateway_info = {
                'network_id': ext_network['id'],
                'enable_snat': enable_snat}
            create_body = self.admin_routers_client.create_router(
                name=name, external_gateway_info=external_gateway_info)
            self.addCleanup(self.admin_routers_client.delete_router,
                            create_body['router']['id'])
            # Verify snat attributes after router creation
            self._verify_router_gateway(create_body['router']['id'],
                                        exp_ext_gw_info=external_gateway_info)
            # Showing this router also return the proper value of snat
            show_body = self.admin_routers_client.show_router(
                create_body['router']['id'])
            self.assertEqual(
                show_body['router']['external_gateway_info']['enable_snat'],
                enable_snat)
            # Check patEnabled flag on VSD: should be accordingly
            nuage_domain = self.nuage_vsd_client.get_l3domain(
                filters='externalID',
                filter_value=self.nuage_vsd_client.get_vsd_external_id(
                    create_body['router']['id']))
            self.assertEqual(
                nuage_domain[0]['PATEnabled'],
                constants.NUAGE_PAT_VSD_ENABLED if enable_snat else
                constants.NUAGE_PAT_VSD_DISABLED)
            # Now update hte enable_snat value
            updated_ext_gw_info = {
                'network_id': ext_network['id'],
                'enable_snat': False if enable_snat else True}
            updated_body = self.admin_routers_client.update_router(
                create_body['router']['id'],
                external_gateway_info=updated_ext_gw_info)
            self._verify_router_gateway(
                updated_body['router']['id'],
                exp_ext_gw_info=updated_ext_gw_info)
            nuage_domain = self.nuage_vsd_client.get_l3domain(
                filters='externalID',
                filter_value=self.nuage_vsd_client.get_vsd_external_id(
                    create_body['router']['id']))
            self.assertEqual(
                nuage_domain[0]['PATEnabled'],
                constants.NUAGE_PAT_VSD_DISABLED if enable_snat else
                constants.NUAGE_PAT_VSD_ENABLED)

    def _verify_show_router_without_ext_gw(self):
        """_verify_show_router_without_ext_gw

        Show router without external gateway

        Response may not include 'external_gateway_info' section
        """
        name = data_utils.rand_name('show-router-without-ext-gw-' +
                                    str(self.nuage_pat_ini))
        # Create the router
        create_body = self.admin_routers_client.create_router(name=name)
        self.addCleanup(self.admin_routers_client.delete_router,
                        create_body['router']['id'])
        # Response should include the given value, if not, the show
        # probably will result in a wrong value as well
        self._verify_router_gateway(create_body['router']['id'])
        # Do a show of this router
        show_body = self.admin_routers_client.show_router(
            create_body['router']['id'])
        self.assertIsNone(show_body['router']['external_gateway_info'])

    def _verify_show_router_with_ext_gw_with_snat(self):
        """_verify_show_router_with_ext_gw_with_snat

        Show router with external gateway and enable_snat

        Response must include enable_snat value as used during creation
        """
        name = data_utils.rand_name('show-router-with-ext-gw-with-snat-' +
                                    str(self.nuage_pat_ini))
        ext_network = self._create_ext_network()
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            external_gateway_info = {
                'network_id': ext_network['id'],
                'enable_snat': enable_snat}
            # Create the router
            create_body = self.admin_routers_client.create_router(
                name=name, external_gateway_info=external_gateway_info)
            self.addCleanup(self.admin_routers_client.delete_router,
                            create_body['router']['id'])
            # Response should include the given value, if not, the show
            # probably will result in a wrong value as well
            self._verify_router_gateway(create_body['router']['id'],
                                        exp_ext_gw_info=external_gateway_info)
            # Do a show of this router
            show_body = self.admin_routers_client.show_router(
                create_body['router']['id'])
            self.assertEqual(
                show_body['router']['external_gateway_info']['enable_snat'],
                enable_snat)

    def _verify_list_router_with_gw_with_snat(self):
        """_verify_list_router_with_gateway_with_snat

        List routers with external gateway and enable_snat

        Depending on the nuage_pat setting in the nuage_plugin.ini file
        the value of enable_snat when not passed may differ:
         False when DefaultDisabled
         True  when DefaultEnabled
        """
        # createdRouterList = list()
        my_router_list = ['router-true', 'router-false',
                          'router-false', 'router-true']
        ext_network = self._create_ext_network()
        for create_router in my_router_list:
            name = data_utils.rand_name(create_router)
            # set enable_snat=true/false according the true/false part
            # in the router-name
            if re.search('true', create_router):
                enable_snat = True
            elif re.search('false', create_router):
                enable_snat = False
            else:
                # use this to check default_disabled/default_enabled behavior
                enable_snat = None
            if enable_snat is None:
                external_gateway_info = {
                    'network_id': ext_network['id']}
            else:
                external_gateway_info = {
                    'network_id': ext_network['id'],
                    'enable_snat': enable_snat}
            create_body = self.admin_routers_client.create_router(
                name=name, external_gateway_info=external_gateway_info)
            self.addCleanup(
                self.admin_routers_client.delete_router,
                create_body['router']['id'])
            # Add this router to our create router list
            # createdRouterList.append(create_body['router']['id'])
            # list all routers and see if this one is part of it
            list_body = self.admin_routers_client.list_routers()
            for router in list_body['routers']:
                created_id = create_body['router']['id']
                listed_id = router['id']
                if created_id == listed_id:
                    # this is ours, check enable_snat
                    if enable_snat is not None:
                        compare_snat = \
                            create_body['router'][
                                'external_gateway_info']['enable_snat']
                        listed_snat = router[
                            'external_gateway_info']['enable_snat']
                        self.assertEqual(
                            compare_snat, listed_snat,
                            "PAT NOK: listed snat values do not match")

    def _verify_router_interface(self, router_id, subnet_id, port_id):
        show_port_body = self.admin_client.show_port(port_id)
        interface_port = show_port_body['port']
        self.assertEqual(router_id, interface_port['device_id'])
        self.assertEqual(subnet_id,
                         interface_port['fixed_ips'][0]['subnet_id'])

    def _verify_router_gateway(self, router_id, exp_ext_gw_info=None):
        show_body = self.admin_routers_client.show_router(router_id)
        actual_ext_gw_info = show_body['router']['external_gateway_info']
        if exp_ext_gw_info is None:
            self.assertIsNone(actual_ext_gw_info)
            return
        # Verify only keys passed in exp_ext_gw_info
        for k, v in exp_ext_gw_info.iteritems():
            self.assertEqual(v, actual_ext_gw_info[k])

    def _cli_create_router_without_ext_gw_neg(self):
        """_cli_create_router_without_ext_gw_neg

        Create a router without external gateway via neutron cli

        Must succeed and no "external+_gateway_info" section may be present
        in the response
        """
        # When I create a router without external gateway info
        self.router = self.create_router()
        # Then I expect the response to contain an empty
        # "external_gateway_info" section
        self.assertEmpty(self.router['external_gateway_info'],
                         "PAT 2 underlay: external_gateway_info section is "
                         "not empty, while it must be")

    def _cli_create_router_without_ext_gw_with_snat_neg(self):
        """_cli_create_router_without_ext_gw_with_snat_neg

        Via CLI, Create router without external gateway, but specify
        enable_snat (True/False)

        Must fail, as enable_snat is only for external gateway routers
        """
        name = data_utils.rand_name('pat-router-without-ext-gw-with-snat-' +
                                    str(self.nuage_pat_ini))
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            external_gateway_info_cli = \
                '--external_gateway_info type=dict enable_snat=' + \
                str(enable_snat)
            # When I create a router and specify external_gateway-info
            # enable_snat, without a network
            # I expect this to fail
            self.assertCommandFailed(self.PAT_NEEDS_EXT_NETWORK,
                                     self.create_router_with_args, name,
                                     external_gateway_info_cli)

    def _cli_create_router_with_ext_gw_without_snat(self):
        """_cli_create_router_with_ext_gw_without_snat

        Create PAT router with external gateway without SNAT

        Router is created, enable_snat depends on the nuage_pat setting
        in the ini file
        empty / default_disabled  -> enable_snat = true, VSD: false
        default_enabled            -> enable_snat = true, VSD: True
        """
        network_name = data_utils.rand_name('ext-pat-network-' +
                                            str(self.nuage_pat_ini))
        router_name = data_utils.rand_name(
            'pat-router-' + str(self.nuage_pat_ini))
        network = self.create_network_with_args(
            network_name, ' --router:external')
        external_gateway_info_cli = \
            '--external_gateway_info type=dict network_id=' + network['id']
        self.router = self.create_router_with_args(
            router_name, external_gateway_info_cli)
        # When I create a router with an external network and do not specify
        # enable_snat
        if self.nuage_pat_ini == constants.NUAGE_PAT_DEFAULTENABLED:
            compare_snat_str = '"enable_snat": true'
            vsd_flag = constants.NUAGE_PAT_VSD_ENABLED
        else:
            # OPENSTACK-981: mismatch between OS and VSD
            compare_snat_str = '"enable_snat": true'
            vsd_flag = constants.NUAGE_PAT_VSD_DISABLED
        # I expect the router to be created and the enable snat value
        # according the nuage_pat .ini settings
        self.assertIn(compare_snat_str.lower(),
                      self.router['external_gateway_info'])
        # And I expect the PATEnabled flag on the VSD to be set accordingly
        nuage_domain = self.nuage_vsd_client.get_l3domain(
            filters='externalID',
            filter_value=self.nuage_vsd_client.get_vsd_external_id(
                self.router['id']))
        self.assertEqual(
            nuage_domain[0]['PATEnabled'],
            vsd_flag)

    def _cli_verify_create_router_with_ext_gw_with_snat(self):
        """_cli_verify_create_router_with_ext_gw_with_snat

        Create router with external gateway and specifying enable_snat
        explicitly

        Response must include the same enable_snat value as in the request
        VSD patEnabled flag must be Dis/Enabled according enable_snat value
        This test must succeed for nuage_pat = DefaultDisabled and
        DefaultEnabled
        """
        network_name = data_utils.rand_name('ext-pat-network-' +
                                            str(self.nuage_pat_ini))
        # Create a router enabling snat attributes
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            router_name = data_utils.rand_name(
                'pat-router-' + str(self.nuage_pat_ini))
            network = self.create_network_with_args(
                network_name, ' --router:external')
            external_gateway_info_cli = \
                '--external_gateway_info type=dict network_id=' + \
                network['id'] + ',enable_snat=' + str(enable_snat)
            self.router = self.create_router_with_args(
                router_name, external_gateway_info_cli)
            compare_snat_str = '"enable_snat": ' + str(enable_snat)
            self.assertIn(
                compare_snat_str.lower(), self.router['external_gateway_info'])
            nuage_domain = self.nuage_vsd_client.get_l3domain(
                filters='externalID',
                filter_value=self.nuage_vsd_client.get_vsd_external_id(
                    self.router['id']))
            self.assertEqual(
                nuage_domain[0]['PATEnabled'],
                constants.NUAGE_PAT_VSD_ENABLED if enable_snat else
                constants.NUAGE_PAT_VSD_DISABLED)

    def _cli_update_router_with_ext_gw_with_snat(self):
        """_cli_update_router_with_ext_gw_with_snat

        Update router with external gateway: change enable_snat value

        Response must include the new enable_snat value
        VSD patEnabled flag changed accordingly
        """
        # Create a router enabling snat attributes
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            network_name = data_utils.rand_name(
                'ext-pat-network-' + str(self.nuage_pat_ini))
            network = self.create_network_with_args(
                network_name, ' --router:external')
            router_name = data_utils.rand_name(
                'pat-update-router-' + str(self.nuage_pat_ini))
            external_gateway_info_cli = \
                '--external_gateway_info type=dict network_id=' + \
                network['id'] + ',enable_snat=' + str(enable_snat)
            self.router = self.create_router_with_args(
                router_name, external_gateway_info_cli)
            compare_snat_str = '"enable_snat": ' + str(enable_snat)
            self.assertIn(compare_snat_str.lower(),
                          self.router['external_gateway_info'])
            nuage_domain = self.nuage_vsd_client.get_l3domain(
                filters='externalID',
                filter_value=self.nuage_vsd_client.get_vsd_external_id(
                    self.router['id']))
            self.assertEqual(
                nuage_domain[0]['PATEnabled'],
                constants.NUAGE_PAT_VSD_ENABLED if enable_snat else
                constants.NUAGE_PAT_VSD_DISABLED)
            # Now update
            new_enable_snat = False if enable_snat else True
            new_ext_gw_info_cli = \
                '--external_gateway_info type=dict network_id=' + \
                network['id'] + ',enable_snat=' + str(new_enable_snat)
            self.update_router_with_args(
                self.router['id'], new_ext_gw_info_cli)
            compare_snat_str = '"enable_snat": ' + str(new_enable_snat)
            show_router = self.show_router(self.router['id'])
            self.assertIn(
                compare_snat_str.lower(), show_router['external_gateway_info'])
            nuage_domain = self.nuage_vsd_client.get_l3domain(
                filters='externalID',
                filter_value=self.nuage_vsd_client.get_vsd_external_id(
                    self.router['id']))
            self.assertEqual(
                nuage_domain[0]['PATEnabled'],
                constants.NUAGE_PAT_VSD_ENABLED if new_enable_snat else
                constants.NUAGE_PAT_VSD_DISABLED)

    def _cli_show_router_without_ext_gw(self):
        """_cli_show_router_without_ext_gw

        Show router without external gateway via neutron cli

        Response may not include 'external_gateway_info' section
        """
        # When I create a router without external gateway info
        self.router = self.create_router()
        # Then I expect the show response to contain a
        # "external_gateway_info section equal to 'null'
        show_router = self.show_router(self.router['id'])
        self.assertEmpty(show_router['external_gateway_info'],
                         "PAT 2 underlay: show-router: "
                         "external_gateway_info section is not empty, "
                         "while it must be")
        # self.addCleanup(self.delete_router, show_router['id'])
        pass

    def _cli_show_router_with_ext_gw_without_snat(self):
        """_cli_show_router_with_ext_gw_without_snat

        Show a router with external gateway created without specifying
        enable_snat

        Response must include the enable_snat value according the setting
        in the .ini file
        """
        network_name = data_utils.rand_name(
            'ext-pat-network-' + str(self.nuage_pat_ini))
        router_name = data_utils.rand_name(
            'pat-router-' + str(self.nuage_pat_ini))
        network = self.create_network_with_args(
            network_name, ' --router:external')
        external_gateway_info_cli = \
            '--external_gateway_info type=dict network_id=' + network['id']
        self.router = self.create_router_with_args(
            router_name, external_gateway_info_cli)
        show_router = self.show_router(self.router['id'])
        # The expected enable_snat value depends on the nuage+pat setting
        # in the .ini file
        if self.nuage_pat_ini == constants.NUAGE_PAT_DEFAULTENABLED:
            compare_snat_str = '"enable_snat": " true'
        else:
            # empty or default_disable is the dame: enable_snat should be false
            compare_snat_str = '"enable_snat": false'
        self.assertIn(
            compare_snat_str.lower(), show_router['external_gateway_info'])
        pass

    def _cli_show_router_with_ext_gw_with_snat(self):
        """_cli_show_router_with_ext_gw_with_snat

        Show a router with external gateway and enable_snat via vli

        Response contains the enable_snat value used during creation
        """
        # Create a router enabling snat attributes
        enable_snat_states = [False, True]
        for enable_snat in enable_snat_states:
            network_name = data_utils.rand_name(
                'ext-pat-network-' + str(self.nuage_pat_ini))
            network = self.create_network_with_args(
                network_name, ' --router:external')
            router_name = data_utils.rand_name(
                'pat-router-' + str(self.nuage_pat_ini))
            external_gateway_info_cli = \
                '--external_gateway_info type=dict network_id=' + \
                network['id'] + ',enable_snat=' + str(enable_snat)
            self.router = self.create_router_with_args(
                router_name, external_gateway_info_cli)
            compare_snat_str = '"enable_snat": ' + str(enable_snat)
            show_router = self.show_router((self.router['id']))
            self.assertIn(
                compare_snat_str.lower(), show_router['external_gateway_info'])

    def _cli_list_router_without_gw(self):
        """_cli_list_router_without_gateway

        List routers without external gateway via cli

        Response includes external_gateway_info = null
        """
        my_router_list = ['pat-list-router-wo-gw-1',
                          'pat-list-router-wo-gw-2',
                          'pat-list-router-wo-gw-3']
        for create_router in my_router_list:
            router_name = data_utils.rand_name(create_router)
            self.router = self.create_router_with_args(router_name)
            router_list = self.parser.listing(self.list_routers())
            for router in router_list:
                created_id = self.router['id']
                listed_id = router['id']
                if created_id == listed_id:
                    # this is ours, check enable_snat
                    listed_snat = router['external_gateway_info']
                    self.assertEqual(
                        listed_snat, 'null',
                        "PAT NOK: external_gateway_info is not null")
        pass

    def _cli_list_router_with_gw_with_snat(self):
        """_cli_list_router_with_gateway_with_snat

        List routers with external gateway with and without and enable_snat

        Depending on the nuage_pat setting in the nuage_plugin.ini file
        the value of enable_snat when not passed may differ:
         False when DefaultDisabled
         True  when DefaultEnabled
        """
        # createdRouterList = list()
        # check for enable_snat = true / false / not given
        # (check default behavior)
        my_router_list = ['list-router-with_snat-true',
                          'list-router-with-snat-false',
                          'list-router-with-snat-none']
        for create_router in my_router_list:
            router_name = data_utils.rand_name(create_router)
            # set enable_snat=true/false according the true/false part in the
            # router-name
            if re.search('true', create_router):
                enable_snat = True
                expected_vsd_pat = constants.NUAGE_PAT_VSD_ENABLED
            elif re.search('false', create_router):
                enable_snat = False
                expected_vsd_pat = constants.NUAGE_PAT_VSD_DISABLED
            else:
                # if not specified, we check the default behavior
                enable_snat = None
                expected_vsd_pat = constants.NUAGE_PAT_VSD_ENABLED
            if enable_snat is None:
                external_gateway_info_cli = \
                    '--external_gateway_info type=dict network_id=' + \
                    CONF.network.public_network_id
            else:
                external_gateway_info_cli = \
                    '--external_gateway_info type=dict network_id=' + \
                    CONF.network.public_network_id + \
                    ',enable_snat=' + str(enable_snat)
            self.router = self.create_router_with_args(
                router_name, external_gateway_info_cli)
            router_list = self.parser.listing(self.list_routers())
            for router in router_list:
                created_id = self.router['id']
                listed_id = router['id']
                if created_id == listed_id:
                    # this is ours, check enable_snat: according value given
                    # at creation or if not given at creation
                    # the value according the default setting in .ini file
                    if enable_snat is not None:
                        # take the value given at creation
                        compare_snat_str = '"enable_snat": ' + str(enable_snat)
                    else:
                        # listed value should be according default in .ini
                        if self.nuage_pat_ini == \
                                constants.NUAGE_PAT_DEFAULTENABLED:
                            compare_snat_str = '"enable_snat": true'
                            expected_vsd_pat = constants.NUAGE_PAT_VSD_ENABLED
                        else:
                            compare_snat_str = '"enable_snat": true'
                            expected_vsd_pat = constants.NUAGE_PAT_VSD_DISABLED
                    self.assertIn(
                        compare_snat_str.lower(),
                        router['external_gateway_info'])
                    nuage_domain = self.nuage_vsd_client.get_l3domain(
                        filters='externalID',
                        filter_value=self.nuage_vsd_client.get_vsd_external_id(
                            created_id))
                    self.assertEqual(
                        nuage_domain[0]['PATEnabled'],
                        expected_vsd_pat)
        pass

    def _cli_add_subnet_to_existing_ext_gw_with_snat(self):
        enable_snat_states = [False, True]
        cidr = IPNetwork('21.11.10.0/24')
        # Avoid overlap of subnets when running the whole class
        # (cleanup at class level, iso test level
        if self.nuage_pat_ini == constants.NUAGE_PAT_DEFAULTDISABLED:
            cidr = cidr.next(10)
        elif self.nuage_pat_ini == constants.NUAGE_PAT_DEFAULTENABLED:
            cidr = cidr.next(20)
        for enable_snat in enable_snat_states:
            network_name = data_utils.rand_name(
                'existing-ext-pat-network-' + str(self.nuage_pat_ini))
            network = self.create_network_with_args(
                network_name, ' --router:external')
            router_name = data_utils.rand_name(
                'existing-pat-router-' + str(self.nuage_pat_ini))
            external_gateway_info_cli = \
                '--external_gateway_info type=dict network_id=' + \
                network['id'] + ',enable_snat=' + str(enable_snat)
            self.router = self.create_router_with_args(
                router_name, external_gateway_info_cli)
            compare_snat_str = '"enable_snat": ' + str(enable_snat)
            self.assertIn(
                compare_snat_str.lower(), self.router['external_gateway_info'])
            # Now create a subnet and add it to the external network
            subnet_name = data_utils.rand_name('os-subnet-to-existing-ext-gw')
            self.subnet = self.create_subnet_with_args(
                network_name, str(cidr.cidr), "--name ", subnet_name)
            cidr = cidr.next(1)
        pass

    def _cli_add_subnet_to_other_tenant_existing_ext_gw_with_snat(self):
        enable_snat_states = [False, True]
        cidr_net = IPNetwork('99.99.0.0/24')
        for enable_snat in enable_snat_states:
            # create the external networks and routers as admin users of
            # admin project
            self._as_admin()
            network_name = data_utils.rand_name(
                'existing-ext-pat-network-' + str(self.nuage_pat_ini))
            network = self.create_network_with_args(
                network_name, ' --router:external')
            router_name = data_utils.rand_name(
                'existing-pat-router-' + str(self.nuage_pat_ini))
            external_gateway_info_cli = \
                '--external_gateway_info type=dict network_id=' + \
                network['id'] + ',enable_snat=' + str(enable_snat)
            self.router = self.create_router_with_args(
                router_name, external_gateway_info_cli)
            compare_snat_str = '"enable_snat": ' + str(enable_snat)
            self.assertIn(
                compare_snat_str.lower(), self.router['external_gateway_info'])
            # Now create a subnet aas non-admin and try to add it to the
            # external network: must fail
            self._as_tenant()
            subnet_name = data_utils.rand_name('os-subnet-to-existing-ext-gw')
            # Now run as "demo" user (non-admin) of demo project
            # convert the cidr_net into a string
            cidr = cidr_net.__str__()
            if Release(Topology.openstack_version) >= Release('pike'):
                msg = "Tenant (.*) not allowed to create " \
                      "subnet on this network"
            else:
                msg = 'The resource could not be found'
            self.assertCommandFailed(msg,
                                     self.create_subnet_with_args,
                                     network_name,
                                     cidr, "--name ", subnet_name)
            # increase cidr_net to next /24 subnet
            cidr_net = cidr_net.next(1)

    def _cli_tenant_create_router_with_ext_gw(self):
        """_cli_tenant_create_router_with_ext_gw

        Try to Create router with external gateway as non-admin

        Must fail: requires admin permissions
        """
        self._as_tenant()
        enable_snat_states = [False, True]
        # Kilo: Policy doesn't allow"
        # Liberty: "<really full cmd name> disallowed by policy"
        # exp_message = "Policy doesn't allow"
        # Take a common part, small as it may be
        exp_message = "olicy"

        for enable_snat in enable_snat_states:

            name = data_utils.rand_name('pat-router-' +
                                        str(self.nuage_pat_ini))
            external_gateway_info_cli = \
                '--external_gateway_info type=dict network_id=' + \
                self.ext_net_id + ',enable_snat=' + str(enable_snat)
            self.LOG.info("exp_message contains : " + exp_message)
            self.assertCommandFailed(
                exp_message,
                self.create_router_with_args, name, external_gateway_info_cli)
