# Copyright 2017 Nokia
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

import testtools
import time

from tempest.test import decorators

from nuage_tempest_plugin.lib import service_mgmt
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

LOG = Topology.get_logger(__name__)


class APIKeyRenewal(NuageBaseTest):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(APIKeyRenewal, cls).setup_clients()
        cls.nuage_vsd_client = NuageRestClient()
        cls.service_manager = service_mgmt.ServiceManager()
        cls.client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)
        sys_conf = cls.nuage_vsd_client.get_system_configuration()

        cls.sys_conf = sys_conf[0]
        cls.conf_id = cls.sys_conf['ID']

    @classmethod
    def resource_setup(cls):
        super(APIKeyRenewal, cls).resource_setup()

    def _set_api_key_renewal_interval(self, interval):
        self.sys_conf['APIKeyRenewalInterval'] = interval
        if 'APIKeyValidity' in self.sys_conf:
            del self.sys_conf['APIKeyValidity']
        self.nuage_vsd_client.update_system_configuration(
            self.conf_id, self.sys_conf)

    def _set_api_key_validity(self, interval):
        self.sys_conf['APIKeyValidity'] = interval
        if 'APIKeyRenewalInterval' in self.sys_conf:
            del self.sys_conf['APIKeyRenewalInterval']
        self.nuage_vsd_client.update_system_configuration(
            self.conf_id, self.sys_conf)

    def _get_current_api_key_from_neutron(self):
        api_key = self.osc_get_database_table_row(
            'nuage_config', assert_table_size=1)[3]
        LOG.debug('API_KEY IS %s', api_key)
        return api_key

    @testtools.skipIf(not Topology.neutron_restart_supported(),
                      'Skipping tests that restart neutron')
    @decorators.attr(type='slow')
    def test_api_key_is_renewed_after_11_mins(self):
        self._set_api_key_renewal_interval(60)
        self._set_api_key_validity(600)
        self.service_manager.start_service(n_constants.NEUTRON_SERVICE)
        self.service_manager.wait_for_service_status(
            n_constants.NEUTRON_SERVICE)
        time.sleep(2)
        current_api_key = self._get_current_api_key_from_neutron()
        time.sleep(300)
        api_key_after_5_mins = self._get_current_api_key_from_neutron()
        self.assertEqual(current_api_key, api_key_after_5_mins)
        time.sleep(300)
        api_key_after_10_mins = self._get_current_api_key_from_neutron()
        self.assertNotEqual(current_api_key, api_key_after_10_mins)

    @testtools.skipIf(not Topology.neutron_restart_supported(),
                      'Skipping tests that restart neutron')
    @decorators.attr(type='slow')
    def test_api_key_renewed_after_401(self):
        """test_api_key_renewed_after_401

        To simulate a 401 set 20 mins interval on VSD and
        neutron. Restart neutron. Then update internal on
        VSD to 10 mins without neutron knowing about it
        """
        self._set_api_key_renewal_interval(60)
        self._set_api_key_validity(1200)
        current_api_key = self._get_current_api_key_from_neutron()
        self.service_manager.start_service(n_constants.NEUTRON_SERVICE)
        self.service_manager.wait_for_service_status(
            n_constants.NEUTRON_SERVICE)
        self._set_api_key_validity(600)
        time.sleep(600)
        # Perform some operation
        network = self.create_network()
        self.create_subnet(network)
        new_api_key = self._get_current_api_key_from_neutron()
        # Should result in 401 and new renewal
        self.assertNotEqual(current_api_key, new_api_key)
