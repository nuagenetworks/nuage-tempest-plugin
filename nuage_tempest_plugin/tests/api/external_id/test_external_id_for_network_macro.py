# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from tempest.api.network import base as base
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils

import testtools

from .external_id import ExternalId

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.lib.utils import exceptions as n_exceptions
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class ExternalIdForNetworkMacroTest(base.BaseAdminNetworkTest):
    class MatchingVsdNetworkMacro(object):
        def __init__(self, outer, net_partition):
            """Construct a Vsd_port. """
            self.test = outer
            self.net_partition = net_partition
            self.vsd_network_macro = None

        def get_by_external_id(self):
            vsd_network_macro = \
                self.test.nuage_client.get_enterprise_net_macro(
                    netpart_name=self.net_partition['name'])
            if NUAGE_FEATURES.os_managed_dualstack_subnets:
                self.test.assertEqual(
                    2, len(vsd_network_macro), "should have network macros")
            else:
                self.test.assertEqual(
                    1, len(vsd_network_macro), "should have network macros")
            vsd_network_macros = \
                self.test.nuage_client.get_enterprise_net_macro(
                    netpart_name=self.net_partition['name'],
                    filters='externalID',
                    filter_value=ExternalId(
                        self.net_partition['id']).at_openstack())

            if NUAGE_FEATURES.os_managed_dualstack_subnets:
                self.test.assertEqual(2, len(vsd_network_macros))
            else:
                self.test.assertEqual(1, len(vsd_network_macros))
            self.vsd_network_macro = vsd_network_macros[0]

            # TODO(team) what should be the name
            # reference = u'5ffc260c-f10d-4cd1-85a3-26e35618e695_0_0'
            # actual    = u'5ffc260c-f10d-4cd1-85a3-26e35618e695'
            # self.test.assertEqual(self.vsd_network_macro['name'],
            #     self.net_partition['id'])

            self.test.assertEqual(
                ExternalId(self.net_partition['id']).at_openstack(),
                self.vsd_network_macro['externalID'])
            return self

        def verify_cannot_delete(self):
            # Can't delete NetworkMacro in VSD
            self.test.assertRaisesRegex(
                n_exceptions.MultipleChoices,
                "Multiple choices",
                self.test.nuage_client.delete_resource,
                n_constants.ENTERPRISE_NET_MACRO,
                self.vsd_network_macro['ID'])

    @classmethod
    def create_port(cls, network, **kwargs):
        if CONF.network.port_vnic_type and 'binding:vnic_type' not in kwargs:
            kwargs['binding:vnic_type'] = CONF.network.port_vnic_type
        if CONF.network.port_profile and 'binding:profile' not in kwargs:
            kwargs['binding:profile'] = CONF.network.port_profile
        return super(ExternalIdForNetworkMacroTest, cls).create_port(network,
                                                                     **kwargs)

    @classmethod
    def setup_clients(cls):
        super(ExternalIdForNetworkMacroTest, cls).setup_clients()
        cls.nuage_client = NuageRestClient()
        cls.nuage_network_client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)

    def _create_netpartition(self):
        name = data_utils.rand_name('netpartition')
        body = self.nuage_network_client.create_netpartition(name)
        netpartition = body['net_partition']
        self.addClassResourceCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.nuage_network_client.delete_netpartition,
            netpartition['id'])
        return netpartition

    @testtools.skipUnless(Topology.from_nuage('4.0R5'),
                          'No upgrade testing on network macro')
    def test_network_macro_matches_to_enterprise(self):
        # Create a dedicated netpartition
        netpartition_b = self._create_netpartition()

        # Create a network 1 in netpartition A
        name = data_utils.rand_name('networkA1')
        network_a1 = self.create_network(network_name=name)
        subnet_a1 = self.create_subnet(
            network_a1, net_partition=netpartition_b['name'])
        self.assertIsNotNone(subnet_a1)  # dummy check to use local variable

        network_macros = self.nuage_client.get_enterprise_net_macro(
            netpart_name=netpartition_b['name'])
        self.assertEqual(
            0, len(network_macros), "should not have network macros")

        self.create_port(
            name=name,
            network=network_a1)

        vsd_network_macro = self.MatchingVsdNetworkMacro(
            self, netpartition_b).get_by_external_id()

        # Delete
        vsd_network_macro.verify_cannot_delete()
