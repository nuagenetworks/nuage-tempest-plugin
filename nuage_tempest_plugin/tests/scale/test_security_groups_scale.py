# Copyright 2019 NOKIA - All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.tests.api.test_security_groups_nuage \
    import SecGroupTestNuageBase

CONF = Topology.get_conf()


class TestSecGroupScaleBase(SecGroupTestNuageBase):

    def _test_create_port_with_security_groups(self, sg_num,
                                               nuage_domain=None,
                                               should_succeed=True):
        # Test the maximal number of security groups when creating a port
        if not nuage_domain:
            nuage_domain = self.nuage_any_domain
        security_groups_list = []
        sg_max = n_constants.MAX_SG_PER_PORT
        for i in range(sg_num):
            group_create_body, name = self._create_security_group()
            security_groups_list.append(group_create_body['security_group']
                                        ['id'])
        post_body = {
            "network_id": self.network['id'],
            "name": data_utils.rand_name('port-'),
            "security_groups": security_groups_list
        }
        if should_succeed:
            port = self._create_port(**post_body)
            vport = self.nuage_client.get_vport(
                self.nuage_domain_type,
                nuage_domain[0]['ID'],
                filters='externalID',
                filter_value=port['id'])
            nuage_policy_grps = self.nuage_client.get_policygroup(
                n_constants.VPORT,
                vport[0]['ID'])
            self.assertEqual(sg_num, len(nuage_policy_grps))
        else:
            msg = (("Number of %s specified security groups exceeds the "
                    "maximum of %s security groups on a port "
                    "supported on nuage VSP") % (sg_num, sg_max))
            self.assertRaisesRegex(
                exceptions.BadRequest,
                msg,
                self._create_port,
                **post_body)


class TestSecGroupScaleTestL2Domain(TestSecGroupScaleBase):

    @classmethod
    def resource_setup(cls):
        super(TestSecGroupScaleTestL2Domain, cls).resource_setup()

        # Nuage specific resource addition
        name = data_utils.rand_name('network-')
        cls.network = cls.create_network(network_name=name)
        cls.subnet = cls.create_subnet(cls.network)
        nuage_l2domain = cls.nuage_client.get_l2domain(
            filters=['externalID', 'address'],
            filter_value=[cls.subnet['network_id'],
                          cls.subnet['cidr']])
        cls.nuage_any_domain = nuage_l2domain
        cls.nuage_domain_type = n_constants.L2_DOMAIN

    def test_create_port_with_max_security_groups(self):
        self._test_create_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT)

    def test_create_port_with_overflow_security_groups_neg(self):
        self._test_create_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT + 1, should_succeed=False)

    def test_update_port_with_max_security_groups(self):
        self._test_update_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT)

    def test_update_port_with_overflow_security_groups_neg(self):
        self._test_update_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT + 1, should_succeed=False)


class TestSecGroupScaleTestL3Domain(TestSecGroupScaleBase):

    @classmethod
    def resource_setup(cls):
        super(TestSecGroupScaleTestL3Domain, cls).resource_setup()

        # Create a network
        name = data_utils.rand_name('network-')
        cls.network = cls.create_network(network_name=name)

        # Create a subnet
        cls.subnet = cls.create_subnet(cls.network)

        # Create a router
        name = data_utils.rand_name('router-')
        create_body = cls.routers_client.create_router(
            name=name, external_gateway_info={
                "network_id": CONF.network.public_network_id},
            admin_state_up=False)
        cls.router = create_body['router']
        cls.routers_client.add_router_interface(
            cls.router['id'], subnet_id=cls.subnet['id'])

        nuage_l3domain = cls.nuage_client.get_l3domain(
            filters='externalID',
            filter_value=cls.router['id'])

        cls.nuage_any_domain = nuage_l3domain
        cls.nuage_domain_type = n_constants.DOMAIN

    def test_create_port_with_max_security_groups(self):
        self._test_create_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT)

    def test_create_port_with_overflow_security_groups_neg(self):
        self._test_create_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT + 1, should_succeed=False)

    def test_update_port_with_max_security_groups(self):
        self._test_update_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT)

    def test_update_port_with_overflow_security_groups_net(self):
        self._test_update_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT + 1, should_succeed=False)
