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
                                               nuage_domain=None):
        # Test the maximal number of security groups when creating a port
        nuage_domain = nuage_domain or self.nuage_any_domain
        sg_ids = []
        for _ in range(sg_num):
            group_create_body, name = self._create_security_group()
            sg_ids.append(group_create_body['security_group']['id'])
        if sg_num <= n_constants.MAX_SG_PER_PORT:
            self._create_nuage_port_with_security_group(sg_ids, self.network)
            vport = self.nuage_client.get_vport(
                self.nuage_domain_type,
                nuage_domain[0]['ID'],
                filters='externalID',
                filter_values=self.port['id'])
            nuage_policy_grps = self.nuage_client.get_policygroup(
                n_constants.VPORT,
                vport[0]['ID'])
            self.assertEqual(sg_num, len(nuage_policy_grps))
        else:
            msg = (("Number of %s specified security groups exceeds the "
                    "maximum of %s security groups on a port "
                    "supported on nuage VSP") % (sg_num,
                                                 n_constants.MAX_SG_PER_PORT))
            self.assertRaisesRegex(
                exceptions.BadRequest,
                msg,
                self._create_nuage_port_with_security_group,
                sg_ids,
                self.network)

    def _test_update_port_with_security_groups(self, sg_num,
                                               nuage_domain=None):
        # Test the maximal number of security groups when updating a port
        nuage_domain = nuage_domain or self.nuage_any_domain
        group_create_body, name = self._create_security_group()
        self._create_nuage_port_with_security_group(
            [group_create_body['security_group']['id']], self.network)
        sg_ids = []
        for _ in range(sg_num):
            group_create_body, name = self._create_security_group()
            sg_ids.append(group_create_body['security_group']['id'])
        sg_body = {"security_groups": sg_ids}
        if sg_num <= n_constants.MAX_SG_PER_PORT:
            self.update_port(self.port, **sg_body)
            vport = self.nuage_client.get_vport(self.nuage_domain_type,
                                                nuage_domain[0]['ID'],
                                                filters='externalID',
                                                filter_values=self.port['id'])
            nuage_policy_grps = self.nuage_client.get_policygroup(
                n_constants.VPORT,
                vport[0]['ID'])
            self.assertEqual(sg_num, len(nuage_policy_grps))

            # clear sgs such that cleanup will work fine
            sg_body = {"security_groups": []}
            self.ports_client.update_port(self.port['id'], **sg_body)
        else:
            msg = (("Number of %s specified security groups exceeds the "
                    "maximum of %s security groups on a port "
                    "supported on nuage VSP") % (sg_num,
                                                 n_constants.MAX_SG_PER_PORT))
            self.assertRaisesRegex(
                exceptions.BadRequest,
                msg,
                self.ports_client.update_port,
                self.port['id'],
                **sg_body)


class TestSecGroupScaleTestL2Domain(TestSecGroupScaleBase):

    @classmethod
    def resource_setup(cls):
        super(TestSecGroupScaleTestL2Domain, cls).resource_setup()

        # Nuage specific resource addition
        name = data_utils.rand_name('network-')
        cls.network = cls.create_network(name)
        cls.subnet = cls.create_subnet(cls.network)
        nuage_l2domain = cls.nuage_client.get_l2domain(by_subnet=cls.subnet)
        cls.nuage_any_domain = nuage_l2domain
        cls.nuage_domain_type = n_constants.L2_DOMAIN

    def test_create_port_with_max_security_groups(self):
        self._test_create_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT)

    def test_create_port_with_overflow_security_groups_neg(self):
        self._test_create_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT + 1)

    def test_update_port_with_max_security_groups(self):
        self._test_update_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT)

    def test_update_port_with_overflow_security_groups_neg(self):
        self._test_update_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT + 1)


class TestSecGroupScaleTestL3Domain(TestSecGroupScaleBase):

    @classmethod
    def resource_setup(cls):
        super(TestSecGroupScaleTestL3Domain, cls).resource_setup()

        # Create a network
        name = data_utils.rand_name('network-')
        cls.network = cls.create_network(name)

        # Create a subnet
        cls.subnet = cls.create_subnet(cls.network)

        # Create a router
        name = data_utils.rand_name('router-')
        cls.router = cls.create_router(
            name, external_network_id=CONF.network.public_network_id)
        cls.create_router_interface(cls.router['id'], cls.subnet['id'])

        nuage_l3domain = cls.nuage_client.get_l3domain(
            filters='externalID',
            filter_values=cls.router['id'])

        cls.nuage_any_domain = nuage_l3domain
        cls.nuage_domain_type = n_constants.DOMAIN

    def test_create_port_with_max_security_groups(self):
        self._test_create_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT)

    def test_create_port_with_overflow_security_groups_neg(self):
        self._test_create_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT + 1)

    def test_update_port_with_max_security_groups(self):
        self._test_update_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT)

    def test_update_port_with_overflow_security_groups_net(self):
        self._test_update_port_with_security_groups(
            n_constants.MAX_SG_PER_PORT + 1)
