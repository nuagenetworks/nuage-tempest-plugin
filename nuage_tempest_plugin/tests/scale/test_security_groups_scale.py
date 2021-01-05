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
import testscenarios

from tempest.lib import exceptions

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants

CONF = Topology.get_conf()
load_tests = testscenarios.load_tests_apply_scenarios


class TestSecGroupScaleBase(nuage_test.NuageBaseTest):

    is_l3 = False

    ip_versions = (4, 6)

    scenarios = testscenarios.scenarios.multiply_scenarios([
        ('L3', {'is_l3': True}),
        ('L2', {'is_l3': False})
    ], [
        ('IPv4', {'ip_versions': (4,)}),
        ('IPv6', {'ip_versions': (6,)}),
        ('Dualstack', {'ip_versions': (4, 6)})
    ])

    @classmethod
    def skip_checks(cls):
        super(TestSecGroupScaleBase, cls).skip_checks()
        if (not Topology.has_single_stack_v6_support() and
                cls.ip_versions == (6,)):
            raise cls.skipException("Single Stack IPV6 not supported")

    @classmethod
    def resource_setup(cls):
        super(TestSecGroupScaleBase, cls).resource_setup()
        cls.network = cls.create_cls_network()
        cls.subnet4 = cls.subnet6 = None
        if 4 in cls.ip_versions:
            cls.subnet4 = cls.create_cls_subnet(cls.network, ip_version=4)
        if 6 in cls.ip_versions:
            cls.subnet6 = cls.create_cls_subnet(cls.network, ip_version=6)
        cls.router = None
        if cls.is_l3:
            cls.router = cls.create_cls_router()
            if cls.subnet4:
                cls.router_cls_attach(cls.router, cls.subnet4)
            if cls.subnet6:
                cls.router_cls_attach(cls.router, cls.subnet6)
            cls.domain = cls.vsd.get_l3_domain_by_subnet(
                cls.subnet4 or cls.subnet6)
        else:
            cls.domain = cls.vsd.get_l2domain(
                by_subnet=cls.subnet4 or cls.subnet6)

    def test_create_update_port_with_max_security_groups(self):
        """test_create_update_port_with_max_security_groups

        Create port with max nr SG
        Create port with max+1 nr SG
        update port with max nr SG
        update port with max+1 nr SG

        """
        num_sg = n_constants.MAX_SG_PER_PORT
        sg_ids = []
        for _ in range(num_sg):
            sg = self.create_security_group()
            sg_ids.append(sg['id'])
        # Sunny side scenario
        port = self.create_port(self.network, security_groups=sg_ids)
        port_update = self.create_port(self.network)
        self.update_port(port_update, security_groups=sg_ids)
        ext_id_filter = self.vsd.get_external_id_filter(port['id'])
        vport = self.domain.vports.get(filter=ext_id_filter)[0]
        pgs = vport.policy_groups.get()
        self.assertEqual(num_sg, len(pgs))
        # Clear SG from port for cleanup
        self.update_port(port, security_groups=[])
        self.update_port(port_update, security_groups=[])

        # Exceed maximum capacity
        sg = self.create_security_group()
        sg_ids.append(sg['id'])

        msg = (("Number of %s specified security groups exceeds the "
                "maximum of %s security groups on a port "
                "supported on nuage VSP") % (num_sg + 1,
                                             n_constants.MAX_SG_PER_PORT))
        self.assertRaisesRegex(
            exceptions.BadRequest,
            msg,
            self.create_port,
            self.network, security_groups=sg_ids)
        port_update = self.create_port(self.network)
        self.assertRaisesRegex(
            exceptions.BadRequest,
            msg,
            self.update_port,
            port_update, security_groups=sg_ids)
