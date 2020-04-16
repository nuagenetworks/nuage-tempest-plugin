# Copyright 2020 NOKIA
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

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.tests.api.orchestration import nuage_base


class NuageHybridMplsSegmentTest(nuage_base.NuageBaseOrchestrationTest):

    @classmethod
    def skip_checks(cls):
        super(NuageHybridMplsSegmentTest, cls).skip_checks()
        if not Topology.beyond_nuage('6.0'):
            raise cls.skipException('VSP release not compatible')

    def test_nuage_hybrid_mpls_segment(self):

        stack_file_name = 'nuage_hybrid_mpls_segment'
        stack_parameters = {'net_type': 'nuage_hybrid_mpls',
                            'segment_type': 'nuage_hybrid_mpls'}
        self.launch_stack(stack_file_name, stack_parameters)

        expected_resources = ['network_mpls', 'subnet_mpls', 'segment_mpls']
        self.verify_stack_resources(expected_resources,
                                    self.template_resources,
                                    self.test_resources)

        network = self.verify_created_network('network_mpls')
        self.verify_created_subnet('subnet_mpls', network)

        # Verify network/segment type
        self.assertEqual('nuage_hybrid_mpls',
                         network['segments'][0]['provider:network_type'])
        self.assertEqual('nuage_hybrid_mpls',
                         network['segments'][1]['provider:network_type'])
