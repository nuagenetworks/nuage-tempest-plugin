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
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology

LOG = Topology.get_logger(__name__)


class E2eTestBase(NuageBaseTest):

    """Base test class for end-to-end tests"""

    hypervisors = None

    @classmethod
    def get_hypervisors(cls):
        if not cls.hypervisors:
            cls.hypervisors = cls.hv_client.list_hypervisors(
                detail=True)['hypervisors']
        return cls.hypervisors

    @classmethod
    def get_hypervisor(cls, server):
        server = server.get_server_details()
        return next(
            hv for hv in cls.get_hypervisors()
            if (hv['hypervisor_hostname'] ==
                server['OS-EXT-SRV-ATTR:hypervisor_hostname']))

    def dump_flows(self, hypervisor):
        """Dump flows on hypervisor"""
        cmd = ('ssh heat-admin@{host_ip} "sudo ovs-dpctl dump-flows -m"'
               .format(host_ip=hypervisor['host_ip']))
        flows = self.execute_from_shell(cmd).splitlines()
        for flow in flows:
            LOG.debug("{}: {}".format(hypervisor['hypervisor_hostname'],
                                      flow))
        return flows

    def restart_openvswitch(self, hypervisor):
        cmd = ('ssh heat-admin@{host_ip} "sudo service openvswitch restart"'
               .format(host_ip=hypervisor['host_ip']))
        return self.execute_from_shell(cmd)
