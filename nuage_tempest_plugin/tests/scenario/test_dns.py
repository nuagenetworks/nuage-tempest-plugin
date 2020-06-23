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

from tempest.test import decorators

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology

LOG = Topology.get_logger(__name__)
CONF = Topology.get_conf()


class DNSScenarioTest(nuage_test.NuageBaseTest):

    default_prepare_for_connectivity = True

    def _test_dns_up_to_vm(self, ip_versions=None, is_l3=None):
        dns = {6: 'cafe:babe:cafe:babe:cafe:babe:cafe:babe',
               4: '1.1.1.1'}

        network = self.create_network()
        subnet = None
        for ip_version in ip_versions:
            subnet = self.create_subnet(network, ip_version=ip_version,
                                        dns_nameservers=[dns.get(ip_version)])
        if is_l3:
            router = self.create_router(
                external_network_id=CONF.network.public_network_id)
            self.router_attach(router, subnet)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        server = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # makes sure that all the DNSs configured.
        server.send(cmd="[ `cat /etc/resolv.conf | grep nameserver | "
                        "wc -l` = {} ]".format(len(ip_versions)),
                    timeout=300)
        result = server.send(cmd="cat /etc/resolv.conf | grep nameserver")

        for ip_version in ip_versions:
            self.assertIn(dns.get(ip_version),
                          result, 'DNS={} is not configured '
                                  'properly.'.format(dns.get(ip_version)))

    @decorators.attr(type='smoke')
    def test_dns_up_to_vm_l2_v4(self):
        self._test_dns_up_to_vm(ip_versions=[4], is_l3=False)

    @testtools.skipIf(not Topology.has_single_stack_v6_support(),
                      'No singe-stack v6 supported')
    def test_dns_up_to_vm_l2_v6(self):
        self._test_dns_up_to_vm(ip_versions=[6], is_l3=False)

    def test_dns_up_to_vm_l3_v4(self):
        self._test_dns_up_to_vm(ip_versions=[4], is_l3=True)

    @testtools.skipIf(not Topology.has_single_stack_v6_support(),
                      'No singe-stack v6 supported')
    @decorators.attr(type='smoke')
    def test_dns_up_to_vm_l3_v6(self):
        self._test_dns_up_to_vm(ip_versions=[6], is_l3=True)

    @testtools.skipUnless(Topology.has_dhcp_v6_support(),
                          'No dhcp v6 supported')
    def test_dns_up_to_vm_l2_dualstack(self):
        self._test_dns_up_to_vm(ip_versions=[6, 4], is_l3=False)

    @testtools.skipUnless(Topology.has_dhcp_v6_support(),
                          'No dhcp v6 supported')
    @decorators.attr(type='smoke')
    def test_dns_up_to_vm_l3_dualstack(self):
        self._test_dns_up_to_vm(ip_versions=[6, 4], is_l3=True)
