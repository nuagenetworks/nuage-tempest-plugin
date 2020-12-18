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
CONF = Topology.get_conf()


class NuagePatToUnderlayScenarioTest(NuageBaseTest):

    # leaving default_prepare_for_connectivity to False!

    def _test_pat_to_underlay_up_to_hv(self, nuage_underlay, should_succeed):
        # Provision OpenStack network resources
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router(
            nuage_underlay=nuage_underlay,
            external_network_id=self.ext_net_id)
        self.router_attach(router, subnet)
        security_group = self.create_open_ssh_security_group()
        port = self.create_port(network,
                                security_groups=[security_group['id']])

        # Launch tenant servers in OpenStack network with cloud-init script
        output_path = '/tmp/ping_result'
        ping_script = ('ping {} -c 1 -w 3\n'
                       'echo $? > {}\n'.format(self.get_local_ip(),
                                               output_path))
        server = self.create_tenant_server(
            ports=[port],
            user_data=ping_script)
        self.sleep(240, msg='waiting for cloud-init script to finish.')

        self.create_fip_to_server(server, port)
        result = server.send('cat {}'.format(output_path)).strip()

        if should_succeed:
            self.assertEqual(result, '0')
        else:
            self.assertNotEqual(result, '0')

    def test_pat_to_underlay_up_to_hv(self):
        self._test_pat_to_underlay_up_to_hv('snat', True)

    def test_pat_to_underlay_disabled_up_to_hv(self):
        self._test_pat_to_underlay_up_to_hv('off', False)
