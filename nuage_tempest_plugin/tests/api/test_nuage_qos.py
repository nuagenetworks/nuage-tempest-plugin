# Copyright 2012 OpenStack Foundation
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
import netaddr

from neutron_tempest_plugin.services.network.json import network_client
from tempest.common import utils
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class BaseNuageQOSTest(NuageBaseTest):
    # This test class only handles nuage specifics about QOS implementation

    max_kbps = 200
    max_burst_kbps = 1000
    min_kbps = 1000

    @classmethod
    def skip_checks(cls):
        super(NuageBaseTest, cls).skip_checks()
        if not utils.is_extension_enabled('qos', 'network'):
            msg = "Qos extension is not enabled."
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(BaseNuageQOSTest, cls).setup_clients()
        # QOS is only allowed for admin
        cls.manager = cls.admin_manager
        cls.neutron_client = network_client.NetworkClientJSON(
            cls.manager.auth_provider, CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.manager.default_params)

    def create_qos_policy(self, name, description=None, shared=False,
                          is_default=False, cleanup=True):
        """Wrapper utility that returns a test QoS policy."""
        body = self.neutron_client.create_qos_policy(
            name=name, description=description, shared=shared,
            is_default=is_default)
        qos_policy = body['policy']
        if cleanup:
            self.addCleanup(self.neutron_client.delete_qos_policy,
                            qos_policy['id'])
        return qos_policy

    def create_qos_bandwidth_limit_rule(self, policy_id, max_kbps,
                                        max_burst_kbps,
                                        direction='egress'):
        """Wrapper utility that returns a test QoS bandwidth limit rule."""
        body = self.neutron_client.create_bandwidth_limit_rule(
            policy_id=policy_id, max_kbps=max_kbps,
            max_burst_kbps=max_burst_kbps, direction=direction)
        qos_rule = body['bandwidth_limit_rule']
        return qos_rule

    def get_qos_for_subnet(self, subnet, router=None, required=True):
        if router:
            subnet = self.vsd.get_subnet(by_subnet=subnet)
            qos = subnet.qoss.get()
        else:
            l2domain = self.vsd.get_l2domain(by_subnet=subnet)
            qos = l2domain.qoss.get()
        if required or qos:
            self.assertNotEmpty(qos, 'Could not find associated qos for '
                                     'subnet.')
            self.assertEqual(1, len(qos), 'More qos objects found '
                                          'than expected for subnet.')
            return qos[0]
        else:
            return None

    def get_qos_for_port(self, subnet, port, router=None,
                         required=True):
        if router:
            subnet = self.vsd.get_subnet(by_subnet=subnet)
            vport = self.vsd.get_vport(subnet=subnet, by_port_id=port['id'])
            qos = vport.qoss.get()
        else:
            l2domain = self.vsd.get_l2domain(by_subnet=subnet)
            vport = self.vsd.get_vport(l2domain=l2domain,
                                       by_port_id=port['id'])
            qos = vport.qoss.get()
        if required or qos:
            self.assertNotEmpty(qos, 'Could not find associated qos for port.')
            self.assertEqual(1, len(qos), 'More qos objects found '
                                          'than expected for port.')
            return qos[0]
        else:
            return None

    def verify_qos(self, policy_id, qos, peak_rate='INFINITY',
                   peak_burst_rate=0, minimum_rate='0'):
        self.assertEqual(self.vsd.external_id(policy_id),
                         qos.external_id, 'External ID not policy ID.')
        self.assertTrue(qos.active)
        self.assertTrue(qos.rate_limiting_active)
        self.assertFalse(qos.bum_rate_limiting_active)
        self.assertFalse(qos.fip_rate_limiting_active)
        self.assertEqual(peak_rate, qos.peak)
        self.assertEqual(str(peak_burst_rate), qos.burst)
        self.assertEqual(minimum_rate, qos.committed_information_rate)
        self.assertEqual('1', qos.committed_burst_size)


class RateLimitingNuageQosTest(BaseNuageQOSTest):

    def _crud_verify_qos_bw_limiter(self, is_l3=False):
        policy = self.create_qos_policy(name='test-bw-limiter',
                                        description='test policy')
        rule = self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'],
            max_kbps=self.max_kbps,
            max_burst_kbps=self.max_burst_kbps,
            direction='egress')
        policy2 = self.create_qos_policy(name='test-bw-limiter',
                                         description='test policy')
        self.create_qos_bandwidth_limit_rule(
            policy_id=policy2['id'],
            max_kbps=self.max_kbps * 2,
            max_burst_kbps=self.max_burst_kbps * 2,
            direction='egress')

        # Create
        network = self.create_network(qos_policy_id=policy['id'])
        cidr = netaddr.IPNetwork('10.0.0.0/24')
        subnet = self.create_subnet(network, cidr=cidr)
        port = self.create_port(network, qos_policy_id=policy['id'])
        router = None
        if is_l3:
            router = self.create_router(
                external_network_id=CONF.network.public_network_id)
            self.router_attach(router, subnet)
            # Re-attach qos policy because of PROD-11066
            self.update_network(network['id'], qos_policy_id=None)
            self.update_network(network['id'], qos_policy_id=policy['id'])

        qos = self.get_qos_for_subnet(subnet, router)
        self.verify_qos(policy['id'], qos,
                        peak_rate=str(self.max_kbps / 1000.0),
                        peak_burst_rate=self.max_burst_kbps)
        qos = self.get_qos_for_port(subnet, port, router)
        self.verify_qos(policy['id'], qos,
                        peak_rate=str(self.max_kbps / 1000.0),
                        peak_burst_rate=self.max_burst_kbps)

        # Update policy
        self.neutron_client.update_bandwidth_limit_rule(
            policy['id'],
            rule['id'],
            max_kbps=self.max_kbps * 3,
            max_burst_kbps=self.max_burst_kbps * 3)
        qos = self.get_qos_for_subnet(subnet, router)
        self.verify_qos(policy['id'], qos,
                        peak_rate=str(self.max_kbps * 3 / 1000.0),
                        peak_burst_rate=self.max_burst_kbps * 3)
        qos = self.get_qos_for_port(subnet, port, router)
        self.verify_qos(policy['id'], qos,
                        peak_rate=str(self.max_kbps * 3 / 1000.0),
                        peak_burst_rate=self.max_burst_kbps * 3)

        # Update network by creating second subnet, always l2
        cidr2 = netaddr.IPNetwork('20.0.0.0/24')
        subnet2 = self.create_subnet(network, cidr=cidr2)
        qos = self.get_qos_for_subnet(subnet2)
        self.verify_qos(policy['id'], qos,
                        peak_rate=str(self.max_kbps * 3 / 1000.0),
                        peak_burst_rate=self.max_burst_kbps * 3)

        # Update to different policy
        self.update_network(network['id'], qos_policy_id=policy2['id'])
        qos = self.get_qos_for_subnet(subnet, router)
        self.verify_qos(policy2['id'], qos,
                        peak_rate=str(self.max_kbps * 2 / 1000.0),
                        peak_burst_rate=self.max_burst_kbps * 2)
        self.update_port(port, qos_policy_id=policy2['id'])
        qos = self.get_qos_for_port(subnet, port, router)
        self.verify_qos(policy2['id'], qos,
                        peak_rate=str(self.max_kbps * 2 / 1000.0),
                        peak_burst_rate=self.max_burst_kbps * 2)

        # Disassociate
        self.update_network(network['id'], qos_policy_id=None)
        self.assertIsNone(self.get_qos_for_subnet(subnet, router,
                                                  required=False))
        self.update_port(port, qos_policy_id=None)
        self.assertIsNone(self.get_qos_for_port(subnet, port, router,
                                                required=False))

    def test_create_update_delete_qos_l2(self):
        self._crud_verify_qos_bw_limiter()

    def test_create_update_delete_qos_l3(self):
        self._crud_verify_qos_bw_limiter(is_l3=True)

    def test_router_attach_qos(self):
        policy = self.create_qos_policy(name='test-bw-limiter',
                                        description='test policy')
        self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'],
            max_kbps=self.max_kbps,
            max_burst_kbps=self.max_burst_kbps,
            direction='egress')

        # Create
        network = self.create_network(qos_policy_id=policy['id'])
        cidr = netaddr.IPNetwork('10.0.0.0/24')
        subnet = self.create_subnet(network, cidr=cidr)
        port = self.create_port(network, qos_policy_id=policy['id'])
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.router_attach(router, subnet)

        qos = self.get_qos_for_subnet(subnet, router)
        self.verify_qos(policy['id'], qos,
                        peak_rate=str(self.max_kbps / 1000.0),
                        peak_burst_rate=self.max_burst_kbps)
        qos = self.get_qos_for_port(subnet, port, router)
        self.verify_qos(policy['id'], qos,
                        peak_rate=str(self.max_kbps / 1000.0),
                        peak_burst_rate=self.max_burst_kbps)

    def test_ingress_rule_neg(self):
        policy = self.create_qos_policy(name='test-bw-limiter',
                                        description='test policy')
        self.create_qos_bandwidth_limit_rule(
            policy_id=policy['id'],
            max_kbps=self.max_kbps,
            max_burst_kbps=self.max_burst_kbps,
            direction='ingress')
        network = self.create_network()
        cidr = netaddr.IPNetwork('10.0.0.0/24')
        self.create_subnet(network, cidr=cidr)
        self.assertRaisesRegex(
            exceptions.Conflict,
            "Rule bandwidth_limit is not supported by port",
            self.create_port,
            network, qos_policy_id=policy['id'])
