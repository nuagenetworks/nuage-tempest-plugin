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
from tempest.lib import decorators
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
        return body['bandwidth_limit_rule']

    def create_qos_dscp_mark_rule(self, policy_id, dscp_mark):
        body = self.neutron_client.create_dscp_marking_rule(
            policy_id=policy_id, dscp_mark=dscp_mark)
        return body['dscp_marking_rule']

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

    def get_adv_fwd_rules(self, domain, vsd_subnet=None, vsd_port=None,
                          required=True):
        if vsd_subnet:
            filter = "'locationID' == '{}'".format(vsd_subnet.id)
        elif vsd_port:
            filter = "'locationType' == 'POLICYGROUP'"
        else:
            filter = "'locationType' == 'ANY'"
        ingress_adv_fwd_templates = domain.ingress_adv_fwd_templates.get()
        self.assertEqual(1, len(ingress_adv_fwd_templates))
        entries = ingress_adv_fwd_templates[
            0].ingress_adv_fwd_entry_templates.get(filter=filter)
        if vsd_port:
            # Filter out irrelevant Pg
            filtered_entries = []
            for entry in entries:
                policygroup_id = entry.location_id
                pg = self.vsd.vspk.NUPolicyGroup(id=policygroup_id)
                pg.fetch()
                vports = pg.vports.get()
                if vsd_port.id in [vport.id for vport in vports]:
                    filtered_entries.append(entry)
            entries = filtered_entries
        # One ipv4 & One ipv6 rule
        if required:
            self.assertEqual(2, len(entries))
        return entries

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

    def verify_adv_fwd_rules(self, policy_id, rules, dscp_mark, is_l3=False,
                             vsd_subnet=None, vsd_port=None):
        prefix = 'OS_QOS_'
        found_ether_types = []
        for rule in rules:
            found_ether_types.append(rule.ether_type)
            if vsd_port:
                self.assertEqual('POLICYGROUP', rule.location_type)
                policygroup_id = rule.location_id
                pg = self.vsd.vspk.NUPolicyGroup(id=policygroup_id)
                pg.fetch()
                self.assertEqual(self.vsd.external_id(policy_id),
                                 rule.external_id,
                                 'External ID not policy ID.')
                self.assertEqual(prefix + policy_id, pg.name)
                self.assertEqual(prefix + policy_id, pg.description)
                self.assertIn(vsd_port.id,
                              [vport.id for vport in pg.vports.get()])
            elif is_l3:
                self.assertEqual('SUBNET', rule.location_type)
                self.assertEqual(vsd_subnet.id, rule.location_id)
            else:
                # L2Domain
                self.assertEqual('ANY', rule.location_type)
            self.assertEqual(self.vsd.external_id(policy_id),
                             rule.external_id,
                             'External ID not policy ID.')
            self.assertEqual(prefix + policy_id, rule.description)
            self.assertEqual('FORWARD', rule.action)
            self.assertEqual(str(dscp_mark), rule.dscp_remarking)

        self.assertEqual(2, len(found_ether_types))
        self.assertIn('0x0800', found_ether_types)
        self.assertIn('0x86DD', found_ether_types)


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

    @decorators.attr(type='smoke')
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


class DSCPRemarkingNuageQosTest(BaseNuageQOSTest):

    def _test_crud_dscp_marking(self, is_l3=False):
        policy = self.create_qos_policy(name='test-dscp',
                                        description='test policy')
        rule = self.create_qos_dscp_mark_rule(
            policy_id=policy['id'],
            dscp_mark=0)
        policy2 = self.create_qos_policy(name='test-dscp',
                                         description='test policy')
        self.create_qos_dscp_mark_rule(
            policy_id=policy2['id'],
            dscp_mark=8)

        # Create
        network = self.create_network(qos_policy_id=policy['id'])
        cidr = netaddr.IPNetwork('10.0.0.0/24')
        subnet = self.create_subnet(network, cidr=cidr)
        port = self.create_port(network, qos_policy_id=policy['id'])
        vsd_subnet = None
        if is_l3:
            router = self.create_router(
                external_network_id=CONF.network.public_network_id)
            self.router_attach(router, subnet)
            # Re-attach qos policy because of VSD-48513
            self.update_network(network['id'], qos_policy_id=None)
            self.update_network(network['id'], qos_policy_id=policy['id'])
            self.update_port(port, qos_policy_id=None)
            domain = self.vsd.get_domain(by_router_id=router['id'])
            pg = domain.policy_groups.get(
                filter="'description' ISNOT 'default'")[0]
            pg.delete()
            self.update_port(port, qos_policy_id=policy['id'])
            domain = self.vsd.get_domain(by_router_id=router['id'])
            vsd_subnet = self.vsd.get_subnet(by_subnet=subnet)
        else:
            domain = self.vsd.get_l2domain(by_subnet=subnet)
        vport = domain.vports.get()[0]

        adv_fwd_rules_subnet = self.get_adv_fwd_rules(domain,
                                                      vsd_subnet=vsd_subnet)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_subnet,
                                  dscp_mark=0,
                                  is_l3=is_l3, vsd_subnet=vsd_subnet)
        adv_fwd_rules_port = self.get_adv_fwd_rules(domain, vsd_port=vport)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_port,
                                  dscp_mark=0,
                                  is_l3=is_l3, vsd_port=vport)
        self.assertLess(max([r.priority for r in adv_fwd_rules_port]),
                        min([r.priority for r in adv_fwd_rules_subnet]))

        # Update policy
        self.neutron_client.update_dscp_marking_rule(
            policy['id'],
            rule['id'],
            dscp_mark=10)
        adv_fwd_rules_subnet = self.get_adv_fwd_rules(domain,
                                                      vsd_subnet=vsd_subnet)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_subnet,
                                  dscp_mark=10,
                                  is_l3=is_l3, vsd_subnet=vsd_subnet)
        adv_fwd_rules_port = self.get_adv_fwd_rules(domain, vsd_port=vport)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_port,
                                  dscp_mark=10,
                                  is_l3=is_l3, vsd_port=vport)
        self.assertLess(max([r.priority for r in adv_fwd_rules_port]),
                        min([r.priority for r in adv_fwd_rules_subnet]))

        # Update network by creating second subnet, always l2
        cidr2 = netaddr.IPNetwork('20.0.0.0/24')
        subnet2 = self.create_subnet(network, cidr=cidr2)
        domain2 = self.vsd.get_l2domain(by_subnet=subnet2)
        adv_fwd_rules_subnet = self.get_adv_fwd_rules(domain2)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_subnet,
                                  dscp_mark=10, is_l3=False)

        # Update to different policy
        self.update_network(network['id'], qos_policy_id=policy2['id'])
        adv_fwd_rules_subnet = self.get_adv_fwd_rules(domain,
                                                      vsd_subnet=vsd_subnet)
        self.verify_adv_fwd_rules(policy2['id'], rules=adv_fwd_rules_subnet,
                                  dscp_mark=8,
                                  is_l3=is_l3, vsd_subnet=vsd_subnet)
        self.update_port(port, qos_policy_id=policy2['id'])
        adv_fwd_rules_port = self.get_adv_fwd_rules(domain, vsd_port=vport)
        self.verify_adv_fwd_rules(policy2['id'], rules=adv_fwd_rules_port,
                                  dscp_mark=8,
                                  is_l3=is_l3, vsd_port=vport)
        self.assertLess(max([r.priority for r in adv_fwd_rules_port]),
                        min([r.priority for r in adv_fwd_rules_subnet]))

        # Disassociate
        self.update_network(network['id'], qos_policy_id=None)
        self.assertEmpty(self.get_adv_fwd_rules(
            domain, vsd_subnet=vsd_subnet, required=False))
        self.update_port(port, qos_policy_id=None)
        self.assertEmpty(self.get_adv_fwd_rules(domain, vsd_port=vport,
                                                required=False))

    def test_create_update_delete_dscp_mark_l2(self):
        self._test_crud_dscp_marking(is_l3=False)

    def test_create_update_delete_dscp_mark_l3(self):
        self._test_crud_dscp_marking(is_l3=True)

    def test_router_attach_dscp(self):
        """test_router_attach_dscp

        Test that when attaching a subnet to a router, the AdvFwdEntries keep
        their original priorities.
        """
        policy = self.create_qos_policy(name='test-dscp',
                                        description='test policy')
        self.create_qos_dscp_mark_rule(
            policy_id=policy['id'],
            dscp_mark=0)

        # Create
        network = self.create_network(qos_policy_id=policy['id'])
        cidr = netaddr.IPNetwork('10.0.0.0/24')
        subnet = self.create_subnet(network, cidr=cidr)
        self.create_port(network, qos_policy_id=policy['id'])
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        domain = self.vsd.get_l2domain(by_subnet=subnet)
        vport = domain.vports.get()[0]
        adv_fwd_rules_subnet_orig = self.get_adv_fwd_rules(domain)
        adv_fwd_rules_port_orig = self.get_adv_fwd_rules(domain,
                                                         vsd_port=vport)

        self.router_attach(router, subnet)
        domain = self.vsd.get_domain(by_router_id=router['id'])
        vsd_subnet = self.vsd.get_subnet(by_subnet=subnet)
        vport = domain.vports.get()[0]

        adv_fwd_rules_subnet = self.get_adv_fwd_rules(domain,
                                                      vsd_subnet=vsd_subnet)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_subnet,
                                  dscp_mark=0,
                                  is_l3=True, vsd_subnet=vsd_subnet)
        adv_fwd_rules_port = self.get_adv_fwd_rules(domain, vsd_port=vport)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_port,
                                  dscp_mark=0,
                                  is_l3=True, vsd_port=vport)
        self.assertLess(max([r.priority for r in adv_fwd_rules_port]),
                        min([r.priority for r in adv_fwd_rules_subnet]))

        orig_subnet_priorities = [r.priority for r in
                                  adv_fwd_rules_subnet_orig]
        l3_subnet_priorities = [r.priority for r in adv_fwd_rules_subnet]
        self.assertEqual(orig_subnet_priorities, l3_subnet_priorities)
        orig_port_priorities = [r.priority for r in adv_fwd_rules_port_orig]
        l3_port_priorities = [r.priority for r in adv_fwd_rules_port]
        self.assertEqual(orig_port_priorities, l3_port_priorities)

        adv_fwd_rules_subnet_orig = adv_fwd_rules_subnet
        adv_fwd_rules_port_orig = adv_fwd_rules_port

        self.router_detach(router, subnet)
        domain = self.vsd.get_l2domain(by_subnet=subnet)
        vport = domain.vports.get()[0]

        adv_fwd_rules_subnet = self.get_adv_fwd_rules(domain)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_subnet,
                                  dscp_mark=0,
                                  is_l3=False)
        adv_fwd_rules_port = self.get_adv_fwd_rules(domain, vsd_port=vport)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_port,
                                  dscp_mark=0,
                                  is_l3=False, vsd_port=vport)
        self.assertLess(max([r.priority for r in adv_fwd_rules_port]),
                        min([r.priority for r in adv_fwd_rules_subnet]))

        orig_subnet_priorities = [r.priority for r in
                                  adv_fwd_rules_subnet_orig]
        l2_subnet_priorities = [r.priority for r in adv_fwd_rules_subnet]
        self.assertEqual(orig_subnet_priorities, l2_subnet_priorities)
        orig_port_priorities = [r.priority for r in
                                adv_fwd_rules_port_orig]
        l2_port_priorities = [r.priority for r in adv_fwd_rules_port]
        self.assertEqual(orig_port_priorities, l2_port_priorities)

        # Check router
        domain = self.vsd.get_domain(by_router_id=router['id'])
        pgs = domain.policy_groups.get()
        self.assertEqual(2, len(pgs), "Unexpected number of PGs found on "
                                      "l3domain.")
        template = domain.ingress_adv_fwd_templates.get()
        self.assertEqual(1, len(template), "Unexpected number of Ingress Adv"
                                           "Fwd templates found on l3domain.")
        rules = template[0].ingress_adv_fwd_entry_templates.get()
        self.assertEqual(2, len(rules), "Unexpected number of Ingress Adv"
                                        "Fwd Rules found on l3domain.")

    def test_router_attach_conflicting_priorities(self):
        """test_router_attach_conflicting_priorities

        Test that when attaching two l2domains to the same l3domain, with
        AdvFwdRules that have the exact same priority, the priority is
        recalculated by VSD correctly, preserving the order between network
        and port dscp rules.

        :return:
        """
        policy = self.create_qos_policy(name='test-dscp',
                                        description='test policy')
        self.create_qos_dscp_mark_rule(
            policy_id=policy['id'],
            dscp_mark=0)
        policy2 = self.create_qos_policy(name='test-dscp2',
                                         description='test policy')
        self.create_qos_dscp_mark_rule(
            policy_id=policy2['id'],
            dscp_mark=10)

        network = self.create_network(qos_policy_id=policy['id'])
        cidr = netaddr.IPNetwork('10.0.0.0/24')
        subnet = self.create_subnet(network, cidr=cidr)
        self.create_port(network, qos_policy_id=policy['id'])
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        network2 = self.create_network(qos_policy_id=policy2['id'])
        cidr = netaddr.IPNetwork('20.0.0.0/24')
        subnet2 = self.create_subnet(network2, cidr=cidr)
        self.create_port(network2, qos_policy_id=policy2['id'])

        # Set priorities of subnet2 to be the same as those for subnet1
        domain = self.vsd.get_l2domain(by_subnet=subnet)
        vport = domain.vports.get()[0]
        adv_fwd_rules_subnet = self.get_adv_fwd_rules(domain)
        adv_fwd_rules_port = self.get_adv_fwd_rules(domain,
                                                    vsd_port=vport)
        domain2 = self.vsd.get_l2domain(by_subnet=subnet2)
        vport2 = domain2.vports.get()[0]
        adv_fwd_rules_subnet2 = self.get_adv_fwd_rules(domain2)
        adv_fwd_rules_port2 = self.get_adv_fwd_rules(domain2,
                                                     vsd_port=vport2)
        adv_fwd_rules_subnet2[0].priority = adv_fwd_rules_subnet[0].priority
        adv_fwd_rules_subnet2[0].save()
        adv_fwd_rules_subnet2[1].priority = adv_fwd_rules_subnet[1].priority
        adv_fwd_rules_subnet2[1].save()
        adv_fwd_rules_port2[0].priority = adv_fwd_rules_port[0].priority
        adv_fwd_rules_port2[0].save()
        adv_fwd_rules_port2[1].priority = adv_fwd_rules_port[1].priority
        adv_fwd_rules_port2[1].save()

        # router attach both
        self.router_attach(router, subnet)
        self.router_attach(router, subnet2)

        # Subnet rules
        domain = self.vsd.get_domain(by_router_id=router['id'])
        vsd_subnet = self.vsd.get_subnet(by_subnet=subnet)
        vsd_subnet2 = self.vsd.get_subnet(by_subnet=subnet2)

        adv_fwd_rules_subnet = self.get_adv_fwd_rules(domain,
                                                      vsd_subnet=vsd_subnet)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_subnet,
                                  dscp_mark=0, is_l3=True,
                                  vsd_subnet=vsd_subnet)
        adv_fwd_rules_subnet2 = self.get_adv_fwd_rules(domain,
                                                       vsd_subnet=vsd_subnet2)
        self.verify_adv_fwd_rules(policy2['id'], rules=adv_fwd_rules_subnet2,
                                  dscp_mark=10, is_l3=True,
                                  vsd_subnet=vsd_subnet2)
        vport = vsd_subnet.vports.get()[0]
        vport2 = vsd_subnet2.vports.get()[0]

        adv_fwd_rules_port = self.get_adv_fwd_rules(domain, vsd_port=vport)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_port,
                                  dscp_mark=0, is_l3=True, vsd_port=vport)
        adv_fwd_rules_port2 = self.get_adv_fwd_rules(domain, vsd_port=vport2)
        self.verify_adv_fwd_rules(policy2['id'], rules=adv_fwd_rules_port2,
                                  dscp_mark=10, is_l3=True, vsd_port=vport2)

        self.assertLess(max([r.priority for r in adv_fwd_rules_port]),
                        min([r.priority for r in adv_fwd_rules_subnet]))
        self.assertLess(max([r.priority for r in adv_fwd_rules_port2]),
                        min([r.priority for r in adv_fwd_rules_subnet2]))

    def test_router_attach_merge_policy(self):
        """test_router_attach_merge_policy

        Test that when two subnets with the same policy are attached or
        detached to a router, Adv Fwd Templates are transfered correctly.
        """
        policy = self.create_qos_policy(name='test-dscp',
                                        description='test policy')
        self.create_qos_dscp_mark_rule(
            policy_id=policy['id'],
            dscp_mark=0)

        network = self.create_network(qos_policy_id=policy['id'])
        cidr = netaddr.IPNetwork('10.0.0.0/24')
        subnet = self.create_subnet(network, cidr=cidr)
        self.create_port(network, qos_policy_id=policy['id'])
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        network2 = self.create_network(qos_policy_id=policy['id'])
        cidr = netaddr.IPNetwork('20.0.0.0/24')
        subnet2 = self.create_subnet(network2, cidr=cidr)
        self.create_port(network2, qos_policy_id=policy['id'])

        # router attach both
        self.router_attach(router, subnet)
        self.router_attach(router, subnet2)

        domain = self.vsd.get_domain(by_router_id=router['id'])
        vsd_subnet = self.vsd.get_subnet(by_subnet=subnet)
        vsd_subnet2 = self.vsd.get_subnet(by_subnet=subnet)

        adv_fwd_rules_subnet = self.get_adv_fwd_rules(domain,
                                                      vsd_subnet=vsd_subnet)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_subnet,
                                  dscp_mark=0, is_l3=True,
                                  vsd_subnet=vsd_subnet)
        adv_fwd_rules_subnet2 = self.get_adv_fwd_rules(domain,
                                                       vsd_subnet=vsd_subnet2)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_subnet2,
                                  dscp_mark=0, is_l3=True,
                                  vsd_subnet=vsd_subnet2)
        vport = vsd_subnet.vports.get()[0]
        vport2 = vsd_subnet.vports.get()[0]

        adv_fwd_rules_port = self.get_adv_fwd_rules(domain, vsd_port=vport)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_port,
                                  dscp_mark=0, is_l3=True, vsd_port=vport)
        adv_fwd_rules_port2 = self.get_adv_fwd_rules(domain, vsd_port=vport2)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_port2,
                                  dscp_mark=0, is_l3=True, vsd_port=vport2)
        template = domain.ingress_adv_fwd_templates.get()
        all_rules = template[0].ingress_adv_fwd_entry_templates.get()
        self.assertEqual(6, len(all_rules))
        self.assertLess(max([r.priority for r in adv_fwd_rules_port]),
                        min([r.priority for r in adv_fwd_rules_subnet]))
        self.assertLess(max([r.priority for r in adv_fwd_rules_port2]),
                        min([r.priority for r in adv_fwd_rules_subnet2]))

        # Detach and verify unmerge
        self.router_detach(router, subnet)
        self.router_detach(router, subnet2)
        domain = self.vsd.get_l2domain(by_subnet=subnet)
        domain2 = self.vsd.get_l2domain(by_subnet=subnet2)
        vport = domain.vports.get()[0]
        vport2 = domain2.vports.get()[0]
        adv_fwd_rules_subnet = self.get_adv_fwd_rules(domain)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_subnet,
                                  dscp_mark=0, is_l3=False,
                                  vsd_subnet=vsd_subnet)
        adv_fwd_rules_subnet2 = self.get_adv_fwd_rules(domain2)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_subnet2,
                                  dscp_mark=0, is_l3=False,
                                  vsd_subnet=vsd_subnet2)

        adv_fwd_rules_port = self.get_adv_fwd_rules(domain, vsd_port=vport)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_port,
                                  dscp_mark=0, is_l3=False, vsd_port=vport)
        adv_fwd_rules_port2 = self.get_adv_fwd_rules(domain2, vsd_port=vport2)
        self.verify_adv_fwd_rules(policy['id'], rules=adv_fwd_rules_port2,
                                  dscp_mark=0, is_l3=False, vsd_port=vport2)
        template = domain.ingress_adv_fwd_templates.get()
        all_rules = template[0].ingress_adv_fwd_entry_templates.get()
        self.assertEqual(4, len(all_rules))
        template = domain2.ingress_adv_fwd_templates.get()
        all_rules = template[0].ingress_adv_fwd_entry_templates.get()
        self.assertEqual(4, len(all_rules))

        self.assertLess(max([r.priority for r in adv_fwd_rules_port]),
                        min([r.priority for r in adv_fwd_rules_subnet]))
        self.assertLess(max([r.priority for r in adv_fwd_rules_port2]),
                        min([r.priority for r in adv_fwd_rules_subnet2]))
