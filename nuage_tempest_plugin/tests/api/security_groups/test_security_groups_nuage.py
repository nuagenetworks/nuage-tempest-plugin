# Copyright 2013 OpenStack Foundation
# All Rights Reserved.
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
import netaddr
import testscenarios

from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants

CONF = Topology.get_conf()
load_tests = testscenarios.load_tests_apply_scenarios


class SecGroupNuageTest(nuage_test.NuageBaseTest):

    is_l3 = False
    # ip_versions: tuple with all ip versions to be used, eg (4, 6)
    ip_versions = (4, 6)

    if Topology.has_single_stack_v6_support():
        scenarios = testscenarios.scenarios.multiply_scenarios([
            ('L3', {'is_l3': True}),
            ('L2', {'is_l3': False})
        ], [
            ('IPv4', {'ip_versions': (4,)}),
            ('IPv6', {'ip_versions': (6,)}),
            ('Dualstack', {'ip_versions': (4, 6)})
        ])
    else:
        scenarios = testscenarios.scenarios.multiply_scenarios([
            ('L3', {'is_l3': True}),
            ('L2', {'is_l3': False})
        ], [
            ('IPv4', {'ip_versions': (4,)}),
            ('Dualstack', {'ip_versions': (4, 6)})
        ])

    @classmethod
    def resource_setup(cls):
        super(SecGroupNuageTest, cls).resource_setup()
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

    def _verify_sg(self, sg, ports, pg_expected_without_port=False,
                   domain=None):
        """_verify_sg

        :param sg: Security Group
        :param ports: Ports currently using SG in class domain
        :param pg_expected_without_port: Is a PG expected even when there are
                                         no ports attached.
        :param domain: VSD domain where the PG is located
        """
        domain = domain or self.domain
        # Retrieve by external id
        ext_id_filter = self.vsd.get_external_id_filter(sg['id'])
        pgs = domain.policy_groups.get(filter=ext_id_filter)
        if ports:
            # PG expected
            self.assertEqual(1, len(pgs),
                             "Unexpected amount of PG found for SG.")
        else:
            if not pg_expected_without_port:
                # Pg cleaned up or never created
                self.assertEmpty(pgs, "Unexpected PG found")
                return
            else:
                # No cleanup expected, verify PG created for previous vport
                self.assertEqual(1, len(pgs),
                                 "Unexpected amount of PG found for SG.")

        pg = pgs[0]
        # Verify PG properties
        self.assertEqual(sg['name'], pg.description)
        self.assertEqual('SOFTWARE', pg.type)

        # Verify attached vports
        vports = pg.vports.get()
        self.assertEqual(len(ports), len(vports))
        expected_ext_port_ids = {self.vsd.external_id(port['id']) for port
                                 in ports}
        actual_ext_vport_ids = {vport.external_id for vport in vports}
        self.assertEqual(expected_ext_port_ids, actual_ext_vport_ids)

        # Verify Sg Rules
        for sg_rule in sg['security_group_rules']:
            self._verify_sg_rule(pg, sg, sg_rule, domain=domain)

    def _verify_sg_rule(self, pg, sg, sg_rule, is_reverse_rule=False,
                        domain=None):
        """_verify_sg_rule

        :param pg: Policygroup
        :param sg: Securitygroup
        :param sg_rule: security group rule to check
        :param is_reverse_rule: True if the rule is a reverse rule of an actual
                                sg_rule. Used for not checking the reverse of a
                                reverse rule.
        :param domain: VSD domain where ACL is located
        """
        domain = domain or self.domain
        is_ipv4 = sg_rule['ethertype'] == 'IPv4'
        stateful_icmp_types = (n_constants.STATEFUL_ICMP_V4_TYPES if is_ipv4
                               else n_constants.STATEFUL_ICMP_V6_TYPES)
        ext_id_filter = self.vsd.get_external_id_filter(sg_rule['id'])
        if sg_rule['direction'] == 'ingress':
            acl_entry = domain.egress_acl_entry_templates.get_first(
                filter=ext_id_filter)
        else:
            acl_entry = domain.ingress_acl_entry_templates.get_first(
                filter=ext_id_filter)
        self.assertIsNotNone(acl_entry,
                             "aclEntryTemplate not found for "
                             "SG Rule: {}".format(sg_rule))
        # Remote group id refers to another Policy Group
        remote_pg = None
        if sg_rule.get('remote_group_id'):
            ext_id_filter = self.vsd.get_external_id_filter(
                sg_rule['remote_group_id'])
            remote_pgs = domain.policy_groups.get(ext_id_filter)
            self.assertNotEmpty(remote_pgs, "Remote PG not found")
            remote_pg = remote_pgs[0]
        # Remote ip prefix refers to enterprise network / network macro
        enterprise_network = None
        if sg_rule.get('remote_ip_prefix'):
            ip_network = netaddr.IPNetwork(sg_rule['remote_ip_prefix'])
            enterprise_network = self._get_enterprise_network(ip_network)
        # Ethertype
        self.assertEqual(
            n_constants.PROTO_NAME_TO_NUM[sg_rule['ethertype']],
            acl_entry.ether_type)
        # Protocol
        os_protocol = sg_rule['protocol']
        try:
            expected_protocol = int(os_protocol)
        except (ValueError, TypeError):
            if not os_protocol:
                expected_protocol = 'ANY'
            elif os_protocol == 'icmp' and sg_rule['ethertype'] == 'IPv6':
                expected_protocol = n_constants.PROTO_NAME_TO_NUM['icmpv6']
            else:
                expected_protocol = n_constants.PROTO_NAME_TO_NUM[
                    os_protocol]
        self.assertEqual(expected_protocol, acl_entry.protocol)
        # Stateful
        if not sg['stateful']:
            expected_stateful = False
        elif str(os_protocol) in ['icmp', 'icmpv6', 'ipv6-icmp', 1, 58]:
            if Topology.up_to_nuage('5.4') and not is_ipv4:
                # no support for icmp v6 in 5.4
                expected_stateful = True
            else:
                # ICMP rules are not stateful unless special cases
                if (not sg_rule['port_range_min'] and not
                        sg_rule['port_range_max']):
                    expected_stateful = False
                elif (sg_rule['port_range_min'] not in
                      stateful_icmp_types):
                    expected_stateful = False
                else:
                    expected_stateful = True
        else:
            expected_stateful = True
        self.assertEqual(expected_stateful, acl_entry.stateful)
        # Network Type
        if (sg_rule.get('remote_group_id') or
                sg_rule.get('remote_external_group_id')):
            expected_network_type = 'POLICYGROUP'
        elif sg_rule.get('remote_ip_prefix'):
            expected_network_type = 'ENTERPRISE_NETWORK'
        else:
            if Topology.from_nuage('20.10'):
                expected_network_type = 'ANY'
            else:
                # Legacy usage of ANY network macro / enterprise network
                expected_network_type = 'ENTERPRISE_NETWORK'
        self.assertEqual(expected_network_type, acl_entry.network_type)
        # Network ID
        if sg_rule.get('remote_external_group_id'):
            expected_network_id = sg_rule['remote_external_group_id']
        elif sg_rule.get('remote_ip_prefix'):
            expected_network_id = enterprise_network.id
        elif sg_rule.get('remote_group_id'):
            expected_network_id = remote_pg.id
        else:
            if Topology.from_nuage('20.10'):
                # No network id, as ANY type is used
                expected_network_id = None
            else:
                # Legacy usage of ANY network macro / enterprise network
                address = '0.0.0.0/0' if is_ipv4 else '::/0'
                ip_network = netaddr.IPNetwork(address)
                enterprise_network = self._get_enterprise_network(
                    ip_network)
                expected_network_id = enterprise_network.id
        self.assertEqual(expected_network_id, acl_entry.network_id)
        # Location type
        self.assertEqual('POLICYGROUP', acl_entry.location_type)
        # Location ID
        self.assertEqual(pg.id, acl_entry.location_id)
        # Action
        self.assertEqual('FORWARD', acl_entry.action)
        # DSCP
        self.assertEqual('*', acl_entry.dscp)
        # TCP/UDP specific attributes
        if sg_rule['protocol'] in ['tcp', 'udp']:
            # Source port
            self.assertEqual('*', acl_entry.source_port)
            # Destination port
            if (not sg_rule['port_range_min'] and not
                    sg_rule['port_range_max']):
                expected_dest_port = '*'
            elif sg_rule['port_range_min'] == sg_rule['port_range_max']:
                expected_dest_port = str(sg_rule['port_range_min'])
            else:
                expected_dest_port = '{}-{}'.format(
                    sg_rule['port_range_min'],
                    sg_rule['port_range_max'])
            self.assertEqual(expected_dest_port,
                             acl_entry.destination_port)
        # ICMP specific attributes
        elif sg_rule['protocol'] in ['icmp', 'icmpv6', 'ipv6-icmp', 1, 58]:
            if sg_rule['port_range_min']:
                self.assertEqual(str(sg_rule['port_range_min']),
                                 acl_entry.icmp_type)
            if sg_rule['port_range_max']:
                self.assertEqual(str(sg_rule['port_range_max']),
                                 acl_entry.icmp_code)
            # check reverse ICMP rule if needed
            if Topology.up_to_nuage('5.4') and not is_ipv4:
                # no support for icmpv6 reverse rules
                return
            else:
                acl_icmp_type = (int(acl_entry.icmp_type) if
                                 acl_entry.icmp_type != '*' else '*')
                if (acl_icmp_type not in stateful_icmp_types and not
                        is_reverse_rule):
                    sg_rule['direction'] = ('ingress' if
                                            sg_rule['direction'] == 'egress'
                                            else 'egress')
                    self._verify_sg_rule(pg, sg, sg_rule, is_reverse_rule=True,
                                         domain=domain)

    def _get_enterprise_network(self, ip_network):
        if ip_network.version == 4:
            vsd_filter = 'address IS "{}" and netmask IS "{}"'.format(
                ip_network.ip, ip_network.netmask)
        else:
            vsd_filter = 'IPv6Address IS "{}"'.format(ip_network)
        enterprise_network = (self.vsd.get_default_enterprise().
                              enterprise_networks.get_first(
                              filter=vsd_filter))
        self.assertIsNotNone(enterprise_network)
        return enterprise_network

    @decorators.attr(type='smoke')
    def test_create_update_delete_sg(self):
        sg = self.create_security_group()
        sg2 = self.create_security_group()
        # Create for ipversions:
        # - normal rule, for all applicable protocols
        # - normal rule, TCP protocol, port 80
        # - normal rule, UDP protocol, port 80, egress
        # - networkmacro rule for 90.0.0.0/24
        # - remote group id rule for SG2
        for ip_version in self.ip_versions:
            ethertype = 'IPv' + str(ip_version)

            # - normal rule, for all applicable protocols
            if ip_version == 6:
                if Topology.up_to_openstack('stein'):
                    protocols = (n_constants.IPV6_PROTO_NAME +
                                 [n_constants.IPV6_PROTO_NAME_LEGACY])
                else:
                    # Train onwards, legacy is canonicalized
                    # https://review.opendev.org/#/c/453346/14
                    protocols = n_constants.IPV6_PROTO_NAME
            else:
                protocols = n_constants.IPV4_PROTO_NAME
            for protocol in protocols:
                self.create_security_group_rule_with_manager(
                    sg, protocol=protocol, direction='ingress',
                    ethertype=ethertype)
            # - normal rule, TCP protocol, port 80
            self.create_security_group_rule_with_manager(
                sg, protocol='tcp', direction='ingress',
                ethertype=ethertype, port_range_min=80,
                port_range_max=80)
            # - normal rule, UDP protocol, port 80, egress
            self.create_security_group_rule_with_manager(
                sg, protocol='udp', direction='egress',
                ethertype=ethertype, port_range_min=80,
                port_range_max=80)
            # - networkmacro rule for 90.0.0.0/24 or cafe:babe::/64
            remote_ip_prefix = ('90.0.0.0/24' if ip_version == 4 else
                                'cafe:babe::/64')
            self.create_security_group_rule_with_manager(
                sg, direction='egress',
                ethertype=ethertype, remote_ip_prefix=remote_ip_prefix)
            # - remote group id rule for SG2
            self.create_security_group_rule_with_manager(
                sg, direction='egress',
                ethertype=ethertype, remote_group_id=sg2['id'])

        port = self.create_port(self.network, security_groups=[sg['id']])
        # Verify VSD
        # Get updated SG with SGRules
        sg = self.get_security_group(sg['id'])
        self._verify_sg(sg, ports=[port])

        # Update Security group name
        name = "updated SG name"
        sg = self.update_security_group(sg, name=name)
        self._verify_sg(sg, ports=[port])

        # Delete port from SG
        self.delete_port(port)
        # cleanup happens before 20.10, not after.
        pg_expected = Topology.from_nuage('20.10')
        self._verify_sg(sg, ports=[], pg_expected_without_port=pg_expected)

    def test_sg_rule_icmp(self):
        # ICMP has stateless and stateful types
        sg = self.create_security_group()
        for ip_version in self.ip_versions:
            if Topology.up_to_nuage('5.4') and ip_version == 6:
                # do not test ipv6 icmp on 5.4 and below
                continue

            ethertype = 'IPv' + str(ip_version)
            stateful_types = (n_constants.STATEFUL_ICMP_V4_TYPES if
                              ip_version == 4 else
                              n_constants.STATEFUL_ICMP_V6_TYPES)
            icmp_protocol = 'icmp' if ip_version == 4 else 'ipv6-icmp'
            # Create stateful rules
            for stateful_type in stateful_types:
                self.create_security_group_rule_with_manager(
                    security_group=sg, direction='ingress',
                    ethertype=ethertype, protocol=icmp_protocol,
                    port_range_min=stateful_type, port_range_max=0)
            # Create stateless rule: icmp_type: 69
            self.create_security_group_rule_with_manager(
                security_group=sg, direction='egress',
                ethertype=ethertype, protocol=icmp_protocol,
                port_range_min=69, port_range_max=0)
            # Check for cross-contamination between IPV4 and IPV6 stateful
            # types by creating with icmp_code that is stateful in the
            # other ethertype
            all_stateful_types = (n_constants.STATEFUL_ICMP_V4_TYPES +
                                  n_constants.STATEFUL_ICMP_V6_TYPES)
            for stateful_type in all_stateful_types:
                if stateful_type not in stateful_types:
                    self.create_security_group_rule_with_manager(
                        security_group=sg, direction='ingress',
                        ethertype=ethertype, protocol=icmp_protocol,
                        port_range_min=stateful_type, port_range_max=0)
            # Check legacy icmpv6 usage
            if ip_version == 6:
                self.create_security_group_rule_with_manager(
                    security_group=sg, direction='egress',
                    ethertype=ethertype, protocol='icmpv6',
                    port_range_min=68, port_range_max=0)

        sg = self.get_security_group(sg['id'])

        port = self.create_port(self.network, security_groups=[sg['id']])
        # Verify VSD
        # Get updated SG with SGRules
        sg = self.get_security_group(sg['id'])
        self._verify_sg(sg, ports=[port])

    def test_sg_multiple_domains(self):
        network2 = self.create_network()
        subnet4 = subnet6 = None
        if 4 in self.ip_versions:
            subnet4 = self.create_subnet(network2, ip_version=4)
        if 6 in self.ip_versions:
            subnet6 = self.create_subnet(network2, ip_version=6)
        if self.is_l3:
            router = self.create_router()
            if subnet4:
                self.router_attach(router, subnet4)
            if subnet6:
                self.router_attach(router, subnet6)
            domain2 = self.vsd.get_l3_domain_by_subnet(
                subnet4 or subnet6)
        else:
            domain2 = self.vsd.get_l2domain(
                by_subnet=subnet4 or subnet6)

        # Create PG with rules, in self.network and network2
        sg = self.create_security_group()
        for ip_version in self.ip_versions:
            ethertype = 'IPv' + str(ip_version)
            self.create_security_group_rule_with_manager(
                security_group=sg, direction='egress',
                ethertype=ethertype, protocol='tcp',
                port_range_min=1830, port_range_max=1830)
        port = self.create_port(self.network, security_groups=[sg['id']])
        port2 = self.create_port(network2, security_groups=[sg['id']])
        # Verify VSD
        # Get updated SG with SGRules
        sg = self.get_security_group(sg['id'])
        self._verify_sg(sg, ports=[port])
        self._verify_sg(sg, ports=[port2], domain=domain2)

    def test_create_security_group_rule_invalid_ip_prefix_negative(self):
        # /0 cidr for a non-single ip prefix
        if 4 not in self.ip_versions:
            self.skipTest("Invalid ip prefix only applicable to IPv4")
        sg = self.create_security_group()
        self.create_security_group_rule_with_manager(
            security_group=sg, direction='ingress',
            ethertype='IPv4', protocol='tcp',
            port_range_min=76,
            port_range_max=77,
            remote_ip_prefix='192.168.1.0/0')
        msg = ('Non supported remote CIDR in security rule:'
               ' Does not match n.n.n.n where n=1-3'
               ' decimal digits and the mask is not all zeros , '
               'address is 192.168.1.0 , mask is 0.0.0.0')
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_port, self.network,
                               security_groups=[sg['id']])

    def test_create_security_group_rule_invalid_nw_macro_negative(self):
        # Non /0 cidr for a single ip prefix.
        if 4 not in self.ip_versions:
            self.skipTest("Invalid ip prefix only applicable to IPv4")

        sg = self.create_security_group()
        self.create_security_group_rule_with_manager(
            security_group=sg, direction='ingress',
            ethertype='IPv4', protocol='tcp',
            port_range_min=1914, port_range_max=1918,
            remote_ip_prefix='172.16.50.210/24')
        msg = ('Non supported remote CIDR in security rule:'
               ' Network IP Address 172.16.50.210 must have'
               ' host bits set to 0.')
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_port, self.network,
                               security_groups=[sg['id']])

    def test_create_security_group_rule_ipv6_ip_prefix(self):
        if 6 not in self.ip_versions:
            self.skipTest("Longer ip prefix only applicable to IPv6")

        sg = self.create_security_group()
        for prefix in [0, 1, 30, 63, 64, 65, 127, 128]:
            if prefix == 0:
                ip_prefix = '::/' + str(prefix)
            else:
                ip_prefix = '2001::/' + str(prefix)
            self.create_security_group_rule_with_manager(
                security_group=sg, direction='ingress',
                ethertype="IPv6", protocol='tcp',
                port_range_min=1940, port_range_max=1945,
                remote_ip_prefix=ip_prefix)
        port = self.create_port(self.network, security_groups=[sg['id']])
        self._verify_sg(sg, [port])

    def test_security_group_rule_invalid_ip_prefix_update_port_negative(self):
        # Update port with invalid security group
        if 4 not in self.ip_versions:
            self.skipTest("Invalid ip prefix only applicable to IPv4")
        sg = self.create_security_group()
        self.create_security_group_rule_with_manager(
            security_group=sg, direction='ingress',
            ethertype='IPv4', protocol='tcp',
            port_range_min=1815, port_range_max=1830,
            remote_ip_prefix='192.168.1.0/0')
        msg = ('Non supported remote CIDR in security rule:'
               ' Does not match n.n.n.n where n=1-3'
               ' decimal digits and the mask is not all zeros , address is'
               ' 192.168.1.0 , mask is 0.0.0.0')
        port = self.create_port(self.network, security_groups=[])
        # Update port with illegal security group -> assert nothing changed
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.update_port,
                               port, security_groups=[sg['id']])

        ext_id_filter = self.vsd.get_external_id_filter(sg['id'])
        pgs = self.domain.policy_groups.get(filter=ext_id_filter)
        self.assertEqual(len(pgs), 0)

        ext_id_filter = self.vsd.get_external_id_filter(port['id'])
        vport = self.domain.vports.get(filter=ext_id_filter)[0]
        self.assertEmpty(vport.policy_groups.get())

    def test_remote_group_id_before_port_usage(self):
        """test_remote_ip_prefix_before_port_usage

        Use a SG as remote group id before using it on a port.
        """
        sg = self.create_security_group()
        sg2 = self.create_security_group()
        for ip_version in self.ip_versions:
            ethertype = 'IPv' + str(ip_version)
            self.create_security_group_rule_with_manager(
                security_group=sg, direction='egress',
                ethertype=ethertype, protocol='tcp',
                port_range_min=1830, port_range_max=1830)
            self.create_security_group_rule_with_manager(
                security_group=sg2, direction='ingress',
                ethertype=ethertype, protocol='tcp',
                port_range_min=1789, port_range_max=1799)
            # Use SG2 as a remote group id in SG1
            self.create_security_group_rule_with_manager(
                security_group=sg, direction='egress',
                ethertype=ethertype, remote_group_id=sg2['id'])
        port = self.create_port(self.network, security_groups=[sg['id']])
        sg = self.get_security_group(sg['id'])
        sg2 = self.get_security_group(sg2['id'])
        self._verify_sg(sg, [port])
        # Verify the entire SG was created correctly even though it is not used
        self._verify_sg(sg2, [], pg_expected_without_port=True)
        port2 = self.create_port(self.network, security_groups=[sg2['id']])
        self._verify_sg(sg2, [port2])

    def test_circular_remote_group_id(self):
        """"test_circular_remote_group_id

        Test whether a circular dependency between two SG within their rules
        is handled.
        """
        sg = self.create_security_group()
        sg2 = self.create_security_group()
        for ip_version in self.ip_versions:
            ethertype = 'IPv' + str(ip_version)
            self.create_security_group_rule_with_manager(
                security_group=sg, direction='egress',
                ethertype=ethertype, remote_group_id=sg2['id'])
            self.create_security_group_rule_with_manager(
                security_group=sg2, direction='egress',
                ethertype=ethertype, remote_group_id=sg['id'])
        port = self.create_port(self.network, security_groups=[sg['id']])
        sg = self.get_security_group(sg['id'])
        sg2 = self.get_security_group(sg2['id'])
        self._verify_sg(sg, [port])
        self._verify_sg(sg2, [], pg_expected_without_port=True)


class TestSecGroupScaleTestRouterAttach(nuage_test.NuageBaseTest):

    def test_pg_id_exhausted_for_this_resource(self):
        # Create a network
        name = data_utils.rand_name('network-')
        network = self.create_network(name)

        # Create a subnet
        subnet = self.create_subnet(network)

        # Create a router
        name = data_utils.rand_name('router-')
        router = self.create_router(
            name, external_network_id=CONF.network.public_network_id)

        # Create security groups
        self.create_security_group()
        sgA = self.create_security_group()
        sgB = self.create_security_group()
        sgC = self.create_security_group()
        sgD = self.create_security_group()
        sgE = self.create_security_group()
        sgF = self.create_security_group()

        # Create security group rules
        self.create_security_group_rule_with_manager(
            sgA, remote_ip_prefix='10.1.129.0/24', protocol='tcp',
            direction='ingress')
        self.create_security_group_rule_with_manager(
            sgA, remote_ip_prefix='192.168.0.0/16', protocol='tcp',
            port_range_min=22, port_range_max=22, direction='ingress')
        self.create_security_group_rule_with_manager(sgA,
                                                     remote_group_id=sgA['id'],
                                                     protocol='icmp',
                                                     direction='ingress')
        self.create_security_group_rule_with_manager(sgA,
                                                     remote_group_id=sgB['id'],
                                                     protocol='tcp',
                                                     port_range_min=2344,
                                                     port_range_max=2344,
                                                     direction='ingress')
        self.create_security_group_rule_with_manager(sgA,
                                                     remote_group_id=sgF['id'],
                                                     protocol='udp',
                                                     port_range_min=161,
                                                     port_range_max=161,
                                                     direction='ingress')
        self.create_security_group_rule_with_manager(sgB,
                                                     remote_group_id=sgA['id'],
                                                     protocol='tcp',
                                                     port_range_min=2344,
                                                     port_range_max=2344,
                                                     direction='ingress')
        self.create_security_group_rule_with_manager(sgB,
                                                     remote_group_id=sgB['id'],
                                                     protocol='tcp',
                                                     direction='ingress')
        self.create_security_group_rule_with_manager(sgC,
                                                     remote_group_id=sgC['id'],
                                                     protocol='tcp',
                                                     direction='ingress')
        self.create_security_group_rule_with_manager(sgD,
                                                     remote_group_id=sgD['id'],
                                                     protocol='tcp',
                                                     direction='ingress')
        self.create_security_group_rule_with_manager(sgE,
                                                     remote_group_id=sgA['id'],
                                                     protocol='tcp',
                                                     port_range_min=12000,
                                                     port_range_max=12000,
                                                     direction='ingress')
        self.create_security_group_rule_with_manager(sgE,
                                                     remote_group_id=sgE['id'],
                                                     protocol='tcp',
                                                     direction='ingress')
        self.create_security_group_rule_with_manager(sgE,
                                                     remote_group_id=sgF['id'],
                                                     protocol='tcp',
                                                     port_range_min=1566,
                                                     port_range_max=1566,
                                                     direction='ingress')
        self.create_security_group_rule_with_manager(sgF,
                                                     remote_group_id=sgA['id'],
                                                     protocol='udp',
                                                     port_range_min=162,
                                                     port_range_max=162,
                                                     direction='ingress')
        self.create_security_group_rule_with_manager(sgF,
                                                     remote_group_id=sgF['id'],
                                                     protocol='tcp',
                                                     direction='ingress')

        # Create ports
        self.create_port(network)
        self.create_port(network, security_groups=[sgA['id'], sgB['id']])
        self.create_port(network, security_groups=[sgC['id'], sgA['id']])
        self.create_port(network, security_groups=[sgE['id'], sgA['id']])
        self.create_port(network, security_groups=[sgD['id'], sgA['id'],
                                                   sgB['id']])
        self.create_port(network, security_groups=[sgF['id'], sgA['id']])
        self.create_port(network, security_groups=[sgA['id']])
        self.create_port(network, security_groups=[sgC['id'], sgA['id']])
        self.create_port(network, security_groups=[sgD['id'], sgA['id']])
        self.create_port(network, security_groups=[sgD['id'], sgA['id']])

        self.router_attach(router, subnet)
