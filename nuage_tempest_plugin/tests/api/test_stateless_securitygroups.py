# Copyright 2018 NOKIA
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

from testtools import matchers

from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES
from nuage_tempest_plugin.lib.mixins import l3
from nuage_tempest_plugin.lib.mixins import network as network_mixin
from nuage_tempest_plugin.lib.mixins import sg as sg_mixin
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

CONF = Topology.get_conf()


class SecurityGroupsTopology(object):
    def __init__(self, vsd_client, network, subnet,
                 router, security_group):
        super(SecurityGroupsTopology, self).__init__()
        self.vsd_client = vsd_client
        self.network = network
        self.subnet = subnet
        self.router = router
        self.port = None
        self.securitygroup = security_group

    @property
    def vsd_vport_parent(self):
        if not getattr(self, '_vsd_vport_parent', False):
            self._vsd_vport_parent = self.vsd_client.get_global_resource(
                self.vsd_vport_parent_resource,
                filters='externalID',
                filter_value=self.subnet['network_id'])[0]
        return self._vsd_vport_parent

    @property
    def vsd_vport_parent_resource(self):
        if not getattr(self, '_vsd_vport_parent_resource', False):
            if self.router:
                self._vsd_vport_parent_resource = constants.SUBNETWORK
            else:
                self._vsd_vport_parent_resource = constants.L2_DOMAIN
        return self._vsd_vport_parent_resource

    @property
    def vsd_domain(self):
        if not getattr(self, '_vsd_domain', False):
            if self.router:
                zone = self.vsd_client.get_global_resource(
                    constants.ZONE + '/' +
                    self.vsd_vport_parent['parentID'])[0]
                self._vsd_domain = self.vsd_client.get_global_resource(
                    constants.DOMAIN + '/' + zone['parentID'])[0]
            else:
                self._vsd_domain = self.vsd_vport_parent
        return self._vsd_domain

    @property
    def vsd_domain_resource(self):
        if not getattr(self, '_vsd_domain_resource', False):
            if self.router:
                self._vsd_domain_resource = constants.DOMAIN
            else:
                self._vsd_domain_resource = constants.L2_DOMAIN
        return self._vsd_domain_resource

    @property
    def vsd_policygroups(self):
        if not getattr(self, '_vsd_policygroups', False):
            self._vsd_policygroups = self.vsd_client.get_policygroup(
                self.vsd_domain_resource,
                self.vsd_domain['ID'],
                'externalID', self.securitygroup['id'])
        return self._vsd_policygroups

    @property
    def vsd_egress_acl_template(self):
        if not getattr(self, '_vsd_egress_acl_templates', False):
            self._vsd_egress_acl_templates = \
                self.vsd_client.get_egressacl_template(
                    self.vsd_domain_resource,
                    self.vsd_domain['ID'])[0]
        return self._vsd_egress_acl_templates

    @property
    def vsd_egress_acl_entries(self):
        if not getattr(self, '_vsd_egress_acl_entries', False):
            self._vsd_egress_acl_entries = \
                self.vsd_client.get_egressacl_entrytemplate(
                    constants.EGRESS_ACL_TEMPLATE,
                    self.vsd_egress_acl_template['ID'])
            if not self._vsd_egress_acl_entries:
                self._vsd_egress_acl_entries = []
        return self._vsd_egress_acl_entries

    @property
    def vsd_ingress_acl_template(self):
        if not getattr(self, '_vsd_ingress_acl_templates', False):
            self._vsd_ingress_acl_templates = \
                self.vsd_client.get_ingressacl_template(
                    self.vsd_domain_resource,
                    self.vsd_domain['ID'])[0]
        return self._vsd_ingress_acl_templates

    @property
    def vsd_ingress_acl_entries(self):
        if not getattr(self, '_vsd_ingress_acl_entries', False):
            self._vsd_ingress_acl_entries = \
                self.vsd_client.get_ingressacl_entrytemplate(
                    constants.INGRESS_ACL_TEMPLATE,
                    self.vsd_ingress_acl_template['ID'])
            if not self._vsd_ingress_acl_entries:
                self._vsd_ingress_acl_entries = []
        return self._vsd_ingress_acl_entries


class StatelessSecuritygroupTest(network_mixin.NetworkMixin,
                                 l3.L3Mixin, sg_mixin.SGMixin):

    credentials = ['admin']
    _ether_type = 'ipv4'
    _cidr = '10.20.30.0/24'

    @classmethod
    def setup_clients(cls):
        super(StatelessSecuritygroupTest, cls).setup_clients()
        cls.vsd_client = NuageRestClient()

    @classmethod
    def skip_checks(cls):
        super(StatelessSecuritygroupTest, cls).skip_checks()
        if not CONF.service_available.neutron:
            # this check prevents this test to be run in unittests
            raise cls.skipException("Neutron support is required")
        if not NUAGE_FEATURES.stateless_security_groups:
            msg = "Stateless securitygroups feature is not available"
            raise cls.skipException(msg)

    @decorators.attr(type='smoke')
    def test_stateless_default_securitygroup(self):
        topology = self._create_topology(with_router=False,
                                         with_securitygroup=False)
        with self.port(topology.network['id']) as port:
            topology.port = port
            topology.securitygroup = self.show_security_group(
                port['security_groups'][0])
            self._validate_os(topology, stateless=False)
            self._validate_vsd(topology, stateless=False)

    @decorators.attr(type='smoke')
    def test_stateless_securitygroup_l2(self):
        topology = self._create_topology(with_router=False)
        self._test_securitygroup(topology, update=False)

    @decorators.attr(type='smoke')
    def test_stateless_securitygroup_l3(self):
        topology = self._create_topology(with_router=True)
        self._test_securitygroup(topology, update=False)

    @decorators.attr(type='smoke')
    def test_stateless_securitygroup_l2_update(self):
        topology = self._create_topology(with_router=False,
                                         stateless_sg=False)
        self._validate_os(topology, stateless=False)
        update_data = {'stateful': False}
        topology.securitygroup = self.update_security_group(
            topology.securitygroup['id'],
            **update_data)
        self._validate_os(topology, stateless=True)
        port_create_data = {'security_groups': [topology.securitygroup['id']]}
        with self.port(topology.network['id'], **port_create_data) as port:
            topology.port = port
            self._validate_vsd(topology, stateless=True)

    @decorators.attr(type=['negative', 'smoke'])
    def test_stateless_fail_create_invalid_value(self):
        invalid_values = [None, 'None', 'invalid', 0xffff]
        for value in invalid_values:
            create_data = {'stateful': value}
            self.assertRaises(lib_exc.BadRequest, self.create_security_group,
                              **create_data)

    @decorators.attr(type=['smoke'])
    def test_stateless_update_securitygroup_in_use_with_same_data(self):
        topology = self._create_topology(with_router=False,
                                         stateless_sg=False)
        port_create_data = {'security_groups': [topology.securitygroup['id']]}
        with self.port(topology.network['id'], **port_create_data) as port:
            topology.port = port
            update_data = {'stateful': True}
            self.update_security_group(topology.securitygroup['id'],
                                       **update_data)
            self._validate_os(topology, stateless=False)
            self._validate_vsd(topology, stateless=False)

    @decorators.attr(type=['negative', 'smoke'])
    def test_stateless_fail_update_securitygroup_in_use(self):
        topology = self._create_topology(with_router=False,
                                         stateless_sg=False)
        port_create_data = {'security_groups': [topology.securitygroup['id']]}
        with self.port(topology.network['id'], **port_create_data) as port:
            topology.port = port
            update_data = {'stateful': False}
            self.assertRaises(lib_exc.Conflict, self.update_security_group,
                              topology.securitygroup['id'],
                              **update_data)

    @decorators.attr(type='smoke')
    def test_stateless_securitygroup_add_rule(self):
        topology = self._create_topology(with_router=False,
                                         stateless_sg=True)
        port_create_data = {'security_groups': [topology.securitygroup['id']]}
        with self.port(topology.network['id'], **port_create_data) as port:
            topology.port = port
            sg_rule = {
                'direction': 'ingress',
                'protocol': 'tcp',
                'port_range_min': 22,
                'port_range_max': 22,
                'ethertype': self._ether_type
            }
            self.create_security_group_rule(topology.securitygroup['id'],
                                            **sg_rule)
            self._validate_os(topology, stateless=True)
            self._validate_vsd(topology, stateless=True)

    @decorators.attr(type='smoke')
    def test_stateless_securitygroup_rule_icmp(self):
        topology = self._create_topology(with_router=False,
                                         stateless_sg=True)
        port_create_data = {'security_groups': [topology.securitygroup['id']]}
        with self.port(topology.network['id'], **port_create_data) as port:
            topology.port = port
            sg_rule = {
                'direction': 'ingress',
                'protocol': 'icmp',
                'ethertype': self._ether_type
            }
            self.create_security_group_rule(topology.securitygroup['id'],
                                            **sg_rule)
            self._validate_os(topology, stateless=True)
            self._validate_vsd(topology, stateless=True)
            self._validate_no_reverse_icmp_rules(
                topology, sg_rule['direction'])

    @decorators.attr(type='smoke')
    def test_stateless_securitygroup_rule_icmp_type_code(self):
        topology = self._create_topology(with_router=False,
                                         stateless_sg=True)
        port_create_data = {'security_groups': [topology.securitygroup['id']]}
        with self.port(topology.network['id'], **port_create_data) as port:
            topology.port = port
            # type == dest unreachable, code host == host unreachable
            sg_rule = {
                'direction': 'ingress',
                'protocol': 'icmp',
                'ethertype': self._ether_type,
                'port_range_min': 3,
                'port_range_max': 1
            }
            self.create_security_group_rule(topology.securitygroup['id'],
                                            **sg_rule)
            self._validate_os(topology, stateless=True)
            self._validate_vsd(topology, stateless=True)
            self._validate_no_reverse_icmp_rules(
                topology, sg_rule['direction'])

    @decorators.attr(type='smoke')
    def test_stateless_securitygroup_rule_icmpv6(self):
        topology = self._create_topology(with_router=False,
                                         stateless_sg=True)
        port_create_data = {'security_groups': [topology.securitygroup['id']]}
        with self.port(topology.network['id'], **port_create_data) as port:
            topology.port = port
            sg_rule = {
                'direction': 'ingress',
                'protocol': 'icmp',
                'ethertype': 'ipv6'
            }
            self.create_security_group_rule(topology.securitygroup['id'],
                                            **sg_rule)
            self._validate_os(topology, stateless=True)
            self._validate_vsd(topology, stateless=True)
            self._validate_no_reverse_icmp_rules(
                topology, sg_rule['direction'])

    def _create_topology(self, with_router=False, with_securitygroup=True,
                         stateless_sg=True):
        router = securitygroup = None
        if with_router:
            router = self.create_router()
        network = self.create_network()
        subnet = self.create_subnet(self._cidr, network['id'])
        if with_router:
            self.add_router_interface(router['id'], subnet_id=subnet['id'])
        if with_securitygroup:
            if stateless_sg:
                kwargs = {'stateful': False}
            else:
                kwargs = {}
            securitygroup = self.create_security_group(**kwargs)
        return SecurityGroupsTopology(self.vsd_client, network,
                                      subnet, router, securitygroup)

    def _test_securitygroup(self, topology, update=False, stateless=True):
        port_create_data = {}
        if not update:
            port_create_data.update(
                {'security_groups': [topology.securitygroup['id']]})
        with self.port(topology.network['id'], **port_create_data) as port:
            topology.port = port
            if update:
                self.update_port(port['id'], as_admin=False,
                                 **self.sg_data)
            self._validate_os(topology, stateless=stateless)
            self._validate_vsd(topology, stateless=stateless)

    def _validate_os(self, topology, stateless=True):
        self.assertEqual(
            topology.securitygroup['stateful'],
            not stateless,
            message=('SecurityGroup %s has incorrect stateful attribute' %
                     topology.securitygroup['id']))

    def _validate_vsd(self, topology, stateless=True):
        self.assertThat(topology.vsd_policygroups,
                        matchers.HasLength(1),
                        message="Unexpected amount of PGs found")
        for acl in (topology.vsd_ingress_acl_entries +
                    topology.vsd_egress_acl_entries):
            if acl.get('locationID') == topology.vsd_policygroups[0]['ID']:
                self.assertEqual(
                    acl['stateful'], not stateless,
                    message=("VSD ACL entry %s has incorrect "
                             "stateful attribute" %
                             acl['ID']))

    def _validate_no_reverse_icmp_rules(self, topology, direction):
        # on VSD the ingress direction is the egress direction and vice versa
        acls = (topology.vsd_ingress_acl_entries if direction == 'ingress'
                else topology.vsd_egress_acl_entries)
        for acl in acls:
            if acl.get('locationID') == topology.vsd_policygroups[0]['ID']:
                self.assertNotEqual(
                    '1', acl.get('protocol'),
                    msg='Found icmp reverse rule - ACL %s' % acl['ID'])


class StatelessSecuritygroupTestV6(StatelessSecuritygroupTest):
    _ether_type = 'ipv6'
    _cidr = 'cafe:babe::/64'
