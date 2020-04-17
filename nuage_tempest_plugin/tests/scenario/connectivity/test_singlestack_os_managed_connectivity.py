# All Rights Reserved.

import sys
import testscenarios
import testtools

from netaddr import IPNetwork
from tempest.lib import decorators

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils

CONF = Topology.get_conf()

load_tests = testscenarios.load_tests_apply_scenarios


class SingleStackOsMgdConnectivityTestBase(NuageBaseTest):

    default_prepare_for_connectivity = True
    nuage_aggregate_flows = 'off'

    # default is IPv4
    _cidr1 = IPNetwork('10.10.1.1/24')
    _cidr2 = IPNetwork('10.10.2.1/24')

    def _create_resources(self, name=None, cidr=None, is_l3=False,
                          enable_dhcp=True):
        network = self.create_network(network_name=name)
        kwargs = {}
        if cidr:
            kwargs.update({'gateway': cidr.ip,
                           'cidr': cidr,
                           'mask_bits': cidr.prefixlen})
        if enable_dhcp:
            kwargs.update({'enable_dhcp': enable_dhcp})

        subnet = self.create_subnet(network, subnet_name=name, **kwargs)

        if is_l3:
            kwargs = {'router_name': name,
                      'external_network_id': self.ext_net_id}
            if self.nuage_aggregate_flows != 'off':
                kwargs['nuage_aggregate_flows'] = self.nuage_aggregate_flows
            router = self.create_router(**kwargs)
            self.router_attach(router, subnet)
        return network, subnet

    def _icmp_connectivity_l3_os_managed_by_name(self, name=None,
                                                 nova_friendly_name=None):
        network, _ = self._create_resources(name=name, is_l3=True)
        # ---
        # for some chars like line tab, nova itself has issues with passing
        # it, hence support for a optional nova friendly name.
        # More specifically, Nova can't deal with line tab in SG name,
        # nor in the instance name.
        # ---
        nova_friendly_name = nova_friendly_name or name

        # create open-ssh security group
        stateful = self.nuage_aggregate_flows == 'off'
        ssh_security_group = self.create_open_ssh_security_group(
            sg_name=nova_friendly_name, stateful=stateful)

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            [network],
            name=nova_friendly_name + '-1',
            security_groups=[ssh_security_group])

        server1 = self.create_tenant_server(
            [network],
            name=nova_friendly_name + '-2',
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test connectivity between peer servers
        self.assert_ping(server1, server2, network)

    def _test_icmp_connectivity_stateful_acl_os_managed(self, is_l3=None,
                                                        stateful=True):
        # Provision OpenStack network resources
        network, subnet = self._create_resources(cidr=self._cidr1)
        ports_actor = []
        ports_hollywood = []

        if is_l3:
            network_fip, subnet_fip = self._create_resources(
                cidr=self._cidr2)
            router = self.create_router(
                external_network_id=self.ext_net_id)
            self.router_attach(router, subnet)
            self.router_attach(router, subnet_fip)
            ssh_sg = self.create_open_ssh_security_group()

            fip_port_actor = self.create_port(
                network_fip, security_groups=[ssh_sg['id']])
            ports_actor.append(fip_port_actor)

            fip_port_hollywood = self.create_port(
                network_fip, security_groups=[ssh_sg['id']])
            ports_hollywood.append(fip_port_hollywood)

        # create two security groups and clean the default rules rules
        sg_hollywood = self.create_security_group(stateful=stateful)
        for sg_rule in sg_hollywood['security_group_rules']:
            self.security_group_rules_client.delete_security_group_rule(
                sg_rule['id'])
        # add an egress rule
        if self._ip_version == 4:
            kwargs = {
                'direction': 'egress',
                'protocol': 'icmp',
                'port_range_min': 8,
                'ethertype': 'IPv4'
            }
        else:
            kwargs = {
                'direction': 'egress',
                'protocol': 'ipv6-icmp',
                'port_range_min': 128,
                'ethertype': 'IPv6'
            }
        self.create_security_group_rule(sg_hollywood, **kwargs)

        sg_actor = self.create_security_group()
        for sg_rule in sg_actor['security_group_rules']:
            self.security_group_rules_client.delete_security_group_rule(
                sg_rule['id'])
        # add an ingress rule
        if self._ip_version == 4:
            kwargs = {
                'direction': 'ingress',
                'protocol': 'icmp',
                'ethertype': 'IPv4'
            }
        else:
            kwargs = {
                'direction': 'ingress',
                'protocol': 'ipv6-icmp',
                'ethertype': 'IPv6'
            }
        self.create_security_group_rule(sg_actor, **kwargs)

        port_hollywood = self.create_port(
            network=network,
            security_groups=[sg_hollywood['id']],
            extra_dhcp_opts=[{'opt_name': 'router', 'opt_value': '0'}]
        )
        ports_hollywood.append(port_hollywood)

        port_actor = self.create_port(
            network=network,
            security_groups=[sg_actor['id']],
            extra_dhcp_opts=[{'opt_name': 'router', 'opt_value': '0'}]
        )
        ports_actor.append(port_actor)

        # Launch 2 tenant servers in OpenStack network
        vm_hollywood = self.create_tenant_server(
            ports=ports_hollywood,
            prepare_for_connectivity=True)

        vm_actor = self.create_tenant_server(
            ports=ports_actor,
            prepare_for_connectivity=True)

        # vm_hollywood can ping vm_actor if the acl is stateful
        self.assert_ping(vm_hollywood, vm_actor, network,
                         should_pass=stateful)

        if stateful:
            self.sleep(seconds=7,
                       msg="The OVS flows take some time to expire, e.g."
                           "for OVRS this is around 5 seconds. For "
                           "stateful ping traffic this means that when "
                           "A->B then the reverse flow B->A will also"
                           "exist for a while. So if B sends ping to A, "
                           "the traffic will be 'unexpectedly' allowed. "
                           "This is obviously not the case for connection "
                           "based traffic like TCP. See also VRS-35482"
                           "where this was determined to be not a BUG.")

        # vm_actor is not supposed to ping vm_hollywood in any case
        self.assert_ping(vm_actor, vm_hollywood, network,
                         should_pass=False)

    def _test_multi_compute_icmp_connectivity_os_managed(
            self, is_l3=False):
        # Provision OpenStack network resources
        network = self.create_network()
        subnet = self.create_subnet(network)

        if is_l3:
            router = self.create_router(
                external_network_id=self.ext_net_id)
            self.router_attach(router, subnet)
        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group])

        kwargs = {'networks': [network],
                  'scheduler_hints': {
                      'different_host': [server2.openstack_data['id']]},
                  'security_groups': [ssh_security_group],
                  'prepare_for_connectivity': True}
        server1 = self.create_tenant_server(**kwargs)

        # Test connectivity between peer servers
        self.assert_ping(
            server1, server2, network)


class Ipv4OsMgdL2ConnectivityTest(SingleStackOsMgdConnectivityTestBase):

    def test_icmp_connectivity_l2_os_managed(self):
        network, _ = self._create_resources()

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group])

        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test connectivity between peer servers
        self.assert_ping(server1, server2, network)

    @decorators.attr(type='smoke')
    @testtools.skipIf(not CONF.scenario.dhcp_client,
                      reason='OPENSTACK-2786')
    def test_icmp_connectivity_l2_os_managed_no_dhcp(self):
        # Provision OpenStack network resources
        network, _ = self._create_resources(enable_dhcp=False)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)
        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test connectivity between peer servers
        self.assert_ping(server1, server2, network)

    @testtools.skipIf(not CONF.scenario.dhcp_client,
                      reason='OPENSTACK-2786')
    def test_icmp_connectivity_l2_os_managed_no_dhcp_neg(self):
        # Provision OpenStack network resources
        network, _ = self._create_resources(enable_dhcp=False)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack networks
        # Force DHCP config even though subnet has no
        # DHCP enabled (won't work)
        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            force_dhcp_config=True)

        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test connectivity between peer servers (should fail)
        self.assert_ping(server1, server2, network, should_pass=False)

    def test_icmp_connectivity_stateful_acl_os_managed_l2(self):
        self._test_icmp_connectivity_stateful_acl_os_managed(is_l3=False)

    def test_icmp_connectivity_stateless_acl_os_managed_l2_neg(self):
        self._test_icmp_connectivity_stateful_acl_os_managed(
            is_l3=False, stateful=False)

    @testtools.skipUnless(CONF.compute.min_compute_nodes > 1,
                          'Less than 2 compute nodes, skipping multinode '
                          'tests.')
    def test_multi_compute_icmp_connectivity_l2_os_managed(self):
        self._test_multi_compute_icmp_connectivity_os_managed(is_l3=False)

    def test_tcp_stateful_connectivity_l2_os_managed(self):
        # Provision OpenStack network resources
        network = self.create_network()
        self.create_subnet(network)
        self.validate_tcp_stateful_traffic(network)


class Ipv4OsMgdL3ConnectivityTest(SingleStackOsMgdConnectivityTestBase):

    # @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_os_managed(self):
        self._icmp_connectivity_l3_os_managed_by_name('test-server')

    @testtools.skipUnless(sys.version_info >= (3, 0),
                          reason='Skip with python 2')
    def test_icmp_connectivity_l3_os_managed_russian(self):
        # Let's serve some Russian horseradish...
        name = (u'\u0445\u0440\u0435\u043d-\u0441-' +
                u'\u0440\u0443\u0447\u043a\u043e\u0439')

        self._icmp_connectivity_l3_os_managed_by_name(name)

    @testtools.skipUnless(sys.version_info >= (3, 0),
                          reason='Skip with python 2')
    def test_icmp_connectivity_l3_os_managed_line_tab(self):
        line_tab = u'\u000b'
        name = 'test' + line_tab + 'server'

        self._icmp_connectivity_l3_os_managed_by_name(name, 'test-server')

    def test_icmp_connectivity_l3_os_managed_neg(self):
        network, _ = self._create_resources(is_l3=True)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            [network],  # in default sg - so not accessible!
            #             -- hence also can't set prepare_for_connectivity
            prepare_for_connectivity=False)

        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test connectivity between peer servers
        self.assert_ping(server1, server2, network, should_pass=False)

    def test_icmp_connectivity_l3_os_managed_dual_nic(self):
        network1, _ = self._create_resources(is_l3=True, cidr=self._cidr1)
        network2, _ = self._create_resources(cidr=self._cidr2)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(
            [network1],
            security_groups=[ssh_security_group])

        server2 = self.create_tenant_server(
            [network2],
            security_groups=[ssh_security_group])

        # create server12 ports
        p1 = self.create_port(
            network=network1,
            security_groups=[ssh_security_group['id']])
        p2 = self.create_port(
            network=network2,
            security_groups=[ssh_security_group['id']],
            extra_dhcp_opts=[{'opt_name': 'router', 'opt_value': '0'}])

        server12 = self.create_tenant_server(
            ports=[p1, p2],
            prepare_for_connectivity=True)

        # Test connectivity between peer servers
        self.assert_ping(server12, server1, network1)
        self.assert_ping(server12, server2, network2)

    @testtools.skipIf(not CONF.scenario.dhcp_client,
                      reason='OPENSTACK-2786')
    def test_icmp_connectivity_l3_os_managed_no_dhcp(self):
        # Provision OpenStack network resources
        network, _ = self._create_resources(is_l3=True, enable_dhcp=False)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group])

        # to make it reachable via FIP, gateway also must be configured.
        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test connectivity between peer servers
        self.assert_ping(server1, server2, network)

    @testtools.skipIf(not CONF.scenario.dhcp_client,
                      reason='OPENSTACK-2786')
    def test_icmp_connectivity_l3_os_managed_no_dhcp_neg(self):
        # Provision OpenStack network resources
        network, _ = self._create_resources(is_l3=True, enable_dhcp=False)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack networks
        # Force DHCP config even though subnet has no
        # DHCP enabled (won't work)
        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            force_dhcp_config=True)

        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test connectivity between peer servers
        self.assert_ping(server1, server2, network, should_pass=False)

    def test_icmp_connectivity_stateful_acl_os_managed_l3(self):
        self._test_icmp_connectivity_stateful_acl_os_managed(is_l3=True)

    def test_icmp_connectivity_stateless_acl_os_managed_l3_neg(self):
        self._test_icmp_connectivity_stateful_acl_os_managed(
            is_l3=True, stateful=False)

    @testtools.skipUnless(CONF.compute.min_compute_nodes > 1,
                          'Less than 2 compute nodes, skipping multinode '
                          'tests.')
    def test_multi_compute_icmp_connectivity_l3_os_managed(self):
        self._test_multi_compute_icmp_connectivity_os_managed(is_l3=True)

    def test_tcp_stateful_connectivity_l3_os_managed(self):
        # Provision OpenStack network resources
        router = self.create_public_router()
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.router_attach(router, subnet)
        self.validate_tcp_stateful_traffic(network)

    def test_icmp_connectivity_multiple_subnets_in_shared_network(self):
        """test_icmp_connectivity_multiple_subnets_in_shared_network

        Check that there is connectivity between VM's with floatingip's
        in different subnets of the same network. These subnets have
        underlay=False so they end up in a new L3 domain on VSD instead of the
        existing shared FIP to underlay domain.

        """
        # Provision OpenStack network resources
        kwargs = {
            "router:external": True
        }
        ext_network = self.create_network(manager=self.admin_manager, **kwargs)
        ext_s1 = self.create_subnet(ext_network, manager=self.admin_manager,
                                    cidr=data_utils.gimme_a_cidr(),
                                    underlay=False)
        ext_s2 = self.create_subnet(ext_network, manager=self.admin_manager,
                                    cidr=data_utils.gimme_a_cidr(),
                                    underlay=False)

        r1 = self.create_router(external_network_id=ext_network['id'])
        r2 = self.create_router(external_network_id=ext_network['id'])
        r_access = self.create_router(external_network_id=self.ext_net_id)

        n1 = self.create_network()
        s1 = self.create_subnet(n1, cidr=IPNetwork('52.0.0.0/24'))
        self.router_attach(r1, s1)

        n2 = self.create_network()
        s2 = self.create_subnet(n2, cidr=IPNetwork('53.0.0.0/24'))
        self.router_attach(r2, s2)

        # create resources in order to ssh into server 1
        n_access = self.create_network()
        s_access = self.create_subnet(n_access, cidr=data_utils.gimme_a_cidr())
        self.router_attach(r_access, s_access)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        p1 = self.create_port(
            network=n1,
            security_groups=[ssh_security_group['id']],
            extra_dhcp_opts=[{'opt_name': 'router', 'opt_value': '0'}]
        )
        p2 = self.create_port(
            network=n2,
            security_groups=[ssh_security_group['id']])
        p_access = self.create_port(
            network=n_access,
            security_groups=[ssh_security_group['id']])

        self.create_floatingip(external_network_id=ext_network['id'],
                               subnet_id=ext_s1['id'], port_id=p1['id'])
        fip2 = self.create_floatingip(external_network_id=ext_network['id'],
                                      subnet_id=ext_s2['id'], port_id=p2['id'])
        server2 = self.create_tenant_server(
            ports=[p2], pre_prepared_fip=fip2,
            prepare_for_connectivity=False)
        server1 = self.create_tenant_server(
            ports=[p_access, p1],
            prepare_for_connectivity=True,
            user_data='ip route add {} via {}'.format(ext_s2['cidr'],
                                                      s1['gateway_ip']))

        # Test connectivity between peer servers
        self.assert_ping(server1, server2, ext_network,
                         address=fip2['floating_ip_address'])

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_os_managed_cross_subnet(self):
        # Provision OpenStack network resources
        # A goal of this tests is also to use the small /30 subnet
        network_1 = self.create_network(port_security_enabled=False)
        subnet_1 = self.create_subnet(network_1)
        network_2 = self.create_network(port_security_enabled=False)
        subnet_2 = self.create_subnet(network_2,
                                      cidr=IPNetwork('10.11.12.1/30'),
                                      mask_bits=30)
        # attach subnets to router
        router = self.create_router(
            external_network_id=self.ext_net_id)
        self.router_attach(router, subnet_1)
        self.router_attach(router, subnet_2)

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            [network_2],
            security_groups=[],
            prepare_for_connectivity=False)

        # to make it reachable via FIP, gateway also must be configured.
        server1 = self.create_tenant_server(
            [network_1],
            security_groups=[],
            prepare_for_connectivity=True)

        # Test connectivity between peer servers
        self.assert_ping(server1, server2, network_2)


class Ipv6OsMgdL2ConnectivityTest(Ipv4OsMgdL2ConnectivityTest):
    _ip_version = 6
    _cidr1 = IPNetwork('cafe:babb::1/64')
    _cidr2 = IPNetwork('cafe:babc::1/64')

    @testtools.skipIf(Topology.has_default_switchdev_port_profile(),
                      reason='VRS-35478')
    def test_icmp_connectivity_stateless_acl_os_managed_l2_neg(self):
        super(Ipv6OsMgdL2ConnectivityTest, self)\
            .test_icmp_connectivity_stateless_acl_os_managed_l2_neg()

    @testtools.skipIf(Topology.has_default_switchdev_port_profile(),
                      reason='VRS-36467')
    def test_icmp_connectivity_stateful_acl_os_managed_l2(self):
        super(Ipv6OsMgdL2ConnectivityTest, self)\
            .test_icmp_connectivity_stateful_acl_os_managed_l2()


class Ipv6OsMgdL3ConnectivityTest(Ipv4OsMgdL3ConnectivityTest):
    _ip_version = 6
    _cidr1 = IPNetwork('cafe:babb::1/64')
    _cidr2 = IPNetwork('cafe:babc::1/64')

    def test_icmp_connectivity_l3_vsd_managed_dualstack_linked_networks(self):
        self.skipTest('Skip for ipv6')

    def test_icmp_connectivity_l3_os_managed_cross_subnet(self):
        self.skipTest('Skip for ipv6')


class OsMgdL3ConnectivityTestWithAggrFlowsTest(
        SingleStackOsMgdConnectivityTestBase):
    scenarios = testscenarios.scenarios.multiply_scenarios([
        # Current PBR based aggregate flows feature blocks non-PBR
        # traffic in the domain. Temporary no connectivity tests for PBR mode.
        # ('Aggregate flow pbr', {'nuage_aggregate_flows': 'pbr'}),
        ('Aggregate flow route', {'nuage_aggregate_flows': 'route'})
    ], [
        ('IPv4', {'_ip_version': 4}),
        ('IPv6', {'_ip_version': 6}),
    ])

    def skip_checks(cls):
        super(OsMgdL3ConnectivityTestWithAggrFlowsTest, cls).skip_checks()
        if Topology.before_nuage('20.5'):
            raise cls.skipException('OS managed aggregate flows available'
                                    'starting 20.5')

    def test_icmp_connectivity_l3_os_managed(self):
        self._icmp_connectivity_l3_os_managed_by_name('test-server')
