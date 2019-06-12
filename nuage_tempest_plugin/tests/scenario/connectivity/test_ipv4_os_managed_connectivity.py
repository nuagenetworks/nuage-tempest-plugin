# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPNetwork

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.test.nuage_test import skip_because
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils
from tempest.lib import decorators

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class Ipv4OsManagedConnectivityTest(NuageBaseTest):

    def test_icmp_connectivity_l2_os_managed(self):
        # Provision OpenStack network resources
        network = self.create_network()
        self.create_subnet(network, gateway=None)

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

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

    def _icmp_connectivity_l3_os_managed_by_name(self, name=None,
                                                 nova_friendly_name=None):
        # Provision OpenStack network resources
        router = self.create_router(
            router_name=name,
            external_network_id=CONF.network.public_network_id)
        network = self.create_network(network_name=name)
        subnet = self.create_subnet(network, subnet_name=name)
        self.router_attach(router, subnet)

        # ---
        # for some chars like line tab, nova itself has issues with passing it,
        # hence support for a optional nova friendly name.
        # More specifically, Nova can't deal with line tab in SG name,
        # nor in the instance name.
        # ---
        nova_friendly_name = nova_friendly_name or name

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group(
            sg_name=nova_friendly_name)

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            [network],
            name=nova_friendly_name + ' 1',
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        server1 = self.create_tenant_server(
            [network],
            name=nova_friendly_name + ' 2',
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_os_managed(self):
        self._icmp_connectivity_l3_os_managed_by_name('hi there')

    @skip_because(bug='OPENSTACK-2570')
    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_os_managed_russian(self):
        # Russian, ask Vlad :)
        name = (u'\u0445\u0440\u0435\u043d-\u0441-' +
                u'\u0440\u0443\u0447\u043a\u043e\u0439')

        self._icmp_connectivity_l3_os_managed_by_name(name)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_os_managed_line_tab(self):
        line_tab = u'\u000b'
        name = 'hi' + line_tab + 'there'

        self._icmp_connectivity_l3_os_managed_by_name(name, 'hi there')

    def test_icmp_connectivity_l3_os_managed_neg(self):
        # Provision OpenStack network resources
        router = self.create_test_router()
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.router_attach(router, subnet)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            [network])  # in default sg - so not accessible!
        #                 -- hence also can't set prepare_for_connectivity

        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network, should_pass=False)

    def test_icmp_connectivity_l3_os_managed_dual_nic(self):
        # Provision OpenStack network resources
        router = self.create_test_router()
        network1 = self.create_network()
        subnet1 = self.create_subnet(network1,
                                     gateway='10.10.1.1',
                                     cidr=IPNetwork('10.10.1.0/24'),
                                     mask_bits=24)
        self.router_attach(router, subnet1)

        network2 = self.create_network()
        self.create_subnet(network2,
                           gateway=None,
                           cidr=IPNetwork('10.10.2.0/24'),
                           mask_bits=24)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(
            [network1],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        server2 = self.create_tenant_server(
            [network2],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

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

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server12, server1, network1)
        self.assert_ping(server12, server2, network2)

    def test_icmp_connectivity_multiple_subnets_in_shared_network(self):
        """test_icmp_connectivity_multiple_subnets_in_shared_network

        Check that there is connectivity between VM's with floatingip's
        in different subnets of the same network
        """
        # Provision OpenStack network resources
        kwargs = {
            "router:external": True
        }
        ext_network = self.create_network(client=self.admin_manager, **kwargs)
        ext_s1 = self.create_subnet(ext_network, client=self.admin_manager,
                                    cidr=data_utils.gimme_a_cidr(),
                                    underlay=True)
        ext_s2 = self.create_subnet(ext_network, client=self.admin_manager,
                                    cidr=data_utils.gimme_a_cidr(),
                                    underlay=True)

        r1 = self.create_router(external_network_id=ext_network['id'])
        r2 = self.create_router(external_network_id=ext_network['id'])

        n1 = self.create_network()
        s1 = self.create_subnet(n1, cidr=IPNetwork('52.0.0.0/24'))
        self.router_attach(r1, s1)

        n2 = self.create_network()
        s2 = self.create_subnet(n2, cidr=IPNetwork('53.0.0.0/24'))
        self.router_attach(r2, s2)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        p1 = self.create_port(
            network=n1,
            security_groups=[ssh_security_group['id']])
        p2 = self.create_port(
            network=n2,
            security_groups=[ssh_security_group['id']])

        fl1 = self.create_floatingip(external_network_id=ext_network['id'],
                                     subnet_id=ext_s1['id'], port_id=p1['id'])
        fl2 = self.create_floatingip(external_network_id=ext_network['id'],
                                     subnet_id=ext_s2['id'], port_id=p2['id'])

        server2 = self.create_tenant_server(
            ports=[p2])
        server1 = self.create_tenant_server(
            ports=[p1])

        server1.associate_fip(fl1['floating_ip_address'])
        server1.validate_authentication()

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, ext_network,
                         address=fl2['floating_ip_address'])

    # @decorators.attr(type='smoke')
    def test_icmp_connectivity_l2_os_managed_no_dhcp_v4(self):
        # Provision OpenStack network resources
        network = self.create_network()
        self.create_subnet(network, enable_dhcp=False)

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

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

    def test_icmp_connectivity_l2_os_managed_no_dhcp_v4_neg(self):
        # Provision OpenStack network resources
        network = self.create_network()
        self.create_subnet(network, enable_dhcp=False)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack networks
        # Force DHCP config even though subnet has no DHCP enabled (won't work)
        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            force_dhcp_config=True,
            prepare_for_connectivity=True)

        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test IPv4 connectivity between peer servers (should fail)
        self.assert_ping(server1, server2, network, should_pass=False)

    def test_icmp_connectivity_l3_os_managed_no_dhcp_v4(self):
        # Provision OpenStack network resources
        network = self.create_network()
        subnet = self.create_subnet(network, enable_dhcp=False)

        # attach subnets to router
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.router_attach(router, subnet)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # to make it reachable via FIP, gateway also must be configured.
        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

    def test_icmp_connectivity_l3_os_managed_no_dhcp_v4_neg(self):
        # Provision OpenStack network resources
        network = self.create_network()
        subnet = self.create_subnet(network, enable_dhcp=False)

        # attach subnets to router
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.create_router_interface(router['id'], subnet['id'])

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack networks
        # Force DHCP config even though subnet has no DHCP enabled (won't work)
        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            force_dhcp_config=True,
            prepare_for_connectivity=True)

        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network, should_pass=False)
