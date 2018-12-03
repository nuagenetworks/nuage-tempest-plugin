# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPNetwork
from tempest.lib import decorators

from nuage_commons import data_utils

from nuage_tempest_lib.tests.nuage_test import NuageBaseTest


class Ipv4OsManagedConnectivityTest(NuageBaseTest):

    def test_icmp_connectivity_l2_os_managed(self):
        # Provision OpenStack network resources
        network = self.create_network()
        self.create_subnet(network, gateway=None)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group])

        server1 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_os_managed(self):
        # Provision OpenStack network resources
        router = self.create_test_router()
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.router_attach(router, subnet)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group])

        server1 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

    def test_icmp_connectivity_l3_os_managed_neg(self):
        # Provision OpenStack network resources
        router = self.create_test_router()
        network = self.create_network()
        subnet = self.create_subnet(network)
        self.router_attach(router, subnet)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True)

        server2 = self.create_tenant_server(
            networks=[network])  # in default sg - so not accessible!

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
                           gateway='10.10.2.1',
                           cidr=IPNetwork('10.10.2.0/24'),
                           mask_bits=24)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # create server12 port
        p1 = self.create_port(
            network=network1,
            security_groups=[ssh_security_group['id']])
        p2 = self.create_port(
            network=network2,
            security_groups=[ssh_security_group['id']],
            extra_dhcp_opts=[{'opt_name': 'router', 'opt_value': '0'}])

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(
            networks=[network1],
            security_groups=[ssh_security_group])

        server2 = self.create_tenant_server(
            networks=[network2],
            security_groups=[ssh_security_group])

        server12 = self.create_tenant_server(
            ports=[p1, p2],
            make_reachable=True)

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

        server2 = self.create_tenant_server(ports=[p2])
        server1 = self.create_tenant_server(ports=[p1])

        server1.associate_fip(fl1['floating_ip_address'])

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, ext_network,
                         address=fl2['floating_ip_address'])
