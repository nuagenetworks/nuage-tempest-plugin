# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPNetwork
from tempest.test import decorators

import nuage_tempest_plugin.lib.test.nuage_test as nuage_test
from nuage_tempest_plugin.lib.test.nuage_test import skip_because
from nuage_tempest_plugin.lib.topology import Topology

LOG = nuage_test.Topology.get_logger(__name__)
CONF = Topology.get_conf()


class Ipv6OsManagedConnectivityTest(nuage_test.NuageBaseTest):

    @skip_because(bug='VSD-34117')
    def test_icmp_connectivity_l2_os_managed_dualstack(self):
        # Provision OpenStack network
        network = self.create_network()
        self.create_subnet(network, gateway=None)
        self.create_subnet(
            network, ip_version=6, enable_dhcp=False, gateway=None)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True,
            configure_dualstack_itf=True)

        server1 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True,
            configure_dualstack_itf=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network, ip_type=6)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_os_managed_dualstack(self):
        # Provision OpenStack network
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network)
        self.create_subnet(network, ip_version=6, enable_dhcp=False)

        router = self.create_test_router()
        self.router_attach(router, ipv4_subnet)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True,
            configure_dualstack_itf=True)

        server1 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True,
            configure_dualstack_itf=True)

        # Test IPv4 connectivity between peer servers
        self.assert_ping(server1, server2, network)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network, ip_type=6)

    def test_icmp_connectivity_l2_os_managed_pure_v6(self):
        # Provision OpenStack network
        networkv6 = self.create_network()
        self.create_subnet(
            networkv6, ip_version=6, enable_dhcp=True, gateway=None)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            networks=[networkv6],
            security_groups=[ssh_security_group])

        server1 = self.create_tenant_server(
            networks=[networkv6],
            security_groups=[ssh_security_group],
            make_reachable=True)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, networkv6, ip_type=6)

    def test_icmp_connectivity_l3_os_managed_pure_v6(self):
        # Provision OpenStack network
        networkv6_1 = self.create_network()
        networkv6_2 = self.create_network()
        networkv4 = self.create_network()

        # provision subnets
        subnetv4 = self.create_subnet(networkv4)
        subnetv6_1 = self.create_subnet(
            networkv6_1, ip_version=6, enable_dhcp=True,
            cidr=IPNetwork("cafe:aabe::/64"))
        subnetv6_2 = self.create_subnet(
            networkv6_2, ip_version=6, enable_dhcp=True,
            cidr=IPNetwork("cafe:babe::/64"))

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # provision ports
        portv6_1 = self.create_port(networkv6_1,
                                    security_groups=[ssh_security_group['id']])
        portv6_2 = self.create_port(networkv6_2,
                                    security_groups=[ssh_security_group['id']])
        portv4 = self.create_port(networkv4,
                                  security_groups=[ssh_security_group['id']])

        # attach subnets to router
        router = self.create_test_router()
        self.router_attach(router, subnetv6_1)
        self.router_attach(router, subnetv4)
        self.router_attach(router, subnetv6_2)

        # Launch tenant servers in OpenStack network
        server2 = self.create_tenant_server(
            ports=[portv6_2])

        server1 = self.create_tenant_server(
            ports=[portv4, portv6_1],
            make_reachable=True)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, networkv6_2, ip_type=6)

    def test_icmp_connectivity_os_managed_dualstack_128_sg_prefix(self):
        # Provision OpenStack network
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network)
        self.create_subnet(network, ip_version=6, enable_dhcp=False)

        router = self.create_test_router()
        self.router_attach(router, ipv4_subnet)

        # create sg with /128 rule
        sg_name = nuage_test.data_utils.rand_name('secgroup-smoke')
        sg_desc = sg_name + " description"
        sg_dict = dict(name=sg_name,
                       description=sg_desc)
        sg_dict['tenant_id'] = self.security_groups_client.tenant_id
        sg1 = self.security_groups_client.create_security_group(
            **sg_dict)['security_group']
        sg_id = sg1['id']
        self.addCleanup(nuage_test.test_utils.call_and_ignore_notfound_exc,
                        self.security_groups_client.delete_security_group,
                        sg_id)
        for sg_rule in sg1['security_group_rules']:
            self.security_group_rules_client.delete_security_group_rule(
                sg_rule['id'])

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack network
        server1 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True,
            configure_dualstack_itf=True)

        server2 = self.create_tenant_server(
            networks=[network],
            security_groups=[ssh_security_group],
            make_reachable=True,
            configure_dualstack_itf=True)

        server3_port = self.create_port(
            network,
            security_groups=[ssh_security_group['id']])

        server3 = self.create_tenant_server(
            ports=[server3_port],
            make_reachable=True,
            configure_dualstack_itf=True)

        dest_addr = server3.get_server_ip_in_network(
            network['name'], ip_type=6)

        for i in range(1, 5):
            server3.send('nc -v -lk -p 8080 -s ' +
                         dest_addr + ' > server.log 2>&1 &')
            netcat_server_log = server3.send('cat server.log')
            self.assertNotEmpty(netcat_server_log,
                                "Couldn't start server")
            if 'bind: Cannot assign requested address' in netcat_server_log:
                if i == 4:
                    self.assertNotEmpty(
                        None,
                        msg='Failed: bind: Cannot assign requested address')
                else:
                    self.sleep(1, "Retry to bind the requested address")
            else:
                break

        self.update_port(server3_port, security_groups=[sg_id])
        server1.send(
            'echo "Do you see this from server1" |'
            ' nc -v ' + dest_addr + ' 8080 > server1.log 2>&1 &')
        server2.send(
            'echo "Do you see this from server2" |'
            ' nc -v ' + dest_addr + ' 8080 > server2.log 2>&1 &')

        # validate if the tcp connection is not yet active.
        self.assertEmpty(server2.send('cat server2.log'),
                         "TCP connection cannot be active")
        self.assertEmpty(server1.send('cat server1.log'),
                         "TCP connection cannot be active")

        ipv6_ip_prefix = server1.get_server_ip_in_network(
            network['name'], ip_type=6) + '/128'
        self.security_group_rules_client.create_security_group_rule(
            security_group_id=sg_id, direction='ingress',
            ethertype="IPv6", protocol='tcp',
            remote_ip_prefix=ipv6_ip_prefix)

        # now validate that TCP will work from server1 with ingress
        # itself although there is no egress rule.
        for i in range(1, 5):
            # now validate that TCP will only work from server1
            self.assertEmpty(server2.send('cat server2.log'),
                             "TCP connection should not work as it does not"
                             " have ingress or egress rules")
            contents_in_file = server1.send('cat server1.log')
            if contents_in_file:
                break
            else:
                LOG.info("Retry to see if the TCP connection is active.")
                self.sleep(1, msg="Retry to see if the TCP"
                                  " connection is active.")

        self.assertNotEmpty(server1.send('cat server1.log'),
                            "TCP connection is not active although"
                            " stateful ingress rule is present.")

    def test_icmp_connectivity_l2_os_managed_no_dhcp_v6(self):
        # Provision OpenStack network resources
        network = self.create_network()
        self.create_subnet(network, enable_dhcp=False, ip_version=6)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()
        port_1 = self.create_port(network,
                                  security_groups=[ssh_security_group['id']])
        port_2 = self.create_port(network,
                                  security_groups=[ssh_security_group['id']])

        # Launch tenant servers in OpenStack network
        self.create_tenant_server(
            ports=[port_1],
            user_data='#!/bin/sh\n/sbin/ifconfig eth0 {}/64 up'.format(
                port_1['fixed_ips'][0]['ip_address']))

        server1 = self.create_tenant_server(
            ports=[port_2],
            make_reachable=True,
            user_data='#!/bin/sh\n/sbin/ifconfig eth1 {}/64 up'.format(
                port_2['fixed_ips'][0]['ip_address']))

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1=server1, timeout=300,
                         address=port_1['fixed_ips'][0]['ip_address'],
                         interface='eth1', ip_type=6)

    def test_icmp_connectivity_l2_os_managed_no_dhcp_v6_neg(self):
        # Provision OpenStack network resources
        network = self.create_network()
        self.create_subnet(network, enable_dhcp=False, ip_version=6)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()
        port_1 = self.create_port(network,
                                  security_groups=[ssh_security_group['id']])
        port_2 = self.create_port(network,
                                  security_groups=[ssh_security_group['id']])

        # Launch tenant servers in OpenStack network
        # There is neither IP config nor DHCP, so connectivity test should fail
        self.create_tenant_server(
            ports=[port_1])

        server1 = self.create_tenant_server(
            ports=[port_2],
            make_reachable=True)

        # Test IPv6 connectivity between peer servers (should fail)
        self.assertFalse(self._assert_ping(
            server=server1, dest=port_1['fixed_ips'][0]['ip_address'],
            interface='eth1'))

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_os_managed_no_dhcp_v6(self):
        # Provision OpenStack network resources
        network = self.create_network()
        subnet = self.create_subnet(network, enable_dhcp=False, ip_version=6)

        # attach subnets to router
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        # self.router_attach(router, subnet)
        self.create_router_interface(router['id'], subnet['id'])

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()
        port_1 = self.create_port(network,
                                  security_groups=[ssh_security_group['id']])
        port_2 = self.create_port(network,
                                  security_groups=[ssh_security_group['id']])

        # Launch tenant servers in OpenStack network
        self.create_tenant_server(
            ports=[port_1],
            user_data='#!/bin/sh\n/sbin/ifconfig eth0 {}/64 up'.format(
                port_1['fixed_ips'][0]['ip_address']))

        # to make it reachable via FIP, gateway also must be configured.
        server1 = self.create_tenant_server(
            ports=[port_2],
            make_reachable=True,
            user_data='#!/bin/sh\n/sbin/ifconfig eth1 {}/64 up;'.format(
                port_2['fixed_ips'][0]['ip_address']))

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1=server1, timeout=300,
                         address=port_1['fixed_ips'][0]['ip_address'],
                         interface='eth1', ip_type=6)

    def test_icmp_connectivity_l3_os_managed_no_dhcp_v6_neg(self):
        # Provision OpenStack network resources
        network = self.create_network()
        subnet = self.create_subnet(network, enable_dhcp=False, ip_version=6)

        # attach subnets to router
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.create_router_interface(router['id'], subnet['id'])

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()
        port_1 = self.create_port(network,
                                  security_groups=[ssh_security_group['id']])
        port_2 = self.create_port(network,
                                  security_groups=[ssh_security_group['id']])

        # Launch tenant servers in OpenStack network
        # There is neither IP config nor DHCP, connectivity should fail
        self.create_tenant_server(
            ports=[port_1])

        server1 = self.create_tenant_server(
            ports=[port_2],
            make_reachable=True)

        # Test IPv6 connectivity between peer servers
        self.assertFalse(self._assert_ping(
            server=server1, dest=port_1['fixed_ips'][0]['ip_address'],
            interface='eth1'))
