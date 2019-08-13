# Copyright 2017 - Nokia
# All Rights Reserved.

from netaddr import IPNetwork
from tempest.test import decorators

import nuage_tempest_plugin.lib.test.nuage_test as nuage_test
from nuage_tempest_plugin.lib.topology import Topology

LOG = nuage_test.Topology.get_logger(__name__)
CONF = Topology.get_conf()


class Ipv6OsManagedConnectivityTest(nuage_test.NuageBaseTest):

    def test_icmp_connectivity_l2_os_managed_dualstack(self):
        # Provision OpenStack network
        network = self.create_network()
        self.create_subnet(network)
        self.create_subnet(network, ip_version=6)

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

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network, ip_type=6)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_os_managed_dualstack(self):
        # Provision OpenStack network
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network)
        self.create_subnet(network, ip_version=6)

        router = self.create_test_router()
        self.router_attach(router, ipv4_subnet)

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

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network, ip_type=6)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l2_os_managed_pure_v6(self):
        # Provision OpenStack network
        network = self.create_network()
        self.create_subnet(network, ip_version=6)

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

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network, ip_type=6)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_os_managed_pure_v6(self):
        # Provision OpenStack network
        network1 = self.create_network('n1')
        network2 = self.create_network('n2')

        # provision subnets
        subnet1 = self.create_subnet(network1, ip_version=6,
                                     cidr=IPNetwork("cafe:babe:1::/64"))
        subnet2 = self.create_subnet(network2, ip_version=6,
                                     cidr=IPNetwork("cafe:babe:2::/64"))

        # attach subnets to router
        router = self.create_test_router()
        self.router_attach(router, subnet1)
        self.router_attach(router, subnet2)

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack networks
        server2 = self.create_tenant_server(
            [network1],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        server1 = self.create_tenant_server(
            [network2],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network1, ip_type=6)

    def test_icmp_connectivity_os_managed_dualstack_128_sg_prefix(self):
        # Provision OpenStack network
        network = self.create_network()
        ipv4_subnet = self.create_subnet(network)
        self.create_subnet(network, ip_version=6)

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
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        server3_port = self.create_port(
            network,
            security_groups=[ssh_security_group['id']])

        server3 = self.create_tenant_server(
            ports=[server3_port],
            prepare_for_connectivity=True)

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

        # Launch tenant servers in OpenStack networks
        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network, ip_type=6)

    def test_icmp_connectivity_l2_os_managed_no_dhcp_v6_neg(self):
        # Provision OpenStack network resources
        network = self.create_network()
        self.create_subnet(network, enable_dhcp=False, ip_version=6)

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

        # Test IPv6 connectivity between peer servers (should fail)
        self.assert_ping(server1, server2, network, ip_type=6,
                         should_pass=False)

    @decorators.attr(type='smoke')
    def test_icmp_connectivity_l3_os_managed_no_dhcp_v6(self):
        # Provision OpenStack network resources
        network = self.create_network()
        subnet = self.create_subnet(network, enable_dhcp=False, ip_version=6)

        # attach subnets to router
        router = self.create_router(
            external_network_id=CONF.network.public_network_id)
        self.create_router_interface(router['id'], subnet['id'])

        # create open-ssh security group
        ssh_security_group = self.create_open_ssh_security_group()

        # Launch tenant servers in OpenStack networks
        server2 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        server1 = self.create_tenant_server(
            [network],
            security_groups=[ssh_security_group],
            prepare_for_connectivity=True)

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network, ip_type=6)

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

        # Test IPv6 connectivity between peer servers
        self.assert_ping(server1, server2, network, ip_type=6,
                         should_pass=False)

    def _test_icmp_connectivity_stateful_acl_os_managed_v6(self, is_l3=None,
                                                           stateful=True):
        # Provision OpenStack network resources
        network = self.create_network()
        subnet = self.create_subnet(network, cidr=IPNetwork('cafe:babe::/64'),
                                    ip_version=6)
        ports_actor = []
        ports_hollywood = []

        if is_l3:
            network_fip = self.create_network()
            subnet_fip = self.create_subnet(network_fip,
                                            cidr=IPNetwork('10.10.2.0/24'))
            router = self.create_router(
                external_network_id=CONF.network.public_network_id)
            self.router_attach(router, subnet)
            self.router_attach(router, subnet_fip)
            ssh_sg = self.create_open_ssh_security_group()

            # we don't want to use existing ports for fip so we create new ones
            fip_port_actor = self.create_port(
                network_fip, security_groups=[ssh_sg['id']])
            ports_actor.append(fip_port_actor)

            fip_port_hollywood = self.create_port(
                network_fip, security_groups=[ssh_sg['id']])
            ports_hollywood.append(fip_port_hollywood)

        # create two security groups and clean the default rules
        sg_hollywood = self.create_security_group(stateful=stateful)
        for sg_rule in sg_hollywood['security_group_rules']:
            self.security_group_rules_client.delete_security_group_rule(
                sg_rule['id'])
        # add an egress rule
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
        kwargs = {
            'direction': 'ingress',
            'protocol': 'ipv6-icmp',
            'ethertype': 'IPv6'
        }
        self.create_security_group_rule(sg_actor, **kwargs)

        port_hollywood = self.create_port(
            network=network,
            security_groups=[sg_hollywood['id']]
        )
        ports_hollywood.append(port_hollywood)

        port_actor = self.create_port(
            network=network,
            security_groups=[sg_actor['id']]
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
        self.assert_ping(vm_hollywood, vm_actor, network, ip_type=6,
                         should_pass=stateful)
        # vm_actor is not supposed to ping vm_hollywood in any case
        self.assert_ping(vm_actor, vm_hollywood, network, ip_type=6,
                         should_pass=False)

    def test_icmp_connectivity_stateful_acl_os_managed_l2_v6(self):
        self._test_icmp_connectivity_stateful_acl_os_managed_v6(is_l3=False)

    def test_icmp_connectivity_stateless_acl_os_managed_l2_v6_neg(self):
        self._test_icmp_connectivity_stateful_acl_os_managed_v6(
            is_l3=False, stateful=False)

    def test_icmp_connectivity_stateful_acl_os_managed_l3_v6(self):
        self._test_icmp_connectivity_stateful_acl_os_managed_v6(is_l3=True)

    def test_icmp_connectivity_stateless_acl_os_managed_l3_v6_neg(self):
        self._test_icmp_connectivity_stateful_acl_os_managed_v6(
            is_l3=True, stateful=False)
