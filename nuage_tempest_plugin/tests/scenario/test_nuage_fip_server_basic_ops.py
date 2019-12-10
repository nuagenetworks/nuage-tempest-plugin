# Copyright 2012 OpenStack Foundation
# Copyright 2013 Hewlett-Packard Development Company, L.P.
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

import collections
import re
import time

from tempest.api.network import base
from tempest.common import utils
from tempest import exceptions
from tempest.lib.common.utils import data_utils
from tempest import test

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.tests.scenario \
    import base_nuage_network_scenario_test

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)

Floating_IP_tuple = collections.namedtuple('Floating_IP_tuple',
                                           ['floating_ip', 'server'])

EXTRA_DHCP_OPT_MTU_VALUE = '1498'
EXTRA_DHCP_OPT_DOMAIN_NAME = 'nuagenetworks.com'
EXTRA_DHCP_OPT_DOMAIN_SEARCH = 'sales.domain.com;eng.domain.org'
FIP_RATE_LIMIT = '5'
FIP_UPDATE_DELAY = 4


class TestNetworkBasicOps(
    base_nuage_network_scenario_test.NuageNetworkScenarioTest,
        base.BaseNetworkTest):

    """TestNetworkBasicOps

    This smoke test suite assumes that Nova has been configured to
    boot VM's with Neutron-managed networking, and attempts to
    verify network connectivity as follows:

     There are presumed to be two types of networks: tenant and
     public.  A tenant network may or may not be reachable from the
     Tempest host.  A public network is assumed to be reachable from
     the Tempest host, and it should be possible to associate a public
     ('floating') IP address with a tenant ('fixed') IP address to
     facilitate external connectivity to a potentially unroutable
     tenant IP address.

     This test suite can be configured to test network connectivity to
     a VM via a tenant network, a public network, or both.  If both
     networking types are to be evaluated, tests that need to be
     executed remotely on the VM (via ssh) will only be run against
     one of the networks (to minimize test execution time).

     Determine which types of networks to test as follows:

     * Configure tenant network checks (via the
       'tenant_networks_reachable' key) if the Tempest host should
       have direct connectivity to tenant networks.  This is likely to
       be the case if Tempest is running on the same host as a
       single-node devstack installation with IP namespaces disabled.

     * Configure checks for a public network if a public network has
       been configured prior to the test suite being run and if the
       Tempest host should have connectivity to that public network.
       Checking connectivity for a public network requires that a
       value be provided for 'public_network_id'.  A value can
       optionally be provided for 'public_router_id' if tenants will
       use a shared router to access a public network (as is likely to
       be the case when IP namespaces are not enabled).  If a value is
       not provided for 'public_router_id', a router will be created
       for each tenant and use the network identified by
       'public_network_id' as its gateway.
    """

    default_prepare_for_connectivity = True

    @classmethod
    def skip_checks(cls):
        super(TestNetworkBasicOps, cls).skip_checks()
        if not (CONF.network.project_networks_reachable or
                CONF.network.public_network_id):
            msg = ('Either tenant_networks_reachable must be "true", or '
                   'public_network_id must be defined.')
            raise cls.skipException(msg)
        for ext in ['router', 'security-group']:
            if not utils.is_extension_enabled(ext, 'network'):
                msg = "%s extension not enabled." % ext
                raise cls.skipException(msg)

    @classmethod
    def setup_credentials(cls):
        # Create no network resources for these tests.
        cls.set_network_resources()
        super(TestNetworkBasicOps, cls).setup_credentials()

    def setUp(self):
        super(TestNetworkBasicOps, self).setUp()
        self.keypairs = {}
        self.servers = []

    def _setup_network_and_servers(self, **kwargs):
        boot_with_port = kwargs.pop('boot_with_port', False)
        self.security_group = self._create_security_group()
        self.network, self.subnet, self.router = self.create_networks(**kwargs)
        self.check_networks()

        self.port_id = None
        if boot_with_port:
            # create a port on the network and boot with that
            # Don't forget to add the security group to allow ssh
            extra_dhcp_opts = [
                {'opt_value': EXTRA_DHCP_OPT_MTU_VALUE,
                 'opt_name': 'mtu'},
                {'opt_value': EXTRA_DHCP_OPT_DOMAIN_NAME,
                 'opt_name': 'domain-name'},
                {'opt_value': EXTRA_DHCP_OPT_DOMAIN_SEARCH,
                 'opt_name': 'domain-search'}
                ]
            port_kwargs = {
                'extra_dhcp_opts': extra_dhcp_opts,
                'security_groups': [self.security_group['id']]
            }
            self.port_id = self._create_port(
                self.network['id'], **port_kwargs)['id']

        name = data_utils.rand_name('server-smoke')
        server = self._create_server(name, self.network, self.port_id)
        self._check_nuage_tenant_network_connectivity()

        # Create floating IP with FIP rate limiting
        result = self.os_primary.floating_ips_client.create_floatingip(
            floating_network_id=CONF.network.public_network_id,
            port_id=self.port_id,
            nuage_fip_rate=FIP_RATE_LIMIT)
        self.floating_ips.append(result['floatingip'])
        floating_ip = result['floatingip']

        self.floating_ip_tuple = Floating_IP_tuple(floating_ip, server)

    def check_networks(self):
        """check_networks

        Checks that we see the newly created network/subnet/router via
        checking the result of list_[networks,routers,subnets]
        """

        seen_nets = self.os_admin.networks_client.\
            list_networks()['networks']
        seen_names = [n['name'] for n in seen_nets]
        seen_ids = [n['id'] for n in seen_nets]
        self.assertIn(self.network['name'], seen_names)
        self.assertIn(self.network['id'], seen_ids)

        if self.subnet:
            seen_subnets = self.os_admin.subnets_client.\
                list_subnets()['subnets']
            seen_net_ids = [n['network_id'] for n in seen_subnets]
            seen_subnet_ids = [n['id'] for n in seen_subnets]
            self.assertIn(self.network['id'], seen_net_ids)
            self.assertIn(self.subnet['id'], seen_subnet_ids)

        if self.router:
            seen_routers = self.os_admin.routers_client.\
                list_routers()['routers']
            seen_router_ids = [n['id'] for n in seen_routers]
            seen_router_names = [n['name'] for n in seen_routers]
            self.assertIn(self.router['name'],
                          seen_router_names)
            self.assertIn(self.router['id'],
                          seen_router_ids)

    def _create_server(self, name, network, port_id=None):
        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        security_groups = [{'name': self.security_group['name']}]
        network = {'uuid': network['id']}
        if port_id is not None:
            network['port'] = port_id

        server = self.create_server(
            name=name,
            networks=[network],
            key_name=keypair['name'],
            security_groups=security_groups,
            wait_until='ACTIVE')
        return server

    def _get_server_key(self, server):
        return self.keypairs[server['key_name']]['private_key']

    def _check_nuage_tenant_network_connectivity(self):
        ssh_login = CONF.validation.image_ssh_user
        for server in self.servers:
            # call the common method in the parent class
            super(TestNetworkBasicOps, self).\
                _check_tenant_network_connectivity(
                    server, ssh_login, self._get_server_key(server),
                    servers_for_debug=self.servers)

    def _check_public_connectivity(
            self, should_connect=True, msg=None,
            should_check_floating_ip_status=True):
        """_check_public_connectivity

        Verifies connectivity to a VM via public network and floating IP,
        and verifies floating IP has resource status is correct.

        :param should_connect: bool. determines if connectivity check is
        negative or positive.
        :param msg: Failure message to add to Error message. Should describe
        the place in the test scenario where the method was called,
        to indicate the context of the failure
        :param should_check_floating_ip_status: bool. should status of
        floating_ip be checked or not
        """
        ssh_login = CONF.validation.image_ssh_user
        floating_ip, server = self.floating_ip_tuple
        ip_address = floating_ip['floating_ip_address']
        private_key = None
        floatingip_status = 'DOWN'
        if should_connect:
            private_key = self._get_server_key(server)
            floatingip_status = 'ACTIVE'
        # Check FloatingIP Status before initiating a connection
        if should_check_floating_ip_status:
            self.check_floating_ip_status(floating_ip, floatingip_status)
        # call the common method in the parent class
        self.check_public_network_connectivity(
            ip_address, ssh_login, private_key, should_connect, msg,
            self.servers)

    def _disassociate_floating_ips(self):
        floating_ip, server = self.floating_ip_tuple
        self._disassociate_floating_ip(floating_ip)
        self.floating_ip_tuple = Floating_IP_tuple(
            floating_ip, None)

    def _reassociate_floating_ips(self):
        floating_ip, server = self.floating_ip_tuple
        name = data_utils.rand_name('new_server-smoke')
        # create a new server for the floating ip
        server = self._create_server(name, self.network)
        self._associate_floating_ip(floating_ip, server)
        self.floating_ip_tuple = Floating_IP_tuple(
            floating_ip, server)

    def _create_new_network(self, create_gateway=False):
        self.new_net = self._create_network(tenant_id=self.tenant_id)
        if create_gateway:
            self.new_subnet = self._create_subnet(
                network=self.new_net)
        else:
            self.new_subnet = self._create_subnet(
                network=self.new_net,
                gateway_ip=None)

    def _hotplug_server(self):
        old_floating_ip, server = self.floating_ip_tuple
        ip_address = old_floating_ip.floating_ip_address
        private_key = self._get_server_key(server)
        ssh_client = self.get_remote_client(ip_address,
                                            private_key=private_key)
        old_nic_list = self._get_server_nics(ssh_client)
        # get a port from a list of one item
        port_list = self._list_ports(device_id=server['id'])
        self.assertEqual(1, len(port_list))
        old_port = port_list[0]
        interface = self.interface_client.create_interface(
            server=server['id'],
            network_id=self.new_net.id)
        self.addCleanup(self.network_client.wait_for_resource_deletion,
                        'port',
                        interface['port_id'])
        self.addCleanup(self.delete_wrapper,
                        self.interface_client.delete_interface,
                        server['id'], interface['port_id'])

        def check_ports():
            self.new_port_list = [port for port in
                                  self._list_ports(device_id=server['id'])
                                  if port['id'] != old_port['id']]
            return len(self.new_port_list) == 1

        if not test.call_until_true(
                check_ports,
                CONF.network.build_timeout,
                CONF.network.build_interval):
            raise exceptions.TimeoutException(
                "No new port attached to the server in time (%s sec)! "
                "Old port: %s. Number of new ports: %d" % (
                    CONF.network.build_timeout, old_port,
                    len(self.new_port_list)))
        new_port = self.net_resources.DeletablePort(
            client=self.network_client, **self.new_port_list[0])

        def check_new_nic():
            new_nic_list = self._get_server_nics(ssh_client)
            self.diff_list = [n for n in new_nic_list if n not in old_nic_list]
            return len(self.diff_list) == 1

        if not test.call_until_true(
                check_new_nic,
                CONF.network.build_timeout,
                CONF.network.build_interval):
            raise exceptions.TimeoutException("Interface not visible on the "
                                              "guest after %s sec"
                                              % CONF.network.build_timeout)

        num, new_nic = self.diff_list[0]
        ssh_client.assign_static_ip(nic=new_nic,
                                    addr=new_port.fixed_ips[0]['ip_address'])
        ssh_client.turn_nic_on(nic=new_nic)

    @staticmethod
    def _get_server_nics(ssh_client):
        reg = re.compile(r'(?P<num>\d+): (?P<nic_name>\w+):')
        ipatxt = ssh_client.get_ip_list()
        return reg.findall(ipatxt)

    def _check_network_internal_connectivity(self, network,
                                             should_connect=True):
        """_check_network_internal_connectivity

        via ssh check VM internal connectivity:
        - ping internal gateway and DHCP port, implying in-tenant connectivity
        pinging both, because L3 and DHCP agents might be on different nodes
        """
        floating_ip, server = self.floating_ip_tuple
        # get internal ports' ips:
        # get all network ports in the new network
        internal_ips = (p['fixed_ips'][0]['ip_address'] for p in
                        self._list_ports(tenant_id=server['tenant_id'],
                                         network_id=network.id)
                        if p['device_owner'].startswith('network'))

        self._check_server_connectivity(floating_ip,
                                        internal_ips,
                                        should_connect)

    def _check_network_external_connectivity(self):
        """_check_network_external_connectivity

        ping public network default gateway to imply external connectivity

        """
        if not CONF.network.public_network_id:
            msg = 'public network not defined.'
            LOG.info(msg)
            return

        # We ping the external IP from the instance using its floating IP
        # which is always IPv4, so we must only test connectivity to
        # external IPv4 IPs if the external network is dualstack.
        v4_subnets = [s for s in self._list_subnets(
            network_id=CONF.network.public_network_id)
            if s['ip_version'] == 4]
        self.assertEqual(1, len(v4_subnets),
                         "Found %d IPv4 subnets" % len(v4_subnets))

        external_ips = [v4_subnets[0]['gateway_ip']]
        self._check_server_connectivity(self.floating_ip_tuple.floating_ip,
                                        external_ips)

    def _check_server_connectivity(self, floating_ip, address_list,
                                   should_connect=True):
        ip_address = floating_ip.floating_ip_address
        private_key = self._get_server_key(self.floating_ip_tuple.server)
        ssh_source = self._ssh_to_server(ip_address, private_key)

        for remote_ip in address_list:
            if should_connect:
                msg = "Timed out waiting for %s to become reachable" \
                      % remote_ip
            else:
                msg = "ip address %s is reachable" % remote_ip
            try:
                self.assertTrue(self._check_remote_connectivity
                                (ssh_source, remote_ip, should_connect),
                                msg)
            except Exception:
                LOG.exception("Unable to access {dest} via ssh to "
                              "floating-ip {src}".format(dest=remote_ip,
                                                         src=floating_ip))
                raise

    @staticmethod
    def _get_server_mtu(ssh_client, interface='eth0'):
        command = 'ip a | grep -v inet | grep ' + interface + \
                  ' | cut -d" " -f 5'
        mtu = ssh_client.exec_command(command)
        return int(mtu)

    @staticmethod
    def _get_server_domain_name(ssh_client):
        command = 'grep search /etc/resolv.conf | cut -d" " -f2'
        domain_name = str(ssh_client.exec_command(command)).rstrip('\n')
        return domain_name

    def _check_extra_dhcp_opts_on_server(self, server, floating_ip_address):
        private_key = self._get_server_key(server)
        ssh_client = self.get_remote_client(floating_ip_address,
                                            private_key=private_key)
        # Fetch MTU FROM ETH0
        # command = 'ip a | grep -v inet | grep eth0 | cut -d" " -f 5'
        mtu = self._get_server_mtu(ssh_client, 'eth0')
        domain_name = self._get_server_domain_name(ssh_client)
        # Compare with values used when creating the port
        self.assertEqual(int(mtu), int(EXTRA_DHCP_OPT_MTU_VALUE),
                         'Extra DHCP option <mut> not set correclty on the VM')
        self.assertEqual(domain_name, EXTRA_DHCP_OPT_DOMAIN_NAME,
                         'Extra DHCP option <domain-name> not set correcty '
                         'on the VM')
        LOG.info("EXTRA DHCP OPTIONS validated OK")

    # TODO(KRIS) FURTHER INVESTIGATE BUT SOMETHING UPSTREAM BROKE THIS TEST
    # TODO(KRIS) CONNECTIVITY IS ANYHOW THESE DAYS TESTED MUCH MORE ALREADY ...
    # TODO(KRIS) ADDED nuage.connectivity.
    # TODO(KRIS) test_icmp_connectivity_os_managed_l3_domain_using_fip
    # TODO(KRIS) for testbed also
    def FIXME_KRIS_test_nuage_fip_network_basic_ops(self):
        """test_nuage_fip_network_basic_ops

        Spin a VM with a security group on an internal network, with
        a floating IP in the public network.
        Relies on the fact that there is connectivity form the test runner
        to this network.
        We use the FIP 2 underlay feature (underlay=true) on the public network
        """
        # Use a port, on which we add :
        #  extra dhcp options (done)
        kwargs = {'boot_with_port': True}
        self._setup_network_and_servers(**kwargs)
        time.sleep(5)  # giving time for servers to come up - TODO(check this)
        self._check_public_connectivity(
            should_connect=True, should_check_floating_ip_status=False)
        # Verify whether our extra dhcp options mad it to the VM
        floating_ip, this_server = self.floating_ip_tuple
        self._check_extra_dhcp_opts_on_server(
            this_server, floating_ip['floating_ip_address'])
        # Check disassociate / associate of the FIP on the same port
        # a number of times
        loop_range = 4
        LOG.info("Starting FIP-2-underlay dis/associate loop on " +
                 str(floating_ip['floating_ip_address']))
        for count in range(1, loop_range, 1):
            self._disassociate_floating_ips()
            time.sleep(FIP_UPDATE_DELAY)
            LOG.info("Loop " + str(count) + "/" + str(loop_range) +
                     " Connectivity is GONE")
            self._check_public_connectivity(
                should_connect=False, should_check_floating_ip_status=False)
            # disassociate de-populates the server in the tuple,
            # populate it again:
            self.floating_ip_tuple = Floating_IP_tuple(
                floating_ip, this_server)
            self._associate_floating_ip(floating_ip, this_server)
            time.sleep(FIP_UPDATE_DELAY)
            LOG.info("Loop " + str(count) + "/" + str(loop_range) +
                     " Connectivity is BACK")
            self._check_public_connectivity(
                should_connect=True, should_check_floating_ip_status=False)
