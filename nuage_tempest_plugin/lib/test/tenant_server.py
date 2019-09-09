# Copyright 2017 - Nokia
# All Rights Reserved.

from base64 import b64encode
import re
import textwrap

from netaddr import IPAddress
from netaddr import IPNetwork

from tempest.common.utils.linux.remote_client import RemoteClient
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class FipAccessConsole(RemoteClient):

    def __init__(self, tenant_server):
        assert tenant_server.associated_fip
        super(FipAccessConsole, self).__init__(
            ip_address=tenant_server.associated_fip,
            username=tenant_server.username,
            password=tenant_server.password,
            pkey=tenant_server.keypair['private_key'],
            servers_client=tenant_server.admin_client)
        self.tenant_server = tenant_server
        self.tag = self.tenant_server.tag

    def exec_command(self, cmd, ssh_shell_prologue=None):
        # Shell options below add more clearness on failures,
        # path is extended for some non-cirros guest oses (centos7)
        if ssh_shell_prologue is None:
            ssh_shell_prologue = self.ssh_shell_prologue
        if ssh_shell_prologue:
            full_cmd = ssh_shell_prologue + " " + cmd
        else:
            full_cmd = cmd

        LOG.debug('[{}] > {}'.format(self.tag, cmd))
        cmd_out = self.ssh_client.exec_command(full_cmd)
        if cmd_out:
            LOG.debug('[{}] < \\\n'
                      '{}'
                      '[EOF]'.format(self.tag, cmd_out))
        else:
            LOG.debug('[{}] <'.format(self.tag))
        return cmd_out

    def send(self, cmd, timeout=CONF.validation.ssh_timeout,
             ssh_shell_prologue=None, one_off_attempt=False,
             assert_success=None, on_failure_return=None):

        output = [on_failure_return]

        if assert_success is None:
            assert_success = not one_off_attempt  # defaulting to False when
            #                                       one-off; else to True

        def send_cmd():
            try:
                cmd_out = self.exec_command(cmd, ssh_shell_prologue)
                output[0] = cmd_out
                return True
            except lib_exc.SSHExecCommandFailed as e:
                LOG.debug('[{}] cmd timed out, got {}'.format(
                    self.tag, e))
                return False
            except Exception as e:
                LOG.debug('[{}] cmd failed, got {} ({})'.format(
                    self.tag, e, e.__class__.__name__))
                raise

        if one_off_attempt:
            success = send_cmd()
        else:
            success = test_utils.call_until_true(send_cmd, timeout, 1)

        if assert_success:
            assert success

        return output[0]

    def ping(self, destination, cnt, interface=None):
        try:
            return self.ping_host(destination, cnt, nic=interface)
        except lib_exc.SSHExecCommandFailed:
            return "SSHExecCommandFailed"


class TenantServer(object):

    """TenantServer

    Object to represent a server managed by the CMS to be consumed by tenants.
    Can be:
    - a tenant VM on a KVM hypervisor
    - a baremetal server
    """
    client = None
    admin_client = None

    def __init__(self, parent_test, client, admin_client,
                 name=None, networks=None, ports=None, security_groups=None,
                 flavor=None, keypair=None, volume_backed=False):
        self.parent_test = parent_test
        self.client = client
        self.admin_client = admin_client

        self.name = name
        self.tag = self.get_display_name()
        self.networks = networks or []
        self.ports = ports or []
        self.security_groups = security_groups or []
        self.flavor = flavor
        self.volume_backed = volume_backed

        self._image_id = None
        self._vm_console = None

        self.username = CONF.validation.image_ssh_user
        self.password = CONF.validation.image_ssh_password
        self.keypair = keypair
        self.openstack_data = None
        self.server_details = None
        self.ips = []
        self.force_dhcp = False
        self.prepare_for_connectivity = False
        self.needs_provisioning = False
        self.associated_fip = None
        self.cloudinit_complete = False
        self.dhcp_validated = False
        self.ips_validated = False
        self.prepare_for_connectivity_complete = False

    def get_display_name(self, shorten_to_x_chars=32,
                         pre_fill_with_spaces=True):
        name = self.name
        if shorten_to_x_chars:
            if len(name) > shorten_to_x_chars:
                name = '...' + name[-(shorten_to_x_chars - 3):]
            elif pre_fill_with_spaces:
                name = ' ' * (shorten_to_x_chars - len(name)) + name
        return name

    def has_console(self):
        return bool(self._vm_console)

    def console(self):
        if not self._vm_console:
            self._vm_console = FipAccessConsole(self)
            self.validate_authentication()
            self.wait_for_cloudinit_to_complete()
        return self._vm_console

    @property
    def image_id(self):
        if not self._image_id:
            self._image_id = CONF.compute.image_ref
        return self._image_id

    @property
    def id(self):
        assert self.openstack_data
        return self.openstack_data['id']

    @staticmethod
    def is_v6_ip(ip):
        return IPAddress(ip['ip_address']).version == 6

    def boot(self, wait_until='ACTIVE', cleanup=True, **kwargs):
        extra_nic_user_data = self.get_user_data_for_nic_prep(
            dhcp_client=CONF.scenario.dhcp_client)
        if extra_nic_user_data:
            # concat both scripts
            if kwargs.get('user_data'):
                kwargs['user_data'] = extra_nic_user_data + kwargs['user_data']
            else:
                kwargs['user_data'] = extra_nic_user_data

        # cleans and logs the user_data script
        if kwargs.get('user_data'):
            if not kwargs['user_data'].startswith('#!'):
                kwargs['user_data'] = '#!/bin/sh\n' + kwargs['user_data']
            LOG.debug('[user-data]\n'
                      '{}'
                      '[EOF]'.format(kwargs['user_data']))
            kwargs['user_data'] = b64encode(textwrap.dedent(
                kwargs['user_data']).lstrip().encode('utf8'))

        LOG.info('[{}] Booting {}'.format(self.tag, self.name))

        self.openstack_data = self.parent_test.osc_create_test_server(
            self.tag, self.client, self.networks, self.ports,
            self.security_groups, wait_until, self.volume_backed,
            self.name, self.flavor, self.image_id, self.keypair, cleanup,
            **kwargs)

        LOG.info('[{}] Became {}'.format(self.tag, wait_until))

        for addresses in self.get_server_details()['addresses'].values():
            address = []
            for addr in addresses:
                address.append(addr['addr'])
            self.ips.append(address)

        LOG.info('[{}] IP\'s are {}'.format(
            self.tag,
            ' and '.join(('/'.join(address for address in addresses))
                         for addresses in self.ips)))
        return self.openstack_data

    def did_deploy(self):
        return bool(self.openstack_data)

    def sync_with(self, osc_server_id):
        self.openstack_data = \
            self.admin_client.show_server(osc_server_id)['server']

    def get_server_details(self, force=False):
        if not self.server_details or force:
            self.server_details = \
                self.admin_client.show_server(self.id)['server']
        return self.server_details

    def get_server_networks(self):
        if self.networks:
            return self.networks
        else:
            networks = []
            for port in self.ports:
                networks.append(port['parent_network'])
            return networks

    def get_server_ips_in_network(self, network_name, filter_by_ip_type=None):
        assert self.did_deploy()
        server = self.get_server_details()
        ip_addresses = []
        self.parent_test.assertIn(network_name, server['addresses'])
        for subnet_interface in server['addresses'][network_name]:
            if (filter_by_ip_type is None or
                    subnet_interface['version'] == filter_by_ip_type):
                ip_addresses.append(subnet_interface['addr'])
        return ip_addresses

    def get_server_ip_in_network(self, network_name, ip_type=4):
        addresses = self.get_server_ips_in_network(network_name,
                                                   filter_by_ip_type=ip_type)
        return addresses[0] if addresses else None

    def is_dhcp_enabled(self, network):
        return (
            self.force_dhcp or
            network.get('v4_subnet') and network['v4_subnet']['enable_dhcp'] or
            network.get('v6_subnet') and network['v6_subnet']['enable_dhcp'])

    def complete_prepare_for_connectivity(self):
        if self.prepare_for_connectivity_complete:
            return  # don't spend further cycles

        if self.prepare_for_connectivity:
            assert self.console()  # with that, enable it also, which includes
            #                        polling for cloudinit to complete

        # if interfaces need to be statically configured, by all means do
        self.provision()

        # if interfaces are dhcp provisioned, validate them, when we can
        if self.has_console():
            self.validate_dhcp()
            # if not self.force_dhcp:
            #     self.validate_ips()   # can't use for multiple v4 networks...
        else:
            # only thing we can do is estimate a time for this VM to be ready
            # for testing
            self.parent_test.sleep(10, 'Estimating time for {} to be ready '
                                       'for action'.format(self.name),
                                   tag=self.parent_test.test_name)

        self.prepare_for_connectivity_complete = True

    def associate_fip(self, fip):
        self.associated_fip = fip

    def send(self, cmd, timeout=CONF.validation.ssh_timeout,
             ssh_shell_prologue=None, as_sudo=True,
             one_off_attempt=False, assert_success=None,
             on_failure_return=None):
        if as_sudo and not cmd.startswith('sudo'):
            cmd = 'sudo ' + cmd
        return self.console().send(cmd,
                                   timeout=timeout,
                                   ssh_shell_prologue=ssh_shell_prologue,
                                   one_off_attempt=one_off_attempt,
                                   assert_success=assert_success,
                                   on_failure_return=on_failure_return)

    def validate_authentication(self):
        LOG.info('[{}] Validating authentication'.format(self.tag))
        self.console().validate_authentication()
        LOG.info('[{}] Authentication succeeded'.format(self.tag))

    def wait_for_cloudinit_to_complete(self):
        if not self.cloudinit_complete:
            LOG.info('[{}] Waiting for cloudinit to complete'.format(self.tag))

            count = 0
            backoff_time = 2

            # TODO(OPENSTACK-2665)
            #   wait_for_cloudinit_to_complete is not OS independent
            while self.send('ps -ef | '
                            'grep /*/datasource/data/user-data | '
                            'grep -v grep '
                            '|| true',
                            assert_success=False, on_failure_return=True):
                if backoff_time < 30:
                    backoff_time *= 2
                    if backoff_time > 30:
                        backoff_time = 30
                if backoff_time == 30:
                    count += 1
                    self.parent_test.assertTrue(count < 5)  # limit
                    # (fail test when count is 5)
                self.parent_test.sleep(
                    backoff_time,
                    'Waiting for cloudinit to complete', tag=self.tag)

            self.cloudinit_complete = True
            LOG.info('[{}] Cloudinit completed'.format(self.tag))

    def provision(self):
        if self.needs_provisioning and not self.force_dhcp:
            LOG.info('[{}] Provisioning'.format(self.tag))

            networks = self.networks
            if not networks:
                networks = []
                for port in self.ports:
                    if port.get('parent_network'):
                        networks.append(port['parent_network'])

            for eth_i, network in enumerate(networks):
                if network.get('v4_subnet'):
                    if not network['v4_subnet']['enable_dhcp']:
                        server_ipv4 = self.get_server_ip_in_network(
                            network['name'])
                        self.configure_static_interface(
                            server_ipv4, subnet=network['v4_subnet'],
                            ip_version=4, device=eth_i)
                if network.get('v6_subnet'):
                    if not network['v6_subnet']['enable_dhcp']:
                        server_ipv6 = self.get_server_ip_in_network(
                            network['name'], ip_type=6)
                        self.configure_static_interface(
                            server_ipv6, subnet=network['v6_subnet'],
                            ip_version=6, device=eth_i)

            self.needs_provisioning = False
            LOG.info('[{}] Provisioning complete'.format(self.tag))

    def validate_dhcp(self):
        if not self.dhcp_validated:
            LOG.info('[{}] Validating DHCP'.format(self.tag))

            networks = self.networks
            if not networks:
                networks = []
                for port in self.ports:
                    if port.get('parent_network'):
                        networks.append(port['parent_network'])

            for eth_i, network in enumerate(networks):
                if network.get('v4_subnet'):
                    if network['v4_subnet']['enable_dhcp']:
                        self.device_served_by_dhclient(
                            'eth{}'.format(eth_i), 4, assert_true=True)
                if network.get('v6_subnet'):
                    if network['v6_subnet']['enable_dhcp']:
                        self.device_served_by_dhclient(
                            'eth{}'.format(eth_i), 6, assert_true=True)
            self.dhcp_validated = True
            LOG.info('[{}] Validation complete'.format(self.tag))

    def is_ip_configured(self, ip, assert_permanent=False,
                         assert_true=False):
        ip_configured = False
        for cnt in range(3):
            if assert_permanent:
                ip_configured = bool(self.send('ip a '
                                               '| grep "{}.* scope global" '
                                               '| grep -v tentative '
                                               '|| true'.format(ip)))
            else:
                ip_configured = bool(self.send('ip a '
                                               '| grep "{}.* scope global" '
                                               '|| true'.format(ip)))
            if ip_configured:
                break
            else:
                self.parent_test.sleep(
                    3, 'Waiting for ip address {} to show up'.format(ip),
                    tag=self.tag)

        if assert_permanent or assert_true:
            self.parent_test.assertTrue(ip_configured)

        if ip_configured:
            LOG.debug('[{}] {} confirmed as {}'.format(
                self.tag,
                ip, 'permanent' if assert_permanent else 'configured'))

        return ip_configured

    def validate_ips(self):
        if not self.ips_validated:
            LOG.info('[{}] Validating server IP\'s'.format(self.tag))

            for addresses in self.ips:
                for address in addresses:
                    self.is_ip_configured(
                        address, assert_permanent=True, assert_true=True)

            self.ips_validated = True
            LOG.info('[{}] Validating server IP\'s OK!'.format(self.tag))

    def device_served_by_dhclient(self, device, ip_version,
                                  assert_true=False):
        LOG.info('[{}] Checking dhclient({}) for {}'.format(
            self.tag, ip_version, device))
        wildcard = '*' if ip_version == 4 else '*-6'
        extra_filter = '| grep -v "\\-6" ' if ip_version == 4 else ''

        served = None
        for attempt in range(10 if assert_true else 1):
            served = bool(self.send('ps -ef '
                                    '| grep "dhclient.{}.*{}" {} '
                                    '| grep -v grep || true'.format(
                                        wildcard, device, extra_filter)))
            if served:
                if attempt > 0:
                    LOG.warn('[{}] Retry on dhclient check helped!'.format(
                        self.tag))
                LOG.info('[{}] {}{} is served by dhclient({})'.format(
                    self.tag,
                    'On attempt {}, '.format(attempt + 1) if attempt else '',
                    device, ip_version))
                break

            else:
                LOG.warn('[{}] {} is NOT served by dhclient({})'.format(
                    self.tag, device, ip_version))
                self.parent_test.sleep(
                    3, 'Waiting for dhclient process to show up',
                    tag=self.tag)

        if assert_true:
            self.parent_test.assertTrue(
                served,
                'DHCPv{} expected to be served on {}/{}!'.format(
                    ip_version, self.name, device))
        return served

    def configure_static_interface(self, ip, subnet, ip_version=4, device=0):
        device = 'eth{}'.format(device)
        ip_v = 'ip' if ip_version == 4 else 'ip -6'

        LOG.info('[{}] Configuring interface {}/{}'.format(
            self.tag, ip, device))

        if ((subnet['enable_dhcp'] or self.force_dhcp) and
                # there is no point in checking for the itf to be served by the
                # dhcp client if the subnet has no dhcp enabled

                # and if dhcp is enabled, and if dhclient is used,
                # check whether it serves the interface already
                (CONF.scenario.dhcp_client == 'dhclient' and
                 self.device_served_by_dhclient(device, ip_version))):

            # if so, nothing to do
            if not self.force_dhcp:
                LOG.info('[{}] Validating {}/{} is set'.format(
                    self.tag, ip, device))
                self.is_ip_configured(ip, assert_true=True)

        else:
            # else, configure statically
            LOG.info('[{}] Configuring it statically'.format(self.tag))

            mask_bits = IPNetwork(subnet['cidr']).prefixlen
            gateway_ip = subnet['gateway_ip']

            attempt = 1
            while (attempt <= 2 and
                    self.send(
                        '{} addr add {}/{} dev {}'.format(
                            ip_v, ip, mask_bits, device),
                        one_off_attempt=True) is None or
                    not self.is_ip_configured(ip)):
                self.send('{} addr del {}/{} dev {} || true'.format(
                    ip_v, ip, mask_bits, device))
                attempt += 1

            self.parent_test.assertTrue(attempt <= 2)

            self.send('ip link set dev {} up || true'.format(device))

            if gateway_ip:
                self.send('{} route add default via {} || true'.format(
                    ip_v, gateway_ip))

        # with all config up now, validate for non-tentative
        self.is_ip_configured(ip, assert_permanent=True)

        LOG.info('[{}] Successfully set {}/{}'.format(self.tag, ip, device))

    def configure_vlan_interface(self, ip, interface, vlan):
        self.send('ip link add link %s name %s.%s type vlan id %s ' % (
            interface, interface, vlan, vlan))
        self.send('ip addr add %s dev %s.%s' % (
            ip, interface, vlan))
        self.send('ip link set dev %s.%s up' % (interface, vlan))

    def configure_ip_fwd(self):
        self.send('sysctl -w net.ipv4.ip_forward=1')

    def bring_down_interface(self, interface):
        self.send('ip link set dev %s down' % interface)

    def configure_sfc_vm(self, vlan):
        self.send('ip link add link eth0 name eth0.%s type vlan id %s ' %
                  (vlan, vlan))
        self.send('ifconfig eth1 up')
        self.send('udhcpc -i eth1')
        ip = self.send("ifconfig eth0 | grep 'inet addr' "
                       "| cut -d ':' -f 2 | cut -d ' ' -f 1")[0]
        self.send('ifconfig eth0.%s %s up' % (vlan, ip))
        self.send('ip link add link eth1 name eth1.%s type vlan id %s ' %
                  (vlan, vlan))
        ip = self.send("ifconfig eth1 | grep 'inet addr' "
                       "| cut -d ':' -f 2 | cut -d ' ' -f 1")[0]
        self.send('ifconfig eth1.%s %s up' % (vlan, ip))
        self.send('brctl addbr br0')
        self.send('brctl addif br0 eth0.%s' % vlan)
        self.send('brctl addif br0 eth1.%s' % vlan)
        self.send('ip link set br0 up')
        self.send('ifconfig eth0.%s up' % vlan)
        self.send('ifconfig eth1.%s up' % vlan)

    def mount_config_drive(self):
        blk_id_out = self.send('blkid | grep -i config-2')
        dev_name = re.match('([^:]+)', blk_id_out[0]).group()
        self.send('mount %s /mnt' % dev_name)

    def unmount_config_drive(self):
        self.send('umount /mnt')

    def get_user_data_for_nic_prep(self, dhcp_client='udhcpc'):
        networks = self.get_server_networks()
        s = ''
        nbr_nics = len(networks)
        first_nic_prepared = True
        for nic, network in enumerate(networks):
            if nic == 0:
                continue   # nic 0 is auto-served
            if self.is_dhcp_enabled(network):
                if first_nic_prepared:
                    LOG.info('[{}] Preparing user-data for {} nics'.format(
                        self.tag, nbr_nics))
                    supported_clients = ['udhcpc', 'dhclient']
                    if dhcp_client not in supported_clients:
                        raise lib_exc.exceptions.InvalidConfiguration(
                            '%s DHCP client unsupported' % dhcp_client)
                    s = '#!/bin/sh\n'
                    first_nic_prepared = False
                if dhcp_client == 'udhcpc':
                    s += '/sbin/cirros-dhcpc up eth%s\n' % nic
                else:
                    s += '/sbin/ip link set eth%s up\n' % nic
                    if network.get('v6_subnet'):
                        s += '/bin/sleep 2\n'  # TODO(OPENSTACK-2666) this is
                        #                         current low-cost approach
                        #                         for v6 DAD to complete, but
                        #                         is platform-dependent
                        s += '/sbin/dhclient -1 -6 eth%s\n' % nic
                    if network.get('v4_subnet'):
                        s += '/sbin/dhclient -1 eth%s\n' % nic
        return s

    def ping(self, destination, count=3, interface=None, should_pass=True):
        self.complete_prepare_for_connectivity()
        # destination readiness is invoker's responsibility!

        ping_out = self.console().ping(destination, count, interface)
        expected_packet_cnt = count if should_pass else 0

        return str(expected_packet_cnt) + ' packets received' in ping_out

    def curl(self, destination_ip, destination_port=80,
             source_port=None, max_time_to_wait_for_response=2,
             max_time_to_retry=10):
        """Curl from this server to destination

        :param self: me
        :param destination_ip: netaddr.IPAddress
        :param destination_port: tcp port (optional)
        :param source_port: tcp port (optional)
        :param max_time_to_wait_for_response: curl will give up after this time
        :param max_time_to_retry: retry until this timer expires
        :return: Output or False on failure
        """

        self.complete_prepare_for_connectivity()
        # destination readiness is invoker's responsibility!

        command = ('curl {ipv6} -g --max-time {max_wait} {source_port} '
                   'http://{destination_ip}:{destination_port}'
                   .format(ipv6='-6' if destination_ip.version == 6 else '',
                           max_wait=max_time_to_wait_for_response,
                           source_port=('--local-port {}'.format(source_port)
                                        if source_port else ''),
                           destination_ip=('[{}]'.format(destination_ip)
                                           if destination_ip.version == 6
                                           else destination_ip),
                           destination_port=destination_port))
        return self.send(command,
                         timeout=max_time_to_retry,
                         assert_success=False,
                         on_failure_return=False)

    def echo_debug_info(self):
        self.send("echo; "
                  "echo '----- ip route -----'; ip route; "
                  "echo '----- ip a     -----'; ip a; "
                  "echo '----- arp -a   -----'; arp -a; "
                  "echo")

    def get_ip_addresses(self):
        ips = self.get_server_details()['addresses'].values()[0]
        fixed_ip4 = fixed_ip6 = None
        for ip in ips:
            if ip['version'] == 4:
                fixed_ip4 = ip['addr']
            else:
                fixed_ip6 = ip['addr']
        return IPAddress(fixed_ip4), IPAddress(fixed_ip6)
