# Copyright 2017 - Nokia
# All Rights Reserved.

from base64 import b64encode
import re
import textwrap

from netaddr import IPAddress
from netaddr import IPNetwork

from tempest.common.utils.linux.remote_client import RemoteClient
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class FipAccessConsole(RemoteClient):

    def __init__(self, tenant_server):
        tenant_server.assert_has_fip()
        super(FipAccessConsole, self).__init__(
            ip_address=tenant_server.get_fip_ip(),
            username=tenant_server.username,
            password=tenant_server.password,
            pkey=tenant_server.keypair['private_key'],
            servers_client=tenant_server.parent.manager.servers_client)
        self.tag = tenant_server.tag

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
            self.ping_host(destination, cnt, nic=interface)
            return True
        except lib_exc.SSHExecCommandFailed:
            return False


class TenantServer(object):

    """TenantServer

    Object to represent a server managed by the CMS to be consumed by tenants.
    Can be:
    - a tenant VM on a KVM hypervisor
    - a baremetal server
    """

    def __init__(self, parent, name=None, networks=None, ports=None,
                 security_groups=None, flavor=None, keypair=None,
                 volume_backed=False):
        self.parent = parent
        self.name = name or data_utils.rand_name('Tenant-')
        self.tag = self.get_display_name()
        self.username = CONF.validation.image_ssh_user
        self.password = CONF.validation.image_ssh_password

        self.networks = networks or []
        self.ports = ports or []
        self.security_groups = security_groups or []
        self.flavor = flavor
        self.volume_backed = volume_backed
        self.keypair = keypair
        self.openstack_data = None
        self.server_details = None
        self.force_dhcp = False
        self.set_to_prepare_for_connectivity = False
        self.cloudinit_complete = False
        self.waiting_for_cloudinit_completion = False
        self.needs_provisioning = False
        self.is_being_provisioned = False
        self.associated_fip = None

        self._image_id = None
        self._vm_console = None

    def __repr__(self):
        return 'TenantServer [{}]: {}'.format(
            self.name,
            {
                'networks': self.networks,
                'ports': self.ports,
                'security_groups': self.security_groups,
                'keypair': self.keypair,
                'associated_fip': self.get_fip_ip()
            }
        )

    def get_display_name(self, shorten_to_x_chars=32,
                         pre_fill_with_spaces=True):
        name = self.name
        if shorten_to_x_chars:
            if len(name) > shorten_to_x_chars:
                name = '...' + name[-(shorten_to_x_chars - 3):]
            elif pre_fill_with_spaces:
                name = ' ' * (shorten_to_x_chars - len(name)) + name
        return name

    def sleep(self, seconds=1, msg=None):
        self.parent.sleep(seconds, msg, tag=self.tag)

    def init_console(self):
        self._vm_console = FipAccessConsole(self)

    def has_console(self):
        return bool(self._vm_console)

    def console(self):
        if not self._vm_console:
            self.init_console()
            self.validate_authentication()
            self.wait_for_cloudinit_to_complete()
            self.provision()
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

    def boot(self, wait_until='ACTIVE', manager=None, cleanup=True, **kwargs):
        extra_nic_user_data = self.get_user_data_for_nic_prep(
            dhcp_client=CONF.scenario.dhcp_client)
        if extra_nic_user_data:
            # concat both scripts
            if kwargs.get('user_data'):
                kwargs['user_data'] = extra_nic_user_data + kwargs['user_data']
            else:
                kwargs['user_data'] = extra_nic_user_data

        # mark the end of cloudinit
        end_of_cloudinit = "awk '{print $1*1000}' /proc/uptime > " \
                           "/tmp/cloudinit_completed\n"
        if kwargs.get('user_data'):
            kwargs['user_data'] += ('\n' + end_of_cloudinit)
        else:
            kwargs['user_data'] = end_of_cloudinit

        if not kwargs['user_data'].startswith('#!'):
            kwargs['user_data'] = '#!/bin/sh\n' + kwargs['user_data']
        LOG.debug('[user-data]\n'
                  '{}'
                  '[EOF]'.format(kwargs['user_data']))

        kwargs['user_data'] = b64encode(textwrap.dedent(
            kwargs['user_data']).lstrip().encode('utf8'))

        # and boot the server
        LOG.info('[{}] Booting {}'.format(self.tag, self.name))
        # (calling  _create_server which is private method, which is intended)
        self.openstack_data = self.parent._create_server(
            self.tag, self.networks, self.ports,
            self.security_groups, wait_until, self.volume_backed,
            self.name, self.flavor, self.image_id, self.keypair,
            manager, cleanup, **kwargs)

        LOG.info('[{}] Became {}'.format(self.tag, wait_until))
        LOG.info('[{}] IP\'s are {}'.format(
            self.tag,
            ' and '.join(
                ('/'.join(address for address in addresses))
                for addresses in self.get_server_ips(manager=manager))))
        return self.openstack_data

    def did_deploy(self):
        return bool(self.openstack_data)

    def sync_with(self, osc_server_id, manager=None):
        self.openstack_data = \
            self.parent.get_server(osc_server_id, manager)

    def get_server_details(self, server_id=None, manager=None):
        if not self.server_details:
            self.server_details = \
                self.parent.get_server(server_id or self.id, manager)
        return self.server_details

    def get_server_networks(self, manager=None):
        if not self.networks:
            for port in self.ports:
                self.networks.append(
                    self.parent.get_network(port['network_id'], manager))
        return self.networks

    def get_server_interfaces(self, network_name=None, manager=None):
        # returning a list of lists, per network
        server_addresses = self.get_server_details(
            manager=manager)['addresses']
        return ([server_addresses[network_name]] if network_name
                else server_addresses.values())

    def get_server_ips(self, network_name=None, manager=None,
                       filter_by_ip_version=None,
                       filter_by_os_ext_ips_type='fixed'):
        ips = []
        for interfaces in self.get_server_interfaces(network_name, manager):
            addresses = []
            for interface in interfaces:
                if ((filter_by_os_ext_ips_type is None or
                        interface['OS-EXT-IPS:type'] ==
                        filter_by_os_ext_ips_type) and
                    (filter_by_ip_version is None or
                     interface['version'] == filter_by_ip_version)):
                    addresses.append(interface['addr'])
            ips.append(addresses)
        return ips

    def get_server_port_in_network(self, network, manager=None):
        return self.parent.get_port_in_network(self.id, network, manager)

    def get_server_ip_in_network(self, network_name, ip_version=4,
                                 manager=None):
        addresses = self.get_server_ips(network_name, manager,
                                        filter_by_ip_version=ip_version)[0]
        return addresses[0] if addresses else None

    def associate_fip(self, fip):
        self.associated_fip = fip

        LOG.info('[{}] Obtained FIP = {}'.format(
            self.tag, fip['floating_ip_address']))

    def get_fip_ip(self):
        return (self.associated_fip['floating_ip_address']
                if self.associated_fip else None)

    def assert_has_fip(self, assert_active_fip=False):
        self.parent.assertIsNotNone(self.associated_fip)
        if assert_active_fip:  # CAUTION: only works for OS managed FIPs...
            self.parent.assertEqual(
                'ACTIVE', self.parent.get_floatingip(
                    self.associated_fip['id'])['status'],
                '[{}] FIP is NOT active: {}'.format(
                    self.tag, self.associated_fip))

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
        if self.has_console():
            LOG.info('[{}] Validating authentication with {}'.format(
                self.tag, self._vm_console.ip_address))
            try:
                self.console().validate_authentication()
            except lib_exc.SSHTimeout as e:
                self.parent.fail('[{}] SSH timeout: {}'.format(
                    self.tag, e))
            LOG.info('[{}] Authentication succeeded'.format(self.tag))
        else:
            self.console()  # doing more than authentication check alone
            #                 (i.e. completing all steps), which is good

    def wait_for_cloudinit_to_complete(self):
        if (not self.cloudinit_complete and
                not self.waiting_for_cloudinit_completion):
            LOG.info('[{}] Waiting for cloudinit to complete'.format(self.tag))
            self.waiting_for_cloudinit_completion = True

            count = 0
            backoff_time = 1.5
            max_backoff_time = 10
            while not self.send('[ -f /tmp/cloudinit_completed ] && echo 1 '
                                '|| true', as_sudo=False):
                if backoff_time < max_backoff_time:
                    backoff_time = int(backoff_time * 2)  # 3, 6, 12, 24, ...
                    if backoff_time > max_backoff_time:
                        backoff_time = max_backoff_time  # 3, 6, 10, 10, ...
                if backoff_time == max_backoff_time:
                    count += 1
                    self.parent.assertTrue(count < 10)  # limit
                self.sleep(backoff_time, 'Waiting for cloudinit to complete')

            # check the cloudinit completion time and add up to 3 secs if no
            # 3 secs elapsed yet
            extra_elapse_time = 3  # this is the 3 seconds - adjust to need...
            cloudinit_uptime = int(self.send('cat /tmp/cloudinit_completed'))
            current_uptime = int(self.send(
                "awk '{print $1*1000}' /proc/uptime"))
            cloudinit_completion_time = int(
                (current_uptime - cloudinit_uptime) / 1000)
            LOG.debug('[{}] Cloudinit completed {} secs ago'.format(
                self.tag, cloudinit_completion_time))

            if cloudinit_completion_time < extra_elapse_time:
                # give elapse time after cloudinit completed, to make sure the
                # server got fully initialized and is now ready for ping test
                extra_sleep = extra_elapse_time - cloudinit_completion_time
                self.sleep(extra_sleep, 'Giving cloudinit some extra time')

            self.waiting_for_cloudinit_completion = False
            self.cloudinit_complete = True
            LOG.info('[{}] Ready for action'.format(self.tag))

    # TODO(Kris) this needs to go out, by provisioning entirely thru cloudinit
    def provision(self, manager=None):
        if self.needs_provisioning and not self.is_being_provisioned:
            LOG.info('[{}] Provisioning'.format(self.tag))

            self.is_being_provisioned = True

            for eth_i, network in enumerate(self.get_server_networks(manager)):
                v4_subnet = self.parent.get_network_subnet(network, 4, manager)
                if v4_subnet and not v4_subnet['enable_dhcp']:
                    server_ipv4 = self.get_server_ip_in_network(
                        network['name'], ip_version=4, manager=manager)
                    self.configure_static_interface(
                        server_ipv4, v4_subnet, ip_version=4, device=eth_i)
                v6_subnet = self.parent.get_network_subnet(network, 6, manager)
                if v6_subnet and not v6_subnet['enable_dhcp']:
                    server_ipv6 = self.get_server_ip_in_network(
                        network['name'], ip_version=6, manager=manager)
                    self.configure_static_interface(
                        server_ipv6, v6_subnet, ip_version=6, device=eth_i)

            self.is_being_provisioned = False
            self.needs_provisioning = False
            LOG.info('[{}] Provisioning complete'.format(self.tag))

    def wait_until_ip_configured(self, ip, assert_permanent=False,
                                 assert_true=False):
        ip_configured = False
        for _ in range(15):
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
                self.sleep(3, 'Waiting for ip {} to show up'.format(ip))

        if assert_permanent or assert_true:
            self.parent.assertTrue(ip_configured)

        if ip_configured:
            LOG.debug('[{}] {} confirmed as {}'.format(
                self.tag,
                ip, 'permanent' if assert_permanent else 'configured'))

        return ip_configured

    def device_served_by_dhclient(self, device, ip_version,
                                  assert_true=False):
        LOG.info('[{}] Checking dhclient({}) for {}'.format(
            self.tag, ip_version, device))
        wildcard = '*' if ip_version == 4 else '*-6'
        extra_filter = '| grep -v "\\-6" ' if ip_version == 4 else ''

        served = None
        for attempt in range(10 if assert_true else 1):
            served = bool(self.send('ps -e '
                                    '| grep "dhclient.{}.*{}" {} '
                                    '|| true'.format(
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
                self.sleep(3, 'Waiting for dhclient process to show up')

        if assert_true:
            self.parent.assertTrue(
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
                self.wait_until_ip_configured(ip, assert_true=True)

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
                    not self.wait_until_ip_configured(ip)):
                self.send('{} addr del {}/{} dev {} || true'.format(
                    ip_v, ip, mask_bits, device))
                attempt += 1

            self.parent.assertTrue(attempt <= 2)

            self.send('ip link set dev {} up || true'.format(device))

            if gateway_ip:
                self.send('{} route add default via {} || true'.format(
                    ip_v, gateway_ip))

        # with all config up now, validate for non-tentative
        self.wait_until_ip_configured(ip, assert_permanent=True)

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

    def get_user_data_for_nic_prep(self, dhcp_client='udhcpc', manager=None):

        if not dhcp_client:
            # Not all images (e.g. RHEL 7-7) use DHCP client
            # they instead configure statically through cloudinit
            return

        networks = self.get_server_networks(manager)
        s = ''
        nbr_nics = len(networks)
        first_nic_prepared = True
        for nic, network in enumerate(networks):
            if nic == 0:
                continue   # nic 0 is auto-served

            # TODO(Kris) check each subnet separately for dhcp seems more
            #            suited?
            if self.force_dhcp or self.parent.is_dhcp_enabled(network):
                if first_nic_prepared:
                    LOG.info('[{}] Preparing user-data for {} nics'.format(
                        self.tag, nbr_nics))
                    supported_clients = ['udhcpc', 'dhclient']
                    if dhcp_client not in supported_clients:
                        raise lib_exc.InvalidConfiguration(
                            '%s DHCP client unsupported' % dhcp_client)
                    s = '#!/bin/sh\n'
                    first_nic_prepared = False
                if dhcp_client == 'udhcpc':
                    s += '/sbin/cirros-dhcpc up eth%s\n' % nic
                else:
                    s += '/sbin/ip link set eth%s up\n' % nic
                    if self.parent.get_network_subnet(network, 6,
                                                      manager=manager):
                        s += '/bin/sleep 2\n'  # TODO(OPENSTACK-2666) this is
                        #                           current low-cost approach
                        #                              for v6 DAD to complete,
                        #                           but is platform-dependent
                        s += '/sbin/dhclient -1 -6 eth%s\n' % nic
                    if self.parent.get_network_subnet(network, 4,
                                                      manager=manager):
                        s += '/sbin/dhclient -1 eth%s\n' % nic
        return s

    def ping(self, destination, count=3, interface=None, should_pass=True):
        passed = self.console().ping(destination, count, interface)
        return should_pass == passed

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
