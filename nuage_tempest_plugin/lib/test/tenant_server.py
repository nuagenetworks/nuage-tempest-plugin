# Copyright 2017 - Nokia
# All Rights Reserved.

from base64 import b64encode
import re
import socket
import textwrap
import time

from netaddr import IPAddress
from netaddr import IPNetwork

from tempest.common.utils.linux.remote_client import RemoteClient
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils as utils

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class FipAccessConsole(RemoteClient):

    def __init__(self, tenant_server):
        tenant_server.assert_has_fip()
        super(FipAccessConsole, self).__init__(
            ip_address=tenant_server.get_fip_ip(),
            username=tenant_server.username,
            password=tenant_server.password,
            pkey=tenant_server.private_key,
            servers_client=tenant_server.parent.manager.servers_client)
        self.tag = tenant_server.tag
        self.parent = tenant_server.parent

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
                      u'{}'
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
                LOG.debug('[{}] cmd failed, got {}'.format(
                    self.tag, e))
                return False
            except Exception as e:
                self.parent.fail('[{}] "{}" cmd failed, got {} ({})'.format(
                    cmd, self.tag, e, e.__class__.__name__))

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

    END_OF_CLOUDINIT_TAG = 'Cloud-init COMPLETE'
    FILL_SERVER_NAME_UP_TO_X_CHARS = 51  # 7 + 1 + 32 + 1 + 10
    # e.g. tempest-_icmp_connectivity_l2_os_managed-186135274

    def __init__(self, parent, name=None, networks=None, ports=None,
                 security_groups=None, flavor=None, keypair=None,
                 volume_backed=False):
        self.parent = parent
        self.name = name or parent.get_randomized_name()
        self.tag = self.get_display_name()
        self.username = CONF.validation.image_ssh_user
        self.password = CONF.validation.image_ssh_password

        self.networks = networks or []
        self.ports = ports or []
        self.security_groups = security_groups or []
        self.flavor = flavor
        self.volume_backed = volume_backed

        # only needed pre-boot
        self.key_name = keypair['name'] if keypair else None

        # remaining needed for ssh login to the server
        self.private_key = keypair['private_key'] if keypair else None

        self.openstack_data = None
        self.server_details = None
        self.force_dhcp = False
        self.associated_fip = None

        self._image_id = None
        self._vm_console = None

        self.set_to_prepare_for_connectivity = False
        self.cloudinit_complete = False
        self.waiting_for_cloudinit_completion = False
        self.needs_provisioning = False
        self.is_being_provisioned = False

        self.boot_time = None
        self.active_time = None
        self.cloudinit_complete_time = None

        self.in_failed_state = False

    def __repr__(self):
        return 'TenantServer [{}]: {}'.format(
            self.name,
            {
                'networks': self.networks,
                'ports': self.ports,
                'security_groups': self.security_groups,
                'private_key': self.private_key,
                'associated_fip': self.get_fip_ip()
            }
        )

    def clone_internal_states(self, origin_server):
        self.set_to_prepare_for_connectivity = \
            origin_server.set_to_prepare_for_connectivity
        self.cloudinit_complete = origin_server.cloudinit_complete
        self.waiting_for_cloudinit_completion = \
            origin_server.waiting_for_cloudinit_completion
        self.needs_provisioning = origin_server.needs_provisioning
        self.is_being_provisioned = origin_server.is_being_provisioned

        self.boot_time = origin_server.boot_time
        self.active_time = origin_server.active_time
        self.cloudinit_complete_time = origin_server.cloudinit_complete_time

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

    def print_debug_info(self, include_on_instance_info=True):
        LOG.debug('Dumping info for instance {} with ID {}'.format(
            self.name, self.id))
        LOG.debug(self.compose_console_log_dump())
        if (include_on_instance_info and
                self.set_to_prepare_for_connectivity and
                self.cloudinit_complete):
            self.send('ip a')
        if self.get_hypervisor_hostname() == socket.gethostname():
            # this is a locally deployed VM
            self.parent.execute_from_shell('sudo ovs-appctl vm/port-show')

    def fail(self, msg, exc=None):
        LOG.error('Instance {} with ID {} FAILED'.format(self.name, self.id))
        if exc:
            msg += ': {}'.format(exc)
        LOG.error('[{}] {}'.format(self.tag, msg))
        if not self.in_failed_state:
            self.in_failed_state = True
            self.print_debug_info()
            self.parent.fail(msg)

    def init_console(self):
        self._vm_console = FipAccessConsole(self)

    def has_console(self):
        return bool(self._vm_console)

    def console(self):
        if not self._vm_console:
            self.init_console()
            self.prepare_for_connectivity()
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

    def get_hypervisor_hostname(self):
        return self.get_server_details()['OS-EXT-SRV-ATTR:hypervisor_hostname']

    @staticmethod
    def is_v6_ip(ip):
        return IPAddress(ip['ip_address']).version == 6

    def get_console_log(self, length=None):
        return self.parent.get_console_log(self.id, length=length)

    def compose_console_log_dump(self, log=None, length=None):
        if log is None:
            log = self.get_console_log(length=length)
        return '[{}] [console-log]\n{}\n[end]'.format(self.tag, log)

    def boot(self, wait_until='ACTIVE', force_config_drive=False,
             manager=None, cleanup=True, **kwargs):
        extra_nic_user_data = self.get_user_data_for_nic_prep(
            dhcp_client=CONF.scenario.dhcp_client, manager=manager)
        if extra_nic_user_data:
            # concat both scripts
            if kwargs.get('user_data'):
                kwargs['user_data'] = extra_nic_user_data + kwargs['user_data']
            else:
                kwargs['user_data'] = extra_nic_user_data

        echo_end_of_cloudinit = 'echo {}\n'.format(self.END_OF_CLOUDINIT_TAG)

        if kwargs.get('user_data'):
            kwargs['user_data'] += ('\n' + echo_end_of_cloudinit)
        else:
            kwargs['user_data'] = echo_end_of_cloudinit

        if not kwargs['user_data'].startswith('#!'):
            kwargs['user_data'] = '#!/bin/sh\n' + kwargs['user_data']
        LOG.debug('[user-data]\n'
                  u'{}'
                  '[EOF]'.format(kwargs['user_data']))

        kwargs['user_data'] = b64encode(textwrap.dedent(
            kwargs['user_data']).lstrip().encode('utf8'))

        # force use of config drive if no metadata agent is configured
        if (force_config_drive or
                not CONF.compute_feature_enabled.metadata_service):
            kwargs['config_drive'] = True

        # and boot the server
        LOG.info('[{}] Booting {}'.format(self.tag, self.name))
        self.boot_time = time.time()
        self.openstack_data = self.parent._create_server(
            self.name, self.tag, self.networks, self.ports,
            self.security_groups, wait_until, self.volume_backed, self.flavor,
            self.image_id, self.key_name, manager, cleanup, **kwargs)

        self.active_time = time.time()

        LOG.info('[{}] Became {} in {} secs'.format(
            self.tag, wait_until, int(self.active_time - self.boot_time)))
        LOG.info('[{}] IP\'s are {}'.format(
            self.tag,
            ' and '.join(
                ('/'.join(address for address in addresses))
                for addresses in self.get_server_ips(manager=manager))))

        return self.openstack_data

    def did_deploy(self):
        return bool(self.openstack_data)

    def sync_with_os(self, server_id=None, manager=None):
        manager = manager or self.parent.admin_manager
        LOG.info('[{}] Resyncing with OS'.format(self.tag))

        if not server_id:
            servers = self.parent.list_servers(name=self.name, manager=manager)
            self.parent.assertEqual(1, len(servers),  # assert uniqueness
                                    'There are {} servers with name {}'.format(
                                        len(servers), self.name)
                                    if len(servers) else
                                    'Could not find any server with '
                                    'name {}'.format(self.name))
            server_id = servers[0]['id']

        # 1. sync openstack data
        self.openstack_data = self.get_server_details(server_id)
        osc_server = self.openstack_data
        LOG.debug('[{}] [resync] OS server resynced: {}'.format(
            self.tag, osc_server))

        # 1b. assert server name matches
        self.parent.assertEqual(self.name, osc_server['name'])

        # 2. sync keypair
        self.get_server_private_key()
        self.parent.assertIsNotNone(self.private_key)
        LOG.debug('[{}] [resync] private_key resynced:\n{}'.format(
            self.tag, self.private_key))

        # 3. sync networks
        self.networks = []
        for network_name in osc_server['addresses']:
            self.networks.append(self.parent.sync_network(network_name,
                                                          cleanup=False))
        LOG.debug('[{}] [resync] {} networks resynced'.format(
            self.tag, len(self.networks)))

        # 4. sync ports
        self.ports = []
        for network in self.networks:
            self.ports.append(
                self.get_server_port_in_network(network, manager))
        LOG.debug('[{}] [resync] {} ports resynced'.format(
            self.tag, len(self.ports)))

        # 5. sync fip
        self.associated_fip = None
        for port in self.ports:
            fip = self.parent.get_floating_ip_by_port_id(
                port['id'], False, manager)
            if fip:
                self.associated_fip = fip
                break
        if self.associated_fip:
            LOG.debug('[{}] [resync] server FIP resynced: {}'.format(
                self.tag, self.associated_fip))
        else:
            LOG.debug('[{}] [resync] no server FIP resynced'.format(self.tag))

        LOG.info('[{}] Resync complete'.format(self.tag))

    def get_server_details(self, server_id=None):
        if not self.server_details:
            self.server_details = \
                self.parent.get_server(server_id or self.id,
                                       self.parent.admin_manager)
        return self.server_details

    def get_server_private_key(self):
        if not self.private_key:
            self.private_key = utils.reunite_chunk_to_str(
                self.openstack_data['metadata'], 'private_key')
        return self.private_key

    def get_server_networks(self, manager=None):
        if not self.networks:
            for port in self.ports:
                self.networks.append(
                    self.parent.get_network(port['network_id'], manager))
        return self.networks

    def get_server_interfaces(self, network_name=None, manager=None):
        # returning a list of lists, per network
        server_addresses = self.get_server_details()['addresses']
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
                self.fail('SSH timeout when connecting to {}'.format(
                    self._vm_console.ip_address), exc=e)
            LOG.info('[{}] Authentication succeeded'.format(self.tag))
        else:
            self.console()  # doing more than authentication check alone
            #                 (i.e. completing all steps), which is good

    def prepare_for_connectivity(self):
        self.wait_for_cloudinit_to_complete()
        self.provision()

    def verify_metadata(self):
        if CONF.compute_feature_enabled.metadata_service:
            LOG.info('[{}] Verify metadata'.format(self.tag))
            metadata = self.send(
                'curl http://169.254.169.254/2009-04-04/meta-data/hostname')
            name_match = self.name.replace('_', '-')  # why is nova replacing?
            self.parent.assertIn(name_match, metadata)
        else:
            LOG.debug('[{}] no metadata verified, '
                      'as metadata service is not enabled'.format(self.tag))

    def verify_userdata(self, string_to_match_with_userdata):
        if CONF.compute_feature_enabled.metadata_service:
            LOG.info('[{}] Verify userdata'.format(self.tag))
            userdata = self.send(
                'curl http://169.254.169.254/2009-04-04/user-data')
            self.parent.assertIn(string_to_match_with_userdata, userdata)
        else:
            LOG.debug('[{}] no userdata verified, '
                      'as metadata service is not enabled'.format(self.tag))

    def poll_for_cloudinit_complete(self, debug_log_console_output=False):
        cloudinit_completed = False
        console_log = None
        interval = 10  # seconds
        max_intervals = int(CONF.nuage_sut.max_cloudinit_polling_time /
                            interval)
        # defaulting to 20, i.e. 200 secs in total
        # -- to be increased on slow systems! --

        # fill server name up with spaces in logging
        server_name = self.name.ljust(self.FILL_SERVER_NAME_UP_TO_X_CHARS)

        for attempt in range(max_intervals):
            console_log = self.get_console_log()
            if debug_log_console_output:
                LOG.debug(self.compose_console_log_dump(console_log))
            if self.END_OF_CLOUDINIT_TAG in console_log:
                cloudinit_completed = True
                break
            elif attempt < max_intervals - 1:
                self.sleep(interval, 'Waiting for {} cloudinit '
                                     'end ({})'.format(server_name,
                                                       attempt + 1))

        if cloudinit_completed:
            self.cloudinit_complete_time = time.time()
            time_to_cloudinit_complete = int(
                self.cloudinit_complete_time - self.active_time)
            LOG.info('[{}] Cloudinit completed in less than {} secs (since '
                     'became active)'.format(
                         self.tag, time_to_cloudinit_complete, interval))
        else:
            LOG.error('Instance {} with ID {} did not reach cloudinit end '
                      'on time'.format(self.name, self.id))
            LOG.error('Last console log received:\n{}'.format(console_log))
            self.fail('Instance did not reach cloudinit end on time')

    def wait_for_cloudinit_to_complete(self):
        if (not self.cloudinit_complete and
                not self.waiting_for_cloudinit_completion):
            LOG.info('[{}] Waiting for cloudinit to complete'.format(self.tag))
            self.waiting_for_cloudinit_completion = True
            self.poll_for_cloudinit_complete()
            self.waiting_for_cloudinit_completion = False
            self.cloudinit_complete = True

            LOG.info('[{}] Ready for action'.format(self.tag))

    @staticmethod
    def is_dhcp_enabled_on_subnet(subnet):
        return (subnet['enable_dhcp'] and
                (subnet['ip_version'] == 4 or Topology.has_dhcp_v6_support()))

    # TODO(Kris) this needs to go out, by provisioning entirely thru cloudinit
    def provision(self, manager=None):
        if self.needs_provisioning and not self.is_being_provisioned:
            LOG.info('[{}] Provisioning'.format(self.tag))
            self.is_being_provisioned = True

            for eth_i, network in enumerate(self.get_server_networks(manager)):
                v4_subnet = self.parent.get_network_subnet(network, 4, manager)
                if v4_subnet and not self.is_dhcp_enabled_on_subnet(v4_subnet):
                    server_ipv4 = self.get_server_ip_in_network(
                        network['name'], ip_version=4, manager=manager)
                    self.configure_static_interface(
                        server_ipv4, v4_subnet, ip_version=4, device=eth_i)
                v6_subnet = self.parent.get_network_subnet(network, 6, manager)
                if v6_subnet and not self.is_dhcp_enabled_on_subnet(v6_subnet):
                    server_ipv6 = self.get_server_ip_in_network(
                        network['name'], ip_version=6, manager=manager)
                    self.configure_static_interface(
                        server_ipv6, v6_subnet, ip_version=6, device=eth_i)

            self.is_being_provisioned = False
            self.needs_provisioning = False
            LOG.info('[{}] Provisioning complete'.format(self.tag))

    def wait_until_ip_established(self, ip, assert_permanent=False,
                                  assert_true=False):
        """wait_until_ip_established

        This method is invoked to wait&query for a given IP to be established
        on a given server, used to verify a server is fully set up for to be
        exercised by this ip (e.g. using ping), before it actually is.

        :param ip: the ip to query for, in string notation
        :param assert_permanent: query for the ip to be declared as permanent
                                 and fail when that is not the case
        :param assert_true: fail when the ip is not established;
                            implicitly set when assert_permanent is set.
        :returns: boolean indication whether the ip got established or not.
                A false result can only be obtained when nor assert_permanent
                nor assert_true are set.
        """
        ip_established = False
        for _ in range(15):
            if assert_permanent:
                ip_established = bool(self.send('ip a '
                                                '| grep "{}.* scope global" '
                                                '| grep -v tentative '
                                                '|| true'.format(ip)))
            else:
                ip_established = bool(self.send('ip a '
                                                '| grep "{}.* scope global" '
                                                '|| true'.format(ip)))
            if ip_established:
                break
            else:
                self.sleep(3, 'Waiting for ip {} to establish'.format(ip))

        if ip_established:
            LOG.debug('[{}] {} confirmed as {}'.format(
                self.tag,
                ip, 'permanent' if assert_permanent else 'established'))
        else:
            if assert_permanent:
                # check whether the IP is present, but never became permanent
                ip_established = bool(self.send('ip a '
                                                '| grep "{}.* scope global" '
                                                '|| true'.format(ip)))
                if ip_established:
                    # it did - that means it remained tentative (DAD issue)
                    self.fail('ip {} remained tentative, indicating a '
                              'DAD issue'.format(ip))

            if assert_true or assert_permanent and not ip_established:
                self.fail('ip {} failed to get established'.format(ip))

        return ip_established

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

        if ((self.is_dhcp_enabled_on_subnet(subnet) or self.force_dhcp) and
                # there is no point in checking for the itf to be served by the
                # dhcp client if the subnet has no dhcp enabled

                # and if dhcp is enabled, and if dhclient is used,
                # check whether it serves the interface already
                (CONF.scenario.dhcp_client == 'dhclient' and
                 self.device_served_by_dhclient(device, ip_version))):

            # if so, nothing to do
            if not self.force_dhcp:
                LOG.info('[{}] Validating {}/{} got established'.format(
                    self.tag, ip, device))
                self.wait_until_ip_established(ip, assert_true=True)

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
                    not self.wait_until_ip_established(ip)):
                self.send('{} addr del {}/{} dev {} || true'.format(
                    ip_v, ip, mask_bits, device))
                attempt += 1

            self.parent.assertTrue(attempt <= 2, 'Interface config did not '
                                                 'succeed')

            self.send('ip link set dev {} up || true'.format(device))

            if gateway_ip:
                # Add the default route if it does not exist yet.
                # Multiple default routes are not possible so the first
                # interface wins. Usually the default route is already in place
                # as FIP access will be using it. Keeping this for backwards
                # compatibility
                self.send('({ip} route | grep ^default) || '
                          '(sudo {ip} route add default via {gw})'
                          .format(ip=ip_v, gw=gateway_ip), as_sudo=False)

        # with all config up now, validate for non-tentative
        self.wait_until_ip_established(ip, assert_permanent=True)

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

    def mount_config_drive(self):
        blk_id_out = self.send('blkid | grep -i config-2')
        dev_name = re.match('([^:]+)', blk_id_out[0]).group()
        self.send('mount %s /mnt' % dev_name)

    def unmount_config_drive(self):
        self.send('umount /mnt')

    def get_user_data_for_nic_prep(self, dhcp_client='udhcpc', manager=None):
        # In an ideal world, interfaces are configured through metadata
        # service/cloudinit without us having to add any user data.
        # Problems:
        #  1) Cirros does not support it properly
        #  2) Before train, a static ip is configured by cloudinit even with
        #     DHCP enabled
        # That is why we have these abstractions configuring each nic
        # manually and we had to modify /etc/cloud/cloud.cfg in the
        # RHEL image to have 'network: config: disabled'
        if not dhcp_client:
            # configured statically through cloudinit
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
            if self.force_dhcp or self.parent.is_dhcp_enabled(
                    network, require_all_subnets_to_match=False,
                    manager=manager):
                if first_nic_prepared:
                    LOG.info('[{}] Preparing user-data for {} nics'.format(
                        self.tag, nbr_nics))
                    supported_clients = ['udhcpc', 'dhclient']
                    if dhcp_client not in supported_clients:
                        raise lib_exc.InvalidConfiguration(
                            '%s DHCP client unsupported' % dhcp_client)
                    s = '#!/bin/sh\n'
                    first_nic_prepared = False
                is_ipv4 = self.parent.get_network_subnet(
                    network, 4, manager=manager) is not None
                is_ipv6 = self.parent.get_network_subnet(
                    network, 6, manager=manager) is not None

                if CONF.nuage_sut.use_network_scripts and is_ipv6:
                    # On RHEL 6 (and apparently also rhel 7) a DHCPv6
                    # client is correctly handled only by NetworkManager
                    # and should not generally be run separately.
                    # That is because DHCPv6, unlike DHCPv4,
                    # is not a standalone network configuration
                    # protocol but is always supposed to be used together with
                    # router discovery.
                    s += ('echo -e "'
                          'DEVICE=eth{nic}\\n'
                          'BOOTPROTO=dhcp\\n'
                          'BOOTPROTOv6=dhcp\\n'
                          'ONBOOT=yes\\n'
                          'TYPE=Ethernet\\n'
                          'IPV6INIT=yes\\n'
                          'IPV4INIT={ipv4}\\n'
                          'PERSISTENT_DHCLIENT=1\\n" '
                          '> /etc/sysconfig/network-scripts/ifcfg-eth{nic}\n'
                          .format(nic=nic, ipv4='yes' if is_ipv4 else 'no'))
                    s += 'systemctl restart network\n'
                    continue

                if dhcp_client == 'udhcpc':
                    s += '/sbin/cirros-dhcpc up eth%s\n' % nic
                else:
                    s += '/sbin/ip link set eth%s up\n' % nic
                    if is_ipv6:
                        s += '/bin/sleep 2\n'  # TODO(OPENSTACK-2666) this is
                        #                           current low-cost approach
                        #                              for v6 DAD to complete,
                        #                           but is platform-dependent
                        s += '/sbin/dhclient -1 -6 eth%s\n' % nic
                    if is_ipv4:
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
