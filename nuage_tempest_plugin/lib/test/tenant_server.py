# Copyright 2017 - Nokia
# All Rights Reserved.

from base64 import b64encode
import re

from netaddr import IPNetwork

from tempest.lib.common.utils.linux.remote_client import RemoteClient
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class FipAccessConsole(RemoteClient):

    def __init__(self, tenant_server):
        super(FipAccessConsole, self).__init__(
            ip_address=tenant_server.associated_fip,
            username=tenant_server.username,
            password=tenant_server.password)
        self.tenant_server = tenant_server

    def send(self, cmd, timeout=CONF.validation.ssh_timeout):
        cmd_out = None

        def send_cmd():
            global cmd_out
            try:
                LOG.info('FipAccessConsole: send: %s.', cmd)
                cmd_out = self.exec_command(cmd)
                LOG.info('FipAccessConsole: rcvd: %s.', cmd_out)

            except lib_exc.SSHExecCommandFailed:
                LOG.warning('Failed to setup interface on %s.',
                            self.ssh_client.host)
                return False
            return True

        assert test_utils.call_until_true(send_cmd, timeout, 1)
        return cmd_out

    def ping(self, destination, cnt, interface=None, ip_type=4):
        try:
            # TODO(Kris) - pass on interface ...
            # today, fail explicitly so we don't loose time investigating
            if interface is not None:
                LOG.error('TODO(Kris): ping to interface not yet supported.')
                assert False

            return self.ping_host(destination, cnt)
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
    image_profiles = {
        'default': {
            'image_name': 'cirros-0.3.5-x86_64-disk',
            'username': 'cirros',
            'password': 'cubswin:)',
            'prompt': '\$'
        },
        'advanced': {
            'alpine',
            'root',
            'tigris',
            '~#'
        } if Topology.use_alpine_for_advanced_image() else {
            # TODO(KRIS) - needs custom cirros image
            'image_name': 'cirros-0.3.5-x86_64-disk',
            'username': 'cirros',
            'password': 'cubswin:)',
            'prompt': '\$'
        }
    }

    def __init__(self, parent_test, client, admin_client,
                 name=None, networks=None, ports=None, security_groups=None,
                 image_profile='default', flavor=None,
                 volume_backed=False):
        self.parent_test = parent_test
        self.client = client
        self.admin_client = admin_client

        self.name = name
        self.networks = networks
        self.ports = ports
        self.security_groups = security_groups
        self.flavor = flavor
        self.volume_backed = volume_backed

        assert image_profile in self.image_profiles
        self.image_profile = self.image_profiles[image_profile]
        self.image_name = self.image_profile['image_name']
        assert self.image_name
        self._image_id = None
        self.username = self.image_profile['username']
        self.password = self.image_profile['password']
        self.prompt = self.image_profile['prompt']
        self.needs_sudo = self.username != 'root'

        self.vm_console = None
        self.openstack_data = None
        self.server_details = None
        self.associated_fip = None
        self.server_connectivity_verified = False

    def console(self):
        return self.vm_console

    def is_cirros(self):
        return 'cirros' in self.image_name

    @property
    def image_id(self):
        if not self._image_id:
            if self.image_profile == 'default':
                self._image_id = CONF.compute.image_ref
            else:
                self._image_id = self.parent_test.osc_get_image_id(
                    self.image_name)
                if not self._image_id:
                    self.parent_test.skipTest('Image ' + self.image_name +
                                              ' could not be found on setup.')
        return self._image_id

    def get_telnet_host_port(self):
        server = self.get_server_details()

        vm_name = server.get('OS-EXT-SRV-ATTR:instance_name')
        instance, number = vm_name.split('-')
        telnet_port = int(number, 16) + 2000

        host = server.get('OS-EXT-SRV-ATTR:hypervisor_hostname')

        LOG.info("VM details:\n"
                 "  VM ID  : {}\n"
                 "  VM name: {}\n"
                 "  VM host: {}\n"
                 "  VM port: {}\n"
                 .format(server['id'], vm_name, host, telnet_port))

        return host, telnet_port

    def id(self):
        return self.openstack_data['id']

    def boot(self, wait_until='ACTIVE', cleanup=True,
             return_none_on_failure=False, **kwargs):

        # add user data for configuring extra nics on cirros
        user_data = self.get_user_data_for_nic_prep()
        if user_data:
            kwargs['user_data'] = user_data

        self.openstack_data = self.parent_test.osc_create_test_server(
            self.client, self.networks, self.ports, self.security_groups,
            wait_until, self.volume_backed, self.name, self.flavor,
            self.image_id, cleanup,
            return_none_on_failure=return_none_on_failure, **kwargs)

        return self.openstack_data

    def did_deploy(self):
        return bool(self.openstack_data)

    def sync_with(self, osc_server_id):
        self.openstack_data = \
            self.admin_client.show_server(osc_server_id)['server']

    def get_server_details(self):
        server_id = self.id()
        if not self.server_details:
            self.server_details = \
                self.admin_client.show_server(server_id)['server']
        return self.server_details

    def associate_fip(self, fip):
        self.associated_fip = fip
        # now is the time to init the fip-access console also
        if not self.vm_console:
            self.vm_console = FipAccessConsole(self)

    def get_server_ip_in_network(self, network_name, ip_type=4):
        server = self.get_server_details()
        ip_address = None
        for subnet_interface in server['addresses'][network_name]:
            if subnet_interface['version'] == ip_type:
                ip_address = subnet_interface['addr']
                break
        return ip_address

    def send(self, cmd, check_sudo=True):
        assert self.console()
        if check_sudo and self.needs_sudo:
            return self.console().send('sudo ' + cmd)
        else:
            return self.console().send(cmd)

    def configure_dualstack_interface(self, ip, subnet, device='eth0'):
        LOG.info('VM configure_dualstack_interface:\n'
                 '  ip: {}\n'
                 '  subnet: {}\n'
                 '  device: {}\n'
                 .format(ip, subnet, device))

        mask_bits = IPNetwork(subnet['cidr']).prefixlen
        gateway_ip = subnet['gateway_ip']

        self.send('ip -6 addr add {}/{} dev {}'.format(ip, mask_bits, device))
        self.send('ip link set dev {} up'.format(device))
        if gateway_ip:  # In L2 domains having a gateway does not make sense
            self.send('ip -6 route add default via {}'.format(gateway_ip))
        self.send('ip a')
        self.send('route -n -A inet6')

        LOG.info('VM configure_dualstack_interface: Done.\n')

    def configure_vlan_interface(self, ip, interface, vlan, check_image=True):
        # check support on the guest vm
        if check_image and not self.send('lsmod | { grep 8021q || true; }'):
            raise OSError('8021q not loaded on guest image ' + self.image_name)

        self.send('ip link add link %s name %s.%s type vlan id %s ' % (
            interface, interface, vlan, vlan))
        self.send('ifconfig %s.%s %s  up' % (interface, vlan, ip))
        self.send('ifconfig')

    def configure_ip_fwd(self):
        self.send('sysctl -w net.ipv4.ip_forward=1')

    def bring_down_interface(self, interface):
        self.send('ifconfig %s 0.0.0.0' % interface)
        self.send('ifconfig')

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

    def get_user_data_for_nic_prep(self):
        if self.is_cirros():
            nbr_nics = len(self.networks) if self.networks else len(self.ports)
            if nbr_nics > 1:
                s = '#!/bin/sh\n'
                for nic in range(1, nbr_nics):
                    s += '/sbin/cirros-dhcpc up eth%s\n' % nic

                LOG.info('get_user_data_for_nic_prep:\n---\n%s---', s)
                return b64encode(s)
        # else
        return None

    def needs_fip_access(self):
        return not self.console()

    def has_fip_access(self):
        return (self.console() and
                isinstance(self.console(), FipAccessConsole))

    def assert_prepared_for_fip_access(self):
        assert self.has_fip_access()

    def check_connectivity(self, retry_cnt=1, force_recheck=False):
        if force_recheck:
            self.server_connectivity_verified = False
        if not self.server_connectivity_verified:
            for attempt in range(retry_cnt):
                try:
                    LOG.error('check_connectivity attempt %d' % attempt)

                    # TODO(Kris) make generic
                    self.assert_prepared_for_fip_access()

                    self.vm_console.validate_authentication()
                    self.server_connectivity_verified = True
                    break

                except lib_exc.SSHTimeout as e:
                    LOG.error('check_connectivity failed (attempt %d) : %s' %
                              (attempt, str(e)))

        return self.server_connectivity_verified

    def ping(self, destination, count=3, interface=None, ip_type=4,
             should_pass=True):
        ping_out = self.vm_console.ping(destination, count, interface, ip_type)
        expected_packet_cnt = count if should_pass else 0

        return str(expected_packet_cnt) + ' packets received' in ping_out

    def echo_debug_info(self):
        self.send("echo; "
                  "echo '----- ip route -----'; ip route; "
                  "echo '----- ip a     -----'; ip a; "
                  "echo '----- arp -a   -----'; arp -a; "
                  "echo", CONF.validation.ssh_timeout)
