# Copyright 2017 - Nokia
# All Rights Reserved.

from base64 import b64encode
import re
import textwrap

from netaddr import IPNetwork

from tempest.common.utils.linux.remote_client import RemoteClient
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
            password=tenant_server.password,
            pkey=tenant_server.keypair['private_key'],
            servers_client=tenant_server.admin_client)
        self.tenant_server = tenant_server

    def send(self, cmd, timeout=CONF.validation.ssh_timeout):
        output = {'output': None}

        def send_cmd():
            try:
                LOG.info('FipAccessConsole: send: %s.', cmd)
                cmd_out = self.exec_command(cmd)
                output['output'] = cmd_out
                LOG.info('FipAccessConsole: rcvd: %s.', cmd_out)

            except lib_exc.SSHExecCommandFailed:
                LOG.warning('Failed to execute command on %s.',
                            self.ssh_client.host)
                return False
            return True

        assert test_utils.call_until_true(send_cmd, timeout, 1)
        return output['output']

    def ping(self, destination, cnt, interface=None, ip_type=4):
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
        self.networks = networks
        self.ports = ports
        self.security_groups = security_groups
        self.flavor = flavor
        self.volume_backed = volume_backed

        self._image_id = None
        self.username = CONF.validation.image_ssh_user
        self.password = CONF.validation.image_ssh_password
        self.keypair = keypair

        self.vm_console = None
        self.openstack_data = None
        self.server_details = None
        self.associated_fip = None
        self.server_connectivity_verified = False

    def console(self):
        return self.vm_console

    @property
    def image_id(self):
        if not self._image_id:
            self._image_id = CONF.compute.image_ref
        return self._image_id

    def id(self):
        return self.openstack_data['id']

    def boot(self, wait_until='ACTIVE', cleanup=True,
             return_none_on_failure=False, **kwargs):

        assert not ("user_data" in kwargs and self.get_user_data_for_nic_prep(
            dhcp_client=CONF.scenario.dhcp_client))  # one of both, not both

        # add user data for configuring extra nics
        if not kwargs.get('user_data'):
            user_data = self.get_user_data_for_nic_prep(
                dhcp_client=CONF.scenario.dhcp_client)
            if user_data:
                kwargs['user_data'] = user_data
        # cleans and logs the user_data script
        if kwargs.get('user_data'):
            kwargs['user_data'] = b64encode(textwrap.dedent(
                kwargs['user_data']).lstrip().encode('utf8'))
            LOG.info('user_data:\n---\n{}---'.format(kwargs['user_data']))

        self.openstack_data = self.parent_test.osc_create_test_server(
            self.client, self.networks, self.ports, self.security_groups,
            wait_until, self.volume_backed, self.name, self.flavor,
            self.image_id, self.keypair, cleanup,
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

    def send(self, cmd):
        assert self.console()
        return self.console().send('sudo ' + cmd)

    def configure_dualstack_interface(self, ip, subnet, device='eth0'):
        LOG.info('VM configure_dualstack_interface:\n'
                 '  ip: {}\n'
                 '  subnet: {}\n'
                 '  device: {}\n'
                 .format(ip, subnet, device))
        # grdinv - assume full blown cloud-init on images
        # where dhclient available. This might not be true,
        # but currently seems a best way to handle ipv6 itf config
        # when we are not sure on interface naming
        if CONF.scenario.dhcp_client == 'dhclient':
            LOG.info('VM configure_dualstack_interface: '
                     'skipping in favor of cloud-init')
            return
        mask_bits = IPNetwork(subnet['cidr']).prefixlen
        gateway_ip = subnet['gateway_ip']

        self.send('ip -6 addr add {}/{} dev {}'.format(ip, mask_bits, device))
        self.send('ip link set dev {} up'.format(device))
        if gateway_ip:  # In L2 domains having a gateway does not make sense
            # gridinv - following may fail if default route does exist on host
            try:
                assert self.console()
                self.console().exec_command(
                    'sudo ip -6 route add default via {}'.format(gateway_ip))
            except lib_exc.SSHExecCommandFailed:
                LOG.warn("Failed to add default route for ipv6")
        self.send('ip a')
        self.send('route -n -A inet6')

        LOG.info('VM configure_dualstack_interface: Done.\n')

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
        nbr_nics = len(self.networks) if self.networks else len(self.ports)
        if nbr_nics > 1:
            supported_clients = ['udhcpc', 'dhclient']
            if dhcp_client not in supported_clients:
                raise lib_exc.exceptions.InvalidConfiguration(
                    '%s DHCP client unsupported' % dhcp_client)
            if dhcp_client == 'udhcpc':
                s = '#!/bin/sh\n'
                for nic in range(1, nbr_nics):
                    s += '/sbin/cirros-dhcpc up eth%s\n' % nic
                return s
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
                  "echo")
