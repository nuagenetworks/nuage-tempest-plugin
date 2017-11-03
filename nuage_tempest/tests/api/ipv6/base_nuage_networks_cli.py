# Copyright 2017 - Nokia
# All Rights Reserved.

import json
from netaddr import IPRange

from tempest import config
from tempest.lib.common.utils import data_utils

from testtools.matchers import ContainsDict
from testtools.matchers import Equals

from nuage_tempest.lib.remote_cli import remote_cli_base_testcase

CONF = config.CONF


def mask_to_prefix(mask):
    return sum([bin(int(x)).count('1') for x in mask.split('.')])


class BaseNuageNetworksCLITestCase(
        remote_cli_base_testcase.RemoteCliBaseTestCase):

    ###########################################################################
    #
    # CLI
    #
    ###########################################################################
    def _cli_create_os_l2_vsd_managed_dualstack_subnet(self, vsd_l2_subnet):
        network_name = data_utils.rand_name('cli_network')
        network = self.create_network_with_args(network_name)
        self.addCleanup(self._delete_network, network['id'])
        self.networks.remove(network)

        subnet_name = data_utils.rand_name('cli-subnet')
        # cidr = str(base_vsd_managed_networks.VSD_L2_SHARED_MGD_CIDR.cidr)
        prefixlen = mask_to_prefix(vsd_l2_subnet['netmask'])
        cidr4 = "%s/%d" % (vsd_l2_subnet['address'], prefixlen)

        net_partition = CONF.nuage.nuage_default_netpartition
        nuagenet = vsd_l2_subnet['ID']
        subnet4 = self.create_subnet_with_args(
            network['name'], cidr4,
            "--name ", subnet_name + "-4",
            "--net-partition ", net_partition,
            "--nuagenet ", nuagenet)
        self.addCleanup(self._delete_subnet, subnet4['id'])
        self.subnets.remove(subnet4)

        cidr6 = vsd_l2_subnet['IPv6Address']
        subnet6 = None
        if cidr6:
            subnet6 = self.create_subnet_with_args(
                network['name'], cidr6,
                "--name ", subnet_name + "-6",
                "--ip-version 6",
                "--disable-dhcp ",
                "--net-partition ", net_partition,
                "--nuagenet ", nuagenet)
            self.addCleanup(self._delete_subnet, subnet6['id'])
            self.subnets.remove(subnet6)

        return network, subnet4, subnet6

    def _cli_create_os_l2_vsd_unmanaged_dualstack_subnet(
            self, vsd_l2_subnet, cidr4=None, cidr6=None):
        network_name = data_utils.rand_name('cli_network')
        network = self.create_network_with_args(network_name)
        self.addCleanup(self._delete_network, network['id'])
        self.networks.remove(network)

        subnet_name = data_utils.rand_name('cli-subnet')
        net_partition = CONF.nuage.nuage_default_netpartition
        nuagenet = vsd_l2_subnet['ID']
        subnet4 = self.create_subnet_with_args(
            network['name'], str(cidr4),
            "--name ", subnet_name + "-4",
            "--disable-dhcp ",
            "--net-partition ", net_partition,
            "--nuagenet ", nuagenet)
        self.addCleanup(self._delete_subnet, subnet4['id'])
        self.subnets.remove(subnet4)

        subnet6 = None
        if cidr6:
            subnet6 = self.create_subnet_with_args(
                network['name'], str(cidr6),
                "--name ", subnet_name + "-6",
                "--ip-version 6",
                "--disable-dhcp ",
                "--net-partition ", net_partition,
                "--nuagenet ", nuagenet)
            self.addCleanup(self._delete_subnet, subnet6['id'])
            self.subnets.remove(subnet6)

        return network, subnet4, subnet6

    def _cli_check_policy_group_in_list(self, pg_id, pg_list):
        pg_present = False
        for pg in pg_list:
            if pg['id'] == pg_id:
                pg_present = True
                break
        return pg_present

    def cli_associate_port_with_policy_group(self, port, policy_group):
        self.update_port_with_args(
            port['id'],
            "--nuage-policy-groups",
            policy_group[0]['ID'],
            "--name port-with-vsd-pg")

    def cli_associate_port_with_multiple_policy_group(
            self, port, policy_group_id_list):
        cli_args = ''
        for pg_id in policy_group_id_list:
            cli_args += "--nuage-policy-groups " + pg_id + " "
        self.update_port_with_args(port['id'],
                                   cli_args,
                                   "--name port-with-multiple-vsd-pg")

    def cli_disassociate_port_from_policy_group(self, port_id):
        self.update_port_with_args(port_id,
                                   "--no-nuage-policy-groups")

    def cli_check_port_in_show_policy_group(self, port_id, policy_group_id):
        port_present = False
        show_pg = self.show_nuage_policy_group(policy_group_id)
        for id in show_pg['ports'].split(","):
            if port_id in id:
                port_present = True
        return port_present

    def _cli_check_all_policy_groups_in_show_port(self, pg_id_list, show_port):
        groups_present = True
        pg_id_list = show_port['nuage_policy_groups'].split(",")
        for pg_id in pg_id_list:
            if pg_id not in pg_id_list:
                groups_present = False
                break
        return groups_present

    def cli_remove_port_allowed_address_pairs(self, port_id):
        self.update_port_with_args(port_id,
                                   "--no-allowed-address-pairs")

    def cli_check_show_port_allowed_address_fields(self, show_port,
                                                   addrpair_ip, addrpair_mac):
        ip_address_present = addrpair_ip in show_port['allowed_address_pairs']
        mac_addres_present = addrpair_mac in show_port['allowed_address_pairs']
        self.assertTrue(ip_address_present and mac_addres_present)

    def cli_check_fip_in_list(self, fip_id, fip_list):
        fip_present = False
        for fip in fip_list:
            if fip['id'] == fip_id:
                fip_present = True
                break
        return fip_present

    def cli_check_fip_in_port_show(self, fip_id, port_id):
        fip_present = False
        nuage_floatingip = self.show_port(port_id)['nuage_floatingip']
        # Check the is only when the item is present
        if nuage_floatingip:
            # there is a nuage_floatingip present: check the id
            if fip_id == json.loads(nuage_floatingip)['id']:
                fip_present = True
        return fip_present

    def cli_associate_fip_to_port(self, fip_id, port_id):
        self.update_port_with_args(port_id,
                                   "--nuage-floatingip", fip_id)

    def cli_disassociate_fip_from_port(self, port_id):
        self.update_port_with_args(port_id,
                                   "--no-nuage-floatingip")

    def _verify_port(self, port, subnet4=None, subnet6=None, **kwargs):
        has_ipv4_ip = False
        has_ipv6_ip = False

        for fixed_ip in port['fixed_ips']:
            ip_address = fixed_ip['ip_address']
            if subnet4 and fixed_ip['subnet_id'] == subnet4['id']:
                start_ip_address = subnet4['allocation_pools'][0]['start']
                end_ip_address = subnet4['allocation_pools'][0]['end']
                ip_range = IPRange(start_ip_address, end_ip_address)
                self.assertIn(ip_address, ip_range)
                has_ipv4_ip = True

            if subnet6 and fixed_ip['subnet_id'] == subnet6['id']:
                start_ip_address = subnet6['allocation_pools'][0]['start']
                end_ip_address = subnet6['allocation_pools'][0]['end']
                ip_range = IPRange(start_ip_address, end_ip_address)
                self.assertIn(ip_address, ip_range)
                has_ipv6_ip = True

        if subnet4:
            self.assertTrue(
                has_ipv4_ip,
                "Must have an IPv4 ip in subnet: %s" % subnet4['id'])

        if subnet6:
            self.assertTrue(
                has_ipv6_ip,
                "Must have an IPv6 ip in subnet: %s" % subnet6['id'])

        self.assertIsNotNone(port['mac_address'])

        # verify all other kwargs as attributes (key,value) pairs
        for key, value in kwargs.iteritems():
            self.assertThat(port, ContainsDict({key: Equals(value)}))
