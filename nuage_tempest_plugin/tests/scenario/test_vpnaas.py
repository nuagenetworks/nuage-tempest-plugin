# Copyright 2017 - Nokia
# All Rights Reserved.

from oslo_log import log as logging
import time

from tempest.api.compute import base as serv_base
from tempest import config

from nuage_tempest_plugin.lib import test_base
from nuage_tempest_plugin.tests.api import test_vpnaas

LOG = logging.getLogger(__name__)
CONF = config.CONF


class VPNaaSScenarioTest(test_vpnaas.VPNaaSBase,
                         serv_base.BaseV2ComputeTest):

    def _create_resources(self):
        """_create_resources

        This proc creates all the resources needed for the end to end test
        """

        fip_vsd_parent_id = None

        for i in range(2):
            # Creating the FIP Network
            fipnetname = 'FIP-net-' + str(i)
            fipkwargs = {'name': fipnetname, 'router:external': True}
            fipnetwork = (
                self.os_handle.admin_networks_client.create_network(
                    **fipkwargs)
            )
            # Adding the FIP Network to the os_data_struct tree
            self.os_data_struct.insert_resource(
                fipnetname, os_data=fipnetwork,
                user_data=fipkwargs, parent='CMS')
            # Adding the FIP Network to cleanup
            self.addCleanup(
                self.os_handle.admin_networks_client.delete_network,
                fipnetwork['network']['id'])

            # Providing FIP Subnet Values
            fipaddr = '172.20.' + str(i) + '.0'
            fipgw = '172.20.' + str(i) + '.1'
            fipcidr = fipaddr + '/24'
            fipsubname = 'FIP-sub-' + str(i)
            fipsubkwargs = {'name': fipsubname,
                            'cidr': fipcidr, 'gateway_ip': fipgw,
                            'network_id': fipnetwork['network']['id'],
                            'ip_version': 4}

            # Creating the FIP Subnet
            if i == 0:
                fipsubnet = (
                    self.os_handle.admin_subnets_client.create_subnet(
                        **fipsubkwargs)
                )
                fip_ext_id = (
                    test_base.get_external_id(fipsubnet['subnet']['id'])
                )
                fip_vsd = self.vsd_handle.get_shared_network_resource(
                    filter=test_base.get_filter_str('externalID', fip_ext_id))
                fip_vsd_parent_id = fip_vsd.parent_id
            else:
                fipsubkwargs['nuage_uplink'] = fip_vsd_parent_id
                fipsubnet = (
                    self.os_handle.admin_subnets_client.create_subnet(
                        **fipsubkwargs)
                )
            # Adding the FIP Subnet to the os_data_struct tree
            self.os_data_struct.insert_resource(
                fipsubname, os_data=fipsubnet,
                user_data=fipsubkwargs, parent=fipnetname)
            # Adding the FIP Subnet to cleanup
            self.addCleanup(self.os_handle.admin_subnets_client.delete_subnet,
                            fipsubnet['subnet']['id'])

            # Creating Networks/Subnets/Router Environment for Site
            # Router Create
            routername = 'router-' + str(i)
            router = (
                self.os_handle.routers_client.create_router(routername)
            )
            # Adding the Router to the os_data_struct tree
            self.os_data_struct.insert_resource(
                routername, os_data=router,
                user_data={'name': routername}, parent=self.def_net_partition)
            # Adding the Router to cleanup
            self.addCleanup(self.os_handle.routers_client.delete_router,
                            router['router']['id'])

            # Network Create
            netname = 'network-' + str(i)
            netkwargs = {'name': netname}
            network = (
                self.os_handle.networks_client.create_network(**netkwargs)
            )
            # Adding the Network to the os_data_struct tree
            self.os_data_struct.insert_resource(
                netname, os_data=network,
                user_data=netkwargs, parent=routername)
            # Adding the Network to cleanup
            self.addCleanup(self.os_handle.networks_client.delete_network,
                            network['network']['id'])

            # Subnet Create
            subname = 'subnet-' + str(i)
            subcidrpre = '26.' + str(i) + '.0'
            subaddr = subcidrpre + '.0'
            subgateway = subcidrpre + '.1'
            cidr = subaddr + '/24'
            subkwargs = {'name': subname,
                         'cidr': cidr, 'gateway_ip': subgateway,
                         'network_id': network['network']['id'],
                         'ip_version': 4}
            subnet = (
                self.os_handle.subnets_client.create_subnet(**subkwargs)
            )
            # Adding the Subnet to the os_data_struct tree
            self.os_data_struct.insert_resource(
                subname, os_data=subnet,
                user_data=subkwargs, parent=netname)
            # Adding the Subnet to cleanup
            self.addCleanup(self.os_handle.subnets_client.delete_subnet,
                            subnet['subnet']['id'])

            # Router interface add
            routerintkwargs = {'subnet_id': subnet['subnet']['id']}
            self.os_handle.routers_client.add_router_interface(
                router['router']['id'], **routerintkwargs)
            # Adding the Router Interface add to cleanup
            self.addCleanup(
                self.os_handle.routers_client.remove_router_interface,
                router['router']['id'], **routerintkwargs)

            # Router gateway set
            routergwkwargs = (
                {'external_gateway_info': {
                    'network_id': fipnetwork['network']['id']}}
            )
            self.os_handle.routers_client.update_router(
                router['router']['id'], **routergwkwargs)
            routernogwkwargs = (
                {'external_gateway_info': ''}
            )
            # Adding the Router Gateway Set add to cleanup
            self.addCleanup(
                self.os_handle.routers_client.update_router,
                router['router']['id'], **routernogwkwargs)

            # VM Booting
            vmname = 'VM-' + str(i)
            vmkwargs = {'name': vmname, 'flavorRef': '1',
                        'imageRef': CONF.compute.image_ref,
                        'networks': [{'uuid': network['network']['id']}]}
            vm = self.os_handle.servers_client.create_server(**vmkwargs)
            # Adding VM to the os_data_struct tree
            self.os_data_struct.insert_resource(
                vmname, os_data=vm,
                user_data=vmkwargs, parent=subname)
            # VM to cleanup in the End will be added at the end

            # create VPN-Service
            vpnname = 'VPN-' + str(i)
            vpnkwargs = {'name': vpnname}
            vpnkwargs['router_id'] = router['router']['id']
            vpnkwargs['subnet_id'] = subnet['subnet']['id']
            vpnservice = (
                self.os_handle.vpnservice_client.create_vpnservice(
                    **vpnkwargs)
            )
            # Adding the VPNService to the os_data_struct tree
            self.os_data_struct.insert_resource(
                vpnname, os_data=vpnservice,
                user_data=vpnkwargs, parent=routername)
            # Adding the VPNService to cleanup
            self.addCleanup(self.os_handle.vpnservice_client.delete_vpnservice,
                            vpnservice['id'])

    def _create_ikepolicy_ipsecpolicy(self):
        # Creating IKEPolicy
        ikepolicyname = 'IKEPolicy'
        ikepolicy = (
            self.os_handle.ikepolicy_client.create_ikepolicy(ikepolicyname)
        )
        # will not add the ikepolicy to os_data_struct tree
        # Adding the IKEPolicy to cleanup
        self.addCleanup(
            self.os_handle.ikepolicy_client.delete_ikepolicy,
            ikepolicy['id']
        )
        # Creating IPSecPolicy
        ipsecpolicyname = 'IPSecPolicy'
        ipsecpolicy = (
            self.os_handle.ipsecpolicy_client.create_ipsecpolicy(
                ipsecpolicyname)
        )
        # will not add the ipsecpolicy to os_data_struct tree
        # Adding the IPSecPolicy to cleanup
        self.addCleanup(
            self.os_handle.ipsecpolicy_client.delete_ipsecpolicy,
            ipsecpolicy['id']
        )
        return ikepolicy, ipsecpolicy

    def _create_ipsecsiteconnection(self, vpn1, vpn2,
                                    subnet2, ikepolicy,
                                    ipsecpolicy, name, vpntag):
        # Creating the IPSecSiteConnection
        ipnkwargs = {'name': name}
        ipsecsiteconnection =\
            self.os_handle.ipsecsiteconnection_client.\
            create_ipsecsiteconnection(
                vpn1['id'], ikepolicy['id'], ipsecpolicy['id'],
                vpn2['external_v4_ip'], vpn2['external_v4_ip'],
                subnet2['subnet']['cidr'], 'secret', **ipnkwargs
            )
        # Adding the IpSecSiteConnection to the os_data_struct tree
        self.os_data_struct.insert_resource(
            name, user_data={'vpn1': vpn1['id'],
                             'vpn2': vpn2['id'],
                             'remotecidr': subnet2['subnet']['cidr'],
                             'secret': 'secret', 'name': 'name'},
            os_data=ipsecsiteconnection, parent=vpntag)
        # Adding the IpSecSiteConnection to cleanup
        self.addCleanup(
            self.os_handle.ipsecsiteconnection_client.
            delete_ipsecsiteconnection, ipsecsiteconnection['id'])
        return ipsecsiteconnection

    def _calculate_vm_port(self, vm):
        vmuuid = vm['server']['id']
        src = 'source admin_rc;'
        novacmd = 'nova show ' + vmuuid + \
            '| awk \'$2 == "OS-EXT-SRV-ATTR:instance_name" {print $4}\''
        instance = self.TB.osc_1.cmd(src + novacmd)
        instance = instance[0][0]
        instance_port = int(instance[-2::], 16)
        instance_port = instance_port + 2000
        return instance_port

    def _get_vm_handle(self, vm, username='cirros',
                       password='cubswin:)'):
        vm_port = self._calculate_vm_port(vm)
        vm_handle = self.TB.vrs_2.ssh.open_vm_console(
            vm_port, username, password=password)
        return vm_handle

    @staticmethod
    def _check_vm_ping(cmd, fromvmhandle, tovm, tonetwork, negative='False'):
        to_vm_ip = tovm['server']['addresses'][tonetwork][0]['addr']
        ping_out = fromvmhandle.send(cmd + to_vm_ip)
        expected_out1 = '0% packet loss'
        out1_result = any(expected_out1 in out for out in ping_out)
        expected_out2 = '64 bytes from ' + to_vm_ip
        out2_result = any(expected_out2 in out for out in ping_out)
        if negative == 'True':
            if out1_result or out2_result:
                LOG.debug((ping_out))
                LOG.error(('This ping should have failed'))
            else:
                LOG.info(('Ping Failed as expected'))
        else:
            if out1_result and out2_result:
                LOG.info(('Ping Passed as expected'))
            elif out2_result and not out1_result:
                LOG.warning((ping_out))
                LOG.warning(('ping not 100% successful'))
            elif out1_result and not out2_result:
                LOG.warning((ping_out))
                LOG.warning(('ping not 64 bytes as expected'))
            else:
                LOG.debug((ping_out))
                LOG.error(('Ping Failed'))

    def test_vpnaas_end_to_end(self):
        """test_vpnaas_end_to_end

        Tests create/show/list/delete of two ipsecsiteconnection
        in two different vpnservices and test end to end connectivity
        """
        self._create_resources()

        subnet1 = self.os_data_struct.get_resource('subnet-0').os_data
        subnet2 = self.os_data_struct.get_resource('subnet-1').os_data
        network2 = self.os_data_struct.get_resource('network-1').os_data
        VM1 = self.os_data_struct.get_resource('VM-0').os_data
        VM2 = self.os_data_struct.get_resource('VM-1').os_data
        vpn1 = self.os_data_struct.get_resource('VPN-0').os_data
        vpn2 = self.os_data_struct.get_resource('VPN-1').os_data

        ikepolicy, ipsecpolicy = self._create_ikepolicy_ipsecpolicy()

        # Creating the IPSecSiteConnection1
        self._create_ipsecsiteconnection(
            vpn1, vpn2, subnet2, ikepolicy, ipsecpolicy,
            'ipsecconn0', 'VPN-0')

        # Creating the IPSecSiteConnection2
        self._create_ipsecsiteconnection(
            vpn2, vpn1, subnet1, ikepolicy, ipsecpolicy,
            'ipsecconn1', 'VPN-1')

        VM1_handle = self._get_vm_handle(VM1)
        VM2 = self.os_handle.servers_client.show_server(VM2['server']['id'])

        # 10 second sleep for interfaces to come up
        time.sleep(10)
        self._check_vm_ping('ping -c 4 ', VM1_handle,
                            VM2, network2['network']['name'])

        # Adding VM to cleanup
        self.addCleanup(
            self.os_handle.servers_client.delete_server,
            VM1['server']['id'])
        self.addCleanup(
            self.os_handle.servers_client.delete_server,
            VM2['server']['id'])
