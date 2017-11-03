# Copyright 2017 - Nokia
# All Rights Reserved.

from tempest import config
from tempest.lib.common.utils import data_utils

from nuage_tempest.lib.test import nuage_test
from nuage_tempest.lib.utils import constants

from nuage_tempest.tests.api.ipv6.base_nuage_networks \
    import NetworkTestCaseMixin
from nuage_tempest.tests.api.ipv6.base_nuage_networks \
    import VsdTestCaseMixin

CONF = config.CONF

###############################################################################
###############################################################################
# Redirect target
###############################################################################
###############################################################################


class VSDManagedRedirectTargetTest(NetworkTestCaseMixin, VsdTestCaseMixin):

    def _verify_redirect_target(self, rt, parent, parentinfo, postinfo):
        redirect_target = self.nuage_vsd_client.get_redirection_target(
            parent, parentinfo['ID'], filters='ID',
            filter_value=rt['nuage_redirect_target']['id'])

        self.assertEqual(
            str(redirect_target[0]['redundancyEnabled']),
            postinfo['redundancy_enabled'])
        self.assertEqual(
            str(redirect_target[0]['endPointType']),
            postinfo['insertion_mode'])
        return redirect_target

    def _verify_redirect_target_rules(self, rtrule,
                                      parent, parentinfo, ruleinfo):
        redirect_target_rule_template = \
            self.nuage_vsd_client.get_advfwd_template(parent, parentinfo['ID'])

        redirect_target_rule = self.nuage_vsd_client.get_advfwd_entrytemplate(
            'ingressadvfwdtemplates',
            str(redirect_target_rule_template[0]['ID']))

        self.assertEqual(
            str(redirect_target_rule[0]['protocol']), ruleinfo['protocol'])
        self.assertEqual(
            str(redirect_target_rule[0]['protocol']), ruleinfo['protocol'])
        self.assertEqual(
            str(redirect_target_rule[0]['action']), ruleinfo['action'])
        self.assertEqual(
            str(redirect_target_rule[0]['ID']),
            rtrule['nuage_redirect_target_rule']['id'])
        if not (str(ruleinfo['protocol']) == str(1)):
            pmin = str(ruleinfo['port_range_min'])
            pmax = str(ruleinfo['port_range_max'])
            self.assertEqual(
                str(redirect_target_rule[0]['destinationPort']),
                pmin + "-" + pmax)

    def _associate_rt_port(self, rtport, rt):
        self.ports_client.update_port(
            rtport['id'],
            nuage_redirect_targets=str(rt['nuage_redirect_target']['id']))

    def _associate_multiple_rt_port(self, rtport, rts):
        nuage_rt_id_list = []
        for rt in rts:
            nuage_rt_id_list.append(rt['nuage_redirect_target']['id'])
        # convert into comaa separated string
        rt_string = ",".join(nuage_rt_id_list)
        self.ports_client.update_port(
            rtport['id'],
            nuage_redirect_targets=rt_string)

    def _disassociate_rt_port(self, rtport, rt):
        # Unassigning port to Redirect Target
        self.ports_client.update_port(
            rtport['id'], nuage_redirect_targets='')
        redirect_vport = self.nuage_vsd_client.get_redirection_target_vports(
            'redirectiontargets',
            rt['nuage_redirect_target']['id'])
        self.assertEqual(redirect_vport, '')

    def _verify_vsd_rt_port(self, rtport, rt, parent, parentinfo):
        # Verifying vport has associated RT
        redirect_vport = self.nuage_vsd_client.get_redirection_target_vports(
            'redirectiontargets',
            rt['nuage_redirect_target']['id'])
        port_ext_id = self.nuage_vsd_client.get_vsd_external_id(
            rtport['id'])
        vsd_vport = self.nuage_vsd_client.get_vport(
            parent, parentinfo['ID'], filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(
            redirect_vport[0]['ID'], vsd_vport[0]['ID'])

    def _assign_unassign_rt_port(self, rtport, rt, parent, parentinfo):
        self.ports_client.update_port(
            rtport['id'],
            nuage_redirect_targets=str(rt['nuage_redirect_target']['id']))
        redirect_vport = self.nuage_vsd_client.get_redirection_target_vports(
            'redirectiontargets',
            rt['nuage_redirect_target']['id'])

        # Verifying vport has associated RT
        port_ext_id = self.nuage_vsd_client.get_vsd_external_id(
            rtport['id'])
        vsd_vport = self.nuage_vsd_client.get_vport(
            parent, parentinfo['ID'], filters='externalID',
            filter_value=port_ext_id)
        self.assertEqual(
            redirect_vport[0]['ID'], vsd_vport[0]['ID'])

        # Unassigning port to Redirect Target
        self.ports_client.update_port(
            rtport['id'], nuage_redirect_targets='')
        redirect_vport = \
            self.nuage_network_client.get_redirection_target_vports(
                'redirectiontargets',
                rt['nuage_redirect_target']['id'])
        self.assertEqual(redirect_vport, '')

    def _check_port_in_show_redirect_target(self, port, rt):
        present = False
        show_rt_body = self.nuage_network_client.show_redirection_target(
            rt['nuage_redirect_target']['id'])
        for show_port in show_rt_body['nuage_redirect_target']['ports']:
            if port['id'] == show_port:
                present = True
                break
        return present

    def _verify_redirect_target_vip(self, rt, vipinfo):
        # Verifying RT has associated vip
        redirect_vip = self.nuage_network_client.get_redirection_target_vips(
            'redirectiontargets',
            rt['nuage_redirect_target']['id'])
        self.assertEqual(
            redirect_vip[0]['virtualIP'], vipinfo['virtual_ip_address'])

    def _find_id_redirect_target_in_list(self, redirect_target_id, subnet):
        rt_found = False
        list_body = self.nuage_network_client.list_redirection_targets(
            id=subnet['id'])
        for rt in list_body['nuage_redirect_targets']:
            if rt['id'] == redirect_target_id:
                rt_found = True
                break
        return rt_found

    def _find_redirect_target_in_list(self, redirect_target_id, subnet):
        rt_found = False
        list_body = self.nuage_network_client.list_redirection_targets(
            id=subnet['id'])
        for rt in list_body['nuage_redirect_targets']:
            if rt['id'] == redirect_target_id:
                rt_found = True
                break
        return rt_found

    def _create_redirect_target_in_l2_subnet(self, l2subnet, name=None):
        if name is None:
            name = data_utils.rand_name('os-l2-rt')
        # parameters for nuage redirection target
        post_body = {'insertion_mode': 'VIRTUAL_WIRE',
                     'redundancy_enabled': 'False',
                     'subnet_id': l2subnet['id'],
                     'name': name}
        redirect_target = self.nuage_network_client.create_redirection_target(
            **post_body)
        return redirect_target

    def _create_redirect_target_rule(self, redirect_target_id,
                                     security_group_id):
        # Creating Redirect Target Rule
        rule_body = {
            'priority': '300',
            'redirect_target_id': redirect_target_id,
            'protocol': '1',
            'origin_group_id': str(security_group_id),
            'remote_ip_prefix': '10.0.0.0/24',
            'action': 'REDIRECT'
        }
        rt_rule = self.nuage_network_client.create_redirection_target_rule(
            **rule_body)
        return rt_rule

    def _list_redirect_target_rule(self, subnet_id):
        return self.nuage_network_client.list_redirection_target_rule(
            subnet_id)

    def _create_redirect_target_in_l3_subnet(self, l3subnet, name=None):
        if name is None:
            name = data_utils.rand_name('os-l3-rt')
        # parameters for nuage redirection target
        post_body = {'insertion_mode': 'L3',
                     'redundancy_enabled': 'False',
                     'subnet_id': l3subnet['id'],
                     'name': name}
        redirect_target = self.nuage_network_client.create_redirection_target(
            **post_body)
        return redirect_target

    @nuage_test.header()
    def test_create_delete_os_redirection_target_l3_mgd_subnet(self):
        # Given I have a VSD-L3-Managed subnet
        vsd_l3_domain, vsd_l3_subnet = self._given_vsd_l3subnet(
            cidr4=self.cidr4, cidr6=self.cidr6)
        network, subnet4, subnet6 = self._given_network_linked_to_vsd_subnet(
            vsd_l3_subnet, cidr4=self.cidr4, cidr6=self.cidr6)

        #  When I create a redirection-target in the VSD-L3-Managed-Subnet
        os_redirect_target = self._create_redirect_target_in_l3_subnet(subnet4)
        # Then I expect the redirection-target in my list
        my_rt_found = self._find_redirect_target_in_list(
            os_redirect_target['nuage_redirect_target']['id'], subnet4)
        self.assertTrue(my_rt_found,
                        "Did not find my redirect-target in the list")
        # and check on VSD
        vsd_redirect_target = self.nuage_vsd_client.get_redirection_target(
            constants.DOMAIN, vsd_l3_domain['ID'], filters='ID',
            filter_value=os_redirect_target['nuage_redirect_target']['id'])
        self.assertIsNotNone(
            vsd_redirect_target,
            message="OS created redirect target not found on VSD")

        #  When I create a redirection-target in the VSD-L3-Managed-Subnet
        os_redirect_target6 = self._create_redirect_target_in_l3_subnet(
            subnet6)
        # Then I expect the redirection-target in my list
        my_rt_found = self._find_redirect_target_in_list(
            os_redirect_target['nuage_redirect_target']['id'], subnet6)
        self.assertTrue(my_rt_found,
                        "Did not find my redirect-target in the list")
        # and check on VSD
        vsd_redirect_target = self.nuage_vsd_client.get_redirection_target(
            constants.DOMAIN, vsd_l3_domain['ID'], filters='ID',
            filter_value=os_redirect_target6['nuage_redirect_target']['id'])
        self.assertIsNotNone(
            vsd_redirect_target,
            message="OS created redirect target not found on VSD")

        # When I associate a port to the redirectict-target
        rtport = self.create_port(network)
        self._associate_rt_port(rtport, os_redirect_target)
        # Then I expect the port in the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(
            rtport, os_redirect_target)
        message = "Associated port not present in " \
                  "show nuage redirect target response"
        self.assertTrue(port_present, message)

        # IPv6
        self._associate_rt_port(rtport, os_redirect_target6)
        port_present = self._check_port_in_show_redirect_target(
            rtport, os_redirect_target6)
        message = "Associated port not present in " \
                  "show nuage redirect target response"
        self.assertTrue(port_present, message)

        # When I disassociate the redirect-target from the port
        self._disassociate_rt_port(rtport, os_redirect_target)
        # I expect the port to be gone from the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(
            rtport, os_redirect_target)
        self.assertEqual(port_present, False,
                         message="Disassociated port still present in "
                                 "show nuage-redirect-target-response")

        self._disassociate_rt_port(rtport, os_redirect_target6)
        # I expect the port to be gone from the show redirect-target response
        port_present = self._check_port_in_show_redirect_target(
            rtport, os_redirect_target6)
        self.assertEqual(port_present, False,
                         message="Disassociated port still present in "
                                 "show nuage-redirect-target-response")

        # When I delete the redirect-target
        self.nuage_network_client.delete_redirection_target(
            os_redirect_target['nuage_redirect_target']['id'])
        # I expect the redirect-target to be gone from the list
        my_rt_found = self._find_redirect_target_in_list(
            os_redirect_target['nuage_redirect_target']['id'], subnet4)
        self.assertEqual(False, my_rt_found,
                         message="Deleted nuage_redirect_target still "
                                 "present in subnet")

        # And the redirect target on VSD is gone as well
        vsd_redirect_target = self.nuage_vsd_client.get_redirection_target(
            constants.DOMAIN, vsd_l3_domain['ID'], filters='ID',
            filter_value=os_redirect_target['nuage_redirect_target']['id'])
        self.assertEqual(vsd_redirect_target, '')

        self.nuage_network_client.delete_redirection_target(
            os_redirect_target6['nuage_redirect_target']['id'])
        # I expect the redirect-target to be gone from the list
        my_rt_found = self._find_redirect_target_in_list(
            os_redirect_target['nuage_redirect_target']['id'], subnet6)
        self.assertEqual(False, my_rt_found,
                         message="Deleted nuage_redirect_target still "
                                 "present in subnet")
        # And the redirect target on VSD is gone as well
        vsd_redirect_target = self.nuage_vsd_client.get_redirection_target(
            constants.DOMAIN, vsd_l3_domain['ID'], filters='ID',
            filter_value=os_redirect_target6['nuage_redirect_target']['id'])
        self.assertEqual(vsd_redirect_target, '')

        pass

    # @nuage_test.header()
    # def test_create_port_with_vsd_floatingip(self):
    #     # Given I have a VSD-FloatingIP-pool
    #     vsd_fip_pool = self._create_vsd_floatingip_pool(
    #          fip_pool_cidr=IPNetwork('120.120.10.0/24'))
    #
    #     # Given I have a VSD-L3-Managed subnet
    #     vsd_l3_domain, vsd_l3_subnet = self._given_vsd_l3subnet(
    #         cidr4=self.cidr4, cidr6=self.cidr6 )
    #     network, subnet4, subnet6 = self._given_network_linked_to_vsd_subnet(
    #         vsd_l3_subnet, cidr4=self.cidr4, cidr6=self.cidr6)
    #
    #     # And I have claimed a VSD-FloatingIP in the VSD-L3-Domain
    #     fip1 = self.nuage_vsd_client.claim_floatingip(vsd_l3_domain['ID'],
    #          vsd_fip_pool['ID'])[0]
    #     fip2 = self.nuage_vsd_client.claim_floatingip(vsd_l3_domain['ID'],
    #          vsd_fip_pool['ID'])[0]
    #
    #     # When I retrieve the nuage-floatingIP-list of the
    #     # OpenStack IPv4 subnet
    #     fip_list = self.nuage_network_client.list_nuage_floatingip_by_subnet(
    #          subnet4['id'])
    #     # Then I expect the VSD-floatingIP in my list
    #     fip_present = self._check_fip_in_list(fip1['ID'], fip_list)
    #     self.assertTrue(fip_present, msg="nuage floatingip not present "
    #          "in list, while expected to be")
    #
    #     # When I retrieve the nuage-floatingIP-list of the
    #     # OpenStack IPv6 subnet
    #     fip_list = self.nuage_network_client.list_nuage_floatingip_by_subnet(
    #         subnet6['id'])
    #     # Then I expect the VSD-floatingIP in my list
    #     fip1present = self._check_fip_in_list(fip1['ID'], fip_list)
    #     self.assertTrue(fip_present,
    #                     msg="nuage floatingip not present in list, "
    #                         "while expected to be")
    #
    #     fip2present = self._check_fip_in_list(fip2['ID'], fip_list)
    #     self.assertTrue(fip_present,
    #                     msg="nuage floatingip not present in list, "
    #                         "while expected to be")
    #
    #     # When I create a port in the network with FIP assigned
    #     kwargs = {"nuage_floatingip": {'id': fip1['ID'] }}
    #     port = self.create_port(network, **kwargs)
    #     # Then this FIP is assigned to the port
    #     self.assertThat(port['nuage_floatingip'],
    #                     ContainsDict({'id': Equals(fip1['ID'])}))
    #
    #     # And I associate this port to the claimed floating ip (via update)
    #     # self._associate_fip_to_port(port, claimed_fip[0]['ID'])
    #
    #     # Then I expect the claimed floating ip in the port show response
    #     if CONF.nuage_sut.nuage_plugin_mode != 'ml2':
    #         fip_present = self._check_fip_in_port_show(port['id'],
    #             fip1['ID'])
    #         self.assertTrue(fip_present,
    #                         msg="associated VSD claimed FIP (%s) not "
    #                             "found in port (%s)" %
    #                             (fip1['ID'], port['id']))
    #
    #     # When I disassociate the claimed fip from the port
    #     self._disassociate_fip_from_port(port)
    #     # Then I no longer expect the claimed floating ip in the
    #     # port show response
    #     if CONF.nuage_sut.nuage_plugin_mode != 'ml2':
    #         fip_present = self._check_fip_in_port_show(port['id'],
    #                           fip1[0]['ID'])
    #         self.assertFalse(fip_present,
    #                          msg="disassociated VSD claimed FIP (%s) "
    #                              "still found in port (%s)" %
    #                              (fip1[0]['ID'], port['id']))
