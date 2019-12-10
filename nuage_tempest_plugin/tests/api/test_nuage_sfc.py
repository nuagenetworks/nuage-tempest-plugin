from netaddr import IPNetwork
import time

from tempest.common import utils
from tempest.lib import exceptions as lib_exec
import testtools

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants as n_constants
from nuage_tempest_plugin.services.networkingsfc.networkingsfc_client \
    import NetworkingSfcClient as nsfc
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON

CONF = Topology.get_conf()


class NuageSfc(NuageBaseTest):
    _interface = 'json'

    @classmethod
    def setup_clients(cls):
        super(NuageSfc, cls).setup_clients()
        cls.nuage_client = NuageRestClient()
        cls.client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)
        cls.nsfc_client = nsfc(
            cls.os_primary.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **cls.os_primary.default_params)

    def setUp(self):
        self.addCleanup(self.resource_cleanup)
        super(NuageSfc, self).setUp()

    @classmethod
    def resource_setup(self):
        super(NuageSfc, self).resource_setup()

    @classmethod
    def skip_checks(cls):
        super(NuageSfc, cls).skip_checks()
        if not utils.is_extension_enabled('sfc', 'network'):
            raise cls.skipException('sfc service is not enabled.'
                                    ' Skipping tests.')

    @classmethod
    def _create_security_disabled_network(self, network_name):
        kwargs = {'name': network_name,
                  'port_security_enabled': 'False'}
        body = self.networks_client.create_network(**kwargs)
        return body['network']

    def _get_vsd_domain_id(self, router):
        router_ext_id = self.nuage_client.get_vsd_external_id(router['id'])
        domain = self.nuage_client.get_l3domain('externalID',
                                                router_ext_id)
        return domain[0]['ID']

    def _get_vsd_l2domain_id(self, subnet, netpart_name=None):
        vsd_subnet = self.nuage_client.get_l2domain(
            filters=['externalID', 'address'],
            filter_value=[subnet['network_id'],
                          subnet['cidr']],
            netpart_name=netpart_name)
        return vsd_subnet[0]['ID']

    def _verify_flow_classifier_l2(self, subnet, ingress_port, egress_port,
                                   netpart_name=None):
        vsd_l2domain_id = self._get_vsd_l2domain_id(subnet, netpart_name)
        self.nuage_client.get_redirection_target(
            'l2domains', vsd_l2domain_id)
        # rt_src_ext_id = 'fc_%s@%s' % (ingress_port['id'], CMS_ID)
        pre_rt_src = 'fc_%s' % ingress_port['id']
        rt_src_ext_id = self.nuage_client.get_vsd_external_id(pre_rt_src)
        rt_src = self.nuage_client.get_redirection_target(
            'l2domains', vsd_l2domain_id, 'externalID', rt_src_ext_id)
        # rt_dest_ext_id = 'fc_%s@%s' % (egress_port['id'], CMS_ID)
        pre_rt_dest_ext_id = 'fc_%s' % egress_port['id']
        rt_dest_ext_id = self.nuage_client.get_vsd_external_id(
            pre_rt_dest_ext_id)

        rt_dest = self.nuage_client.get_redirection_target(
            'l2domains', vsd_l2domain_id, filters='externalID',
            filter_value=rt_dest_ext_id)
        self.assertNotEqual(
            rt_src, '',
            "expected that source port rt is created but it is not")
        self.assertNotEqual(
            rt_dest, '',
            "expected that destination port rt is created but it is not")
        src_pg = self.nuage_client.get_policygroup(
            'l2domains', vsd_l2domain_id, 'externalID', rt_src_ext_id)
        dest_pg = self.nuage_client.get_policygroup(
            'l2domains', vsd_l2domain_id, 'externalID', rt_dest_ext_id)
        return rt_src, rt_dest, src_pg, dest_pg

    def _verify_flow_classifier(self, ingress_port, egress_port, router=None,
                                vsd_domain_id=None):
        if not vsd_domain_id and router:
            vsd_domain_id = self._get_vsd_domain_id(router)
        self.nuage_client.get_redirection_target(
            'domains', vsd_domain_id)
        # rt_src_ext_id = 'fc_%s@%s' % (ingress_port['id'], CMS_ID)
        pre_rt_src = 'fc_%s' % ingress_port['id']
        rt_src_ext_id = self.nuage_client.get_vsd_external_id(pre_rt_src)

        rt_src = self.nuage_client.get_redirection_target(
            'domains', vsd_domain_id, 'externalID', rt_src_ext_id)
        # rt_dest_ext_id = 'fc_%s@%s' % (egress_port['id'], CMS_ID)
        pre_rt_dest_ext_id = 'fc_%s' % egress_port['id']
        rt_dest_ext_id = self.nuage_client.get_vsd_external_id(
            pre_rt_dest_ext_id)

        rt_dest = self.nuage_client.get_redirection_target(
            'domains', vsd_domain_id, 'externalID', rt_dest_ext_id)
        self.assertNotEqual(
            rt_src, '',
            "expected that source port rt is created but it is not")
        self.assertNotEqual(
            rt_dest, '',
            "expected that destination port rt is created but it is not")
        src_pg = self.nuage_client.get_policygroup(
            n_constants.DOMAIN, vsd_domain_id, 'externalID', rt_src_ext_id)
        dest_pg = self.nuage_client.get_policygroup(
            n_constants.DOMAIN, vsd_domain_id, 'externalID', rt_dest_ext_id)
        return rt_src, rt_dest, src_pg, dest_pg

    def _get_l3_port_pair_group_redirect_target_pg(
            self, port_pair_group, router=None, vsd_domain_id=None,
            bidirectional_port=None):
        if not vsd_domain_id and router:
            vsd_domain_id = self._get_vsd_domain_id(router)
        if bidirectional_port == 'true':
            pre_rt_ingress_egress_ext_id = 'ingress_egress_%s' % (
                port_pair_group['port_pair_group']['id'])
            rt_ingress_egress_ext_id = \
                self.nuage_client.get_vsd_external_id(
                    pre_rt_ingress_egress_ext_id)
            rt_ingress_egress = self.nuage_client.get_redirection_target(
                'domains', vsd_domain_id,
                'externalID', rt_ingress_egress_ext_id)
            port_pair_group_ingress_pg = self.nuage_client.get_policygroup(
                'domains', vsd_domain_id,
                'externalID', rt_ingress_egress_ext_id)
            return rt_ingress_egress, port_pair_group_ingress_pg
        else:
            pre_rt_ingress_ext_id = 'ingress_%s' % (
                port_pair_group['port_pair_group']['id'])
            rt_ingress_ext_id = self.nuage_client.get_vsd_external_id(
                pre_rt_ingress_ext_id)
            rt_ingress = self.nuage_client.get_redirection_target(
                'domains', vsd_domain_id, 'externalID', rt_ingress_ext_id)
            # rt_egress_ext_id = 'egress_%s@%s' % (
            #     port_pair_group['port_pair_group']['id'], CMS_ID)
            pre_rt_egress_ext_id = 'egress_%s' % port_pair_group[
                'port_pair_group']['id']
            rt_egress_ext_id = self.nuage_client.get_vsd_external_id(
                pre_rt_egress_ext_id)
            rt_egress = self.nuage_client.get_redirection_target(
                'domains', vsd_domain_id, 'externalID', rt_egress_ext_id)
            port_pair_group_ingress_pg = self.nuage_client.get_policygroup(
                'domains', vsd_domain_id, 'externalID', rt_ingress_ext_id)
            port_pair_group_egress_pg = self.nuage_client.get_policygroup(
                'domains', vsd_domain_id, 'externalID', rt_egress_ext_id)
            return rt_ingress, rt_egress, port_pair_group_ingress_pg, \
                port_pair_group_egress_pg

    def _get_l2_port_pair_group_redirect_target_pg(
            self, port_pair_group, subnet, bidirectional_port=None,
            netpart_name=None):
        vsd_l2domain_id = self._get_vsd_l2domain_id(subnet, netpart_name)
        if bidirectional_port == 'true':
            # rt_ingress_egress_ext_id = 'ingress_egress_%s@%s' % (
            #     port_pair_group['port_pair_group']['id'], CMS_ID)
            pre_rt_ingress_egress_ext_id = \
                'ingress_egress_%s' % port_pair_group['port_pair_group']['id']
            rt_ingress_egress_ext_id = \
                self.nuage_client.get_vsd_external_id(
                    pre_rt_ingress_egress_ext_id)
            rt_ingress_egress = self.nuage_client.get_redirection_target(
                'l2domains', vsd_l2domain_id,
                'externalID', rt_ingress_egress_ext_id)
            port_pair_group_ingress_pg = self.nuage_client.get_policygroup(
                'l2domains', vsd_l2domain_id,
                'externalID', rt_ingress_egress_ext_id)
            return rt_ingress_egress, port_pair_group_ingress_pg
        else:
            # rt_ingress_ext_id = 'ingress_%s@%s' % (
            #     port_pair_group['port_pair_group']['id'], CMS_ID)
            pre_rt_ingress_ext_id = 'ingress_%s' % port_pair_group[
                'port_pair_group']['id']
            rt_ingress_ext_id = self.nuage_client.get_vsd_external_id(
                pre_rt_ingress_ext_id)
            rt_ingress = self.nuage_client.get_redirection_target(
                'l2domains', vsd_l2domain_id,
                'externalID', rt_ingress_ext_id)
            # rt_egress_ext_id = 'egress_%s@%s' % (
            #     port_pair_group['port_pair_group']['id'], CMS_ID)
            pre_rt_egress_ext_id = 'egress_%s' % port_pair_group[
                'port_pair_group']['id']
            rt_egress_ext_id = self.nuage_client.get_vsd_external_id(
                pre_rt_egress_ext_id)
            rt_egress = self.nuage_client.get_redirection_target(
                'l2domains', vsd_l2domain_id,
                'externalID', rt_egress_ext_id)
            port_pair_group_ingress_pg = self.nuage_client.get_policygroup(
                'l2domains', vsd_l2domain_id,
                'externalID', rt_ingress_ext_id)
            port_pair_group_egress_pg = self.nuage_client.get_policygroup(
                'l2domains', vsd_l2domain_id,
                'externalID', rt_egress_ext_id)
            return rt_ingress, rt_egress, port_pair_group_ingress_pg, \
                port_pair_group_egress_pg

    def _get_adv_fwd_rules_port_chain_l2(self, pc, subnet, netpart_name=None):
        vsd_l2domain_id = self._get_vsd_l2domain_id(subnet, netpart_name)
        # pc_ext_id = '%s@%s' % (pc['port_chain']['id'], CMS_ID)
        pc_ext_id = self.nuage_client.get_vsd_external_id(
            pc['port_chain']['id'])
        adv_fwd_template = self.nuage_client.get_advfwd_template(
            'l2domains', vsd_l2domain_id, 'externalID', pc_ext_id)
        rules = self.nuage_client.get_advfwd_entrytemplate(
            'ingressadvfwdtemplates', adv_fwd_template[0]['ID'])
        return rules

    def _get_adv_fwd_rules_port_chain(
            self, pc, router=None, vsd_domain_id=None):
        if not vsd_domain_id and router:
            vsd_domain_id = self._get_vsd_domain_id(router)

        # pc_ext_id = '%s@%s' % (pc['port_chain']['id'], CMS_ID)
        pc_ext_id = self.nuage_client.get_vsd_external_id(
            pc['port_chain']['id'])
        adv_fwd_template = self.nuage_client.get_advfwd_template(
            'domains', vsd_domain_id, 'externalID', pc_ext_id)
        rules = self.nuage_client.get_advfwd_entrytemplate(
            'ingressadvfwdtemplates', adv_fwd_template[0]['ID'])
        return rules

    def _create_l3_port_chain(self, network, subnet, router):
        pp_list = []
        ppg_list = []
        src_port = self.create_port(network, name='src_port')
        dest_port = self.create_port(network, name='dest_port')
        fc1 = self._create_flow_classifier(
            'fc1', src_port['id'], dest_port['id'], '10', 'icmp')
        p1 = self.create_port(network, name='p1', port_security_enabled=False)
        p2 = self.create_port(network, name='p2', port_security_enabled=False)
        p3 = self.create_port(network, name='p3', port_security_enabled=False)
        p4 = self.create_port(network, name='p4', port_security_enabled=False)

        self.create_tenant_server(ports=[p1, p2], name='sfc-vm1')
        self.create_tenant_server(ports=[p3, p4], name='sfc-vm2')

        time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1, p2)
        ppg1 = self._create_port_pair_group('ppg1', pp1)
        pp_list.append(pp1)
        ppg_list.append(ppg1)
        pp2 = self._create_port_pair('pp2', p3, p4)
        ppg2 = self._create_port_pair_group('ppg2', pp2)
        pp_list.append(pp2)
        ppg_list.append(ppg2)

        pc1 = self. _create_port_chain('pc1', [ppg1, ppg2], [fc1])
        self._verify_adv_fwd_rules_l3(network, subnet, router,
                                      src_port, dest_port, ppg_list,
                                      fc1, pc1, '10')
        return pc1, fc1, ppg_list, pp_list, src_port, dest_port

    def _verify_adv_fwd_rules_l3(self, network, subnet, router,
                                 src_port, dest_port, ppg_list, fc, pc, vlan):
        # assumption ppg_list is the order used in the creation of port chain
        rt_src, rt_dest, src_pg, dest_pg = self._verify_flow_classifier(
            src_port, dest_port, router)

        if len(ppg_list) == 1:
            ppg1 = ppg_list[0]
            ppg1_rt_ingress, ppg1_rt_egress, \
                ppg1_ingress_pg, ppg1_egress_pg = \
                self._get_l3_port_pair_group_redirect_target_pg(ppg1, router)
            rules = self._get_adv_fwd_rules_port_chain(pc, router=router)
            rule_src_insfcvm1 = rule_sfcvm1_dest = None
            for rule in rules:
                if rule['locationID'] == src_pg[0]['ID']:
                    rule_src_insfcvm1 = rule
                    self.assertEqual(
                        rule['redirectVPortTagID'],
                        ppg1_rt_ingress[0]['ID'],
                        "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                    vlan_range = '%s' % (vlan)
                    self.assertEqual(
                        rule['vlanRange'],
                        vlan_range,
                        "sfc to sfc-vm1 vlan range is wrong")
                    self.assertEqual(rule['redirectRewriteType'], 'VLAN')
                if rule['locationID'] == ppg1_egress_pg[0]['ID']:
                    rule_sfcvm1_dest = rule
                    self.assertEqual(
                        rule['redirectVPortTagID'],
                        rt_dest[0]['ID'],
                        "sfcvm1 to dest adv fwd rule redirect target is wrong")
            self.assertIsNotNone(rule_src_insfcvm1)
            self.assertIsNotNone(rule_sfcvm1_dest)

        if len(ppg_list) == 2:
            ppg1 = ppg_list[0]
            ppg2 = ppg_list[1]
            ppg1_rt_ingress, ppg1_rt_egress, \
                ppg1_ingress_pg, ppg1_egress_pg = \
                self._get_l3_port_pair_group_redirect_target_pg(ppg1, router)
            ppg2_rt_ingress, ppg2_rt_egress, \
                ppg2_ingress_pg, ppg2_egress_pg = \
                self._get_l3_port_pair_group_redirect_target_pg(ppg2, router)
            rules = self._get_adv_fwd_rules_port_chain(pc, router=router)
            rule_src_insfcvm1 = rule_sfcvm1_sfcvm2 = rule_sfcvm2_dest = None
            for rule in rules:
                if rule['locationID'] == src_pg[0]['ID']:
                    rule_src_insfcvm1 = rule
                    self.assertEqual(
                        rule['redirectVPortTagID'],
                        ppg1_rt_ingress[0]['ID'],
                        "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                    vlan_range = '%s' % (vlan)
                    self.assertEqual(
                        rule['vlanRange'],
                        vlan_range,
                        "sfc to sfc-vm1 vlan range is wrong")
                    self.assertEqual(rule['redirectRewriteType'], 'VLAN')
                    self.assertEqual(
                        rule['redirectRewriteValue'], str(
                            pc['port_chain']['chain_parameters'][
                                'correlation_id']))
                if rule['locationID'] == ppg1_egress_pg[0]['ID']:
                    rule_sfcvm1_sfcvm2 = rule
                    self.assertEqual(
                        rule['redirectVPortTagID'],
                        ppg2_rt_ingress[0]['ID'],
                        "sfcvm1 to sfcvm2 adv fwd rule redirect target "
                        "is wrong")
                if rule['locationID'] == ppg2_egress_pg[0]['ID']:
                    rule_sfcvm2_dest = rule
                    self.assertEqual(
                        rule['redirectVPortTagID'],
                        rt_dest[0]['ID'],
                        "sfcvm1 to dest adv fwd rule redirect target is wrong")
            self.assertIsNotNone(rule_src_insfcvm1)
            self.assertIsNotNone(rule_sfcvm1_sfcvm2)
            self.assertIsNotNone(rule_sfcvm2_dest)

        if len(ppg_list) == 3:
            ppg1 = ppg_list[0]
            ppg2 = ppg_list[1]
            ppg3 = ppg_list[2]
            ppg1_rt_ingress, ppg1_rt_egress, \
                ppg1_ingress_pg, ppg1_egress_pg = \
                self._get_l3_port_pair_group_redirect_target_pg(ppg1, router)
            ppg2_rt_ingress, ppg2_rt_egress, \
                ppg2_ingress_pg, ppg2_egress_pg = \
                self._get_l3_port_pair_group_redirect_target_pg(ppg2, router)
            ppg3_rt_ingress, ppg3_rt_egress, \
                ppg3_ingress_pg, ppg3_egress_pg = \
                self._get_l3_port_pair_group_redirect_target_pg(ppg3, router)
            rules = self._get_adv_fwd_rules_port_chain(pc, router=router)
            rule_src_insfcvm1 = rule_sfcvm1_sfcvm2 = None
            rule_sfcvm2_sfcvm3 = rule_sfcvm3_dest = None
            for rule in rules:
                if rule['locationID'] == src_pg[0]['ID']:
                    rule_src_insfcvm1 = rule
                    self.assertEqual(
                        rule['redirectVPortTagID'],
                        ppg1_rt_ingress[0]['ID'],
                        "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                    vlan_range = '%s' % (vlan)
                    self.assertEqual(
                        rule['vlanRange'],
                        vlan_range,
                        "sfc to sfc-vm1 vlan range is wrong")
                    self.assertEqual(rule['redirectRewriteType'], 'VLAN')
                if rule['locationID'] == ppg1_egress_pg[0]['ID']:
                    rule_sfcvm1_sfcvm2 = rule
                    self.assertEqual(
                        rule['redirectVPortTagID'],
                        ppg2_rt_ingress[0]['ID'],
                        "sfcvm1 to sfcvm2 adv fwd rule redirect target "
                        "is wrong")
                if rule['locationID'] == ppg2_egress_pg[0]['ID']:
                    rule_sfcvm2_sfcvm3 = rule
                    self.assertEqual(
                        rule['redirectVPortTagID'],
                        ppg3_rt_ingress[0]['ID'],
                        "sfcvm2 to sfcvm3 adv fwd rule redirect target "
                        "is wrong")
                if rule['locationID'] == ppg3_egress_pg[0]['ID']:
                    rule_sfcvm3_dest = rule
                    self.assertEqual(
                        rule['redirectVPortTagID'],
                        rt_dest[0]['ID'],
                        "sfcvm1 to dest adv fwd rule redirect target is wrong")

            self.assertIsNotNone(rule_src_insfcvm1)
            self.assertIsNotNone(rule_sfcvm1_sfcvm2)
            self.assertIsNotNone(rule_sfcvm2_sfcvm3)
            self.assertIsNotNone(rule_sfcvm3_dest)

    def _create_port_pair(self, name, ingress, egress):
        port_pair1 = self.nsfc_client.create_port_pair(
            name, ingress['id'], egress['id'])
        self.addCleanup(
            self.nsfc_client.delete_port_pair,
            port_pair1['port_pair']['id'])
        return port_pair1

    def _create_port_pair_group(self, name, port_pair):
        ppg1 = self.nsfc_client.create_port_pair_group(name, port_pair)
        self.addCleanup(
            self.nsfc_client.delete_port_pair_group,
            ppg1['port_pair_group']['id'])
        return ppg1

    def _create_flow_classifier(
            self, name, logical_src_port, logical_dest_port, vlan,
            protocol=None, ethertype='IPv4', source_port_range_max=None,
            source_port_range_min=None, destination_port_range_min=None,
            destination_port_range_max=None):
        params = {'name': name,
                  'logical_source_port': logical_src_port,
                  'logical_destination_port': logical_dest_port,
                  'ethertype': ethertype,
                  'vlan_range_min': vlan,
                  'vlan_range_max': vlan}
        if protocol is not None:
            params['protocol'] = protocol
        if source_port_range_max is not None:
            params['source_port_range_max'] = source_port_range_max
        if source_port_range_min is not None:
            params['source_port_range_min'] = source_port_range_min
        if destination_port_range_min is not None:
            params['destination_port_range_min'] = destination_port_range_min
        if destination_port_range_max is not None:
            params['destination_port_range_max'] = destination_port_range_max

        fc1 = self.nsfc_client.create_flow_classifier(**params)
        self.addCleanup(
            self.nsfc_client.delete_flow_classifier,
            fc1['flow_classifier']['id'])
        return fc1

    def _create_port_chain(self, name, ppg_list, fc_list, chain_params=None):
        fc_id_list = []
        ppg_id_list = []
        for fc in fc_list:
            fc_id_list.append(fc['flow_classifier']['id'])
        for ppg in ppg_list:
            ppg_id_list.append(ppg['port_pair_group']['id'])

        params = {
            'name': name,
            'port_pair_groups': ppg_id_list,
            'flow_classifiers': fc_id_list}
        if chain_params:
            params['chain_parameters'] = chain_params
        pc1 = self.nsfc_client.create_port_chain(**params)
        self.addCleanup(
            self.nsfc_client.delete_port_chain,
            pc1['port_chain']['id'])
        return pc1

    def test_create_del_l2_l3_port_pair_group(self):
        l3network = self.create_network()
        l3subnet = self.create_subnet(l3network)
        router = self.create_router()
        self.create_router_interface(router['id'], l3subnet['id'])
        l2network = self.create_network()
        self.create_subnet(l2network)

        network_list = [l3network, l2network]
        for network in network_list:
            port1 = self.create_port(network, name='port1',
                                     port_security_enabled=False)
            port2 = self.create_port(network, name='port2',
                                     port_security_enabled=False)
            self.create_tenant_server(ports=[port1, port2])
            port_pair1 = self._create_port_pair('pp1', port1, port2)
            self._create_port_pair_group('ppg1', port_pair1)

    def test_create_delete_port_pair_group_single_port(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router()
        self.create_router_interface(router['id'], subnet['id'])
        port1 = self.create_port(network, name='port1',
                                 port_security_enabled=False)
        self.create_tenant_server(ports=[port1])
        port_pair1 = self._create_port_pair('pp1', port1, port1)
        self._create_port_pair_group('ppg1', port_pair1)

    def test_update_port_pair_group(self):
        l3network = self.create_network()
        l3subnet = self.create_subnet(l3network)
        router = self.create_router()
        self.create_router_interface(router['id'], l3subnet['id'])
        l2network = self.create_network()
        self.create_subnet(l2network)
        network_list = [l3network, l2network]
        for network in network_list:
            port1 = self.create_port(network, name='port1',
                                     port_security_enabled=False)
            port2 = self.create_port(network, name='port2',
                                     port_security_enabled=False)
            port3 = self.create_port(network, name='port3',
                                     port_security_enabled=False)
            port4 = self.create_port(network, name='port4',
                                     port_security_enabled=False)
            self.create_tenant_server(ports=[port1, port2], name='vm1')
            self.create_tenant_server(ports=[port3, port4], name='vm2')
            time.sleep(5)
            port_pair1 = self._create_port_pair('pp1', port1, port2)
            port_pair2 = self._create_port_pair('pp2', port3, port4)
            ppg1 = self._create_port_pair_group('ppg1', port_pair1)

            # update
            self.nsfc_client.update_port_pair_group(
                ppg1['port_pair_group']['id'], port_pair2)

    def test_create_delete_flow_classifier(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router()
        self.create_router_interface(router['id'], subnet['id'])
        port1 = self.create_port(network, name='port1',
                                 port_security_enabled=False)
        port2 = self.create_port(network, name='port2',
                                 port_security_enabled=False)
        self._create_flow_classifier(
            'fc1', port1['id'], port2['id'], '10', 'tcp',
            source_port_range_max='23', source_port_range_min='23',
            destination_port_range_min='100', destination_port_range_max='100')
        self._verify_flow_classifier(port1, port2, router)

    def test_create_multi_fc_same_src_dest(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router()
        self.create_router_interface(router['id'], subnet['id'])

        port1 = self.create_port(network, name='port1',
                                 port_security_enabled=False)
        port2 = self.create_port(network, name='port2',
                                 port_security_enabled=False)
        fc1 = self.nsfc_client.create_flow_classifier(
            name="fc1",
            ethertype='IPv4', logical_destination_port=port2['id'],
            logical_source_port=port1['id'], protocol='tcp',
            source_port_range_max='23', source_port_range_min='23',
            destination_port_range_min='100',
            destination_port_range_max='100',
            vlan_range_min=10, vlan_range_max=10)

        fc2 = self.nsfc_client.create_flow_classifier(
            name="fc1",
            ethertype='IPv4', logical_destination_port=port2['id'],
            logical_source_port=port1['id'], protocol='icmp',
            vlan_range_max='100', vlan_range_min='100')

        fc3 = self.nsfc_client.create_flow_classifier(
            name="fc1",
            ethertype='IPv4', logical_destination_port=port2['id'],
            logical_source_port=port1['id'], protocol='udp',
            vlan_range_max='105', vlan_range_min='105')

        self._verify_flow_classifier(port1, port2, router)
        self.nsfc_client.delete_flow_classifier(fc1['flow_classifier']['id'])
        self._verify_flow_classifier(port1, port2, router)
        self.nsfc_client.delete_flow_classifier(fc2['flow_classifier']['id'])
        self._verify_flow_classifier(port1, port2, router)
        self.nsfc_client.delete_flow_classifier(fc3['flow_classifier']['id'])

    def test_create_delete_port_chain_symmetric(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router()
        self.create_router_interface(router['id'], subnet['id'])
        src_port = self.create_port(network, name='src_port')
        dest_port = self.create_port(network, name='dest_port')
        fc1 = self._create_flow_classifier(
            'fc1', src_port['id'], dest_port['id'], '10', 'tcp',
            source_port_range_max='23', source_port_range_min='23',
            destination_port_range_min='100', destination_port_range_max='100')
        p1 = self.create_port(network, name='p1', port_security_enabled=False)
        p2 = self.create_port(network, name='p2', port_security_enabled=False)
        p3 = self.create_port(network, name='p3', port_security_enabled=False)
        p4 = self.create_port(network, name='p4', port_security_enabled=False)

        self.create_tenant_server(ports=[p1, p2], name='sfc-vm1')
        self.create_tenant_server(ports=[p3, p4], name='sfc-vm2')

        time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1, p2)
        ppg1 = self._create_port_pair_group('ppg1', pp1)

        pp2 = self._create_port_pair('pp2', p3, p4)
        ppg2 = self._create_port_pair_group('ppg2', pp2)
        pc1 = self. _create_port_chain(
            'pc1', [ppg1, ppg2], [fc1], {'symmetric': 'true'})

        # verify
        rt_src, rt_dest, src_pg, dest_pg = self._verify_flow_classifier(
            src_port, dest_port, router)
        ppg1_rt_ingress, ppg1_rt_egress, ppg1_ingress_pg, ppg1_egress_pg = \
            self._get_l3_port_pair_group_redirect_target_pg(ppg1, router)
        ppg2_rt_ingress, ppg2_rt_egress, ppg2_ingress_pg, ppg2_egress_pg = \
            self._get_l3_port_pair_group_redirect_target_pg(ppg2, router)
        rules = self._get_adv_fwd_rules_port_chain(pc1, router=router)

        rule_src_insfcvm1 = rule_sfcvm1_sfcvm2 = rule_sfcvm2_dest = None
        rev_rule_dest_egsfcvm2 = rev_rule_sfcvm2_sfcvm1 = None
        rev_rule_sfcvm1_src = None
        for rule in rules:
            if rule['locationID'] == src_pg[0]['ID']:
                rule_src_insfcvm1 = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    ppg1_rt_ingress[0]['ID'],
                    "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                self.assertEqual(
                    rule['vlanRange'],
                    '10',
                    "sfc to sfc-vm1 vlan range is wrong")
                self.assertEqual(rule['redirectRewriteType'], 'VLAN')
            if rule['locationID'] == ppg1_egress_pg[0]['ID']:
                rule_sfcvm1_sfcvm2 = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    ppg2_rt_ingress[0]['ID'],
                    "sfcvm1 to sfcvm2 adv fwd rule redirect target is wrong")
            if rule['locationID'] == ppg2_egress_pg[0]['ID']:
                rule_sfcvm2_dest = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    rt_dest[0]['ID'],
                    "sfcvm1 to dest adv fwd rule redirect target is wrong")
            if rule['locationID'] == dest_pg[0]['ID']:
                rev_rule_dest_egsfcvm2 = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    ppg2_rt_egress[0]['ID'],
                    "dest to sfc-vm2 rev adv fwd rule redirect vport is wrong")
                self.assertEqual(
                    rule['vlanRange'],
                    '10',
                    "sfc dest to sfc-vm2 vlan range is wrong")
            if rule['locationID'] == ppg2_ingress_pg[0]['ID']:
                rev_rule_sfcvm2_sfcvm1 = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    ppg1_rt_egress[0]['ID'],
                    "sfcvm2 ingress to sfcvm1 egress rev adv fwd rule "
                    "redirect target is wrong")
            if rule['locationID'] == ppg1_ingress_pg[0]['ID']:
                rev_rule_sfcvm1_src = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    rt_src[0]['ID'],
                    "sfcvm1 to src rev  adv fwd rule redirect target is wrong")
        self.assertIsNotNone(rule_src_insfcvm1)
        self.assertIsNotNone(rule_sfcvm1_sfcvm2)
        self.assertIsNotNone(rule_sfcvm2_dest)
        self.assertIsNotNone(rev_rule_dest_egsfcvm2)
        self.assertIsNotNone(rev_rule_sfcvm2_sfcvm1)
        self.assertIsNotNone(rev_rule_sfcvm1_src)

    def test_create_delete_port_chain_one_ppg_l2(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        src_port = self.create_port(network, name='src_port')
        dest_port = self.create_port(network, name='dest_port')

        fc1 = self._create_flow_classifier(
            'fc1', src_port['id'], dest_port['id'], '10', 'tcp',
            source_port_range_max='23', source_port_range_min='23',
            destination_port_range_min='100', destination_port_range_max='100')
        p1 = self.create_port(network, name='p1', port_security_enabled=False)
        p2 = self.create_port(network, name='p2', port_security_enabled=False)
        self.create_tenant_server(ports=[p1, p2], name='sfc-vm1')
        time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1, p2)
        ppg1 = self._create_port_pair_group('ppg1', pp1)
        pc1 = self. _create_port_chain('pc1', [ppg1], [fc1])
        # verify
        self.assertNotEqual(
            pc1, '', 'port chain is empty')
        rt_src, rt_dest, src_pg, dest_pg = self._verify_flow_classifier_l2(
            subnet, src_port, dest_port)

        ppg1_rt_ingress, ppg1_rt_egress, ppg1_ingress_pg, ppg1_egress_pg = \
            self._get_l2_port_pair_group_redirect_target_pg(
                ppg1, subnet)
        rules = self._get_adv_fwd_rules_port_chain_l2(pc1, subnet)
        rule_src_insfcvm1 = rule_sfcvm1_dest = None
        for rule in rules:
            if rule['locationID'] == src_pg[0]['ID']:
                rule_src_insfcvm1 = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    ppg1_rt_ingress[0]['ID'],
                    "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                self.assertEqual(
                    rule['vlanRange'],
                    '10',
                    "sfc to sfc-vm1 vlan range is wrong")
                self.assertEqual(rule['redirectRewriteType'], 'VLAN')
            if rule['locationID'] == ppg1_egress_pg[0]['ID']:
                rule_sfcvm1_dest = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    rt_dest[0]['ID'],
                    "sfcvm1 to dest adv fwd rule redirect target is wrong")
        self.assertIsNotNone(rule_src_insfcvm1)
        self.assertIsNotNone(rule_sfcvm1_dest)

    @testtools.skipUnless(
        CONF.nuage_sut.image_is_advanced,
        "Advanced image is required to run this test.")
    def test_create_delete_port_chain_one_ppg(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_public_router()
        self.create_router_interface(router['id'], subnet['id'])
        ssh_security_group = self._create_security_group(
            namestart='tempest-open-ssh')
        src_port = self.create_port(network, name='src_port',
                                    security_groups=[ssh_security_group['id']])
        dest_port = self.create_port(
            network,
            name='dest_port',
            security_groups=[ssh_security_group['id']])

        fc1 = self._create_flow_classifier(
            'fc1', src_port['id'], dest_port['id'], '10', 'icmp')
        p1 = self.create_port(network, name='p1', port_security_enabled=False)
        p2 = self.create_port(network, name='p2', port_security_enabled=False)

        self.create_tenant_server(ports=[src_port], name='srcvm')
        # srcvm_ip = srcvm.get_server_ip_in_network(network['name'])

        # Skipping following checks until we have image to support validation
        # self.prepare_for_nic_provisioning(srcvm)
        # srcvm.configure_vlan_interface(srcvm_ip, 'eth0', '10')
        # srcvm.bring_down_interface('eth0')  # Kris added

        self.create_tenant_server(ports=[dest_port], name='destvm')
        # destvm_ip = destvm.get_server_ip_in_network(network['name'])

        # Skipping following checks until we have image to support validation
        # self.prepare_for_nic_provisioning(destvm)
        # destvm.configure_vlan_interface(destvm_ip, 'eth0', '10')
        # destvm.bring_down_interface('eth0')

        self.create_tenant_server(ports=[p1, p2], name='sfc-vm1')
        # time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1, p2)
        ppg1 = self._create_port_pair_group('ppg1', pp1)
        pc1 = self. _create_port_chain('pc1', [ppg1], [fc1])
        # redirect_vlan = pc1['port_chain']['chain_parameters']
        # ['correlation_id']
        # Skipping following checks until we have image to support validation
        # sfcvm1.configure_ip_fwd()
        # sfcvm1.configure_sfc_vm(redirect_vlan)

        ppg_list = [ppg1]
        # verify
        self._verify_adv_fwd_rules_l3(
            network, subnet, router, src_port, dest_port, ppg_list,
            fc1, pc1, '10')

        # sfcvm1.send('tcpdump -i eth0.10 -n > log &')  # Kris changed to .10
        # self.assert_ping(srcvm, destvm, network, should_pass=True,
        #                interface='eth0.10', ping_count=20)
        # output = sfcvm1.send('cat log | grep "echo request"')
        # msg = '%s > %s: ICMP echo request' % (srcvm_ip, destvm_ip)
        # self.assertThat(output[3], Contains(msg))

    def test_update_port_chain_add_remove_ppg_reorder(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router()
        self.create_router_interface(router['id'], subnet['id'])
        pc1, fc1, ppg_list, pp_list, src_port, dest_port = \
            self._create_l3_port_chain(network, subnet, router)
        p5 = self.create_port(network, name='p5', port_security_enabled=False)
        p6 = self.create_port(network, name='p6', port_security_enabled=False)
        self.create_tenant_server(ports=[p5, p6], name='sfc-vm3')
        time.sleep(5)
        ppg1 = ppg_list[0]
        ppg2 = ppg_list[1]

        pp3 = self._create_port_pair('pp3', p5, p6)
        ppg3 = self._create_port_pair_group('ppg3', pp3)

        ppg_list.append(ppg3)
        pp_list.append(pp3)
        update_pc_ppg_list = []
        for ppg in ppg_list:
            update_pc_ppg_list.append(ppg['port_pair_group']['id'])
        verify_ppg_list = [ppg1, ppg2, ppg3]
        pc1 = self.nsfc_client.update_port_chain(
            pc1['port_chain']['id'],
            port_pair_groups=update_pc_ppg_list,
            flow_classifiers=fc1['flow_classifier']['id'])
        self._verify_adv_fwd_rules_l3(
            network, subnet, router, src_port, dest_port, verify_ppg_list,
            fc1, pc1, '10')
        # reorder pc1 ppg
        update_pc_ppg_list.reverse()
        pc1 = self.nsfc_client.update_port_chain(
            pc1['port_chain']['id'],
            port_pair_groups=update_pc_ppg_list,
            flow_classifiers=fc1['flow_classifier']['id'])
        verify_ppg_list.reverse()
        self._verify_adv_fwd_rules_l3(
            network, subnet, router, src_port, dest_port, verify_ppg_list,
            fc1, pc1, '10')
        update_pc_ppg_list.reverse()
        verify_ppg_list.reverse()
        # remove ppg3 for pc1
        update_pc_ppg_list.remove(ppg3['port_pair_group']['id'])
        verify_ppg_list.remove(ppg3)
        pc1 = self.nsfc_client.update_port_chain(
            pc1['port_chain']['id'],
            port_pair_groups=update_pc_ppg_list,
            flow_classifiers=fc1['flow_classifier']['id'])
        self._verify_adv_fwd_rules_l3(
            network, subnet, router, src_port, dest_port, verify_ppg_list,
            fc1, pc1, '10')
        # update with 1 ppg
        update_pc_ppg_list.remove(ppg2['port_pair_group']['id'])
        verify_ppg_list.remove(ppg2)
        pc1 = self.nsfc_client.update_port_chain(
            pc1['port_chain']['id'],
            port_pair_groups=update_pc_ppg_list,
            flow_classifiers=fc1['flow_classifier']['id'])
        self._verify_adv_fwd_rules_l3(
            network, subnet, router, src_port, dest_port, verify_ppg_list,
            fc1, pc1, '10')

    def test_update_port_chain_update_ppg(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router()
        self.create_router_interface(router['id'], subnet['id'])
        pc1, fc1, ppg_list, pp_list, src_port, dest_port = \
            self._create_l3_port_chain(network, subnet, router)
        p5 = self.create_port(network, name='p5', port_security_enabled=False)
        p6 = self.create_port(network, name='p6', port_security_enabled=False)
        self.create_tenant_server(ports=[p5, p6], name='sfc-vm3')

        time.sleep(5)
        ppg1 = ppg_list[0]
        ppg2 = ppg_list[1]
        pp3 = self._create_port_pair('pp3', p5, p6)
        pp1 = pp_list[0]
        self._verify_flow_classifier(src_port, dest_port, router)
        ppg1_rt_ingress, ppg1_rt_egress, ppg1_ingress_pg, ppg1_egress_pg = \
            self._get_l3_port_pair_group_redirect_target_pg(ppg1, router)
        self._get_l3_port_pair_group_redirect_target_pg(ppg2, router)

        # update
        ppg1 = self.nsfc_client.update_port_pair_group(
            ppg1['port_pair_group']['id'], pp3)
        ppg1_ingress_rt_vport = \
            self.nuage_client.get_redirection_target_vports(
                'redirectiontargets', ppg1_rt_ingress[0]['ID'])
        ppg1_egress_rt_vport = \
            self.nuage_client.get_redirection_target_vports(
                'redirectiontargets', ppg1_rt_egress[0]['ID'])
        self.assertEqual(ppg1_ingress_rt_vport[0]['name'], p5['id'])
        self.assertEqual(ppg1_egress_rt_vport[0]['name'], p6['id'])
        # cleanup
        self.nsfc_client.update_port_pair_group(
            ppg1['port_pair_group']['id'], pp1)

    def test_multiple_pc(self):
        network1 = self.create_network()
        subnet1 = self.create_subnet(network1)
        router = self.create_router()
        self.create_router_interface(router['id'], subnet1['id'])
        gw = '2.10.0.1'
        cidr = '2.10.0.0/24'
        cidr1 = IPNetwork(cidr)
        mask = 24
        network2 = self.create_network()
        subnet2 = self.create_subnet(
            network2, gateway=gw, cidr=cidr1, mask_bits=mask)
        self.create_router_interface(router['id'], subnet2['id'])
        self._create_l3_port_chain(network1, subnet1, router)
        self._create_l3_port_chain(network2, subnet2, router)
        self._create_l3_port_chain(network1, subnet1, router)
        self._create_l3_port_chain(network2, subnet2, router)

    def test_port_pair_diff_subnet_neg(self):
        network1 = self.create_network()
        subnet1 = self.create_subnet(network1)
        router = self.create_router()
        self.create_router_interface(router['id'], subnet1['id'])
        gw = '2.10.0.1'
        cidr = '2.10.0.0/24'
        cidr1 = IPNetwork(cidr)
        mask = 24
        network2 = self.create_network()
        subnet2 = self.create_subnet(
            network2, gateway=gw, cidr=cidr1, mask_bits=mask)
        router2 = self.create_router()
        self.create_router_interface(router2['id'], subnet2['id'])
        p1 = self.create_port(network1, name='p1', port_security_enabled=False)
        p2 = self.create_port(network2, name='p2', port_security_enabled=False)
        self.create_tenant_server(ports=[p1, p2], name='sfc-vm1')

        time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1, p2)
        self.assertRaises(
            lib_exec.BadRequest,
            self.nsfc_client.create_port_pair_group,
            name='ppg1',
            port_pair=pp1)
        # Details: {u'message': u'Bad request: Nuage only supports grouping of
        # ports belonging to one subnet', u'type': u'NuageBadRequest',
        # u'detail': u''}

    def test_port_pair_vm_shutoff(self):
        network1 = self.create_network()
        subnet1 = self.create_subnet(network1)
        router = self.create_router()
        self.create_router_interface(router['id'], subnet1['id'])
        p1 = self.create_port(network1, name='p1', port_security_enabled=False)
        p2 = self.create_port(network1, name='p2', port_security_enabled=False)

        sfcvm1 = self.create_tenant_server(ports=[p1, p2], name='sfc-vm1')
        time.sleep(5)
        self.stop_tenant_server(sfcvm1.openstack_data['id'])
        pp1 = self.nsfc_client.create_port_pair('pp1', p1['id'], p2['id'])
        ppg1 = self.nsfc_client.create_port_pair_group('ppg1', pp1)
        self._get_l3_port_pair_group_redirect_target_pg(ppg1, router)
        self.nsfc_client.delete_port_pair_group(ppg1['port_pair_group']['id'])
        self.nsfc_client.delete_port_pair(pp1['port_pair']['id'])

    def test_pc_multiple_fcs(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router()
        self.create_router_interface(router['id'], subnet['id'])
        src_port = self.create_port(network, name='src_port')
        dest_port = self.create_port(network, name='dest_port')
        fc1 = self._create_flow_classifier(
            'fc1', src_port['id'], dest_port['id'], '10', 'tcp',
            source_port_range_max='23', source_port_range_min='23',
            destination_port_range_min='100',
            destination_port_range_max='100')

        src_port1 = self.create_port(network, name='src_port1')
        dest_port1 = self.create_port(network, name='dest_port1')
        fc2 = self._create_flow_classifier(
            'fc2', src_port1['id'], dest_port1['id'], '12', 'icmp')

        src_port2 = self.create_port(network, name='src_port2')
        dest_port2 = self.create_port(network, name='dest_port2')
        self._create_flow_classifier(
            'fc3', src_port2['id'], dest_port2['id'], '14')

        p1 = self.create_port(network, name='p1', port_security_enabled=False)
        self.create_tenant_server(ports=[p1], name='sfc-vm1')

        p2 = self.create_port(network, name='p2', port_security_enabled=False)
        self.create_tenant_server(ports=[p2], name='sfc-vm2')
        time.sleep(5)

        pp1 = self._create_port_pair('pp1', p1, p1)
        ppg1 = self._create_port_pair_group('ppg1', pp1)
        pp2 = self._create_port_pair('pp2', p2, p2)
        ppg2 = self._create_port_pair_group('ppg2', pp2)
        pc1 = self. _create_port_chain('pc1', [ppg1, ppg2], [fc1, fc2])
        rt_src, rt_dest, src_pg, dest_pg = self._verify_flow_classifier(
            src_port, dest_port, router)
        rt_src1, rt_dest1, src_pg1, dest_pg1 = self._verify_flow_classifier(
            src_port1, dest_port1, router)
        ppg1_rt_ingress_egress, ppg1_ingress_egress_pg = \
            self._get_l3_port_pair_group_redirect_target_pg(
                ppg1, router, bidirectional_port='true')
        ppg2_rt_ingress_egress, ppg2_ingress_egress_pg = \
            self._get_l3_port_pair_group_redirect_target_pg(
                ppg2, router, bidirectional_port='true')
        rules = self._get_adv_fwd_rules_port_chain(pc1, router)

        rule_src_insfcvm1 = rule_sfcvm1_sfcvm2 = rule_sfcvm2_dest = None
        rule_src1_insfcvm1 = rule_sfcvm2_dest1 = None
        for rule in rules:
            if rule['locationID'] == src_pg[0]['ID']:
                rule_src_insfcvm1 = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    ppg1_rt_ingress_egress[0]['ID'],
                    "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                self.assertEqual(
                    rule['vlanRange'],
                    '10',
                    "sfc to sfc-vm1 vlan range is wrong")
                self.assertEqual(rule['redirectRewriteType'], 'VLAN')
                self.assertEqual(
                    rule['redirectRewriteValue'],
                    str(pc1['port_chain']['chain_parameters'][
                        'correlation_id']))
            if rule['locationID'] == ppg1_ingress_egress_pg[0]['ID']:
                rule_sfcvm1_sfcvm2 = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    ppg2_rt_ingress_egress[0]['ID'],
                    "ssfc-vm1 to sfc-vm2 adv fwd rule redirect vport is wrong")
            if (rule['locationID'] == ppg2_ingress_egress_pg[0]['ID'] and
                    rule['redirectRewriteValue'] == '10'):
                rule_sfcvm2_dest = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    rt_dest[0]['ID'],
                    "sfcvm1 to dest adv fwd rule redirect target is wrong")
            if rule['locationID'] == src_pg1[0]['ID']:
                rule_src1_insfcvm1 = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    ppg1_rt_ingress_egress[0]['ID'],
                    "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                self.assertEqual(
                    rule['vlanRange'],
                    '12',
                    "sfc to sfc-vm1 vlan range is wrong")
                self.assertEqual(rule['redirectRewriteType'], 'VLAN')
                self.assertEqual(
                    rule['redirectRewriteValue'], str(
                        pc1['port_chain']['chain_parameters'][
                            'correlation_id']))
            if (rule['locationID'] == ppg2_ingress_egress_pg[0]['ID'] and
                    rule['redirectRewriteValue'] == '12'):
                rule_sfcvm2_dest1 = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    rt_dest1[0]['ID'],
                    "sfcvm1 to dest1 adv fwd rule redirect target is wrong")

        self.assertIsNotNone(rule_src_insfcvm1)
        self.assertIsNotNone(rule_sfcvm1_sfcvm2)
        self.assertIsNotNone(rule_sfcvm2_dest)
        self.assertIsNotNone(rule_src1_insfcvm1)
        self.assertIsNotNone(rule_sfcvm2_dest1)

    def test_port_chain_create_delete_non_def_netpart(self):
        netpart_body = self.client.create_netpartition(name=None)
        nondef_netpart = netpart_body['net_partition']
        self.addCleanup(self.client.delete_netpartition, nondef_netpart['id'])
        nondef_network = self.create_network()
        nondef_subnet = self.create_subnet(
            nondef_network, net_partition=nondef_netpart['id'])
        src_port = self.create_port(nondef_network, name='src_port')
        dest_port = self.create_port(nondef_network, name='dest_port')
        fc1 = self._create_flow_classifier(
            'fc1', src_port['id'], dest_port['id'], '10', 'tcp',
            source_port_range_max='23', source_port_range_min='23',
            destination_port_range_min='100', destination_port_range_max='100')
        p1 = self.create_port(nondef_network, name='p1',
                              port_security_enabled=False)
        p2 = self.create_port(nondef_network, name='p2',
                              port_security_enabled=False)

        self.create_tenant_server(ports=[p1, p2], name='sfc-vm1')
        time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1, p2)
        ppg1 = self._create_port_pair_group('ppg1', pp1)
        pc1 = self. _create_port_chain('pc1', [ppg1], [fc1])
        # verify
        self.assertNotEqual(
            pc1, '', 'port chain is empty')
        rt_src, rt_dest, src_pg, dest_pg = self._verify_flow_classifier_l2(
            nondef_subnet, src_port, dest_port, nondef_netpart['name'])

        ppg1_rt_ingress, ppg1_rt_egress, ppg1_ingress_pg, ppg1_egress_pg = \
            self._get_l2_port_pair_group_redirect_target_pg(
                ppg1, nondef_subnet, netpart_name=nondef_netpart['name'])
        rules = self._get_adv_fwd_rules_port_chain_l2(
            pc1, nondef_subnet, netpart_name=nondef_netpart['name'])
        rule_src_insfcvm1 = rule_sfcvm1_dest = None
        for rule in rules:
            if rule['locationID'] == src_pg[0]['ID']:
                rule_src_insfcvm1 = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    ppg1_rt_ingress[0]['ID'],
                    "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                self.assertEqual(
                    rule['vlanRange'],
                    '10',
                    "sfc to sfc-vm1 vlan range is wrong")
                self.assertEqual(rule['redirectRewriteType'], 'VLAN')
            if rule['locationID'] == ppg1_egress_pg[0]['ID']:
                rule_sfcvm1_dest = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    rt_dest[0]['ID'],
                    "sfcvm1 to dest adv fwd rule redirect target is wrong")
        self.assertIsNotNone(rule_src_insfcvm1)
        self.assertIsNotNone(rule_sfcvm1_dest)

    def test_multi_pc_with_overlap_ppg(self):
        network = self.create_network()
        subnet = self.create_subnet(network)
        router = self.create_router()
        self.create_router_interface(router['id'], subnet['id'])
        src_port = self.create_port(network, name='src_port')
        dest_port = self.create_port(network, name='dest_port')
        fc1 = self._create_flow_classifier(
            'fc1', src_port['id'], dest_port['id'], '11', 'icmp')
        src_port2 = self.create_port(network, name='src_port2')
        dest_port2 = self.create_port(network, name='dest_port2')
        fc2 = self._create_flow_classifier(
            'fc2', src_port2['id'], dest_port2['id'], '12', 'icmp')

        src_port3 = self.create_port(network, name='src_port3')
        dest_port3 = self.create_port(network, name='dest_port3')
        fc3 = self._create_flow_classifier(
            'fc3', src_port3['id'], dest_port3['id'], '14', 'icmp')
        p1 = self.create_port(network, name='p1', port_security_enabled=False)
        p2 = self.create_port(network, name='p2', port_security_enabled=False)
        p3 = self.create_port(network, name='p3', port_security_enabled=False)
        p4 = self.create_port(network, name='p4', port_security_enabled=False)
        p5 = self.create_port(network, name='p5', port_security_enabled=False)
        p6 = self.create_port(network, name='p6', port_security_enabled=False)

        self.create_tenant_server(ports=[p1, p2], name='sfc-vm1')
        self.create_tenant_server(ports=[p3, p4], name='sfc-vm2')
        self.create_tenant_server(ports=[p5, p6], name='sfc-vm3')

        time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1, p2)
        ppg1 = self._create_port_pair_group('ppg1', pp1)
        pp2 = self._create_port_pair('pp2', p3, p4)
        ppg2 = self._create_port_pair_group('ppg2', pp2)
        pp3 = self._create_port_pair('pp3', p5, p6)
        ppg3 = self._create_port_pair_group('ppg3', pp3)
        pc1 = self. _create_port_chain('pc1', [ppg1, ppg2, ppg3], [fc1])
        pc2 = self. _create_port_chain('pc2', [ppg1, ppg2], [fc2])
        pc3 = self. _create_port_chain('pc3', [ppg1, ppg3], [fc3])
        ppg_list_1 = [ppg1, ppg2, ppg3]
        self._verify_adv_fwd_rules_l3(network, subnet, router,
                                      src_port, dest_port, ppg_list_1,
                                      fc1, pc1, '11')
        ppg_list_2 = [ppg1, ppg2]
        self._verify_adv_fwd_rules_l3(network, subnet, router,
                                      src_port2, dest_port2, ppg_list_2,
                                      fc2, pc2, '12')
        ppg_list_3 = [ppg1, ppg3]
        self._verify_adv_fwd_rules_l3(network, subnet, router,
                                      src_port3, dest_port3,
                                      ppg_list_3, fc2, pc3, '14')

    @testtools.skipUnless(
        CONF.nuage_sut.image_is_advanced,
        "Advanced image is required to run this test.")
    def test_vsd_managed_port_chain(self):
        vsd_l3domain_template = self.vsd.create_l3domain_template()
        self.addCleanup(vsd_l3domain_template.delete)

        vsd_l3domain = self.vsd.create_l3domain(
            template_id=vsd_l3domain_template.id)
        self.addCleanup(vsd_l3domain.delete)

        vsd_zone = self.vsd.create_zone(domain=vsd_l3domain)
        self.addCleanup(vsd_zone.delete)
        cidr = IPNetwork('40.40.40.0/24')
        gateway = '40.40.40.1'
        vsd_l3domain_subnet = self.vsd.create_subnet(
            zone=vsd_zone,
            cidr4=cidr,
            gateway4=gateway)
        self.addCleanup(vsd_l3domain_subnet.delete)

        self.vsd.define_any_to_any_acl(vsd_l3domain)

        # Provision OpenStack network linked to VSD network resources
        network = self.create_network()
        self.create_subnet(
            network,
            cidr=cidr,
            gateway=gateway,
            mask_bits=24,
            nuagenet=vsd_l3domain_subnet.id,
            net_partition=self.vsd.default_netpartition_name)

        src_port = self.create_port(network, name='src_port')
        dest_port = self.create_port(network, name='dest_port')

        fc1 = self._create_flow_classifier(
            'fc1', src_port['id'], dest_port['id'], '10', 'icmp')
        p1 = self.create_port(network, name='p1')
        p2 = self.create_port(network, name='p2')

        self.create_tenant_server(ports=[src_port], name='srcvm')
        # self.prepare_for_nic_provisioning(srcvm, vsd_domain=vsd_l3domain,
        #                                  vsd_subnet=vsd_l3domain_subnet)
        # srcvm_ip = srcvm.get_server_ip_in_network(network['name'])
        # srcvm.configure_vlan_interface(srcvm_ip, interface='eth0', vlan='10')

        self.create_tenant_server(ports=[dest_port], name='destvm')
        # self.prepare_for_nic_provisioning(destvm, vsd_domain=vsd_l3domain,
        #                                   vsd_subnet=vsd_l3domain_subnet)
        # destvm_ip = destvm.get_server_ip_in_network(network['name'])
        # destvm.configure_vlan_interface(destvm_ip, interface='eth0',
        #  vlan='10')
        # destvm.bring_down_interface('eth0')

        self.create_tenant_server(ports=[p1, p2], name='sfc-vm1')
        # time.sleep(5)
        pp1 = self._create_port_pair('pp1', p1, p2)
        ppg1 = self._create_port_pair_group('ppg1', pp1)
        pc1 = self. _create_port_chain('pc1', [ppg1], [fc1])
        # redirect_vlan = pc1['port_chain']['chain_parameters']
        # ['correlation_id']
        # sfcvm1.configure_ip_fwd()
        # sfcvm1.configure_sfc_vm(redirect_vlan)
        # verify
        rt_src, rt_dest, src_pg, dest_pg = \
            self._verify_flow_classifier(src_port, dest_port,
                                         vsd_domain_id=vsd_l3domain.id)
        ppg1_rt_ingress, ppg1_rt_egress, ppg1_ingress_pg, ppg1_egress_pg = \
            self._get_l3_port_pair_group_redirect_target_pg(
                ppg1, vsd_domain_id=vsd_l3domain.id)
        rules = self._get_adv_fwd_rules_port_chain(
            pc1, vsd_domain_id=vsd_l3domain.id)
        vlan = '10'
        rule_src_insfcvm1 = rule_sfcvm1_dest = None
        for rule in rules:
            if rule['locationID'] == src_pg[0]['ID']:
                rule_src_insfcvm1 = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    ppg1_rt_ingress[0]['ID'],
                    "src to sfc-vm1 adv fwd rule redirect vport is wrong")
                vlan_range = '%s' % (vlan)
                self.assertEqual(
                    rule['vlanRange'],
                    vlan_range,
                    "sfc to sfc-vm1 vlan range is wrong")
                self.assertEqual(rule['redirectRewriteType'], 'VLAN')
            if rule['locationID'] == ppg1_egress_pg[0]['ID']:
                rule_sfcvm1_dest = rule
                self.assertEqual(
                    rule['redirectVPortTagID'],
                    rt_dest[0]['ID'],
                    "sfcvm1 to dest adv fwd rule redirect target is wrong")
        self.assertIsNotNone(rule_src_insfcvm1)
        self.assertIsNotNone(rule_sfcvm1_dest)
        # cmd = 'tcpdump -i eth0.1 -n > log &'
        # sfcvm1.console().send(cmd, timeout=5)
        # self.assert_ping(
        #    srcvm, destvm, network, interface='eth0.10', ping_count=20)
        # output = sfcvm1.console().send('cat log | grep "echo request"',
        #                                timeout=5)
        # msg = '%s > %s: ICMP echo request' % (srcvm_ip, destvm_ip)
        # self.assertThat(output[3], Contains(msg))
