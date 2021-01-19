# Copyright 2021 NOKIA
# All Rights Reserved.

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import data_utils as utils
from nuage_tempest_plugin.services.nuage_client import NuageRestClient
from nuage_tempest_plugin.tests.upgrade.test_upgrade_base \
    import NuageUpgradeMixin
from nuage_tempest_plugin.tests.upgrade.test_upgrade_base \
    import NuageUpgradeSubTestMixin

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# CAUTION : THIS SUITE IS HIGHLY INTRUSIVE
#           - it relies heavily on devstack env
#           - it installs new packages in the tox env (like neutron)
#           - it changes the neutron branch out of which neutron runs
#           - it restarts neutron
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

LOG = Topology.get_logger(__name__)


class CorrectHwvtepMixin(NuageUpgradeSubTestMixin):

    physnet = 'physnet1'
    # L3: VSD managed l3domains, not router attached.
    is_l3 = False

    def __init__(self, parent):
        super(CorrectHwvtepMixin, self).__init__(parent)
        self._resources = {'networks': [],
                           'l3_subnets': [],
                           'fips': []}

    def _setup(self):
        self._create_os_resources()
        self._manually_create_bridge_ports()

    def _create_os_resources(self):
        # Trunking requires admin user
        self.parent.manager = self.parent.admin_manager
        cidr_parent = utils.gimme_a_cidr()
        cidr_sub1 = utils.gimme_a_cidr()
        cidr_sub2 = utils.gimme_a_cidr()
        cidr_sub3 = utils.gimme_a_cidr()

        if self.is_l3:
            # Create vsd managed l3 domain and subnets
            vsd_l3dom_tmplt = self.parent.vsd.create_l3domain_template()
            self.parent.addCleanup(vsd_l3dom_tmplt.delete)
            vsd_l3dom = self.parent.vsd.create_domain(
                template_id=vsd_l3dom_tmplt.id)
            self.parent.addCleanup(vsd_l3dom.delete)
            vsd_zone = self.parent.vsd.create_zone(domain=vsd_l3dom)
            self.parent_resource = self.parent.vsd.create_subnet(
                zone=vsd_zone,
                ip_type='IPV4',
                enable_dhcpv4=False,
                cidr4=cidr_parent)
            self.parent.addCleanup(self.parent_resource.delete)
            self.sub_resource1 = self.parent.vsd.create_subnet(
                zone=vsd_zone,
                ip_type='IPV4',
                enable_dhcpv4=False,
                cidr4=cidr_sub1)
            self.parent.addCleanup(self.sub_resource1.delete)
            self.sub_resource2 = self.parent.vsd.create_subnet(
                zone=vsd_zone,
                ip_type='IPV4',
                enable_dhcpv4=False,
                cidr4=cidr_sub2)
            self.parent.addCleanup(self.sub_resource2.delete)
            self.sub_resource3 = self.parent.vsd.create_subnet(
                zone=vsd_zone,
                ip_type='IPV4',
                enable_dhcpv4=False,
                cidr4=cidr_sub3)
            self.parent.addCleanup(self.sub_resource3.delete)

        # Parent network
        kwargs = {'provider:network_type': 'flat',
                  'provider:physical_network': self.physnet}
        self.parent_network = self.parent.create_network(**kwargs)
        subnet_kwargs = {}
        if self.is_l3:
            subnet_kwargs['nuagenet'] = self.parent_resource.id
            subnet_kwargs['net_partition'] = (
                self.parent.default_netpartition_name)

        self.parent_subnet = self.parent.create_subnet(
            self.parent_network, cidr=cidr_parent,
            mask_bits=cidr_parent.prefixlen, enable_dhcp=False,
            **subnet_kwargs)

        # first subport network
        kwargs = {'provider:network_type': 'vlan',
                  'provider:physical_network': self.physnet}
        self.sub_network1 = self.parent.create_network(**kwargs)
        subnet_kwargs = {}
        if self.is_l3:
            subnet_kwargs['nuagenet'] = self.sub_resource1.id
            subnet_kwargs['net_partition'] = (
                self.parent.default_netpartition_name)
        self.sub_subnet1 = self.parent.create_subnet(
            self.sub_network1, cidr=cidr_sub1, mask_bits=cidr_sub1.prefixlen,
            enable_dhcp=False, **subnet_kwargs)

        # second subport network
        self.sub_network2 = self.parent.create_network(**kwargs)
        subnet_kwargs = {}
        if self.is_l3:
            subnet_kwargs['nuagenet'] = self.sub_resource2.id
            subnet_kwargs['net_partition'] = (
                self.parent.default_netpartition_name)
        self.sub_subnet2 = self.parent.create_subnet(
            self.sub_network2, cidr=cidr_sub2, mask_bits=cidr_sub2.prefixlen,
            enable_dhcp=False, **subnet_kwargs)

        # Third subport network
        self.sub_network3 = self.parent.create_network(**kwargs)
        subnet_kwargs = {}
        if self.is_l3:
            subnet_kwargs['nuagenet'] = self.sub_resource3.id
            subnet_kwargs['net_partition'] = (
                self.parent.default_netpartition_name)
        self.sub_subnet3 = self.parent.create_subnet(
            self.sub_network3, cidr=cidr_sub3, mask_bits=cidr_sub3.prefixlen,
            enable_dhcp=False, **subnet_kwargs)

        # Get domains
        if not self.is_l3:
            self.parent_resource = self.parent.vsd.get_l2domain(
                by_subnet=self.parent_subnet)
            self.sub_resource1 = self.parent.vsd.get_l2domain(
                by_subnet=self.sub_subnet1)
            self.sub_resource2 = self.parent.vsd.get_l2domain(
                by_subnet=self.sub_subnet2)
            self.sub_resource3 = self.parent.vsd.get_l2domain(
                by_subnet=self.sub_subnet3)
        # Create trunk with two subports
        self.parent_port = self.parent.create_port(self.parent_network)
        self.sub_port1 = self.parent.create_port(self.sub_network1)
        self.sub_port2 = self.parent.create_port(self.sub_network2)
        self.sub_port3 = self.parent.create_port(self.sub_network3)
        subport_dicts = [
            {
                'port_id': self.sub_port1['id'],
                'segmentation_type': 'vlan',
                'segmentation_id': 100
            },
            {
                'port_id': self.sub_port2['id'],
                'segmentation_type': 'vlan',
                'segmentation_id': 101
            },
            {
                'port_id': self.sub_port3['id'],
                'segmentation_type': 'vlan',
                'segmentation_id': 102
            },
        ]
        self.trunk = self.parent.create_trunk(
            port=self.parent_port, subports=subport_dicts,
            client=self.parent.plugin_network_client_admin)
        # Create a VM on sub_network3: No need to manually correct then for
        # sub_network3
        self.vm = self.parent.create_tenant_server(
            networks=[self.sub_network3], prepare_for_connectivity=False)
        # Create a VM on the parentport
        self.vm = self.parent.create_tenant_server(
            ports=[self.parent_port], prepare_for_connectivity=False)

    def _manually_create_bridge_ports(self):
        # Depending on the deployment, the parent port has 1 to multiple
        # bindings
        nuage_client = self.parent.plugin_network_client_admin
        self.parent_port_bindings = nuage_client.list_switchport_bindings(
            neutron_port_id=self.parent_port['id'])['switchport_bindings']

        # 1: Create vlan object
        # 2: Create bridgeport with vlan object in appropriate domain
        vlan1 = self.sub_network1['provider:segmentation_id']
        vlan2 = self.sub_network2['provider:segmentation_id']

        # Store VSD resources per parent binding for later verification
        self.parent_binding_resources = {}
        self.vports3 = self.sub_resource3.vports.get()

        for parent_binding in self.parent_port_bindings:
            # there are multiple physical ports on VSD that need processing
            # The mapping ID is not returned in the binding, so we use the
            # switch_id to retrieve the binding, as in the test environment
            # there is only one port per switch.
            parent_mapping = nuage_client.list_switchport_mappings(
                switch_id=parent_binding['switch_id']
            )['switchport_mappings'][0]
            if parent_mapping['redundant_port_uuid']:
                gw_port = self.parent.vsd.vspk.NUVsgRedundantPort(
                    id=parent_mapping['redundant_port_uuid'])
            else:
                gw_port = self.parent.vsd.vspk.NUPort(
                    id=parent_mapping['port_uuid'])

            gw_port.fetch()
            # Create vlan + USE permission
            vsd_vlan1 = self.parent.vsd.vspk.NUVLAN(value=vlan1)
            gw_port.create_child(vsd_vlan1)
            self.parent.addCleanup(vsd_vlan1.delete)
            permission1 = self.parent.vsd.vspk.NUEnterprisePermission(
                permitted_action='USE',
                permitted_entity_id=self.parent.vsd.get_default_enterprise().id
            )
            vsd_vlan1.create_child(permission1)
            vsd_vlan2 = self.parent.vsd.vspk.NUVLAN(value=vlan2)
            gw_port.create_child(vsd_vlan2)
            self.parent.addCleanup(vsd_vlan2.delete)
            permission2 = self.parent.vsd.vspk.NUEnterprisePermission(
                permitted_action='USE',
                permitted_entity_id=self.parent.vsd.get_default_enterprise().id
            )
            vsd_vlan2.create_child(permission2)

            # Create vport
            vport1 = self.parent.vsd.vspk.NUVPort(
                type='BRIDGE', name='Bridge Vport ' + vsd_vlan1.id,
                vlanid=vsd_vlan1.id, address_spoofing='ENABLED')
            self.sub_resource1.create_child(vport1)
            self.parent.addCleanup(vport1.delete)
            vport2 = self.parent.vsd.vspk.NUVPort(
                type='BRIDGE', name='Bridge Vport ' + vsd_vlan2.id,
                vlanid=vsd_vlan2.id, address_spoofing='ENABLED')
            self.sub_resource2.create_child(vport2)
            self.parent.addCleanup(vport2.delete)

            # Create Bridge interface
            attached_net_type = 'SUBNET' if self.is_l3 else 'L2DOMAIN'
            bridge_interface1 = self.parent.vsd.vspk.NUBridgeInterface(
                vport_id=vport1.id,
                name="BRIDGE INTERFACE(" + vport1.id + ")",
                attached_network_type=attached_net_type)
            vport1.create_child(bridge_interface1)
            self.parent.addCleanup(bridge_interface1.delete)
            bridge_interface2 = self.parent.vsd.vspk.NUBridgeInterface(
                vport_id=vport2.id,
                name="BRIDGE INTERFACE(" + vport2.id + ")",
                attached_network_type=attached_net_type)
            vport2.create_child(bridge_interface2)
            self.parent.addCleanup(bridge_interface2.delete)

            # Get resources for subnet3
            vport3 = [vport for vport in self.vports3 if
                      vport.gateway_port_name == parent_mapping['port_id']][0]
            bridge_interface3 = vport3.bridge_interfaces.get()[0]
            vsd_vlan3 = self.parent.vsd.vspk.NUVLAN(id=vport3.vlanid)
            # Populate class variables
            self.parent_binding_resources[parent_binding['id']] = {
                'vport1': vport1,
                'vport2': vport2,
                'vport3': vport3,
                'bridge_interface1': bridge_interface1,
                'bridge_interface2': bridge_interface2,
                'bridge_interface3': bridge_interface3,
                'vsd_vlan1': vsd_vlan1,
                'vsd_vlan2': vsd_vlan2,
                'vsd_vlan3': vsd_vlan3
            }

    def _verify_os_managed_resources(self):
        # Iterate over bindings:
        for parent_binding in self.parent_port_bindings:
            binding_resources = self.parent_binding_resources[
                parent_binding['id']]
            # refetch all resources
            for key in binding_resources:
                binding_resources[key].fetch()
            # Verify vport external id
            self.parent.assertEqual(
                self.parent.vsd.external_id(self.sub_network1['id']),
                binding_resources['vport1'].external_id)
            self.parent.assertEqual(
                self.parent.vsd.external_id(self.sub_network2['id']),
                binding_resources['vport2'].external_id)
            self.parent.assertEqual(
                self.parent.vsd.external_id(self.sub_network3['id']),
                binding_resources['vport3'].external_id)

            # Verify bridge interface external id
            self.parent.assertEqual(
                self.parent.vsd.external_id(self.sub_network1['id']),
                binding_resources['bridge_interface1'].external_id)
            self.parent.assertEqual(
                self.parent.vsd.external_id(self.sub_network2['id']),
                binding_resources['bridge_interface2'].external_id)
            self.parent.assertEqual(
                self.parent.vsd.external_id(self.sub_network3['id']),
                binding_resources['bridge_interface3'].external_id)

            # Verify vsd vlan external id
            for vsd_vlan in [binding_resources['vsd_vlan1'],
                             binding_resources['vsd_vlan2'],
                             binding_resources['vsd_vlan3']]:
                expected_vlan_ext_id = self.parent.vsd.external_id(
                    vsd_vlan.parent_id + '.' + str(vsd_vlan.value))
                self.parent.assertEqual(expected_vlan_ext_id,
                                        vsd_vlan.external_id)
            # Verify switchport binding

            self._verify_switchport_binding(
                parent_binding, self.sub_port1,
                binding_resources['vport1'], self.sub_network1)
            self._verify_switchport_binding(
                parent_binding, self.sub_port2,
                binding_resources['vport2'], self.sub_network2)
            self._verify_switchport_binding(
                parent_binding, self.sub_port3,
                binding_resources['vport3'], self.sub_network3)

    def _verify_switchport_binding(self, parent_binding, sub_port,
                                   vport, network):
        nuage_client = self.parent.plugin_network_client_admin
        subport_binding = nuage_client.list_switchport_bindings(
            neutron_port_id=sub_port['id'],
            switch_id=parent_binding['switch_id'])['switchport_bindings']
        self.parent.assertEqual(1, len(subport_binding))
        subport_binding = subport_binding[0]
        self.parent.assertEqual(vport.id,
                                subport_binding['nuage_vport_id'])
        self.parent.assertEqual(parent_binding['port_uuid'],
                                subport_binding['port_uuid'])
        self.parent.assertEqual(parent_binding['port_id'],
                                subport_binding['port_id'])
        self.parent.assertEqual(
            network['provider:segmentation_id'],
            subport_binding['segmentation_id'])


class CorrectHwvtepTrunkingTest(NuageBaseTest, NuageUpgradeMixin):

    _from_release = '6.0'
    _to_release = '6.0'

    @classmethod
    def skip_checks(cls):
        super(CorrectHwvtepTrunkingTest, cls).skip_checks()
        cls._upgrade_skip_check()

    @classmethod
    def setup_clients(cls):
        super(CorrectHwvtepTrunkingTest, cls).setup_clients()
        cls.vsd_client = NuageRestClient()

    @classmethod
    def setUpClass(cls):
        super(CorrectHwvtepTrunkingTest, cls).setUpClass()
        cls._set_up()

    @classmethod
    def _get_from_branch(cls):
        return 'release-6.0.10-' + cls._openstack_version

    @classmethod
    def _get_to_branch(cls):
        return '6.0/' + cls._openstack_version

    @classmethod
    def _get_from_api_version(cls):
        return 'v6'

    @classmethod
    def _get_to_api_version(cls):
        return 'v6'

    @classmethod
    def _get_upgrade_script_name(cls):
        # mind, the name of the script WITHOUT .py
        return 'nuage_correct_hwvtep_manual_trunking'

    def _execute_the_upgrade_script(self, expected_exit_code=0, dryrun=False):
        ml2_conf = '/etc/neutron/plugins/ml2/ml2_conf.ini'

        LOG.info('[{}] _execute_the_upgrade_script:start{}'.format(
            self.cls_name, ' (dry-run)' if dryrun else ''))

        cmd = ('python {} --neutron-conf {} --nuage-conf {} '
               '--neutron-ml2-conf {}').format(
            self._get_upgrade_script_path(),
            self._neutron_conf, self._plugin_conf, ml2_conf)
        if dryrun:
            cmd += ' --dry-run'
        errcode = self.execute_from_shell(cmd, success_expected=False,
                                          return_output=False)
        self.assertEqual(expected_exit_code, errcode)
        log_data = self._fetch_upgrade_log_data()
        self.assertNotIn('ERROR ', log_data)
        LOG.info('[{}] _execute_the_upgrade_script:end'.format(
            self.cls_name))

    def test_upgrade(self):
        #   ----------------------------------------------------   #
        #
        #   T H I S   I S   T H E   T E S T
        #
        #   Mind : there can be only one upgrade test!
        #   ----------------------------------------------------   #

        self._test_upgrade(alembic_expected=False)

    class CorrectHWVtepTest(CorrectHwvtepMixin):
        physnet = 'physnet1'

        def setup(self):
            self._setup()

        def verify(self):
            self._verify_os_managed_resources()
            self.parent._execute_the_upgrade_script()
            self._verify_os_managed_resources()

    class CorrectHWVtepActiveActiveTest(CorrectHwvtepMixin):
        physnet = 'physnet2'
        is_l3 = True

        def setup(self):
            self._setup()

        def verify(self):
            self._verify_os_managed_resources()
            self.parent._execute_the_upgrade_script()
            self._verify_os_managed_resources()

    class CorrectHWVtepActiveStandbyTest(CorrectHwvtepMixin):
        physnet = 'physnet3'

        def setup(self):
            self._setup()

        def verify(self):
            self._verify_os_managed_resources()
            self.parent._execute_the_upgrade_script()
            self._verify_os_managed_resources()
