import netaddr
from oslo_log import log as logging

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest import test
from testtools.matchers import Contains
from testtools.matchers import Not

from nuage_tempest.lib.openstackData import openstackData
from nuage_tempest.lib.test import nuage_test

from nuage_tempest.services.vpnaas.vpnaas_mixins import VPNMixin
from nuage_tempest.tests import nuage_ext

LOG = logging.getLogger(__name__)
CONF = config.CONF


class VPNaaSBase(VPNMixin):

    @classmethod
    def skip_checks(cls):
        raise cls.skipException('VPNaaS is no longer supported with Nuage.')

    @classmethod
    @test.requires_ext(extension="vpnaas", service="network")
    def resource_setup(self):
        super(VPNaaSBase, self).resource_setup()
        self.def_net_partition = CONF.nuage.nuage_default_netpartition
        self.os_data_struct = openstackData()
        self.os_data_struct.insert_resource(self.def_net_partition,
                                            parent='CMS')

    @classmethod
    def resource_cleanup(cls):
        cls.os_data_struct.delete_resource(cls.def_net_partition)
        super(VPNaaSBase, cls).resource_cleanup()


class VPNaaSTest(VPNaaSBase):

    def _find_dummy_router(self, router_id):
        """_find_dummy_router

        Given the router ID for vpnservice find dummy router created by plugin.
        """

        routers = self.routers_client.list_routers()
        routers = routers['routers']
        dummy_router_name = 'r_d_' + router_id
        dummy_router = (
            (router for router in routers
             if router['name'] == dummy_router_name).next()
        )
        return dummy_router

    def _find_dummy_subnet(self, subnet_id):
        """_find_dummy_subnet

        Given the subnet ID for vpnservice find dummy subnet created by plugin.
        """

        subnets = self.subnets_client.list_subnets()
        subnets = subnets['subnets']
        dummy_subnet_name = 's_d_' + subnet_id
        dummy_subnet = (
            (subnet for subnet in subnets
             if subnet['name'] == dummy_subnet_name).next()
        )
        return dummy_subnet

    def test_ikepolicy_create_delete(self):
        """Create delete ikepolicy """

        ikepolicies = self.ikepolicy_client.list_ikepolicy()
        pre_ids = [ikepolicy['id'] for ikepolicy in ikepolicies]
        with self.ikepolicy('ikepolicy') as created_ikepolicy:
            ikepolicies = self.ikepolicy_client.list_ikepolicy()
            post_ids = [ikepolicy['id'] for ikepolicy in ikepolicies]
            self.assertThat(pre_ids, Not(Contains(created_ikepolicy['id'])))
            self.assertThat(post_ids, Contains(created_ikepolicy['id']))

    def test_ipsecpolicy_create_delete(self):
        """Create delete ipsecpolicy """

        ipsecpolicies = self.ipsecpolicy_client.list_ipsecpolicy()
        pre_ids = [ipsecpolicy['id'] for ipsecpolicy in ipsecpolicies]
        with self.ipsecpolicy('ipsecpolicy') as created_ipsecpolicy:
            ipsecpolicies = self.ipsecpolicy_client.list_ipsecpolicy()
            post_ids = [ipsecpolicy['id'] for ipsecpolicy in ipsecpolicies]
            self.assertThat(pre_ids, Not(Contains(created_ipsecpolicy['id'])))
            self.assertThat(post_ids, Contains(created_ipsecpolicy['id']))

    def test_vpnservice_create_delete(self):
        """test_vpnservice_create_delete

        Create delete vpnservice with environment.
        Also verifies the dummy router and subnet created by plugin.
        """

        vpnservices = self.vpnservice_client.list_vpnservice()
        pre_ids = [vpnservice['id'] for vpnservice in vpnservices]
        routers = self.routers_client.list_routers()
        subnets = self.subnets_client.list_subnets()
        router_id = routers['routers'][0]['id']
        self.os_data_struct.insert_resource(
            'router1', os_data=routers['routers'][0],
            parent=self.def_net_partition
        )
        subnet_id = subnets['subnets'][0]['id']
        self.os_data_struct.insert_resource(
            'subnet1', os_data=subnets['subnets'][0],
            parent='router1'
        )
        kwargs = {'name': 'vpnservice'}

        # Creating the vpn service
        with self.vpnservice(router_id, subnet_id,
                             **kwargs) as created_vpnservice:
            vpnservices = self.vpnservice_client.list_vpnservice()
            self.os_data_struct.insert_resource(
                'vpnservice', os_data=created_vpnservice,
                parent='router1'
            )
            # Finding the dummy router and subnet
            # created by plugin and adding to the os_data_struct
            dummy_router = self._find_dummy_router(router_id)
            dummy_subnet = self._find_dummy_subnet(subnet_id)
            self.os_data_struct.insert_resource(
                'dummyrouter', os_data=dummy_router,
                parent='vpnservice'
            )
            self.os_data_struct.insert_resource(
                'dummysubnet', os_data=dummy_subnet,
                parent='dummyrouter'
            )
            post_ids = [vpnservice['id'] for vpnservice in vpnservices]
            self.assertThat(pre_ids, Not(Contains(created_vpnservice['id'])))
            self.assertThat(post_ids, Contains(created_vpnservice['id']))

            # VSD verification
            tag_name = 'verify_vpn_dummy_router'
            nuage_ext.nuage_extension.nuage_components(
                nuage_ext._generate_tag(tag_name, self.__class__.__name__),
                self)

        # Deleting all resources from the os_data_struct
        self.os_data_struct.delete_resource('vpnservice')
        self.os_data_struct.delete_resource('subnet1')
        self.os_data_struct.delete_resource('router1')

    def test_ipsecsiteconnection_create_delete(self):
        """test_ipsecsiteconnection_create_delete

        Create delete of ipsecsiteconnection using ikepolicy, ipsecpolicy and
        vpnservice. Also verifies the dummy router and subnet and the
        vm interface created by plugin.
        """

        ipsecsiteconnections = (
            self.ipsecsiteconnection_client.list_ipsecsiteconnection()
        )
        pre_ids = (
            [ipsecsiteconnection['id']
             for ipsecsiteconnection in ipsecsiteconnections]
        )
        routers = self.routers_client.list_routers()
        subnets = self.subnets_client.list_subnets()
        router_id = routers['routers'][0]['id']
        self.os_data_struct.insert_resource(
            'router1', os_data=routers['routers'][0],
            parent=self.def_net_partition
        )
        subnet_id = subnets['subnets'][0]['id']
        self.os_data_struct.insert_resource(
            'subnet1', os_data=subnets['subnets'][0],
            parent='router1'
        )
        kwargs = {'name': 'vpn'}
        with self.vpnservice(router_id, subnet_id, **kwargs) \
                as created_vpnservice, \
                self.ikepolicy('ikepolicy') as created_ikepolicy, \
                self.ipsecpolicy('ipsecpolicy') as created_ipsecpolicy:
            vpnservices = self.vpnservice_client.list_vpnservice()
            self.os_data_struct.insert_resource(
                'vpnservice', os_data=created_vpnservice,
                parent='router1'
            )

            # Finding the dummy router and subnet
            # created by plugin and adding to the os_data_struct
            dummy_router = self._find_dummy_router(router_id)
            dummy_subnet = self._find_dummy_subnet(subnet_id)
            self.os_data_struct.insert_resource(
                'dummyrouter', os_data=dummy_router,
                parent='vpnservice'
            )
            self.os_data_struct.insert_resource(
                'dummysubnet', os_data=dummy_subnet,
                parent='dummyrouter'
            )
            post_ids = [vpnservice['id'] for vpnservice in vpnservices]
            self.assertThat(pre_ids, Not(Contains(created_vpnservice['id'])))
            self.assertThat(post_ids, Contains(created_vpnservice['id']))

            # VSD verification
            tag_name = 'verify_vpn_dummy_router'
            nuage_ext.nuage_extension.nuage_components(
                nuage_ext._generate_tag(tag_name, self.__class__.__name__),
                self)

            ipnkwargs = {'name': 'ipsecconn'}
            with self.ipsecsiteconnection(
                    created_vpnservice['id'], created_ikepolicy['id'],
                    created_ipsecpolicy['id'], '172.20.0.2',
                    '172.20.0.2', '2.0.0.0/24', 'secret',
                    **ipnkwargs) as created_ipsecsiteconnection:
                ipsecsiteconnections = (
                    self.ipsecsiteconnection_client.list_ipsecsiteconnection()
                )
                self.os_data_struct.insert_resource(
                    'ipsecsiteconnection', os_data=created_ipsecsiteconnection,
                    parent='vpnservice'
                )
                post_ids = (
                    [ipsecsiteconnection['id']
                     for ipsecsiteconnection in ipsecsiteconnections]
                )
                self.assertThat(pre_ids, Not(
                    Contains(created_ipsecsiteconnection['id'])))
                self.assertThat(post_ids, Contains(
                    created_ipsecsiteconnection['id']))

                # VSD Verification
                tag_name = 'verify_ipsec_vminterface'
                nuage_ext.nuage_extension.nuage_components(
                    nuage_ext._generate_tag(tag_name, self.__class__.__name__),
                    self)

            self.os_data_struct.delete_resource('ipsecsiteconnection')
        self.os_data_struct.delete_resource('vpnservice')
        self.os_data_struct.delete_resource('subnet1')
        self.os_data_struct.delete_resource('router1')


class VPNaaSCliTests(VPNaaSBase):

    @staticmethod
    def _verify_resource_list(resource, resource_dict, present):
        """Verify the resources created from list of resources """
        resource_list = [resources['id'] for resources in resource_dict]
        if present:
            if resource in resource_list:
                LOG.debug('Found %s', resource)
                return True
            else:
                LOG.debug('ERROR: Not Found %s', resource)
                return False
        else:
            if resource in resource_list:
                LOG.debug('ERROR: Found %s', resource)
                return False
            else:
                LOG.debug('Not Found %s', resource)
                return True

    def _create_verify_ikepolicy(self, name):
        """Creates and verifies ikepolicy in neutron DB """
        name = data_utils.rand_name(name)
        # Creating a IKE Policy
        ikepolicy = self.vpnservice_client.create_ikepolicy(name)
        # Showing the created IKE Policy
        ikepolicy_info = self.vpnservice_client.show_ikepolicy(name)
        self.os_data_struct.insert_resource(ikepolicy['ikepolicy']['name'],
                                            user_data={'name': name},
                                            os_data=ikepolicy,
                                            parent='CMS')
        self.assertEqual(ikepolicy_info['name'], name)
        return ikepolicy['ikepolicy']

    def _delete_verify_ikepolicy(self, id, name):
        """Deletes and verifies ikepolicy in neutron DB """
        # Deleting the IKE Policy
        self.vpnservice_client.delete_ikepolicy(id)
        # Verifying delete in list IKE Policy
        ikepolicies = self.vpnservice_client.list_ikepolicy()
        result = self._verify_resource_list(id, ikepolicies, False)
        self.os_data_struct.delete_resource(name)
        self.assertEqual(result, True)

    def _create_verify_ipsecpolicy(self, name):
        """Creates and verifies ipsecpolicy in neutron DB """
        name = data_utils.rand_name(name)
        # Creating a IPSecPolicy
        ipsecpolicy = self.vpnservice_client.create_ipsecpolicy(name)
        # Showing the created IPSecPolicy
        ipsecpolicy_info = self.vpnservice_client.show_ipsecpolicy(name)
        self.os_data_struct.insert_resource(ipsecpolicy['ipsecpolicy']['name'],
                                            user_data={'name': name},
                                            os_data=ipsecpolicy,
                                            parent='CMS')
        self.assertEqual(ipsecpolicy_info['name'], name)
        return ipsecpolicy['ipsecpolicy']

    def _delete_verify_ipsecpolicy(self, id, name):
        """Deletes and verifies ipsecpolicy in neutron DB """
        # Deleting the IPSecPolicy
        self.vpnservice_client.delete_ipsecpolicy(id)
        # Verifying delete in list IPSecPolicy
        ipsecpolicies = self.vpnservice_client.list_ipsecpolicy()
        result = self._verify_resource_list(id, ipsecpolicies, False)
        self.os_data_struct.delete_resource(name)
        self.assertEqual(result, True)

    def _create_verify_vpn_environment(self, name, cidr, public):
        """Creates router and subnet for vpn service """
        # Creating Network
        netname = name + '-network-'
        netname = data_utils.rand_name(netname)
        network = self.create_network(network_name=netname)
        # Creating Subnet
        mask_bit = int(cidr.split("/")[1])
        gateway_ip = cidr.split("/")[0][:cidr.rfind(".")] + ".1"
        cidr = netaddr.IPNetwork(cidr)
        subkwargs = {'name': netname}
        subnet = (
            self.subnets_client.create_subnet(
                network, gateway=gateway_ip,
                cidr=cidr, mask_bits=mask_bit, **subkwargs
            )
        )
        # Creating router
        routername = name + '-router-'
        routername = data_utils.rand_name(routername)
        router = self.routers_client.create_router(router_name=routername)
        # Adding created resources to os_data_struct
        self.routers_client.add_router_interface(
            router['id'], subnet['id']
        )
        self.routers_client.set_router_gateway_with_args(
            router['id'], public['network']['id']
        )
        self.os_data_struct.insert_resource(router['name'],
                                            user_data={'name': routername},
                                            os_data=router,
                                            parent='CMS')
        self.os_data_struct.insert_resource(subnet['name'],
                                            user_data={'name': netname,
                                                       'cidr': cidr,
                                                       'gateway': gateway_ip},
                                            os_data=subnet,
                                            parent=router['name'])
        publicsub = (
            self.subnets_client.show_subnet(
                public['network']['subnets'])
        )
        if not self.os_data_struct.is_resource_present(
                public['network']['name']):
            self.os_data_struct.insert_resource(public['network']['name'],
                                                os_data=publicsub['subnet'],
                                                parent='CMS')
        return subnet, router

    def _delete_verify_vpn_environment(self, router, subnet):
        """Deleting and verifying the router and subnet"""
        # Deleting from neutron DB
        self.routers_client.delete_router(
            router['id'])
        self.networks_client.delete_network(
            subnet['network_id'])
        # Deleting from os_data_struct
        self.os_data_struct.delete_resource(subnet['name'])
        self.os_data_struct.delete_resource(router['name'])

    def _create_verify_vpnservice(self, name, router, subnet):
        """Creating and verifying the vpnservice"""
        name = name + '-vpnservice-'
        name = data_utils.rand_name(name)
        # Creating a VPNService
        vpnservice = (
            self.vpnaas_client.create_vpnservice(
                router['id'], subnet['id'], name
            )
        )
        # Adding to os_data_struct
        self.os_data_struct.insert_resource(
            name, user_data={'name': name,
                             'router': router['id'],
                             'subnet': subnet['id']},
            os_data=vpnservice, parent=router['name'])

        # Showing the created VPNService
        vpnservice_info = self.vpnservice_client.show_vpnservice(
            vpnservice['vpnservice']['id'])
        self.assertEqual(vpnservice_info['name'], name)

        # Verifying that the dummy router and subnet is created
        dummy_router, dummy_subnet = (
            self._verify_vpnaas_dummy_router(
                router, subnet, vpnservice['vpnservice'])
        )
        return vpnservice['vpnservice'], dummy_router, dummy_subnet

    def _verify_vpnaas_dummy_router(self, router, subnet, vpnservice):
        """Verifies the dummy router created by vpnservice """
        # Creating Dummy Router and subnet name
        dummy_router_name = 'r_d_' + router['id']
        dummy_subnet_name = 's_d_' + subnet['id']
        # Searching for dummy router in neutron
        dummy_router_info = (
            self.routers_client.show_router(dummy_router_name)
        )
        dummy_router_info = dummy_router_info['router']
        self.assertEqual(dummy_router_info['name'], dummy_router_name)
        self.os_data_struct.insert_resource(
            dummy_router_name, os_data=dummy_router_info,
            parent=vpnservice['name']
        )
        # Searching for dummy subnet in neutron
        dummy_subnet_info = (
            self.subnets_client.show_subnet(dummy_subnet_name)
        )
        dummy_subnet_info = dummy_subnet_info['subnet']
        self.assertEqual(dummy_subnet_info['name'], dummy_subnet_name)
        self.os_data_struct.insert_resource(
            dummy_subnet_name, os_data=dummy_subnet_info,
            parent=dummy_router_name
        )
        return dummy_router_info, dummy_subnet_info

    def _delete_verify_vpnservice(self, id, name):
        """Deletes and verifies the vpnservice """
        # Deleting the VPNService
        self.vpnservice_client.delete_vpnservice(id)
        # Verifying delete in list VPNService
        vpnservices = self.vpnservice_client.list_vpnservice()
        result = self._verify_resource_list(id, vpnservices, False)
        # Deleting from os_data_struct
        self.os_data_struct.delete_resource(name)
        self.assertEqual(result, True)

    def _create_verify_ipsecsiteconnection(self, vpnservice_id, ikepolicy_id,
                                           ipsecpolicy_id, peer_address,
                                           peer_id, peer_cidrs, psk,
                                           name, parent):
        """Creates and verifies the ipsecsiteconnection """
        name = name + '-ipsecsiteconnection-'
        name = data_utils.rand_name(name)
        # Creating a IPSecSiteConnection
        ipsecsiteconnection = (
            self.vpnservice_client.create_ipsecsiteconnection(
                vpnservice_id, ikepolicy_id, ipsecpolicy_id,
                peer_address, peer_id, peer_cidrs, psk, name
            )
        )
        # Adding to os_data_struct
        self.os_data_struct.insert_resource(
            name, user_data={'name': name,
                             'vpnservice_id': vpnservice_id,
                             'ikepolicy_id': ikepolicy_id,
                             'ipsecpolicy_id': ipsecpolicy_id,
                             'peer_address': peer_address,
                             'peer_id': peer_id,
                             'peer_cidrs': peer_cidrs,
                             'psk': psk},
            os_data=ipsecsiteconnection, parent=parent)

        # Showing the created IPSecSiteConnection
        ipsecsiteconnection_info = (
            self.vpnservice_client.show_ipsecsiteconnection(
                ipsecsiteconnection['ipsecsiteconnection']['id']
            )
        )
        self.assertEqual(ipsecsiteconnection_info['name'], name)
        return ipsecsiteconnection['ipsecsiteconnection']

    def _delete_verify_ipsecsiteconnection(self, id, name):
        """Deletes and verifies the ipsecsiteconnection """
        # Deleting the VPNService
        self.vpnservice_client.delete_ipsecsiteconnection(id)
        # Verifying delete in list VPNService
        ipsecsiteconnections = (
            self.vpnservice_client.list_ipsecsiteconnection()
        )
        result = self._verify_resource_list(id, ipsecsiteconnections, False)
        # Deleting resource from the os_data_struct
        self.os_data_struct.delete_resource(name)
        self.assertEqual(result, True)

    @nuage_test.header()
    def test_create_delete_ikepolicy(self):
        """TestCase to create/show/list/delete ikepolicy """
        # Create Verify
        ikepolicy = self._create_verify_ikepolicy('ikepolicy')
        ikepolicy_id = ikepolicy['id']
        ikepolicy_name = ikepolicy['name']
        # Delete Verify
        self._delete_verify_ikepolicy(
            ikepolicy_id, ikepolicy_name
        )

    def test_create_delete_ipsecpolicy(self):
        """TestCase to create/show/list/delete ipsecpolicy """
        # Create Verify
        ipsecpolicy = self._create_verify_ipsecpolicy('ipsecpolicy')
        ipsecpolicy_id = ipsecpolicy['id']
        ipsecpolicy_name = ipsecpolicy['name']
        # Delete Verify
        self._delete_verify_ipsecpolicy(
            ipsecpolicy_id, ipsecpolicy_name
        )

    def test_create_delete_vpnservice(self):
        """TestCase to create/show/list/delete vpnservice """
        name = 'vpn'
        pubnetid = CONF.network.public_network_id
        pubnet = self.networks_client.show_network(pubnetid)
        self.os_data_struct.insert_resource(
            'testtags', parent='CMS'
        )
        self.os_data_struct.insert_resource(
            'publicnettag', user_data={'name': pubnet['network']['name']},
            parent='testtags'
        )
        # Creating Site for VPN Service
        subnet, router = (
            self._create_verify_vpn_environment(
                name, '10.20.0.0/24', pubnet
            )
        )
        # Storing router/subnet tagname to os_data_struct
        self.os_data_struct.insert_resource(
            'routertag', user_data={'name': router['name']},
            parent='testtags'
        )
        self.os_data_struct.insert_resource(
            'subnettag', user_data={'name': subnet['name']},
            parent='testtags'
        )
        # Create Verify VPNService
        vpnservice, dummy_router, dummy_subnet = (
            self._create_verify_vpnservice(
                name, router, subnet
            )
        )
        # Storing vpnservice tagname to os_data_struct
        self.os_data_struct.insert_resource(
            'vpnservicetag', user_data={'name': vpnservice['name']},
            parent='testtags'
        )
        # Storing dummy router/subnet tagname to os_data_struct
        self.os_data_struct.insert_resource(
            'dummyroutertag', user_data={'name': dummy_router['name']},
            parent='testtags'
        )
        self.os_data_struct.insert_resource(
            'dummysubnettag', user_data={'name': dummy_subnet['name']},
            parent='testtags'
        )
        # VSD Verification
        tag_name = 'verify_vpn_dummy_router'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

        # Delete Verify VPNService
        self._delete_verify_vpnservice(
            vpnservice['id'], vpnservice['name'],
        )
        # Delete environment
        self._delete_verify_vpn_environment(
            router, subnet
        )
        self.os_data_struct.delete_resource('testtags')

    def test_create_duplicate_vpnservice(self):
        """Tests creation of duplicate vpnservice """
        name = 'vpn'
        pubnetid = CONF.network.public_network_id
        pubnet = self.networks_client.show_network(pubnetid)
        self.os_data_struct.insert_resource(
            'testtags2', parent='CMS'
        )
        # Creating Site for VPN Service
        subnet, router = (
            self._create_verify_vpn_environment(
                name, '10.20.0.0/24', pubnet
            )
        )
        # Storing router/subnet tagname to os_data_struct
        self.os_data_struct.insert_resource(
            'routertag', user_data={'name': router['name']},
            parent='testtags2'
        )
        self.os_data_struct.insert_resource(
            'subnettag', user_data={'name': subnet['name']},
            parent='testtags2'
        )
        self.os_data_struct.insert_resource(
            'publicnettag', user_data={'name': pubnet['network']['name']},
            parent='testtags2'
        )
        # Create First Verify VPNService
        vpnservice, dummy_router, dummy_subnet = (
            self._create_verify_vpnservice(
                name, router, subnet
            )
        )
        # Storing vpnservice tagname to os_data_struct
        self.os_data_struct.insert_resource(
            'vpnservicetag', user_data={'name': vpnservice['name']},
            parent='testtags2'
        )
        # Storing dummy router/subnet tagname to os_data_struct
        self.os_data_struct.insert_resource(
            'dummyroutertag', user_data={'name': dummy_router['name']},
            parent='testtags2'
        )
        self.os_data_struct.insert_resource(
            'dummysubnettag', user_data={'name': dummy_subnet['name']},
            parent='testtags2'
        )
        # Create Duplicate VPNService
        self.vpnservice_client.create_vpnservice(
            router['id'], subnet['id'], name, positive=False)

        tag_name = 'verify_vpn_dummy_router'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

        # Delete Verify VPNService
        self._delete_verify_vpnservice(
            vpnservice['id'], vpnservice['name']
        )
        # Delete environment
        self._delete_verify_vpn_environment(
            router, subnet
        )
        self.os_data_struct.delete_resource('testtags2')

    def test_create_delete_ipsecsiteconnection(self):
        """Tests create/show/list/delete of ipsecsiteconnection

        In two different vpnservices
        """
        pubnetid = CONF.network.public_network_id
        pubnet = self.networks_client.show_network(pubnetid)
        self.os_data_struct.insert_resource(
            'testtags3', parent='CMS'
        )
        self.os_data_struct.insert_resource(
            'publicnettag', user_data={'name': pubnet['network']['name']},
            parent='testtags3'
        )

        # Creating Site1
        name1 = 'vpn1'
        cidr1 = '10.20.0.0/24'
        subnet1, router1 = (
            self._create_verify_vpn_environment(
                name1, cidr1, pubnet
            )
        )

        # Storing Site1 info in os_data_struct
        self.os_data_struct.insert_resource(
            'routertag1', user_data={'name': router1['name']},
            parent='testtags3'
        )
        self.os_data_struct.insert_resource(
            'subnettag1', user_data={'name': subnet1['name']},
            parent='testtags3'
        )

        # Creating VPN1
        vpnservice1, dummy_router1, dummy_subnet1 = (
            self._create_verify_vpnservice(
                name1, router1, subnet1
            )
        )

        # Storing VPN1 info in os_data_struct
        self.os_data_struct.insert_resource(
            'vpnservicetag1', user_data={'name': vpnservice1['name']},
            parent='testtags3'
        )
        self.os_data_struct.insert_resource(
            'dummyroutertag1', user_data={'name': dummy_router1['name']},
            parent='testtags3'
        )
        self.os_data_struct.insert_resource(
            'dummysubnettag1', user_data={'name': dummy_subnet1['name']},
            parent='testtags3'
        )

        # Creating Site2
        name2 = 'vpn2'
        cidr2 = '10.30.0.0/24'
        subnet2, router2 = (
            self._create_verify_vpn_environment(
                name2, cidr2, pubnet
            )
        )

        # Storing Site2 info in os_data_struct
        self.os_data_struct.insert_resource(
            'routertag2', user_data={'name': router2['name']},
            parent='testtags3'
        )
        self.os_data_struct.insert_resource(
            'subnettag2', user_data={'name': subnet2['name']},
            parent='testtags3'
        )

        # Creating VPN2
        vpnservice2, dummy_router2, dummy_subnet2 = (
            self._create_verify_vpnservice(
                name2, router2, subnet2
            )
        )

        # Storing VPN2 info in os_data_struct
        self.os_data_struct.insert_resource(
            'vpnservicetag2', user_data={'name': vpnservice2['name']},
            parent='testtags3'
        )
        self.os_data_struct.insert_resource(
            'dummyroutertag2', user_data={'name': dummy_router2['name']},
            parent='testtags3'
        )

        self.os_data_struct.insert_resource(
            'dummysubnettag2', user_data={'name': dummy_subnet2['name']},
            parent='testtags3'
        )

        tag_name = 'verify_vpn_dummy_router'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

        # Creating IKE Policy
        ikepolicy = self._create_verify_ikepolicy('ikepolicy')
        ikepolicy_id = ikepolicy['id']
        ikepolicy_name = ikepolicy['name']

        # Creating IPSecPolicy
        ipsecpolicy = self._create_verify_ipsecpolicy('ipsecpolicy')
        ipsecpolicy_id = ipsecpolicy['id']
        ipsecpolicy_name = ipsecpolicy['name']

        # Creating IPSecSiteConnection1
        vpn_ip1 = vpnservice1['external_v4_ip']
        ipsecsiteconnection1 = (
            self._create_verify_ipsecsiteconnection(
                vpnservice1['id'], ikepolicy_id,
                ipsecpolicy_id, vpn_ip1, vpn_ip1,
                cidr1, 'secret', name1, vpnservice1['name']
            )
        )
        # Storing ipsecsiteconnection in os_data_struct
        self.os_data_struct.insert_resource(
            'ipsecsiteconnection1',
            user_data={'name': ipsecsiteconnection1['name']},
            parent='testtags3'
        )

        # Creating IPSecSiteConnection2
        vpn_ip2 = vpnservice2['external_v4_ip']
        ipsecsiteconnection2 = (
            self._create_verify_ipsecsiteconnection(
                vpnservice2['id'], ikepolicy_id,
                ipsecpolicy_id, vpn_ip2, vpn_ip2,
                cidr2, 'secret', name2, vpnservice2['name']
            )
        )
        # Storing ipsecsiteconnection in os_data_struct
        self.os_data_struct.insert_resource(
            'ipsecsiteconnection2',
            user_data={'name': ipsecsiteconnection2['name']},
            parent='testtags3'
        )

        tag_name = 'verify_ipsec_vminterface'
        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag(tag_name, self.__class__.__name__), self)

        # Delete IPSecSiteconnections
        self._delete_verify_ipsecsiteconnection(
            ipsecsiteconnection1['id'], ipsecsiteconnection1['name']
        )
        self._delete_verify_ipsecsiteconnection(
            ipsecsiteconnection2['id'], ipsecsiteconnection2['name']
        )

        # Delete VPNService
        self._delete_verify_vpnservice(
            vpnservice1['id'], vpnservice1['name']
        )
        self._delete_verify_vpnservice(
            vpnservice2['id'], vpnservice2['name']
        )

        # Delete IKEpolicy and IPSecPolicy
        self._delete_verify_ipsecpolicy(
            ipsecpolicy_id, ipsecpolicy_name
        )
        self._delete_verify_ikepolicy(
            ikepolicy_id, ikepolicy_name
        )

        # Delete Routers and Subnets
        self._delete_verify_vpn_environment(
            router1, subnet1
        )
        self._delete_verify_vpn_environment(
            router2, subnet2
        )
        # Delete all the testtags3
        self.os_data_struct.delete_resource('testtags3')
