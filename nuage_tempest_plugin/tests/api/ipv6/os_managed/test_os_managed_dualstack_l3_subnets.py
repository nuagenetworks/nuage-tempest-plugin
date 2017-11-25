# Copyright 2017 - Nokia
# All Rights Reserved.

from tempest import config

from nuage_tempest_plugin.lib.features import NUAGE_FEATURES
from nuage_tempest_plugin.lib.test import nuage_test
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.test import tags
from nuage_tempest_plugin.tests.api.upgrade.external_id.external_id \
    import ExternalId

from tempest.lib import decorators

CONF = config.CONF


@nuage_test.class_header(tags=[tags.ML2])
class OsManagedDualStackL3SubnetsTest(NuageBaseTest):

    @classmethod
    def skip_checks(cls):
        super(OsManagedDualStackL3SubnetsTest, cls).skip_checks()
        if not NUAGE_FEATURES.os_managed_dualstack_subnets:
            raise cls.skipException(
                'OS Managed Dual Stack is not supported in this release')

    def create_v6_subnet(self, network, cleanup=True):
        return self.create_subnet(network, ip_version=6, enable_dhcp=False,
                                  cleanup=cleanup)

    def _verify_ipv6_subnet_with_vsd_l2_domain(self, subnet, external_id):
        vsd_l2_domain = self.vsd.get_l2domain(
            vspk_filter='externalID == "{}"'.format(external_id))
        self.assertIsNotNone(vsd_l2_domain)
        self.assertEqual('DUALSTACK', vsd_l2_domain.ip_type)
        self.assertIsNone(subnet['ipv6_ra_mode'])
        self.assertIsNone(subnet['ipv6_address_mode'])
        self.assertEqual(subnet['cidr'], vsd_l2_domain.ipv6_address)
        self.assertEqual(subnet['gateway_ip'], vsd_l2_domain.ipv6_gateway)
        self.assertFalse(subnet['vsd_managed'])
        self.assertEqual(subnet['enable_dhcp'],
                         False, "IPv6 subnet MUST have enable_dhcp=FALSE")

    ###########################################################################
    # Typical
    ###########################################################################
    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_os_managed_dual_stack_l3_subnet(self):
        # Provision OpenStack network
        network = self.create_network()

        # When I create an IPv4 subnet
        ipv4_subnet = self.create_subnet(network)
        self.assertIsNotNone(ipv4_subnet)

        # Then a VSD L2 domain is created with type IPv4
        vsd_l2_domain = self.vsd.get_l2domain(by_subnet_id=ipv4_subnet['id'])
        self.assertIsNotNone(vsd_l2_domain)
        self.assertEqual("IPV4", vsd_l2_domain.ip_type)

        # When I add an IPv6 subnet
        ipv6_subnet = self.create_subnet(
            network, ip_version=6, enable_dhcp=False)
        self.assertIsNotNone(ipv6_subnet)

        # Then the VSD L2 domain is changed to IP type DualStack
        self._verify_ipv6_subnet_with_vsd_l2_domain(
            ipv6_subnet, ExternalId(ipv4_subnet['id']).at_cms_id())

        router = self.create_router()
        self.assertIsNotNone(router)

        vsd_l3_domain = self.vsd.get_l3domain(by_router_id=router['id'])
        self.assertIsNotNone(vsd_l3_domain)

        self.router_attach(router, ipv4_subnet)

        vsd_l3_domain.fetch()
        vsd_l3_subnet = self.vsd.get_subnet_from_domain(
            domain=vsd_l3_domain, by_subnet_id=ipv4_subnet['id'])

        port = self.create_port(network)
        self._verify_port(port, subnet4=ipv4_subnet, subnet6=None),
        self._verify_vport_in_l3_subnet(port, vsd_l3_subnet)

        server1 = self.create_tenant_server(
            ports=[port])
        self.assertIsNotNone(server1)

    ###########################################################################
    # A few smoky scenario's with subnet attach
    ###########################################################################

    # -------------------------------------------------------------------------
    # Section A: attach the ipv4 subnet and check proceeding of a few scenarios
    # -------------------------------------------------------------------------

    # eventually delete this - this is obviously elsewhere tested
    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_pure_ipv4_attach_and_cleanup(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)

        self.router_attach(router, ipv4_subnet)

    # eventually delete this - this is obviously elsewhere tested
    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_dualstack_attach_ipv4_and_cleanup(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)
        self.create_v6_subnet(network)

        self.router_attach(router, ipv4_subnet)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_dualstack_attach_ipv4_delete_ipv6_and_cleanup(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)
        ipv6_subnet = self.create_v6_subnet(network, cleanup=False)

        self.router_attach(router, ipv4_subnet)

        self.delete_subnet(ipv6_subnet)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_dualstack_attach_ipv4_delete_ipv6_and_recreate(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)
        ipv6_subnet = self.create_v6_subnet(network, cleanup=False)

        self.router_attach(router, ipv4_subnet)

        # delete the ipv6 subnet
        self.delete_subnet(ipv6_subnet)

        # recreate an ipv6 subnet
        self.create_v6_subnet(network)

    # -------------------------------------------------------------------------
    # Section B: attach the ipv6 subnet and check proceeding of a few scenarios
    # -------------------------------------------------------------------------

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_pure_ipv6_attach_and_cleanup(self):
        network = self.create_network()
        router = self.create_router()

        ipv6_subnet = self.create_v6_subnet(network)

        self.router_attach(router, ipv6_subnet)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_dualstack_attach_ipv6_and_cleanup(self):
        network = self.create_network()
        router = self.create_router()

        self.create_subnet(network)
        ipv6_subnet = self.create_v6_subnet(network)

        self.router_attach(router, ipv6_subnet)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_dualstack_attach_ipv6_delete_ipv4_and_cleanup(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network, cleanup=False)
        ipv6_subnet = self.create_v6_subnet(network)

        self.router_attach(router, ipv6_subnet)

        self.delete_subnet(ipv4_subnet)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    # This is the scenario described in OPENSTACK-1990
    def test_dualstack_attach_ipv6_delete_ipv4_and_recreate(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network, cleanup=False)
        ipv6_subnet = self.create_v6_subnet(network)

        self.router_attach(router, ipv6_subnet)

        # delete the ipv4 subnet
        self.delete_subnet(ipv4_subnet)

        # recreate an ipv4 subnet
        self.create_subnet(network)

    # -------------------------------------------------------------------------
    # Section C: Double attachment
    # -------------------------------------------------------------------------

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_dualstack_attach_in_v4_then_v6_order_and_cleanup(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)
        ipv6_subnet = self.create_v6_subnet(network)

        self.router_attach(router, ipv4_subnet)
        self.router_attach(router, ipv6_subnet)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_dualstack_attach_in_v4_then_v6_order_and_cleanup_reversely(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)
        ipv6_subnet = self.create_v6_subnet(network)

        self.router_attach(router, ipv4_subnet, cleanup=False)
        self.router_attach(router, ipv6_subnet)

        self.router_detach(router, ipv4_subnet)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_dualstack_attach_in_v6_then_v4_order_and_cleanup(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)
        ipv6_subnet = self.create_v6_subnet(network)

        self.router_attach(router, ipv6_subnet)
        self.router_attach(router, ipv4_subnet)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_dualstack_attach_in_v6_then_v4_order_and_cleanup_reversely(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)
        ipv6_subnet = self.create_v6_subnet(network)

        self.router_attach(router, ipv6_subnet, cleanup=False)
        self.router_attach(router, ipv4_subnet)

        self.router_detach(router, ipv6_subnet)

    # -------------------------------------------------------------------------
    # Section D: Special cases
    # -------------------------------------------------------------------------

    @decorators.attr(type='smoke')
    @nuage_test.header()
    def test_router_attach_ipv4_and_add_ipv6(self):
        network = self.create_network()
        router = self.create_router()

        ipv4_subnet = self.create_subnet(network)

        self.router_attach(router, ipv4_subnet, cleanup=False)

        # now add ipv6 subnet
        self.create_v6_subnet(network)

        # and detach ipv4
        self.router_detach(router, ipv4_subnet)

    @decorators.attr(type='smoke')
    @nuage_test.header()
    # This is the scenario described in OPENSTACK-2004
    def test_router_attach_ipv6_and_add_ipv4(self):
        network = self.create_network()
        router = self.create_router()

        ipv6_subnet = self.create_v6_subnet(network)

        self.router_attach(router, ipv6_subnet, cleanup=False)

        # now add ipv4 subnet
        self.create_subnet(network)

        # and detach ipv6
        self.router_detach(router, ipv6_subnet)
