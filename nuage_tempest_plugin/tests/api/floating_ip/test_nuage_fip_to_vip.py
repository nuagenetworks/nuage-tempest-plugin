# Copyright 2017 NOKIA
# All Rights Reserved.

from netaddr import IPNetwork
import testtools

from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()


class NuageFipToVip(NuageBaseTest):

    @decorators.attr(type='smoke')
    def test_fip2vip_when_fip_preexists(self):
        # Base resources

        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")
        subnet = self.create_subnet(network)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        self.router_attach(router, subnet)

        # Create VIP_port
        vip_port = self.create_port(network=network, device_owner="nuage:vip")
        self.assertIsNotNone(vip_port, "Unable to create vip port")

        # Create floating ip and attach to VIP_PORT
        floating_ip = self.create_floatingip()
        self.assertIsNotNone(floating_ip, "Unable to create floating ip")
        self.update_floatingip(floatingip=floating_ip,
                               port_id=vip_port['id'])

        # Create Port with AAP of VIP Port
        vport = self.create_port(network=network)
        self.assertIsNotNone(vport, "Unable to create port")

        # Add Allowable_address_pair to port, this should result in the
        # floating ip attaching to the virtual ip on VSD.
        aap_ip = vip_port['fixed_ips'][0]['ip_address']
        aap_mac = vport['mac_address']
        self.update_port(port=vport,
                         allowed_address_pairs=[{"ip_address": aap_ip,
                                                "mac_address": aap_mac}])

        # Check VSD status
        nuage_vip = self.vsd.get_vport_vip(vport_id=vport['id'],
                                           router_id=router['id'])
        self.assertIsNotNone(nuage_vip, "Not able to find VIP on VSD.")
        self.assertIsNotNone(nuage_vip.associated_floating_ip_id,
                             "No floating ip associated to the VIP port")

    @decorators.attr(type='smoke')
    def test_fip_to_vip_on_non_vip_port(self):
        # Referencing OPENSTACK-2141

        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")
        subnet = self.create_subnet(network)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        self.router_attach(router, subnet)
        # Create VIP_port
        # VIP port is wrongly created without appropriate device owner
        vip_port = self.create_port(network=network)
        self.assertIsNotNone(vip_port, "Unable to create vip port")

        # Create Port with AAP of VIP Port
        AAP_port = self.create_port(network=network)
        self.assertIsNotNone(AAP_port, "Unable to create port")

        # Add Allowable_address_pair to port, this should result in the
        # VIP creation on VSD.
        # If nuage_vsd_managed ipam driver is enabled this will fail, as
        # nuage:vip port is required in this case.
        aap_ip = vip_port['fixed_ips'][0]['ip_address']
        aap_mac = AAP_port['mac_address']
        if CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed':
            self.assertRaisesRegex(
                exceptions.BadRequest,
                "Unable to find 'vip' reservation port for "
                "allowed address pair with ip",
                self.update_port, port=AAP_port,
                allowed_address_pairs=[{"ip_address": aap_ip,
                                        "mac_address": aap_mac}])
            return
        self.update_port(port=AAP_port,
                         allowed_address_pairs=[{"ip_address": aap_ip,
                                                "mac_address": aap_mac}])

        # Create floating ip and attach to VIP_PORT
        floating_ip = self.create_floatingip()
        self.assertIsNotNone(floating_ip, "Unable to create floating ip")
        self.update_floatingip(floatingip=floating_ip,
                               port_id=vip_port['id'])

        # Check VSD status
        nuage_vip = self.vsd.get_vport_vip(vport_id=AAP_port['id'],
                                           router_id=router['id'])
        self.assertIsNotNone(nuage_vip, "Not able to find VIP on VSD.")
        self.assertIsNone(nuage_vip.associated_floating_ip_id,
                          "Floating ip associated with port that does not"
                          "have the correct device owner.")
        # Assert FIP associated to vport for fake vip neutron port
        vsd_subnet = self.vsd.get_subnet_from_domain(
            by_subnet=subnet)
        nuage_vport_for_fake_vip = self.vsd.get_vport(
            subnet=vsd_subnet, by_port_id=vip_port['id'])
        self.assertIsNotNone(
            nuage_vport_for_fake_vip.associated_floating_ip_id,
            "Floating ip not correctly attached to fake nuage_vip port.")

        # disassociate fip
        self.update_floatingip(floatingip=floating_ip,
                               port_id=None)

        # Assert FIP disassociated
        nuage_vip = self.vsd.get_vport_vip(vport_id=AAP_port['id'],
                                           router_id=router['id'])
        self.assertIsNotNone(nuage_vip, "Not able to find VIP on VSD.")
        self.assertIsNone(nuage_vip.associated_floating_ip_id,
                          "Floating ip associated with port that does not "
                          "have the correct device owner.")
        nuage_vport_for_fake_vip = self.vsd.get_vport(
            subnet=vsd_subnet, by_port_id=vip_port['id'])
        self.assertIsNone(
            nuage_vport_for_fake_vip.associated_floating_ip_id,
            "Floating ip not correctly detached from fake nuage_vip port.")

        # Assert FIP as available
        self.update_floatingip(floatingip=floating_ip,
                               port_id=AAP_port['id'])
        nuage_vport = self.vsd.get_vport(
            subnet=vsd_subnet, by_port_id=AAP_port['id'])
        self.assertIsNotNone(
            nuage_vport.associated_floating_ip_id,
            "Floating ip not correctly attached to the vport.")

    @decorators.attr(type='smoke')
    def test_fip2vip_dualstack_port(self):
        # openstack-2192
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")
        subnet = self.create_subnet(network, cidr=IPNetwork("99.0.0.0/24"),
                                    mask_bits=24)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        subnet2 = self.create_subnet(network, cidr=IPNetwork("1::/64"),
                                     mask_bits=64, ip_version=6)
        router = self.create_router(
            admin_state_up=True,
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        self.router_attach(router, subnet)
        self.router_attach(router, subnet2)

        # Create VIP_port
        vip_port = self.create_port(network=network, device_owner="nuage:vip")
        self.assertIsNotNone(vip_port, "Unable to create vip port")

        # Create Port with AAP of VIP Port
        vport = self.create_port(network=network)
        self.assertIsNotNone(vport, "Unable to create port")

        # Add Allowable_address_pair to port
        aap1 = vip_port['fixed_ips'][0]
        aap2 = vip_port['fixed_ips'][1]
        aap_mac = vport['mac_address']
        if aap1['subnet_id'] == subnet['id']:
            aap = {"ip_address": aap1['ip_address'],
                   "mac_address": aap_mac}
        else:
            aap = {"ip_address": aap2['ip_address'],
                   "mac_address": aap_mac}

        self.update_port(port=vport,
                         allowed_address_pairs=[aap])

        # Create floating ip and attach to VIP_PORT
        floating_ip = self.create_floatingip(cleanup=False)
        self.assertIsNotNone(floating_ip, "Unable to create floating ip")
        self.update_floatingip(floatingip=floating_ip,
                               port_id=vip_port['id'])

        # Check VSD status
        nuage_vip = self.vsd.get_vport_vip(vport_id=vport['id'],
                                           router_id=router['id'])
        self.assertIsNotNone(nuage_vip, "Not able to find VIP on VSD.")
        self.assertIsNotNone(nuage_vip.associated_floating_ip_id,
                             "No floating ip associated to the VIP port")

        # Delete floating ip
        self.delete_floatingip(floating_ip['id'])
        nuage_vip = self.vsd.get_vport_vip(vport_id=vport['id'],
                                           router_id=router['id'])
        self.assertIsNotNone(nuage_vip, "Not able to find VIP on VSD.")
        self.assertIsNone(nuage_vip.associated_floating_ip_id,
                          "No floating ip should be associated to the "
                          "VIP port after floating ip delete.")

    @decorators.attr(type='smoke')
    def test_fip2vip_dualstack_port_with_fip_first_then_vip(self):
        # openstack-2192
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")
        subnet = self.create_subnet(network, cidr=IPNetwork("99.0.0.0/24"),
                                    mask_bits=24)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        subnet2 = self.create_subnet(network, cidr=IPNetwork("1::/64"),
                                     mask_bits=64, ip_version=6)
        router = self.create_router(
            admin_state_up=True,
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        self.router_attach(router, subnet)
        self.router_attach(router, subnet2)

        # Create VIP_port
        vip_port = self.create_port(network=network, device_owner="nuage:vip")
        self.assertIsNotNone(vip_port, "Unable to create vip port")

        # Create floating ip and attach to VIP_PORT
        floating_ip = self.create_floatingip(cleanup=False)
        self.assertIsNotNone(floating_ip, "Unable to create floating ip")
        self.update_floatingip(floatingip=floating_ip,
                               port_id=vip_port['id'])

        # Create Port with AAP of VIP Port
        vport = self.create_port(network=network)
        self.assertIsNotNone(vport, "Unable to create port")

        # Add Allowable_address_pair to port
        aap1 = vip_port['fixed_ips'][0]
        aap2 = vip_port['fixed_ips'][1]
        aap_mac = vport['mac_address']
        if aap1['subnet_id'] == subnet['id']:
            aap = {"ip_address": aap1['ip_address'],
                   "mac_address": aap_mac}
        else:
            aap = {"ip_address": aap2['ip_address'],
                   "mac_address": aap_mac}

        self.update_port(port=vport,
                         allowed_address_pairs=[aap])

        # Check VSD status
        nuage_vip = self.vsd.get_vport_vip(vport_id=vport['id'],
                                           router_id=router['id'])
        self.assertIsNotNone(nuage_vip, "Not able to find VIP on VSD.")
        self.assertIsNotNone(nuage_vip.associated_floating_ip_id,
                             "No floating ip associated to the VIP port")

        # Delete floating ip
        self.delete_floatingip(floating_ip['id'])
        nuage_vip = self.vsd.get_vport_vip(vport_id=vport['id'],
                                           router_id=router['id'])
        self.assertIsNotNone(nuage_vip, "Not able to find VIP on VSD.")
        self.assertIsNone(nuage_vip.associated_floating_ip_id,
                          "No floating ip should be associated to the "
                          "VIP port after floating ip delete.")

    @decorators.attr(type='smoke')
    def test_fip_to_vip_delete_nuage_vip_port_disassociate(self):
        # Referencing OPENSTACK-2202

        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")
        subnet = self.create_subnet(network)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        self.router_attach(router, subnet)
        # Create VIP_port
        vip_port = self.create_port(network=network, device_owner="nuage:vip",
                                    cleanup=False)
        self.assertIsNotNone(vip_port, "Unable to create vip port")

        # Create Port with AAP of VIP Port
        AAP_port = self.create_port(network=network)
        self.assertIsNotNone(AAP_port, "Unable to create port")

        # Add Allowable_address_pair to port, this should result in the
        # VIP creation on VSD.
        aap_ip = vip_port['fixed_ips'][0]['ip_address']
        aap_mac = AAP_port['mac_address']
        self.update_port(port=AAP_port,
                         allowed_address_pairs=[{"ip_address": aap_ip,
                                                "mac_address": aap_mac}])

        # Create floating ip and attach to VIP_PORT
        floating_ip = self.create_floatingip()
        self.assertIsNotNone(floating_ip, "Unable to create floating ip")
        self.update_floatingip(floatingip=floating_ip,
                               port_id=vip_port['id'])

        # Check VSD status
        nuage_vip = self.vsd.get_vport_vip(vport_id=AAP_port['id'],
                                           router_id=router['id'])
        self.assertIsNotNone(nuage_vip, "Not able to find VIP on VSD.")
        self.assertIsNotNone(nuage_vip.associated_floating_ip_id,
                             "Floating ip not associated with vip.")

        # Delete nuage:fip port
        self.delete_port(vip_port)

        # Assert FIP disassociated
        nuage_vip = self.vsd.get_vport_vip(vport_id=AAP_port['id'],
                                           router_id=router['id'])
        self.assertIsNotNone(nuage_vip, "Not able to find VIP on VSD.")
        self.assertIsNone(nuage_vip.associated_floating_ip_id,
                          "Floating ip still associated to vip.")

        # Assert FIP as available
        self.update_floatingip(floatingip=floating_ip,
                               port_id=AAP_port['id'])
        vsd_subnet = self.vsd.get_subnet_from_domain(
            by_subnet=subnet)
        nuage_vport = self.vsd.get_vport(
            subnet=vsd_subnet, by_port_id=AAP_port['id'])
        self.assertIsNotNone(
            nuage_vport.associated_floating_ip_id,
            "Floating ip not correctly attached to the vport.")

    @decorators.attr(type='smoke')
    def test_fip_to_vip_with_vm(self):
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")
        subnet = self.create_subnet(network)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        self.router_attach(router, subnet)

        # Create VIP_port
        vip_port = self.create_port(network=network, device_owner="nuage:vip")
        self.assertIsNotNone(vip_port, "Unable to create vip port")

        # Create Port with AAP of VIP Port
        AAP_port = self.create_port(network=network)
        self.assertIsNotNone(AAP_port, "Unable to create port")

        # Add Allowable_address_pair to port, this should result in the
        # VIP creation on VSD.
        aap_ip = vip_port['fixed_ips'][0]['ip_address']
        aap_mac = AAP_port['mac_address']
        self.update_port(port=AAP_port,
                         allowed_address_pairs=[{"ip_address": aap_ip,
                                                "mac_address": aap_mac}])

        # Create server on port
        self.create_tenant_server(ports=[AAP_port])

        # Create floating ip and attach to VIP_PORT
        floating_ip = self.create_floatingip()
        self.assertIsNotNone(floating_ip, "Unable to create floating ip")
        self.update_floatingip(floatingip=floating_ip,
                               port_id=vip_port['id'])

        # Check VSD status
        nuage_vip = self.vsd.get_vport_vip(vport_id=AAP_port['id'],
                                           router_id=router['id'])
        self.assertIsNotNone(nuage_vip, "Not able to find VIP on VSD.")
        self.assertIsNotNone(nuage_vip.associated_floating_ip_id,
                             "Floating ip not associated with vip.")

    @decorators.attr(type='smoke')
    @testtools.skipIf(Topology.before_nuage('20.5'),
                      'OPENSTACK-2912 fixed as of 20.5 only.')
    def test_fip_to_vip_when_previously_assigned(self):
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")
        subnet = self.create_subnet(network)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        self.router_attach(router, subnet)

        # Create VIP_port
        vip_port = self.create_port(network=network, device_owner="nuage:vip")
        self.assertIsNotNone(vip_port, "Unable to create vip port")

        # Create Port with AAP of VIP Port
        AAP_port = self.create_port(network=network)
        self.assertIsNotNone(AAP_port, "Unable to create port")

        # Add Allowable_address_pair to port, this should result in the
        # VIP creation on VSD.
        aap_ip = vip_port['fixed_ips'][0]['ip_address']
        aap_mac = AAP_port['mac_address']
        self.update_port(port=AAP_port,
                         allowed_address_pairs=[{"ip_address": aap_ip,
                                                "mac_address": aap_mac}])

        # Create floating ip and attach to non-vip port
        floating_ip = self.create_floatingip()
        self.assertIsNotNone(floating_ip, "Unable to create floating ip")
        self.update_floatingip(floatingip=floating_ip,
                               port_id=AAP_port['id'])

        # Update floating ip to be attached to vip port
        self.update_floatingip(floatingip=floating_ip,
                               port_id=vip_port['id'])

        # Check VSD status
        nuage_vip = self.vsd.get_vport_vip(vport_id=AAP_port['id'],
                                           router_id=router['id'])
        self.assertIsNotNone(nuage_vip, "Not able to find VIP on VSD.")
        self.assertIsNotNone(nuage_vip.associated_floating_ip_id,
                             "Floating ip not associated with vip.")

    @decorators.attr(type='smoke')
    def test_fip_to_vip_subnet_detach(self):
        # OPENSTACK-3008 / VSD-53322
        n1 = self.create_network()
        self.assertIsNotNone(n1, "Unable to create network")
        s1 = self.create_subnet(n1)
        self.assertIsNotNone(s1, "Unable to create subnet")
        r1 = self.create_router(
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(r1, "Unable to create r1")
        self.router_attach(r1, s1)

        # Create VIP_port
        vip_port = self.create_port(network=n1, device_owner="nuage:vip")
        self.assertIsNotNone(vip_port, "Unable to create vip port")

        # Create Port with AAP of VIP Port
        AAP_port = self.create_port(network=n1)
        self.assertIsNotNone(AAP_port, "Unable to create port")

        # Add Allowable_address_pair to port, this should result in the
        # VIP creation on VSD.
        aap_ip = vip_port['fixed_ips'][0]['ip_address']
        aap_mac = AAP_port['mac_address']
        self.update_port(port=AAP_port,
                         allowed_address_pairs=[{"ip_address": aap_ip,
                                                "mac_address": aap_mac}])

        # Create floating ip and attach to vip port to create fip2vip
        floating_ip = self.create_floatingip()
        self.assertIsNotNone(floating_ip, "Unable to create floating ip")
        self.update_floatingip(floatingip=floating_ip,
                               port_id=vip_port['id'])

        # Check VSD status
        nuage_vip = self.vsd.get_vport_vip(vport_id=AAP_port['id'],
                                           router_id=r1['id'])
        self.assertIsNotNone(nuage_vip, "Not able to find VIP on VSD.")
        self.assertIsNotNone(nuage_vip.associated_floating_ip_id,
                             "Floating ip not associated with vip.")

        # Delete floating ip
        self.delete_floatingip(floating_ip['id'])

        # Detach s1 from router
        self.router_detach(r1, s1)

        # Create new router (So new Domain)
        r2 = self.create_router(
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(r1, "Unable to create r2")

        self.router_attach(r2, s1)

        # Create floating ip and attach to vip port to create fip2vip
        floating_ip = self.create_floatingip()
        self.assertIsNotNone(floating_ip, "Unable to create floating ip")
        self.update_floatingip(floatingip=floating_ip,
                               port_id=vip_port['id'])

        # Check VSD status
        nuage_vip = self.vsd.get_vport_vip(vport_id=AAP_port['id'],
                                           router_id=r2['id'])
        self.assertIsNotNone(nuage_vip, "Not able to find VIP on VSD after "
                                        "router detach.")
        self.assertIsNotNone(nuage_vip.associated_floating_ip_id,
                             "Floating ip not associated with vip.")
