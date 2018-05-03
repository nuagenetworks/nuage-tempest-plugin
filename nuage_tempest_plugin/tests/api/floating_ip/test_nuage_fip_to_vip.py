# Copyright 2017 NOKIA
# All Rights Reserved.

from netaddr import IPNetwork

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
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])

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
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        # Create VIP_port
        # VIP port is wrongly created without appropriate device owner
        vip_port = self.create_port(network=network)
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
        self.assertIsNone(nuage_vip.associated_floating_ip_id,
                          "Floating ip associated with port that does not"
                          "have the correct device owner.")
        # Assert FIP associated to vport for fake vip neutron port
        vsd_subnet = self.vsd.get_subnet_from_domain(by_subnet_id=subnet['id'])
        nuage_vport_for_fake_vip = self.vsd.get_vport(
            subnet=vsd_subnet, by_port_id=vip_port['id'])
        self.assertIsNotNone(
            nuage_vport_for_fake_vip.associated_floating_ip_id,
            "Floating ip not correctly attached to fake nuage_vip port.")

        # dissassociate fip
        self.update_floatingip(floatingip=floating_ip,
                               port_id=None)

        # Assert FIP dissassociated
        nuage_vip = self.vsd.get_vport_vip(vport_id=AAP_port['id'],
                                           router_id=router['id'])
        self.assertIsNotNone(nuage_vip, "Not able to find VIP on VSD.")
        self.assertIsNone(nuage_vip.associated_floating_ip_id,
                          "Floating ip associated with port that does not"
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
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet2["id"])

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
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet2["id"])

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
