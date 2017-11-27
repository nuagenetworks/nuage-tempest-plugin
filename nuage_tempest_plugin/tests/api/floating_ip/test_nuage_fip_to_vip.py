# Copyright 2017 NOKIA
# All Rights Reserved.

from oslo_log import log as logging

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest

from tempest import config
from tempest.test import decorators

CONF = config.CONF


class NuageFipToVip(NuageBaseTest):

    LOG = logging.getLogger(__name__)

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
        self.assertIsNotNone(floating_ip, "Unabe to create floating ip")
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
