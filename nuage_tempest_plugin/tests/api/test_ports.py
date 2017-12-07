# Copyright 2017 NOKIA
# All Rights Reserved.

from netaddr import IPNetwork

from oslo_log import log as logging
from tempest import config
from tempest.lib import exceptions
from tempest.test import decorators

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest

CONF = config.CONF


class PortsTest(NuageBaseTest):
    LOG = logging.getLogger(__name__)

    @decorators.attr(type='smoke')
    def test_nuage_port_create(self):
        network = self.create_network()
        self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                           mask_bits=24)
        self.create_port(network)

    def test_nuage_port_update_fixed_ips_negative(self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        subnet2 = self.create_subnet(network, cidr=IPNetwork("20.0.0.0/24"),
                                     mask_bits=28)
        self.assertIsNotNone(subnet2, "Unable to create second subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet2["id"])
        # Create port
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")

        # update within subnet should succeed
        fixed_ips = [
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }

        ]
        port = self.update_port(port=port, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to update port")
        self.assertEqual(port["fixed_ips"][0]["ip_address"], "10.0.0.4",
                         message="The port did not update properly.")

        # update within subnet with 2 ips should fail
        fixed_ips = [
            {
                "ip_address": "10.0.0.5",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.6",
                "subnet_id": subnet["id"]
            }

        ]
        try:
            self.update_port(port=port, fixed_ips=fixed_ips)
            self.fail("Exception expected when updating to"
                      " a different subnet!")
        except exceptions.BadRequest as e:
            if "It is not allowed to add more than one ip" in e._error_string:
                pass
            else:
                # Differentiate between VSD failure and update failure
                self.LOG.debug(e._error_string)
                self.fail("A different NuageBadRequest exception"
                          " was expected for this operation.")

        # Update to subnet2 should fail
        fixed_ips = [
            {
                "ip_address": "20.0.0.3",
                "subnet_id": subnet2["id"]
            }
        ]
        try:
            self.update_port(port=port, fixed_ips=fixed_ips)
            self.fail("Exception expected when updating to"
                      " a different subnet!")
        except exceptions.BadRequest as e:
            if "Updating fixed ip of port" in e._error_string:
                pass
            else:
                # Differentiate between VSD failure and update failure
                self.LOG.debug(e._error_string)
                self.fail("A different NuageBadRequest exception"
                          " was expected for this operation.")
