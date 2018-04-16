# Copyright 2017 NOKIA
# All Rights Reserved.

from netaddr import IPNetwork

from tempest.lib import exceptions
from tempest.scenario import manager
from tempest.test import decorators

from nuage_tempest_plugin.lib.test.nuage_test import NuageAdminNetworksTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class PortsTest(NuageAdminNetworksTest,
                manager.NetworkScenarioTest):
    @classmethod
    def setup_clients(cls):
        super(PortsTest, cls).setup_clients()
        cls.vsd_client = NuageRestClient()

    @decorators.attr(type='smoke')
    def test_nuage_port_create(self):
        network = self.create_network()
        self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                           mask_bits=24)
        self.create_port(network)

    def _create_server(self, name, network, port_id=None):
        keypair = self.create_keypair()
        network = {'uuid': network['id']}
        if port_id is not None:
            network['port'] = port_id
        server = self.create_server(
            name=name,
            networks=[network],
            key_name=keypair['name'],
            wait_until='ACTIVE')
        return server

    @decorators.attr(type='smoke')
    def test_nuage_port_update_fixed_ips_negative(self):
        if self.is_dhcp_agent_present():
            raise self.skipException(
                'Multiple subnets in a network not supported when DHCP agent '
                'is enabled.')
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
                LOG.debug(e._error_string)
                self.fail("A different NuageBadRequest exception"
                          " was expected for this operation.")

    @decorators.attr(type='smoke')
    def test_nuage_port_create_fixed_ips_same_subnet_l2(self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")

        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }

        ]

        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.L2_DOMAIN,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])

    @decorators.attr(type='smoke')
    def test_nuage_port_update_fixed_ips_same_subnet_l2(self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.L2_DOMAIN,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])

        # update within subnet should succeed
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }

        ]
        port = self.update_port(port=port, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to update port")
        nuage_vport = self.vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])

    @decorators.attr(type='smoke')
    def test_nuage_port_create_fixed_ips_same_subnet_l3(self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }

        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.3']
        vip_mismatch = False
        mac_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            if nuage_vport_vip['MAC'] != port['mac_address']:
                mac_mismatch = True
        self.assertEqual(vip_mismatch, False)
        self.assertEqual(mac_mismatch, False)

    @decorators.attr(type='smoke')
    def test_nuage_port_create_fixed_ips_same_subnet_l3_no_security(self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }

        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                port_security_enabled=False)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.3']
        vip_mismatch = False
        mac_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            if nuage_vport_vip['MAC'] != port['mac_address']:
                mac_mismatch = True
        self.assertEqual(vip_mismatch, False)
        self.assertEqual(mac_mismatch, False)

    @decorators.attr(type='smoke')
    def test_nuage_port_update_fixed_ips_same_subnet_l3_no_security(self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            }
        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.5',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network,
                                fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])

        # update within subnet should succeed
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.update_port(port=port, fixed_ips=fixed_ips,
                                allowed_address_pairs=[],
                                security_groups=[],
                                port_security_enabled=False)
        self.assertIsNotNone(port, "Unable to update port")
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.3']
        vip_mismatch = False
        mac_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            if nuage_vport_vip['MAC'] != port['mac_address']:
                mac_mismatch = True
        self.assertEqual(vip_mismatch, False)
        self.assertEqual(mac_mismatch, False)

    @decorators.attr(type='smoke')
    def test_nuage_port_update_fixed_ips_same_subnet_l3(self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])

        # update within subnet should succeed
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }

        ]
        port = self.update_port(port=port, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to update port")
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.3']
        vip_mismatch = False
        mac_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            if nuage_vport_vip['MAC'] != port['mac_address']:
                mac_mismatch = True
        self.assertEqual(vip_mismatch, False)
        self.assertEqual(mac_mismatch, False)

    @decorators.attr(type='smoke')
    def test_nuage_port_create_fixed_ips_same_subnet_l2_with_aap(self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")

        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }

        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.50',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.L2_DOMAIN,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])

    @decorators.attr(type='smoke')
    def test_nuage_port_update_fixed_ips_same_subnet_l2_with_aap(self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.L2_DOMAIN,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])

        # update within subnet should succeed
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }

        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.50',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.update_port(port=port,
                                fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to update port")
        nuage_vport = self.vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])

    @decorators.attr(type='smoke')
    def test_nuage_port_create_fixed_ips_same_subnet_l3_with_aap(self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }

        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.5',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.3', allowed_address_pairs[0]['ip_address']]
        vip_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            self.assertEqual(vip_mismatch, False)

    @decorators.attr(type='smoke')
    def test_nuage_port_create_fixed_ips_same_subnet_l3_with_aap_outside_cidr(
            self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }
        ]
        allowed_address_pairs = [{'ip_address': '1.1.1.5',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.3']
        vip_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            self.assertEqual(vip_mismatch, False)

    @decorators.attr(type='smoke')
    def test_nuage_port_update_fixed_ips_same_subnet_l3_with_aap(self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])

        # update within subnet should succeed
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }

        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.5',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.update_port(port=port, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to update port")
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.3', allowed_address_pairs[0]['ip_address']]
        vip_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            self.assertEqual(vip_mismatch, False)

    @decorators.attr(type='smoke')
    def test_nuage_port_update_fixed_ips_same_subnet_l3_with_aap_with_vm(self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }
        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.10',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = [fixed_ips[0]["ip_address"],
                      allowed_address_pairs[0]['ip_address']]
        vip_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            self.assertEqual(vip_mismatch, False)

        self._create_server(name='vm-' + network['name'],
                            network=network, port_id=port['id'])

        # update within subnet should succeed
        fixed_ips = [
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.5",
                "subnet_id": subnet["id"]
            }
        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.6',
                                  'mac_address': 'fe:a0:36:4b:c8:70'},
                                 {'ip_address': '10.0.0.10',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.update_port(port=port, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to update port")
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = [fixed_ips[0]["ip_address"],
                      allowed_address_pairs[0]['ip_address'],
                      allowed_address_pairs[1]['ip_address']]
        vip_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            self.assertEqual(vip_mismatch, False)

    @decorators.attr(type='smoke')
    def test_nuage_port_update_app_to_fixed_ips_l3_with_vm(self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }
        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.5',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = [fixed_ips[0]["ip_address"],
                      allowed_address_pairs[0]['ip_address']]
        vip_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            self.assertEqual(vip_mismatch, False)

        self._create_server(name='vm-' + network['name'],
                            network=network, port_id=port['id'])

        # update within subnet should succeed
        fixed_ips = [
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.5",
                "subnet_id": subnet["id"]
            }
        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.6',
                                  'mac_address': 'fe:a0:36:4b:c8:70'},
                                 {'ip_address': '10.0.0.10',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.update_port(port=port, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to update port")
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = [fixed_ips[0]["ip_address"],
                      allowed_address_pairs[0]['ip_address'],
                      allowed_address_pairs[1]['ip_address']]
        vip_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            self.assertEqual(vip_mismatch, False)

    @decorators.attr(type='smoke')
    def test_nuage_port_update_fixed_ip_with_vm_and_conflict_with_aap_neg(
            self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }
        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.10',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = [fixed_ips[0]["ip_address"],
                      allowed_address_pairs[0]['ip_address']]
        vip_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            self.assertEqual(vip_mismatch, False)

        self._create_server(name='vm-' + network['name'],
                            network=network, port_id=port['id'])
        fixed_ips = [
            {
                "ip_address": "10.0.0.8",
                "subnet_id": subnet["id"]
            }
        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.5',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        self.create_port(network=network, fixed_ips=fixed_ips,
                         allowed_address_pairs=allowed_address_pairs)

        # update within subnet should succeed
        fixed_ips = [
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.5",
                "subnet_id": subnet["id"]
            }
        ]
        # below update will fail with proper roll back
        try:
            self.update_port(port=port, fixed_ips=fixed_ips)
            self.fail("Exception expected when updating to"
                      " a different subnet!")
        except exceptions.BadRequest as e:
            if ('Bad request: The IP Address 10.0.0.5 is'
                    ' currently in use by subnet' in e._error_string):
                vsd_vport_parent = self.vsd_client.get_global_resource(
                    constants.SUBNETWORK,
                    filters='externalID',
                    filter_value=subnet['id'])[0]
                nuage_vport = self.vsd_client.get_vport(
                    constants.SUBNETWORK,
                    vsd_vport_parent['ID'],
                    filters='externalID',
                    filter_value=port['id'])
                self.assertEqual(constants.INHERITED,
                                 nuage_vport[0]['addressSpoofing'])
                nuage_vport_vips = self.vsd_client.get_virtual_ip(
                    constants.VPORT,
                    nuage_vport[0]['ID'])
                vip_mismatch = False
                if valid_vips and not nuage_vport_vips:
                    vip_mismatch = True
                for nuage_vport_vip in nuage_vport_vips:
                    if nuage_vport_vip['virtualIP'] not in valid_vips:
                        vip_mismatch = True
                    self.assertEqual(vip_mismatch, False)
                pass
            else:
                # Differentiate between VSD failure and update failure
                LOG.debug(e._error_string)
                self.fail("A different NuageBadRequest exception"
                          " was expected for this operation.")

    @decorators.attr(type='smoke')
    def test_nuage_port_create_fixed_ip_same_as_aap(self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        fixed_ips = [
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.5",
                "subnet_id": subnet["id"]
            }
        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.5',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = [fixed_ips[0]["ip_address"],
                      allowed_address_pairs[0]['ip_address']]
        vip_mismatch = False
        mac_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            if nuage_vport_vip['MAC'] != port['mac_address']:
                mac_mismatch = True
            self.assertEqual(vip_mismatch, False)
            self.assertEqual(mac_mismatch, False)

    @decorators.attr(type='smoke')
    def test_nuage_port_update_fixed_ips_same_as_aap(self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }
        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.5',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = [fixed_ips[0]["ip_address"],
                      allowed_address_pairs[0]['ip_address']]
        vip_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            self.assertEqual(vip_mismatch, False)

        fixed_ips = [
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.5",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.update_port(port=port, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to update port")
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = [fixed_ips[0]["ip_address"],
                      allowed_address_pairs[0]['ip_address']]
        vip_mismatch = False
        mac_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            self.assertEqual(vip_mismatch, False)
            if nuage_vport_vip['MAC'] != port['mac_address']:
                mac_mismatch = True
            self.assertEqual(vip_mismatch, False)
            self.assertEqual(mac_mismatch, False)

    @decorators.attr(type='smoke')
    def test_nuage_port_create_fixed_ips_same_subnet_with_aap_router_attach(
            self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")

        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }

        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.5',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")

        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.L2_DOMAIN,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        # Attach subnet
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])

        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.3', allowed_address_pairs[0]['ip_address']]
        vip_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            self.assertEqual(vip_mismatch, False)
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])

    @decorators.attr(type='smoke')
    def test_nuage_port_update_fixed_ips_same_subnet_with_aap_router_detach(
            self):
        # Set up resources
        # Base resources
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router(
            admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.create_router_interface(router_id=router["id"],
                                     subnet_id=subnet["id"])
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])

        # update within subnet should succeed
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }

        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.5',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.update_port(port=port, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to update port")
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.INHERITED,
                         nuage_vport[0]['addressSpoofing'])
        valid_vips = ['10.0.0.3', allowed_address_pairs[0]['ip_address']]
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        vip_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            self.assertEqual(vip_mismatch, False)

        self.admin_routers_client.remove_router_interface(
            router['id'],
            subnet_id=subnet['id'])
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.L2_DOMAIN,
            filters='externalID',
            filter_value=subnet['id'])[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(constants.ENABLED,
                         nuage_vport[0]['addressSpoofing'])
