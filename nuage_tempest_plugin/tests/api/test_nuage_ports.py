# Copyright 2017 NOKIA
# All Rights Reserved.

from netaddr import IPNetwork
import testtools

from tempest.common import custom_matchers
from tempest.common import waiters
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions
from tempest.scenario import manager
from tempest.test import decorators

from nuage_tempest_plugin.lib.test.nuage_test import NuageAdminNetworksTest
from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.services.nuage_client import NuageRestClient

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)

SPOOFING_ENABLED = constants.ENABLED
SPOOFING_DISABLED = (constants.INHERITED if Topology.is_v5
                     else constants.DISABLED)


class PortsTest(NuageBaseTest, NuageAdminNetworksTest,
                manager.NetworkScenarioTest):

    if Topology.is_v5:
        msg_base = 'Bad request: '
    else:
        msg_base = 'Bad request: Error in REST call to VSD: '

    @classmethod
    def setup_clients(cls):
        super(PortsTest, cls).setup_clients()
        cls.vsd_client = NuageRestClient()

    def show_port(self, port_id):
        """Wrapper utility that shows a given port."""
        body = self.ports_client.show_port(port_id)
        return body['port']

    # NOTE: By convention, all tests in this class that deploy a VM,  must have
    # 'with_vm' in their name.
    # Switchdev test pipeline with exclude them.
    def _create_a_server(self, name, network, port_id=None):
        keypair = self.create_keypair()
        network = {'uuid': network['id']}
        if port_id is not None:
            network['port'] = port_id
        return self.create_server(
            name=name,
            networks=[network],
            key_name=keypair['name'],
            wait_until='ACTIVE')

    def _delete_server(self, server_id, clients=None):
        if clients is None:
            clients = self.os_primary
        clients.servers_client.delete_server(server_id)
        waiters.wait_for_server_termination(clients.servers_client, server_id)

    @decorators.attr(type='smoke')
    def test_nuage_port_show(self):
        network = self.create_network()
        self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                           mask_bits=24)
        create_port = self.create_port(network)
        show_port = self.show_port(create_port['id'])

        self.assertIn('id', show_port)
        # NOTE(rfolco): created_at and updated_at may get inconsistent values
        # due to possible delay between POST request and resource creation.
        self.assertThat(create_port,
                        custom_matchers.MatchesDictExceptForKeys
                        (show_port, excluded_keys=['nuage_floatingip',
                                                   'nuage_policy_groups',
                                                   'nuage_redirect_targets',
                                                   'created_at',
                                                   'updated_at']))

    @decorators.attr(type='smoke')
    def test_nuage_dhcp_port_create_check_status(self):
        network = self.create_network()
        self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                           mask_bits=24)
        filters = {
            'device_owner': 'network:dhcp:nuage',
            'network_id': network['id']
        }
        dhcp_port = self.ports_client.list_ports(**filters)['ports'][0]
        self.assertEqual('ACTIVE', dhcp_port['status'])

    @decorators.attr(type='smoke')
    def test_nuage_dhcp_port_with_router_detach_check_status(self):
        network = self.create_network()
        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=24)
        router = self.create_router(
            admin_state_up=True,
            external_network_id=self.ext_net_id)
        self.router_attach(router, subnet, cleanup=False)
        self.router_detach(router, subnet)
        filters = {
            'device_owner': 'network:dhcp:nuage',
            'network_id': network['id']
        }
        dhcp_port = self.ports_client.list_ports(**filters)['ports'][0]
        self.assertEqual('ACTIVE', dhcp_port['status'])

    @decorators.attr(type='smoke')
    def test_nuage_port_create_show_check_status(self):
        network = self.create_network()
        self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                           mask_bits=24)
        port = self.create_port(network)
        self.assertEqual('DOWN', port['status'])
        port = self.show_port(port['id'])
        # state has to remain DOWN as long as port is not bound
        self.assertEqual('DOWN', port['status'])

    @decorators.attr(type='smoke')
    def test_nuage_port_with_vm_create_delete_check_status_with_vm(self):
        network = self.create_network()
        self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                           mask_bits=24)
        port = self.create_port(network)
        server = self._create_a_server('s1', network, port['id'])
        port = self.show_port(port['id'])
        self.assertEqual('ACTIVE', port['status'])
        self._delete_server(server['id'])
        port = self.show_port(port['id'])
        self.assertEqual('DOWN', port['status'])

    @decorators.attr(type='smoke')
    def test_nuage_port_create_fixed_ips_negative(self):
        # Set up resources
        # Base resources
        if self.is_dhcp_agent_present():
            raise self.skipException(
                'Cannot run this test case when DHCP agent is enabled')
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        subnet2 = self.create_subnet(network, cidr=IPNetwork("20.0.0.0/24"),
                                     mask_bits=28)
        self.assertIsNotNone(subnet2, "Unable to create second subnet")

        fixed_ips = [
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "20.0.0.4",
                "subnet_id": subnet2["id"]
            }
        ]
        # Fail
        msg = "Port can't have multiple IPv4 IPs of different subnets"
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_port,
                               network=network, fixed_ips=fixed_ips)

    def test_nuage_os_managed_subnet_port_create_with_nuage_policy_negative(
            self):

        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")

        msg = ("Cannot use VSP policy groups on OS managed subnets,"
               " use neutron security groups instead.")

        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_port,
                               network=network,
                               nuage_policy_groups=['Random_value'])

    def test_nuage_os_managed_subnet_port_update_with_nuage_policy_negative(
            self):

        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")

        port = self.create_port(network=network)

        self.assertIsNotNone(port, "Unable to create port")

        msg = ("Cannot use VSP policy groups on OS managed subnets,"
               " use neutron security groups instead.")

        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.update_port,
                               port=port,
                               nuage_policy_groups=['Random_value'])

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
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.router_attach(router, subnet)
        self.router_attach(router, subnet2)
        # Create port
        fixed_ips = [
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")

        # update within subnet should succeed
        fixed_ips = [
            {
                "ip_address": "10.0.0.5",
                "subnet_id": subnet["id"]
            }

        ]
        port = self.update_port(port=port, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to update port")
        self.assertEqual(port["fixed_ips"][0]["ip_address"], "10.0.0.5",
                         message="The port did not update properly.")

        # Update to subnet2 should fail
        fixed_ips = [
            {
                "ip_address": "20.0.0.4",
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

    def _nuage_port_update_fixed_ips_dual_subnets_with_vm(self, is_l2):
        network = self.create_network()
        subnetv4 = self.create_subnet(network, cidr=IPNetwork(
            "10.0.0.0/24"), cleanup=False)
        subnetv6 = self.create_subnet(network,
                                      cidr=IPNetwork("cafe:babe::/64"),
                                      ip_version=6, cleanup=False)
        if is_l2:
            resource = constants.L2_DOMAIN
            router = None
        else:
            router = self.create_router(
                admin_state_up=True,
                external_network_id=self.ext_net_id)
            self.assertIsNotNone(router, "Unable to create router")
            # Attach subnet
            self.router_attach(router, subnetv6, cleanup=False)
            resource = constants.SUBNETWORK
        filters, filter_values = self.vsd_client.get_subnet_filters(subnetv4)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            resource,
            filters=filters,
            filter_values=filter_values)[0]
        fixed_ips = [
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "10.0.0.5",
                "subnet_id": subnetv4["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                cleanup=False)
        self.assertIsNotNone(port, "Unable to create port on network")
        self._create_a_server(name='vm-' + network['name'],
                              network=network, port_id=port['id'])
        vm_interface = self.vsd_client.get_vm_iface(
            resource, vsd_vport_parent['ID'],
            filters='externalID', filter_values=port['id'])[0]
        self.assertEqual(vm_interface['IPAddress'], "10.0.0.5")
        self.assertIsNone(vm_interface.get('IPv6Address'))
        # Fixed ips from pure ipv4 ips to dual ips
        fixed_ips = [
            {
                "ip_address": "10.0.0.6",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "10.0.0.7",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "cafe:babe::4",
                "subnet_id": subnetv6["id"]
            },
            {
                "ip_address": "cafe:babe::5",
                "subnet_id": subnetv6["id"]
            }
        ]
        port = self.update_port(port=port, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to update port")
        self.assertEqual(port["fixed_ips"], fixed_ips,
                         message="The port did not update properly.")
        vm_interface = self.vsd_client.get_vm_iface(
            resource, vsd_vport_parent['ID'],
            filters='externalID', filter_values=port['id'])[0]
        self.assertEqual(vm_interface['IPAddress'], "10.0.0.7")
        self.assertEqual(vm_interface['IPv6Address'], "cafe:babe::5/64")

        if not Topology.has_single_stack_v6_support():
            self.delete_port(port)
            if not is_l2:
                self.router_detach(router, subnetv6)
            self.delete_subnet(subnetv6)
            self.delete_subnet(subnetv4)

            return  # halt here - rest requires single-stack v6 support

        # Fixed ips from dual ips to pure ipv6 ips
        fixed_ips = [
            {
                "ip_address": "cafe:babe::6",
                "subnet_id": subnetv6["id"]
            },
            {
                "ip_address": "cafe:babe::7",
                "subnet_id": subnetv6["id"]
            }
        ]
        port = self.update_port(port=port, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to update port")
        self.assertEqual(port["fixed_ips"], fixed_ips,
                         message="The port did not update properly.")
        vm_interface = self.vsd_client.get_vm_iface(
            resource, vsd_vport_parent['ID'],
            filters='externalID', filter_values=port['id'])[0]
        self.assertEqual(vm_interface['IPv6Address'], "cafe:babe::7/64")
        self.assertIsNone(vm_interface.get('IPAddress'))

        # Delete ipv4 subnet to changing dualstack to pure ipv6 stack with vm
        self.delete_subnet(subnetv4)
        filters, filter_values = self.vsd_client.get_subnet_filters(subnetv6)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            resource,
            filters=filters,
            filter_values=filter_values)[0]
        self.assertEqual(vsd_vport_parent['IPType'], 'IPV6')
        # Create ipv6 subnet to changing pure ipv6 stack to dualstack with vm
        subnetv4 = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"))

        # Fixed ips from pure ipv6 ips to pure ipv4 ips
        fixed_ips = [
            {
                "ip_address": "10.0.0.8",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "10.0.0.9",
                "subnet_id": subnetv4["id"]
            }
        ]
        port = self.update_port(port=port, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to update port")
        self.assertEqual(port["fixed_ips"], fixed_ips,
                         message="The port did not update properly.")
        vm_interface = self.vsd_client.get_vm_iface(
            resource, vsd_vport_parent['ID'],
            filters='externalID', filter_values=port['id'])[0]
        self.assertEqual(vm_interface['IPAddress'], "10.0.0.9")
        self.assertIsNone(vm_interface.get('IPv6Address'))

        if not is_l2:
            self.router_detach(router, subnetv6)
            self.router_attach(router, subnetv4)
        # Delete ipv6 subnet to changing dualstack to pure ipv4 stack with vm
        self.delete_subnet(subnetv6)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            resource,
            filters='externalID',
            filter_values=network['id'])[0]
        self.assertEqual(vsd_vport_parent['IPType'], 'IPV4')
        # Create ipv6 subnet to changing pure ipv4 stack to dualstack with vm
        self.create_subnet(network, cidr=IPNetwork("cafe:babe::/64"),
                           ip_version=6)
        self.delete_port(port)

    @decorators.attr(type='smoke')
    def test_nuage_port_update_fixed_ips_dual_subnets_with_vm_l2(self):
        self._nuage_port_update_fixed_ips_dual_subnets_with_vm(is_l2=True)

    @decorators.attr(type='smoke')
    def test_nuage_port_update_fixed_ips_dual_subnets_with_vm_l3(self):
        self._nuage_port_update_fixed_ips_dual_subnets_with_vm(is_l2=False)

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
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.5",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.L2_DOMAIN,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
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
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.L2_DOMAIN,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
                         nuage_vport[0]['addressSpoofing'])

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
        port = self.update_port(port=port, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to update port")
        nuage_vport = self.vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
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
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.router_attach(router, subnet)
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
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.4']
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
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.router_attach(router, subnet)
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
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                port_security_enabled=False)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.4']
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
    @testtools.skipIf(CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed',
                      'VIP is in use in nuage_vsd_managed ipam case.')
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
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.router_attach(router, subnet)
        fixed_ips = [
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }
        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.5',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network,
                                fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
                         nuage_vport[0]['addressSpoofing'])

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
        port = self.update_port(port=port, fixed_ips=fixed_ips,
                                allowed_address_pairs=[],
                                security_groups=[],
                                port_security_enabled=False)
        self.assertIsNotNone(port, "Unable to update port")
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.4']
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
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.router_attach(router, subnet)
        fixed_ips = [
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
                         nuage_vport[0]['addressSpoofing'])

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
        port = self.update_port(port=port, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to update port")
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.4']
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

    @testtools.skipIf(not Topology.has_single_stack_v6_support(),
                      'No singe-stack v6 supported')
    @decorators.attr(type='smoke')
    def test_nuage_port_fixed_ips_update_dhcp_disabled_subnet_with_vm(self):
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnetv4 = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                      mask_bits=28, enable_dhcp=False)
        subnetv6 = self.create_subnet(network,
                                      cidr=IPNetwork("cafe:babe::/64"),
                                      ip_version=6, enable_dhcp=False)
        filters, filter_values = self.vsd_client.get_subnet_filters(subnetv4)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.L2_DOMAIN,
            filters=filters,
            filter_values=filter_values)[0]
        fixed_ips = [
            {
                "ip_address": "10.0.0.3",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "cafe:babe::3",
                "subnet_id": subnetv6["id"]
            },
            {
                "ip_address": "cafe:babe::4",
                "subnet_id": subnetv6["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        self._create_a_server(name='vm-' + network['name'],
                              network=network, port_id=port['id'])
        vm_interface = self.vsd_client.get_vm_iface(
            constants.L2_DOMAIN, vsd_vport_parent['ID'],
            filters='externalID', filter_values=port['id'])[0]
        self.assertEqual('10.0.0.4', vm_interface['IPAddress'])
        self.assertEqual(vm_interface['IPv6Address'], "cafe:babe::4/64")
        fixed_ips = [
            {
                "ip_address": "10.0.0.5",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "10.0.0.6",
                "subnet_id": subnetv4["id"]
            },
            {
                "ip_address": "cafe:babe::5",
                "subnet_id": subnetv6["id"]
            },
            {
                "ip_address": "cafe:babe::6",
                "subnet_id": subnetv6["id"]
            }
        ]
        port = self.update_port(port=port, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to update port")
        self.assertEqual(port["fixed_ips"], fixed_ips,
                         message="The port did not update properly.")
        vm_interface = self.vsd_client.get_vm_iface(
            constants.L2_DOMAIN, vsd_vport_parent['ID'],
            filters='externalID', filter_values=port['id'])[0]
        self.assertEqual(vm_interface['IPAddress'], "10.0.0.6")
        self.assertEqual(vm_interface['IPv6Address'], "cafe:babe::6/64")

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
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.5",
                "subnet_id": subnet["id"]
            }

        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.50',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.L2_DOMAIN,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_ENABLED,
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
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.L2_DOMAIN,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
                         nuage_vport[0]['addressSpoofing'])

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
            filter_values=port['id'])
        self.assertEqual(SPOOFING_ENABLED,
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
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.router_attach(router, subnet)
        if CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed':
            # vsd managed ipam requires nuage:vip port
            self.create_port(network=network,
                             fixed_ips=[{'ip_address': '10.0.0.6'}],
                             device_owner='nuage:vip')
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
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.4', allowed_address_pairs[0]['ip_address']]
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
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.router_attach(router, subnet)
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
        allowed_address_pairs = [{'ip_address': '1.1.1.5',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.4']
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
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.router_attach(router, subnet)
        fixed_ips = [
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
                         nuage_vport[0]['addressSpoofing'])

        if CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed':
            # vsd managed ipam requires nuage:vip port
            self.create_port(network=network,
                             fixed_ips=[{'ip_address': '10.0.0.6'}],
                             device_owner='nuage:vip')

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
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.update_port(port=port, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to update port")
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
                         nuage_vport[0]['addressSpoofing'])
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.4', allowed_address_pairs[0]['ip_address']]
        vip_mismatch = False
        if valid_vips and not nuage_vport_vips:
            vip_mismatch = True
        for nuage_vport_vip in nuage_vport_vips:
            if nuage_vport_vip['virtualIP'] not in valid_vips:
                vip_mismatch = True
            self.assertEqual(vip_mismatch, False)

    @decorators.attr(type='smoke')
    @testtools.skipIf(CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed',
                      'VIP is in use in nuage_vsd_managed ipam case.')
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
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.router_attach(router, subnet)
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
        allowed_address_pairs = [{'ip_address': '10.0.0.10',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
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

        self._create_a_server(name='vm-' + network['name'],
                              network=network, port_id=port['id'])

        # update within subnet should succeed
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
        allowed_address_pairs = [{'ip_address': '10.0.0.7',
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
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
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
    @testtools.skipIf(CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed',
                      'VIP is in use in nuage_vsd_managed ipam case.')
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
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.router_attach(router, subnet)
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
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
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

        self._create_a_server(name='vm-' + network['name'],
                              network=network, port_id=port['id'])

        # update within subnet should succeed
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
        allowed_address_pairs = [{'ip_address': '10.0.0.7',
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
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
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
    @testtools.skipIf(CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed',
                      'VIP is in use in nuage_vsd_managed ipam case.')
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
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.router_attach(router, subnet)
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
        allowed_address_pairs = [{'ip_address': '10.0.0.10',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
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

        self._create_a_server(name='vm-' + network['name'],
                              network=network, port_id=port['id'])
        fixed_ips = [
            {
                "ip_address": "10.0.0.8",
                "subnet_id": subnet["id"]
            }
        ]
        allowed_address_pairs = [{'ip_address': '10.0.0.6',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        self.create_port(network=network, fixed_ips=fixed_ips,
                         allowed_address_pairs=allowed_address_pairs)

        # update within subnet should succeed
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
        # below update will fail with proper roll back
        try:
            self.update_port(port=port, fixed_ips=fixed_ips)
            self.fail("Exception expected when updating to"
                      " a different subnet!")
        except exceptions.BadRequest as e:
            self.assertIn(self.msg_base +
                          'The IP Address 10.0.0.6 is currently in use '
                          'by subnet', str(e))
            filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
            vsd_vport_parent = self.vsd_client.get_global_resource(
                constants.SUBNETWORK,
                filters=filters,
                filter_values=filter_values)[0]
            nuage_vport = self.vsd_client.get_vport(
                constants.SUBNETWORK,
                vsd_vport_parent['ID'],
                filters='externalID',
                filter_values=port['id'])
            self.assertEqual(SPOOFING_DISABLED,
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
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.router_attach(router, subnet)
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
        allowed_address_pairs = [{'ip_address': '10.0.0.6',
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_ENABLED,
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
    @testtools.skipIf(CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed',
                      'VIP is in use in nuage_vsd_managed ipam case.')
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
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.router_attach(router, subnet)
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
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
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
                "ip_address": "10.0.0.5",
                "subnet_id": subnet["id"]
            },
            {
                "ip_address": "10.0.0.6",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.update_port(port=port, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to update port")
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_ENABLED,
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
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")

        if CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed':
            # vsd managed ipam requires nuage:vip port
            self.create_port(network=network,
                             fixed_ips=[{'ip_address': '10.0.0.6'}],
                             device_owner='nuage:vip')
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
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.create_port(network=network, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.L2_DOMAIN,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_ENABLED,
                         nuage_vport[0]['addressSpoofing'])
        # Attach subnet
        self.router_attach(router, subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport_vips = self.vsd_client.get_virtual_ip(
            constants.VPORT,
            nuage_vport[0]['ID'])
        valid_vips = ['10.0.0.4', allowed_address_pairs[0]['ip_address']]
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
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
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
            external_network_id=self.ext_net_id)
        self.assertIsNotNone(router, "Unable to create router")
        # Attach subnet
        self.router_attach(router, subnet)
        fixed_ips = [
            {
                "ip_address": "10.0.0.4",
                "subnet_id": subnet["id"]
            }
        ]
        port = self.create_port(network=network, fixed_ips=fixed_ips)
        self.assertIsNotNone(port, "Unable to create port on network")
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.SUBNETWORK,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
                         nuage_vport[0]['addressSpoofing'])

        if CONF.nuage_sut.ipam_driver == 'nuage_vsd_managed':
            # vsd managed ipam requires nuage:vip port
            self.create_port(network=network,
                             fixed_ips=[{'ip_address': '10.0.0.6'}],
                             device_owner='nuage:vip')

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
                                  'mac_address': 'fe:a0:36:4b:c8:70'}]
        port = self.update_port(port=port, fixed_ips=fixed_ips,
                                allowed_address_pairs=allowed_address_pairs)
        self.assertIsNotNone(port, "Unable to update port")
        nuage_vport = self.vsd_client.get_vport(
            constants.SUBNETWORK,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_DISABLED,
                         nuage_vport[0]['addressSpoofing'])
        valid_vips = ['10.0.0.4', allowed_address_pairs[0]['ip_address']]
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
        filters, filter_values = self.vsd_client.get_subnet_filters(subnet)
        vsd_vport_parent = self.vsd_client.get_global_resource(
            constants.L2_DOMAIN,
            filters=filters,
            filter_values=filter_values)[0]
        nuage_vport = self.vsd_client.get_vport(
            constants.L2_DOMAIN,
            vsd_vport_parent['ID'],
            filters='externalID',
            filter_values=port['id'])
        self.assertEqual(SPOOFING_ENABLED,
                         nuage_vport[0]['addressSpoofing'])

    @decorators.attr(type='smoke')
    def test_delete_unbound_port_with_hanging_vminterface(self):
        # OPENSTACK-2797
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        port = self.create_port(network=network, cleanup=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.manager.ports_client.delete_port,
                        port['id'])

        # Find vport
        l2domain = self.vsd.get_l2domain(by_subnet=subnet)
        vport = self.vsd.get_vport(l2domain=l2domain, by_port_id=port['id'])

        # Create "Fake" VM interface to simulate following behavior:
        # -> Port is being bound -> VM created -> port deleted ->
        # Port not bound but leftover VM on VSD
        vminterface = self.vsd.vspk.NUVMInterface(
            name='test-fip-vm', vport_id=vport.id,
            external_id=self.vsd.external_id(port['id']),
            mac='E6:04:AA:7A:AA:86', ip_address='10.0.0.10')
        vm = self.vsd.vspk.NUVM(name='test-port-delete-vm',
                                uuid='1339f7f4-f7a0-445f-b257-8dbfaf0d6fc8',
                                external_id=self.vsd.external_id(
                                    '1339f7f4-f7a0-445f-b257-8dbfaf0d6fc8'),
                                interfaces=[vminterface])
        # Impersonate tenant user for appropriate permissions on VM
        self.vsd.session().impersonate(port['tenant_id'],
                                       self.default_netpartition_name)
        self.vsd.session().user.create_child(vm)
        self.vsd.session().stop_impersonate()

        # Delete port, VM should be deleted in this request
        self.delete_port(port)

        # Verify that vport is deleted
        vport = self.vsd.get_vport(l2domain=l2domain, by_port_id=port['id'])
        self.assertIsNone(vport, 'Vport not deleted by Port delete statement')

    @testtools.skipIf(Topology.is_v5, 'Unsupported pre-6.0')
    def test_delete_ips_from_port_with_vm(self):
        # OPENSTACK-2808
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        port = self.create_port(network=network,
                                fixed_ips=[{'ip_address': '10.0.0.10'}],
                                cleanup=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.manager.ports_client.delete_port,
                        port['id'])

        self._create_a_server(name='vm-' + network['name'],
                              network=network, port_id=port['id'])
        # update port to not have ip
        self.update_port(port=port, fixed_ips=[])
        l2domain = self.vsd.get_l2domain(by_subnet=subnet)
        vport = self.vsd.get_vport(l2domain=l2domain, by_port_id=port['id'])
        self.assertIsNone(vport, "vport should be deleted by setting "
                                 "# fixed ips to 0.")

        # Re-add ip to port
        port = self.update_port(port=port, fixed_ips=port['fixed_ips'])
        vport = self.vsd.get_vport(l2domain=l2domain, by_port_id=port['id'])
        self.assertIsNotNone(vport, "Port updated to have ip,"
                                    "vport should exist.")
        vm_interfaces = vport.vm_interfaces.get()
        self.assertNotEmpty(vm_interfaces, "vm_interface not created.")
        vm_interface = vm_interfaces[0]

        self.assertEqual(port['device_id'], vm_interface.vmuuid,
                         "Port device id should be equal to vm_interface "
                         "attached VM uuid")

    def test_add_ips_from_port_with_vm(self):
        """test_add_ips_from_port_with_vm

        Test that adding an IP to a port results in the IP being updated in VSD

        """
        network = self.create_network()
        self.assertIsNotNone(network, "Unable to create network")

        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        self.assertIsNotNone(subnet, "Unable to create subnet")
        router = self.create_router()
        self.router_attach(router, subnet)
        port = self.create_port(network=network,
                                fixed_ips=[{'ip_address': '10.0.0.10'}],
                                cleanup=False)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.manager.ports_client.delete_port,
                        port['id'])

        self._create_a_server(name='vm-' + network['name'],
                              network=network, port_id=port['id'])

        # update port to have two ips
        port = self.update_port(port=port,
                                fixed_ips=[{'ip_address': '10.0.0.9'},
                                           {'ip_address': '10.0.0.10'}])

        l3subnet = self.vsd.get_subnet_from_domain(by_subnet=subnet)
        vport = self.vsd.get_vport(subnet=l3subnet, by_port_id=port['id'])
        self.assertIsNotNone(vport, "Port updated to have two ips,"
                                    "vport should exist.")
        vips = vport.virtual_ips.get()
        self.assertNotEmpty(vips, "vip not created.")
        vip = vips[0]
        self.assertEqual('10.0.0.9', vip.virtual_ip,
                         "Port lowest ip address should be equal to "
                         "vip ip address")
        vm_interfaces = vport.vm_interfaces.get()
        self.assertNotEmpty(vm_interfaces, "vm_interface not created.")
        vm_interface = vm_interfaces[0]
        self.assertEqual(port['device_id'], vm_interface.vmuuid,
                         "Port device id should be equal to vm_interface "
                         "attached VM uuid")
        self.assertEqual('10.0.0.10', vm_interface.ip_address,
                         "Port highest ip address should be equal to "
                         "vm_interface ip address")

    @testtools.skipIf(Topology.is_v5 or Topology.at_nuage('20.5'),
                      'Unsupported pre-6.0 and in 20.5')
    def test_remove_device_id_before_vm_delete_with_vm(self):
        """test_remove_device_id_before_vm_delete_with_vm

        This test deletes the port before deleting the VM in Nova. This
        simulates the scenario where there is a delay between resetting the
        device_id and deleting the VM. In this case Nova will not call Neutron
        to clear the binding.

        Create Port
        Create server using Port
        reset device_id to "" for Port
        Assert VMInterface deleted from VSD
        Delete Port
        Delete VM
        """
        # Create Port
        network = self.create_network()
        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        port = self.create_port(network=network)

        # Create Server using Port
        server = self._create_a_server(name='vm-' + network['name'],
                                       network=network, port_id=port['id'])
        # Reset device_id to "" for Port
        self.update_port(port=port, device_id='', device_owner='')

        # Assert VMInterface deleted on VSD
        l2domain = self.vsd.get_l2domain(by_subnet=subnet)
        vport = self.vsd.get_vport(l2domain=l2domain, by_port_id=port['id'])
        vm_interfaces = vport.vm_interfaces.get()
        self.assertEmpty(vm_interfaces)

        # Delete Port
        self.delete_port(port)
        vport = self.vsd.get_vport(l2domain=l2domain, by_port_id=port['id'])
        self.assertIsNone(vport)

        # Delete VM
        self.delete_server(server['id'])

    @testtools.skipIf(Topology.is_v5 or Topology.at_nuage('20.5'),
                      'Unsupported pre-6.0 and in 20.5')
    def test_remove_device_id_before_vm_delete_no_waiting_with_vm(self):
        """test_remove_device_id_before_vm_delete_no_waiting_with_vm

        This test does not wait between deleting the device_id and deleting
        the Server. This triggers different behavior in Nova.
        In this scenario it will still clear the neutron Port as normal, while
        in the case where a wait is introduced, nova will not call neutron.

        Create Port
        Create server using Port
        reset device_id to "" for Port
        Delete VM
        Assert VMInterface deleted on VSD
        Delete Port
        """
        # Create Port
        network = self.create_network()
        subnet = self.create_subnet(network, cidr=IPNetwork("10.0.0.0/24"),
                                    mask_bits=28)
        port = self.create_port(network=network)

        # Create Server using Port
        server = self._create_a_server(name='vm-' + network['name'],
                                       network=network, port_id=port['id'])
        # Reset device_id to "" for Port
        self.update_port(port=port, device_id='', device_owner='')

        # Delete VM & wait for server deletion
        self.delete_server(server['id'])

        # Assert VMInterface deleted on VSD
        l2domain = self.vsd.get_l2domain(by_subnet=subnet)
        vport = self.vsd.get_vport(l2domain=l2domain, by_port_id=port['id'])
        vm_interfaces = vport.vm_interfaces.get()
        self.assertEmpty(vm_interfaces)

        # Delete port
        self.delete_port(port)
        vport = self.vsd.get_vport(l2domain=l2domain, by_port_id=port['id'])
        self.assertIsNone(vport)
