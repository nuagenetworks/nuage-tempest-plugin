# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

import copy
import functools
import inspect
import os.path
from oslo_utils import excutils
import pymysql
import re
import testtools
import yaml

from netaddr import IPAddress
from netaddr import IPNetwork
from netaddr import IPRange
from oslo_log import log as oslo_logging

from testtools.matchers import ContainsDict
from testtools.matchers import Equals

from nuage_tempest.lib.features import NUAGE_FEATURES
from nuage_tempest.lib.test import tags as test_tags
from nuage_tempest.lib.test.tenant_server import TenantServer
from nuage_tempest.lib.test import vsd_helper
from nuage_tempest.lib.topology import Topology

from nuage_tempest.lib.utils import constants as nuage_constants
from nuage_tempest.services.nuage_client import NuageRestClient

from tempest.common import waiters
from tempest import config
from tempest.lib.common import rest_client
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest.scenario import manager
from tempest.services import orchestration

CONF = config.CONF
LOG = oslo_logging.getLogger(__name__)


# noinspection PyUnusedLocal
def nuage_skip_because(*args, **kwargs):
    """A decorator useful to skip tests hitting known bugs

    @param bug: bug number causing the test to skip
    @param condition: optional condition to be True for the skip to have place
    @param interface: skip the test if it is the same as self._interface
    """
    def decorator(f):
        # noinspection PyUnusedLocal
        @functools.wraps(f)
        def wrapper(self, *func_args, **func_kwargs):
            msg = "UNDEFINED"
            if "message" in func_kwargs:
                message = func_kwargs["message"]

                msg = "Skipped because: %s" % message
                if message.startswith("OPENSTACK_") or \
                        message.startswith("VSD_"):
                    uri = "http://mvjira.mv.usa.alcatel.com/browse/" + message
                    msg += "\n"
                    msg += uri

            raise testtools.TestCase.skipException(msg)
        return wrapper
    return decorator


def header(tags=None, since=None, until=None):
    """A decorator to log info on the test, add tags and release filtering.

    :param tags: A set of tags to tag the test with. header(tags=['smoke'])
    behaves the same as test.attr(type='smoke'). It exists for convenience.
    :param since: Optional. Mark a test with a 'since' release version to
    indicate this test should only run on setups with release >= since
    :param until: Optional. Mark a test with a 'until' release version to
    indicate this test should only run on setups with release < until
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(self, *func_args, **func_kwargs):

            if f.func_code.co_name != 'wrapper':
                LOG.info("TEST CASE STARTED: {}".format(f.func_code.co_name))

                # Dump the message + the name of this function to the log.
                LOG.info("in {}:{}".format(
                    f.func_code.co_filename,
                    f.func_code.co_firstlineno
                ))

            result = f(self, *func_args, **func_kwargs)

            if f.func_code.co_name != 'wrapper':
                LOG.info("TEST CASE COMPLETED: {}".format(f.func_code.co_name))
            return result

        _add_tags_to_method(tags, wrapper)
        if since:
            wrapper._since = since
        if until:
            wrapper._until = until
        return wrapper
    return decorator


def _add_tags_to_method(tags, wrapper):
    if tags:
        if isinstance(tags, str):
            tags = {tags}
        else:
            tags = tags
        try:
            existing = copy.deepcopy(wrapper.__testtools_attrs)
            # deepcopy the original one, otherwise it will affect other
            # classes which extend this class.
            if test_tags.ML2 in tags and test_tags.MONOLITHIC in existing:
                existing.remove(test_tags.MONOLITHIC)
            if test_tags.MONOLITHIC in tags and test_tags.ML2 in existing:
                existing.remove(test_tags.ML2)
            existing.update(tags)
            wrapper.__testtools_attrs = existing
        except AttributeError:
            wrapper.__testtools_attrs = set(tags)


def class_header(tags=None, since=None, until=None):
    """Applies the header decorator to all test_ methods of this class.

    :param tags: Optional. A set of tags to tag the test with.
    header(tags=['smoke']) behaves the same as test.attr(type='smoke'). It
    exists for convenience.
    :param since: Optional. Mark a test with a 'since' release version to
    indicate this test should only run on setups with release >= since
    :param until: Optional. Mark a test with a 'until' release version to
    indicate this test should only run on setups with release < until
    """
    method_wrapper = header(tags=tags, since=since, until=until)

    def decorator(cls):
        for name, method in inspect.getmembers(cls, inspect.ismethod):
            if name.startswith('test_'):
                setattr(cls, name, method_wrapper(method))
        return cls
    return decorator


class NuageBaseTest(manager.NetworkScenarioTest):

    """NuageBaseTest

    Base class for all testcases.
    This class will have all the common function and will initiate object
    of other class in setup_client rather then inheritance.
    """
    # Default to ipv4.
    _ip_version = 4

    credentials = ['primary', 'admin']

    default_netpartition_name = CONF.nuage.nuage_default_netpartition
    default_enterprise = None  # the default enterprise

    image_name_to_id_cache = {}

    @classmethod
    def _base_uri_to_version(cls, base_uri):
        pattern = re.compile(r'(\d+_\d+)')
        match = pattern.search(base_uri)
        version = match.group()
        version = "v" + str(version)
        return version

    @classmethod
    def setup_credentials(cls):
        super(NuageBaseTest, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        super(NuageBaseTest, cls).setup_clients()
        cls.manager = cls.get_client_manager()
        cls.admin_manager = cls.get_client_manager(credential_type='admin')

        cls.nuage_vsd_client = NuageRestClient()

        version = cls._base_uri_to_version(CONF.nuage.nuage_base_uri)
        address = CONF.nuage.nuage_vsd_server
        cls.vsd = vsd_helper.VsdHelper(address, version=version)

    @classmethod
    def resource_setup(cls):
        super(NuageBaseTest, cls).resource_setup()
        cls.setup_network_resources(cls)

    @classmethod
    def resource_cleanup(cls):
        super(NuageBaseTest, cls).resource_cleanup()

    def setUp(self):
        super(NuageBaseTest, self).setUp()

    def skipTest(self, reason):
        LOG.warn('TEST SKIPPED: ' + reason)
        super(NuageBaseTest, self).skipTest(reason)

    @staticmethod
    # As reused by other classes, left as static and passing cls explicitly
    def setup_network_resources(cls):
        cls.cidr4 = IPNetwork(CONF.network.project_network_cidr)
        cls.mask_bits4 = CONF.network.project_network_mask_bits
        cls.mask_bits4_unsliced = cls.prefix_length(cls.cidr4)
        assert cls.mask_bits4 >= cls.mask_bits4_unsliced
        cls.gateway4 = str(IPAddress(cls.cidr4) + 1)
        cls.netmask4 = str(cls.cidr4.netmask)

        cls.cidr6 = IPNetwork(CONF.network.project_network_v6_cidr)
        cls.mask_bits6 = cls.prefix_length(cls.cidr6)

        # TODO(Kris) this needs to go out but i need to find out how
        if cls.mask_bits6 < 64:
            cls.cidr6 = IPNetwork('cafe:babe::/64')
            cls.mask_bits6 = 64

        cls.gateway6 = str(IPAddress(cls.cidr6) + 1)

        cls.net_partition = CONF.nuage.nuage_default_netpartition

        LOG.info("setup_network_resources: ipv4 config: {}"
                 .format(str(cls.cidr4)))
        LOG.info("setup_network_resources: ipv6 config: {}"
                 .format(str(cls.cidr6)))

    @staticmethod
    def sleep(seconds, msg=None):
        if not msg:
            LOG.error(
                "Added a {}s sleep without clarification. "
                "Please add motivation for this sleep.".format(seconds))
        else:
            LOG.warning("Sleeping for {}s. {}.".format(seconds, msg))

    @staticmethod
    def prefix_length(cidr):
        return cidr._prefixlen

    def create_network(self, network_name=None, client=None,
                       cleanup=True, **kwargs):
        """Wrapper utility that returns a test network."""
        network_name = network_name or data_utils.rand_name('test-network')

        if not client:
            client = self.manager

        body = client.networks_client.create_network(
            name=network_name, **kwargs)
        network = body['network']
        if cleanup:
            self.addCleanup(
                client.networks_client.delete_network, network['id'])
        return network

    def create_subnet(self, network, subnet_name=None, gateway='', cidr=None,
                      mask_bits=None,
                      ip_version=None, client=None, cleanup=True, **kwargs):
        """Wrapper utility that returns a test subnet."""
        # allow tests to use admin client
        if not client:
            client = self.manager

        subnet_name = subnet_name or data_utils.rand_name('test-subnet-')

        # The cidr and mask_bits depend on the ip version.
        ip_version = ip_version if ip_version is not None else self._ip_version
        gateway_not_set = gateway == ''
        if ip_version == 4:
            cidr = cidr or self.cidr4
            if mask_bits is None:
                mask_bits = self.mask_bits4
        elif ip_version == 6:
            cidr = cidr or self.cidr6
            if mask_bits is None:
                mask_bits = self.mask_bits6

        if mask_bits < cidr.prefixlen:
            msg = ('mask_bits of {} does not allow for subnet creation'
                   'in cidr {}.').format(mask_bits, cidr)
            raise ValueError(msg)

        # Find a cidr that is not in use yet and create a subnet with it
        for subnet_cidr in cidr.subnet(mask_bits):
            if gateway_not_set:
                gateway_ip = str(IPAddress(subnet_cidr) + 1)
            else:
                gateway_ip = gateway
            try:
                body = client.subnets_client.create_subnet(
                    name=subnet_name,
                    network_id=network['id'],
                    cidr=str(subnet_cidr),
                    ip_version=ip_version,
                    gateway_ip=gateway_ip,
                    **kwargs)
                break
            except lib_exc.BadRequest as e:
                is_overlapping_cidr = 'overlaps with another subnet' in str(e)
                if not is_overlapping_cidr:
                    raise
        else:
            message = 'Available CIDR for subnet creation could not be found'
            # raise exceptions.BuildErrorException(message)  # QA repo
            raise ValueError(message)  # dev repo
        subnet = body['subnet']

        if cleanup:
            self.addCleanup(client.subnets_client.delete_subnet, subnet['id'])
        return subnet

    def update_subnet(self, subnet, client=None, **kwargs):
        """Wrapper utility that updates a test subnet."""
        if not client:
            client = self.manager
        body = client.subnets_client.update_subnet(subnet['id'],
                                                   **kwargs)
        return body['subnet']

    def create_l2_vsd_managed_subnet(self, network, vsd_l2domain, ip_version=4,
                                     dhcp_managed=True):
        if not isinstance(vsd_l2domain, self.vsd.vspk.NUL2Domain):
            self.fail("Must have an VSD L2 domain")

        if ip_version == 4:
            cidr = IPNetwork(vsd_l2domain.address + "/" +
                             vsd_l2domain.netmask),
            gateway = vsd_l2domain.gateway,
        elif ip_version == 6:
            gateway = vsd_l2domain.ipv6_gateway,
            cidr = IPNetwork(vsd_l2domain.ipv6_address),
        else:
            self.fail("IP version {} is not supported".format(ip_version))

        subnet = self.create_subnet(
            network,
            enable_dhcp=dhcp_managed,
            ip_version=ip_version,
            cidr=cidr[0],
            mask_bits=cidr[0].prefixlen,
            gateway=gateway[0],
            nuagenet=vsd_l2domain.id,
            net_partition=vsd_l2domain.parent_object.name)

        return subnet

    def create_l3_vsd_managed_subnet(self, network, vsd_subnet,
                                     dhcp_managed=True, ip_version=4):
        if not isinstance(vsd_subnet, self.vsd.vspk.NUSubnet):
            self.fail("Must have an VSD L3 subnet")

        if ip_version == 4:
            cidr = IPNetwork(vsd_subnet.address + "/" + vsd_subnet.netmask),
            gateway = vsd_subnet.gateway,
        elif ip_version == 6:
            gateway = vsd_subnet.ipv6_gateway,
            cidr = IPNetwork(vsd_subnet.ipv6_address),
        else:
            self.fail("IP version {} is not supported".format(ip_version))

        # subnet -> zone -> domain -> enterprise
        net_partition = \
            vsd_subnet.parent_object.parent_object.parent_object.name

        subnet = self.create_subnet(
            network,
            enable_dhcp=dhcp_managed,
            ip_version=ip_version,
            cidr=cidr[0],
            mask_bits=cidr[0].prefixlen,
            gateway=gateway[0],
            nuagenet=vsd_subnet.id,
            net_partition=net_partition)

        return subnet

    def create_port(self, network, client=None, cleanup=True, **kwargs):
        """Wrapper utility that returns a test port."""
        if not client:
            client = self.manager
        body = client.ports_client.create_port(network_id=network['id'],
                                               **kwargs)
        port = body['port']
        if cleanup:
            self.addCleanup(client.ports_client.delete_port, port['id'])
        return port

    def update_port(self, port, client=None, **kwargs):
        """Wrapper utility that updates a test port."""
        if not client:
            client = self.manager
        body = client.ports_client.update_port(port['id'],
                                               **kwargs)
        return body['port']

    def _verify_port(self, port, subnet4=None, subnet6=None, **kwargs):
        has_ipv4_ip = False
        has_ipv6_ip = False

        for fixed_ip in port['fixed_ips']:
            ip_address = fixed_ip['ip_address']
            if subnet4 and fixed_ip['subnet_id'] == subnet4['id']:
                start_ip_address = subnet4['allocation_pools'][0]['start']
                end_ip_address = subnet4['allocation_pools'][0]['end']
                ip_range = IPRange(start_ip_address, end_ip_address)
                self.assertIn(ip_address, ip_range)
                has_ipv4_ip = True

            if subnet6 and fixed_ip['subnet_id'] == subnet6['id']:
                start_ip_address = subnet6['allocation_pools'][0]['start']
                end_ip_address = subnet6['allocation_pools'][0]['end']
                ip_range = IPRange(start_ip_address, end_ip_address)
                self.assertIn(ip_address, ip_range)
                has_ipv6_ip = True

        if subnet4:
            self.assertTrue(
                has_ipv4_ip,
                "Must have an IPv4 ip in subnet: %s" % subnet4['id'])

        if subnet6:
            self.assertTrue(
                has_ipv6_ip,
                "Must have an IPv6 ip in subnet: %s" % subnet6['id'])

        self.assertIsNotNone(port['mac_address'])

        # verify all other kwargs as attributes (key,value) pairs
        for key, value in kwargs.iteritems():
            if isinstance(value, dict):
                # compare dict
                # replaced throwing NotImplementedError as that makes
                # the class abstract
                self.fail('isinstance(value, dict) not implemented')
            if isinstance(value, list):
                # self.assertThat(port, ContainsDict({key: Equals(value)}))
                self.assertItemsEqual(port[key], value)
            else:
                self.assertThat(port, ContainsDict({key: Equals(value)}))

    def _verify_vport_in_l2_domain(self, port, vsd_l2domain, **kwargs):
        nuage_vports = self.nuage_vsd_client.get_vport(
            nuage_constants.L2_DOMAIN,
            vsd_l2domain.id,
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(
            len(nuage_vports), 1,
            "Must find one VPort matching port: %s" % port['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport,
                        ContainsDict({'name': Equals(port['id'])}))

        # verify all other kwargs as attributes (key,value) pairs
        for key, value in kwargs.iteritems():
            if isinstance(value, dict):
                # compare dict
                # replaced throwing NotImplementedError as that makes
                # the class abstract
                self.fail('isinstance(value, dict) not implemented')
            if isinstance(value, list):
                # self.assertThat(port, ContainsDict({key: Equals(value)}))
                self.assertItemsEqual(port[key], value)
            else:
                self.assertThat(port, ContainsDict({key: Equals(value)}))

    def _verify_vport_in_l3_subnet(self, port, vsd_l3_subnet, **kwargs):
        nuage_vports = self.nuage_vsd_client.get_vport(
            nuage_constants.SUBNETWORK,
            vsd_l3_subnet.id,
            filters='externalID',
            filter_value=port['id'])
        self.assertEqual(
            len(nuage_vports), 1,
            "Must find one VPort matching port: %s" % port['name'])
        nuage_vport = nuage_vports[0]
        self.assertThat(nuage_vport,
                        ContainsDict({'name': Equals(port['id'])}))

        # verify all other kwargs as attributes (key,value) pairs
        for key, value in kwargs.iteritems():
            if isinstance(value, dict):
                # compare dict
                # replaced throwing NotImplementedError as that makes
                # the class abstract
                self.fail('isinstance(value, dict) not implemented')
            if isinstance(value, list):
                # self.assertThat(port, ContainsDict({key: Equals(value)}))
                self.assertItemsEqual(port[key], value)
            else:
                self.assertThat(port, ContainsDict({key: Equals(value)}))

    def create_test_router(self):
        if Topology.telnet_console_access_to_vm_enabled():
            return self.create_router()  # can be an isolated router
        else:
            return self.create_public_router()  # needs FIP access

    def create_public_router(self, delay_cleanup_for_nuage_bug=False):
        return self.create_router(
            external_network_id=CONF.network.public_network_id,
            delay_cleanup_for_nuage_bug=delay_cleanup_for_nuage_bug)

    def create_router(self, router_name=None, admin_state_up=True,
                      external_network_id=None, enable_snat=None,
                      client=None, cleanup=True,
                      delay_cleanup_for_nuage_bug=False, **kwargs):
        """Wrapper utility that creates a router."""
        ext_gw_info = {}
        router_name = router_name or data_utils.rand_name('test-router-')
        if not client:
            client = self.manager
        if external_network_id:
            ext_gw_info['network_id'] = external_network_id
        if enable_snat is not None:
            ext_gw_info['enable_snat'] = enable_snat
        body = client.routers_client.create_router(
            name=router_name, external_gateway_info=ext_gw_info,
            admin_state_up=admin_state_up, **kwargs)
        router = body['router']
        if cleanup:
            self.addCleanup(self.delete_router, router, client,
                            delay_cleanup_for_nuage_bug)
        return router

    # TODO(TEAM) - OPENSTACK-1880 : DELETE ROUTER OFTEN FAILS WHEN
    # TODO(TEAM) - DONE TOO SOON AFTER SUBNET DETACH. MEANWHILE THIS IS A
    # TODO(TEAM) - WORK-AROUND, BY GIVING DELAY TO THIS METHOD
    def delete_router(self, router, client=None,
                      delay_cleanup_for_nuage_bug=False):
        if not client:
            client = self.manager
        if delay_cleanup_for_nuage_bug:
            nbr_attempts = 3
            attempt = 1
            while attempt <= nbr_attempts:
                try:
                    self.sleep(attempt)
                    client.routers_client.delete_router(router['id'])
                    break
                except lib_exc.ServerFault as e:
                    if 'Nuage API: vPort has VMInterface network interfaces ' \
                            'associated with it.' not in str(e):
                        raise e
                    LOG.error('Domain deletion failed! (%d)', attempt)
                    attempt += 1

        else:
            client.routers_client.delete_router(router['id'])

    def create_floatingip(self, external_network_id=None,
                          client=None, cleanup=True):
        """Wrapper utility that creates a floating IP."""
        if not external_network_id:
            external_network_id = CONF.network.public_network_id
        if not client:
            client = self.manager
        body = client.floating_ips_client.create_floatingip(
            floating_network_id=external_network_id)
        fip = body['floatingip']
        if cleanup:
            self.addCleanup(client.floating_ips_client.delete_floatingip,
                            fip['id'])
        return fip

    def create_associate_vsd_managed_floating_ip(self, server, port_id=None,
                                                 vsd_domain=None,
                                                 vsd_subnet=None,
                                                 external_network_id=None):
        if not external_network_id:
            external_network_id = CONF.network.public_network_id
        if not port_id:
            port_id, ip4 = self._get_server_port_id_and_ip4(server)

        floatingip_subnet_id = self.osc_list_networks(
            id=external_network_id)[0]['subnets'][0]
        filter = self.vsd.get_external_id_filter(
            floatingip_subnet_id
        )
        shared_network_resource_id = self.vsd.get_shared_network_resource(
            filter=filter
        ).id
        # Create floating ip
        floating_ip = self.vsd.create_floating_ip(
            vsd_domain,
            shared_network_resource_id=shared_network_resource_id)
        self.addCleanup(floating_ip.delete)
        # Associate floating ip
        filter = self.vsd.get_external_id_filter(port_id)
        vport = self.vsd.get_vport(vsd_subnet, filter=filter)
        vport.associated_floating_ip_id = floating_ip.id
        vport.save()

        def cleanup_floatingip_vport(vport):
            vport.associated_floating_ip_id = None
            vport.save()

        self.addCleanup(cleanup_floatingip_vport, vport)
        return floating_ip

    def update_floatingip(self, floatingip, client=None, **kwargs):
        """Wrapper utility that updates a floating IP."""
        if not client:
            client = self.manager
        body = client.floating_ips_client.update_floatingip(
            floatingip["id"], **kwargs)
        fip = body['floatingip']
        return fip

    def create_router_interface(self, router_id, subnet_id, client=None,
                                cleanup=True):
        """Wrapper utility that creates a router interface."""
        if not client:
            client = self.manager
        interface = client.routers_client.add_router_interface(
            router_id, subnet_id=subnet_id)
        if cleanup:
            self.addCleanup(self.remove_router_interface, router_id, subnet_id,
                            client)
        return interface

    def remove_router_interface(self, router_id, subnet_id, client=None):
        """Wrapper utility that removes a router interface."""
        if not client:
            client = self.manager
        client.routers_client.remove_router_interface(
            router_id, subnet_id=subnet_id)

    def router_attach(self, router, subnet, cleanup=True):
        self.create_router_interface(router['id'], subnet['id'],
                                     cleanup=cleanup)

    def router_detach(self, router, subnet):
        self.remove_router_interface(router['id'], subnet['id'])

    def osc_get_database_table_row(self, table_name, row=0,
                                   assert_table_size=None):
        db_name = 'neutron'
        db_username = Topology.database_user
        db_password = Topology.database_password
        db_cmd = 'SELECT * FROM ' + table_name

        if Topology.is_devstack():
            db_connection = pymysql.connect(host='localhost',
                                            user=db_username,
                                            passwd=db_password,
                                            db=db_name)
            cursor = db_connection.cursor()
            cursor.execute(db_cmd)
            db_row_cnt = cursor.rowcount
            db_row = cursor.fetchone() if row == 0 else cursor.fetchall()[row]
            db_connection.close()
        else:
            output = self.TB.osc_1.cmd(
                'mysql -u ' + db_username + ' -p' + db_password +
                ' -D ' + db_name + ' -e \"' + db_cmd + ';\"')
            db_row_cnt = len(output)
            db_row = output[row][1].split('\t')

        if assert_table_size is not None:
            assert db_row_cnt == assert_table_size

        return db_row

    def osc_list_networks(self, client=None, *args, **kwargs):
        """List networks using admin creds else provide client """
        if not client:
            client = self.admin_manager
        networks_list = client.networks_client.list_networks(
            *args, **kwargs)
        return networks_list['networks']

    def osc_list_subnets(self, client=None, *args, **kwargs):
        """List subnets using admin creds else provide client"""
        if not client:
            client = self.admin_manager
        subnets_list = client.subnets_client.list_subnets(
            *args, **kwargs)
        return subnets_list['subnets']

    def osc_list_routers(self, client=None, *args, **kwargs):
        """List routers using admin creds else provide client"""
        if not client:
            client = self.admin_manager
        routers_list = client.routers_client.list_routers(
            *args, **kwargs)
        return routers_list['routers']

    def osc_list_ports(self, client=None, *args, **kwargs):
        """List ports using admin creds else provide client"""
        if not client:
            client = self.admin_manager
        ports_list = client.ports_client.list_ports(
            *args, **kwargs)
        return ports_list['ports']

    def osc_get_server_port_in_network(self, server, network):
        return self.osc_list_ports(
            device_id=server.id(),
            network_id=network['id'])[0]

    def osc_list_server(self, server_id, client=None):
        """List server using admin creds else provide client"""
        if not client:
            client = self.admin_manager
        server_list = client.servers_client.show_server(server_id)
        return server_list['server']

    def osc_get_image_id(self, image_name, client=None):
        # check cache first
        if image_name in self.image_name_to_id_cache:
            return self.image_name_to_id_cache[image_name]

        if not client:
            client = self.manager
        images = client.image_client_v2.list_images()
        for i in images['images']:
            if image_name == i['name']:
                self.image_name_to_id_cache[image_name] = i['id']
                return i['id']
        return None

    def osc_server_add_interface(self, server, port, client=None):
        if not client:
            client = self.manager
        port_id = port['id']
        iface = client.interfaces_client.create_interface(
            server.server_details['id'],
            port_id=port_id)['interfaceAttachment']
        iface = waiters.wait_for_interface_status(
            client.interfaces_client, server.server_details['id'],
            iface['port_id'], 'ACTIVE')
        self.addCleanup(
            client.interfaces_client.delete_interface,
            server.server_details['id'],
            iface['port_id'])

    # noinspection PyBroadException
    def osc_create_test_server(self, client=None, tenant_networks=None,
                               ports=None, wait_until='ACTIVE',
                               volume_backed=False, name=None, flavor=None,
                               image_id=None, cleanup=True, **kwargs):
        """Common wrapper utility returning a test server.

        :param client: Client manager which provides OpenStack Tempest clients.
        :param tenant_networks: Tenant networks used for creating the server.
        :param ports: Tenant ports used for creating the server.
        :param wait_until: Server status to wait for the server to reach after
        its creation.
        :param volume_backed: Whether the instance is volume backed or not.
        :param name: Instance name.
        :param flavor: Instance flavor.
        :param image_id: Instance image ID.
        :param cleanup: Flag for cleanup (leave True for auto-cleanup).
        :returns: a tuple
        """
        if not client:
            client = self.manager

        if name is None:
            name = data_utils.rand_name(__name__ + "-instance")
        if flavor is None:
            flavor = CONF.compute.flavor_ref
        if image_id is None:
            image_id = CONF.compute.image_ref

        params = copy.copy(kwargs) or {}
        if tenant_networks:
            params.update({"networks": []})
            for network in tenant_networks:
                if 'id' in network.keys():
                    params['networks'].append({'uuid': network['id']})
        if ports:
            params.update({"networks": []})
            for port in ports:
                if 'id' in port.keys():
                    params['networks'].append({'port': port['id']})

        kwargs = copy.copy(params) or {}
        if volume_backed:
            volume_name = data_utils.rand_name('volume')
            volumes_client = client.volumes_v2_client
            if CONF.volume_feature_enabled.api_v1:
                volumes_client = client.volumes_client
            volume = volumes_client.create_volume(
                display_name=volume_name,
                imageRef=image_id)
            volumes_client.wait_for_volume_status(volume['volume']['id'],
                                                  'available')

            bd_map_v2 = [{
                         'uuid': volume['volume']['id'],
                         'source_type': 'volume',
                         'destination_type': 'volume',
                         'boot_index': 0,
                         'delete_on_termination': True}]
            kwargs['block_device_mapping_v2'] = bd_map_v2

            # Since this is boot from volume an image does not need
            # to be specified.
            image_id = ''

        body = client.servers_client.create_server(name=name,
                                                   imageRef=image_id,
                                                   flavorRef=flavor,
                                                   **kwargs)

        # get the servers
        vm = rest_client.ResponseBody(body.response, body['server'])
        LOG.info("Id of vm %s", vm['id'])

        if wait_until:
            try:
                waiters.wait_for_server_status(client.servers_client,
                                               vm['id'], wait_until)

            except Exception:
                with excutils.save_and_reraise_exception():
                    if ('preserve_server_on_error' not in kwargs or
                            kwargs['preserve_server_on_error'] is False):
                        try:
                            client.servers_client.delete_server(vm['id'])
                        except Exception:
                            LOG.exception(
                                'Deleting server %s failed', vm['id'])

        def cleanup_server():
            client.servers_client.delete_server(vm['id'])
            waiters.wait_for_server_termination(client.servers_client,
                                                vm['id'])

        if cleanup:
            self.addCleanup(cleanup_server)

        return vm

    def create_tenant_server(self, client=None, tenant_networks=None,
                             ports=None, wait_until='ACTIVE',
                             volume_backed=False, name=None, flavor=None,
                             image_profile='default', cleanup=True,
                             **kwargs):

        name = name or data_utils.rand_name('test-server')

        server = TenantServer(client, self.admin_manager.servers_client,
                              image_profile)
        image_id = None
        if image_profile != 'default':
            image_id = self.osc_get_image_id(server.image_name)
            if not image_id:
                self.skipTest('Image ' + server.image_name +
                              ' could not be found on setup.')
        server.openstack_data = self.osc_create_test_server(
            client, tenant_networks, ports, wait_until, volume_backed,
            name, flavor, image_id, cleanup, **kwargs)
        server.nbr_nics_configured = len(tenant_networks) \
            if tenant_networks else 0

        server.init_console()

        self.addCleanup(server.cleanup)
        return server

    def create_fip_to_server(self, server, port=None, validate_access=True,
                             vsd_domain=None, vsd_subnet=None):
        """Create a fip and connect it to the given server

        :param server:
        :param port:
        :param validate_access:
        :param vsd_domain: L3Domain VSPK object
        :param vsd_subnet: L3Subnet VSPK object
        :return:
        """
        if not server.associated_fip:
            if vsd_domain:
                fip = self.create_associate_vsd_managed_floating_ip(
                    server.get_server_details(),
                    port_id=port['id'] if port else None,
                    vsd_domain=vsd_domain,
                    vsd_subnet=vsd_subnet
                ).address
            else:
                fip = self.create_floating_ip(
                    server.get_server_details(),
                    port_id=port['id'] if port else None
                )['floating_ip_address']

            server.associate_fip(fip)
        if validate_access:
            server.check_connectivity()
        return server.associated_fip

    def prepare_for_ping_test(self, server, port=None, vsd_domain=None,
                              vsd_subnet=None):
        if server.needs_fip_access():
            self.create_fip_to_server(server, port, vsd_domain=vsd_domain,
                                      vsd_subnet=vsd_subnet)

    def prepare_for_nic_provisioning(self, server, port=None, vsd_domain=None,
                                     vsd_subnet=None):
        if server.needs_fip_access():
            self.create_fip_to_server(server, port, vsd_domain=vsd_domain,
                                      vsd_subnet=vsd_subnet)

    def start_tenant_server(self, server, wait_until=None):
        self.servers_client.start_server(server.openstack_data['id'])
        if wait_until:
            try:
                waiters.wait_for_server_status(
                    self.servers_client, server.openstack_data['id'],
                    wait_until)
            except Exception:
                LOG.exception('Starting server %s failed',
                              server.openstack_data['id'])
        server.init_console()

    def stop_tenant_server(self, server_id, wait_until='SHUTOFF'):
        self.servers_client.stop_server(server_id)  # changed for dev ci
        if wait_until:
            try:
                waiters.wait_for_server_status(
                    self.servers_client, server_id, wait_until)
            except Exception:
                LOG.exception('Stopping server %s failed', server_id)

    def assert_ping(self, server1, server2, network, ip_type=4,
                    should_pass=True, interface=None, ping_count=5):
        if not server1.console():
            self.skipTest('This test cannot complete assert_ping request '
                          'as it has no console access.')

        server1.prepare_nics()  # server2 is assumed to be prepared
        address2 = server2.get_server_ip_in_network(
            network['name'], ip_type)
        ping_pass = 'FAILED'
        nbr_retries = 5
        try_cnt = 1
        while try_cnt <= nbr_retries:
            LOG.info('assert_ping: ping attempt %d start', try_cnt)

            ping_result = server1.ping(address2, ping_count, interface,
                                       ip_type, should_pass)
            if ping_result:
                ping_pass = 'PASSED'
            LOG.info('assert_ping: ping attempt %d %s', try_cnt, ping_pass)
            if ping_result == should_pass:
                return
            else:
                self.sleep(1)
                try_cnt += 1

        LOG.error(
            'Ping from server {} to server {} on IP address {} {}.'
            .format(server1.id(), server2.id(), address2, ping_pass))

        # TODO(team): do more diagnostics here
        # finally fail
        self.fail('Ping unexpectedly ' + ping_pass)

    def assert_ping6(self, server1, server2, network, should_pass=True):
        self.assert_ping(server1, server2, network, ip_type=6,
                         should_pass=should_pass)

    def start_webserver(self, vm_handle, port_number):
        # pkill not present on cirros
        output = vm_handle._send(cmd='killall nc', timeout=50)
        LOG.info("output of pkill command is %s", output)
        output = vm_handle._send(cmd='netstat -an | grep ' + port_number,
                                 timeout=50)
        LOG.info("output of netstat command is %s", output)
        output = vm_handle._send(
            cmd='echo -e \"got connected working fine 200 OKnn $(ifconfig)\" '
                '| nc -lp ' + port_number + ' &', timeout=50)
        LOG.info("output of start webserver is %s", output)
        complete_output = str(output).strip('[]')
        if "Address already in use" in complete_output:
            LOG.info("some process is running on this port " +
                     complete_output)
            self.fail("Fail to start webserver on port " + port_number)
        else:
            LOG.info("Webserver is successfully started on portnumber " +
                     port_number)

    def stop_webserver(self, vm_handle):
        output = vm_handle._send(cmd='killall nc', timeout=50)
        LOG.info("output of pkill command is %s", output)

    def verify_tcp_curl(self, vm_handle, completeurl, tcppass=True,
                        verify_ip_address=None):
        output = vm_handle._send(cmd='curl -m 2 ' + completeurl, timeout=50)
        LOG.info("output of curl command is %s", output)
        complete_output = str(output).strip('[]')
        if tcppass:
            expected_result = "got connected working fine"
        else:
            expected_result = "couldn't connect to host"
        if expected_result in complete_output:
            LOG.info("traffic is received as expected: " +
                     expected_result)
            if tcppass and verify_ip_address:
                if verify_ip_address in complete_output:
                    LOG.info("found the expected ipaddress " +
                             verify_ip_address)
                else:
                    LOG.info("ip address not coming as expected " +
                             verify_ip_address)
                    self.fail("ip address is not found in the curl " +
                              complete_output)
        else:
            self.fail("traffic is not received as expected " + complete_output)

    def _create_loginable_secgroup_rule(self, security_group_rules_client=None,
                                        secgroup=None,
                                        security_groups_client=None):

        if NUAGE_FEATURES.os_managed_dualstack_subnets:
            return super(NuageBaseTest, self)._create_loginable_secgroup_rule(
                security_group_rules_client, secgroup, security_groups_client)
        else:
            # NEED TO OVERRULE FOR NOT SUPPORTING IPV6 SG ...
            """Create loginable security group rule

            This function will create:
            1. egress and ingress tcp port 22 allow rule
            2. egress and ingress ipv4 icmp allow rule
            """

            if security_group_rules_client is None:
                security_group_rules_client = self.security_group_rules_client
            if security_groups_client is None:
                security_groups_client = self.security_groups_client
            rules = []
            rulesets = [
                dict(
                    # ssh
                    protocol='tcp', port_range_min=22, port_range_max=22
                ),
                dict(
                    # ping
                    protocol='icmp'
                )
            ]
            sec_group_rules_client = security_group_rules_client
            for ruleset in rulesets:
                for r_direction in ['ingress', 'egress']:
                    ruleset['direction'] = r_direction
                    try:
                        sg_rule = self._create_security_group_rule(
                            sec_group_rules_client=sec_group_rules_client,
                            secgroup=secgroup,
                            security_groups_client=security_groups_client,
                            **ruleset)
                    except lib_exc.Conflict as ex:
                        # if rule already exist - skip rule and continue
                        msg = 'Security group rule already exists'
                        if msg not in ex._error_string:
                            raise ex
                    else:
                        self.assertEqual(r_direction, sg_rule['direction'])
                        rules.append(sg_rule)

            return rules

    def osc_delete_test_server(self, vm_id, client=None):
        """Common wrapper utility delete a test server."""
        if not client:
            client = self.manager
        client.servers_client.delete_server(vm_id)
        waiters.wait_for_server_termination(client.servers_client, vm_id)

    def osc_delete_network(self, network, client=None):
        """Common wrapper utility delete a Network."""
        if not client:
            client = self.manager

        client.networks_client.delete_network(network['id'])

    def delete_router_interface(self, router, subnet, client=None):
        """Wrapper utility that returns a router interface."""
        if not client:
            client = self.manager
        client.routers_client.remove_router_interface(router['id'],
                                                      subnet_id=subnet['id'])

    def delete_subnet(self, subnet, client=None):
        """Wrapper utility that delete subnet."""
        if not client:
            client = self.manager
        client.subnets_client.delete_subnet(subnet['id'])

    def verify_ip_in_allocation_pools(self, ip_address, allocation_pools):
        in_pool = False
        for pool in allocation_pools:
            start_ip_address = pool['start']
            end_ip_address = pool['end']
            ip_range = IPRange(start_ip_address, end_ip_address)

            if IPAddress(ip_address) in ip_range:
                in_pool = True
        self.assertTrue(in_pool, msg="IP address not in allocation pools")


class NuageBaseOrchestrationTest(NuageBaseTest):
    """Base test case class for all Nuage Orchestration API tests."""
    @classmethod
    def setup_credentials(cls):
        super(NuageBaseOrchestrationTest, cls).setup_credentials()
        stack_owner_role = CONF.orchestration.stack_owner_role
        cls.os = cls.get_client_manager(roles=[stack_owner_role])

    @classmethod
    def skip_checks(cls):
        super(NuageBaseOrchestrationTest, cls).skip_checks()
        if not CONF.service_available.heat:
            raise cls.skipException("Heat support is required")
        if not CONF.service_available.neutron:
            raise cls.skipException("Neutron support is required")

    @classmethod
    def setup_clients(cls):
        super(NuageBaseOrchestrationTest, cls).setup_clients()

        # add ourselves for now as was removed upstream
        cls.orchestration_client = orchestration.OrchestrationClient(
            cls.os_admin.auth_provider,
            CONF.orchestration.catalog_type,
            CONF.orchestration.region or CONF.identity.region,
            endpoint_type=CONF.orchestration.endpoint_type,
            build_interval=CONF.orchestration.build_interval,
            build_timeout=CONF.orchestration.build_timeout,
            **cls.os_admin.default_params)

        cls.admin_networks_client = cls.os_admin.networks_client
        cls.admin_routers_client = cls.os_admin.routers_client

    @classmethod
    def resource_setup(cls):
        super(NuageBaseOrchestrationTest, cls).resource_setup()

        cls.build_timeout = CONF.orchestration.build_timeout
        cls.build_interval = CONF.orchestration.build_interval

        cls.net_partition_name = CONF.nuage.nuage_default_netpartition
        cls.private_net_name = data_utils.rand_name('heat-network-')

        cls.test_resources = {}
        cls.template_resources = {}

    def launch_stack(self, stack_file_name, stack_parameters):
        stack_name = data_utils.rand_name('heat-' + stack_file_name)
        template = self.read_template(stack_file_name)

        self.launch_stack_template(stack_name, template, stack_parameters)

    def launch_stack_template(self, stack_name, template, stack_parameters):
        LOG.debug("Stack launched: %s", template)
        LOG.debug("Stack parameters: %s", stack_parameters)

        # create the stack
        self.stack_identifier = self.create_stack(
            stack_name,
            template,
            stack_parameters
        )
        self.stack_id = self.stack_identifier.split('/')[1]
        self.orchestration_client.wait_for_stack_status(
            self.stack_id, 'CREATE_COMPLETE')

        resources = self.orchestration_client.list_resources(
            self.stack_identifier)
        resources = resources['resources']
        self.test_resources = {}
        for resource in resources:
            self.test_resources[resource['logical_resource_id']] = resource

        # load to dict
        my_dict = yaml.safe_load(template)

        self.template_resources = my_dict['resources']

    # def load_stack_resources(self, stack_file_name):
    #     loaded_template = self.load_template(stack_file_name)
    #     return loaded_template['resources']

    def verify_stack_resources(self, expected_resources,
                               template_resourses, actual_resources):
        for resource_name in expected_resources:
            resource_type = template_resourses[resource_name]['type']
            resource = actual_resources.get(resource_name, None)
            self.assertIsInstance(resource, dict)
            self.assertEqual(resource_name, resource['logical_resource_id'])
            self.assertEqual(resource_type, resource['resource_type'])
            self.assertEqual('CREATE_COMPLETE', resource['resource_status'])

    @classmethod
    def get_full_template_path(cls, name, ext='yaml'):
        loc = ["templates", "%s.%s" % (name, ext)]
        return os.path.join(os.path.dirname(__file__), *loc)

    @classmethod
    def read_template(cls, name, ext='yaml'):
        full_path = cls.get_full_template_path(name, ext)
        # loc = ["templates", "%s.%s" % (name, ext)]
        # full_path = os.path.join(os.path.dirname(__file__), *loc)

        with open(full_path, "r") as f:
            content = f.read()
            return content

    @classmethod
    def load_template(cls, name, ext='yaml'):
        full_path = cls.get_full_template_path(name, ext)
        # loc = ["templates", "%s.%s" % (name, ext)]
        # fullpath = os.path.join(os.path.dirname(__file__), *loc)

        with open(full_path, "r") as f:
            return yaml.safe_load(f)

    def create_stack(self, stack_name, template_data, parameters=None,
                     environment=None, files=None):
        if parameters is None:
            parameters = {}
        body = self.orchestration_client.create_stack(
            stack_name,
            template=template_data,
            parameters=parameters,
            environment=environment,
            files=files)
        stack_id = body.response['location'].split('/')[-1]
        stack_identifier = '%s/%s' % (stack_name, stack_id)

        self.addCleanup(self._clear_stack, stack_identifier)
        return stack_identifier

    def _clear_stack(self, stack_identifier):
        try:
            self.orchestration_client.delete_stack(stack_identifier)
        except lib_exc.NotFound:
            pass

        try:
            self.orchestration_client.wait_for_stack_status(
                stack_identifier, 'DELETE_COMPLETE',
                failure_pattern="DELETE_FAILED")
        except lib_exc.NotFound:
            pass

    @staticmethod
    def stack_output(stack, output_key):
        """Return a stack output value for a given key."""
        return next((o['output_value'] for o in stack['outputs']
                     if o['output_key'] == output_key), None)

    def assert_fields_in_dict(self, obj, *fields):
        for field in fields:
            self.assertIn(field, obj)

    def list_resources(self, stack_identifier):
        """Get a dict mapping of resource names to types."""
        resources = self.client.list_resources(stack_identifier)['resources']
        self.assertIsInstance(resources, list)
        for res in resources:
            self.assert_fields_in_dict(res, 'logical_resource_id',
                                       'resource_type', 'resource_status',
                                       'updated_time')

        return dict((r['resource_name'], r['resource_type'])
                    for r in resources)

    def get_stack_output(self, stack_identifier, output_key):
        body = self.client.show_stack(stack_identifier)['stack']
        return self.stack_output(body, output_key)
