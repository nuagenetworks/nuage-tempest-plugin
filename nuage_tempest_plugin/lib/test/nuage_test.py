# Copyright 2017 Alcatel-Lucent
# All Rights Reserved.

import copy
import functools
import inspect
import os.path
import pymysql
from six import iteritems
import testtools
import time
import yaml

from netaddr import IPAddress
from netaddr import IPNetwork
from netaddr import IPRange

from tempest.api.network import base
from tempest.common import waiters
from tempest.lib.common import rest_client
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest.scenario import manager
from tempest.services import orchestration

from testtools.matchers import ContainsDict
from testtools.matchers import Equals

from nuage_tempest_plugin.lib.test import tags as test_tags
from nuage_tempest_plugin.lib.test.tenant_server import TenantServer
from nuage_tempest_plugin.lib.test import vsd_helper
from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


def skip_because(*args, **kwargs):
    """A decorator useful to skip tests hitting known bugs

    @param bug: bug number causing the test to skip
    @param condition: optional condition to be True for the skip to have place
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(self, *func_args, **func_kwargs):
            skip = False
            if "condition" in kwargs:
                if kwargs["condition"] is True:
                    skip = True
            else:
                skip = True
            if "bug" in kwargs and skip is True:
                msg = "Skipped until Bug: %s is resolved." % kwargs["bug"]
                raise testtools.TestCase.skipException(msg)
            return f(self, *func_args, **func_kwargs)
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

            if f.__code__.co_name != 'wrapper':
                LOG.info('TEST CASE STARTED: {}'.format(f.__code__.co_name))

                # Dump the message + the name of this function to the log.
                LOG.info("in {}:{}".format(
                    f.__code__.co_filename,
                    f.__code__.co_firstlineno
                ))

            result = f(self, *func_args, **func_kwargs)

            if f.__code__.co_name != 'wrapper':
                LOG.info('TEST CASE COMPLETED: {}'.format(f.__code__.co_name))
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
    default_netpartition_name = Topology.def_netpartition
    image_name_to_id_cache = {}
    dhcp_agent_present = None

    ssh_security_group = None

    @classmethod
    def setup_clients(cls):
        super(NuageBaseTest, cls).setup_clients()
        cls.manager = cls.get_client_manager()
        cls.admin_manager = cls.get_client_manager(credential_type='admin')
        cls.vsd = vsd_helper.VsdHelper()
        cls.networks_client = cls.manager.networks_client
        cls.subnets_client = cls.manager.subnets_client
        cls.ports_client = cls.manager.ports_client

    @classmethod
    def resource_setup(cls):
        super(NuageBaseTest, cls).resource_setup()
        cls.setup_network_resources(cls)

    @classmethod
    def skip_checks(cls):
        super(NuageBaseTest, cls).skip_checks()
        if not CONF.service_available.neutron:
            # this check prevents this test to be run in unittests
            raise cls.skipException("Neutron support is required")

    def skipTest(self, reason):
        LOG.warn('TEST SKIPPED: ' + reason)
        super(NuageBaseTest, self).skipTest(reason)

    @staticmethod
    # As reused by other classes, left as static and passing cls explicitly
    def setup_network_resources(cls):
        cls.cidr4 = IPNetwork(CONF.network.project_network_cidr)
        cls.mask_bits4 = CONF.network.project_network_mask_bits
        cls.mask_bits4_unsliced = cls.cidr4.prefixlen
        assert cls.mask_bits4 >= cls.mask_bits4_unsliced
        cls.gateway4 = str(IPAddress(cls.cidr4) + 1)
        cls.netmask4 = str(cls.cidr4.netmask)

        cls.cidr6 = IPNetwork(CONF.network.project_network_v6_cidr)
        cls.mask_bits6 = cls.cidr6.prefixlen

        # TODO(Kris) this needs to go out but i need to find out how
        if cls.mask_bits6 < 64:
            cls.cidr6 = IPNetwork('cafe:babe::/64')
            cls.mask_bits6 = 64

        cls.gateway6 = str(IPAddress(cls.cidr6) + 1)

        cls.net_partition = Topology.def_netpartition

        LOG.info("setup_network_resources: ipv4 config: {}"
                 .format(str(cls.cidr4)))
        LOG.info("setup_network_resources: ipv6 config: {}"
                 .format(str(cls.cidr6)))

    @classmethod
    def is_dhcp_agent_present(cls):
        if cls.dhcp_agent_present is None:
            agents = cls.os_admin.network_agents_client.list_agents() \
                .get('agents')
            if agents:
                cls.dhcp_agent_present = any(
                    agent for agent in agents if agent['alive'] and
                    agent['binary'] == 'neutron-dhcp-agent')
            else:
                cls.dhcp_agent_present = False

        return cls.dhcp_agent_present

    @staticmethod
    def sleep(seconds=1, msg=None):
        if not msg:
            LOG.error(
                "Added a {}s sleep without clarification. "
                "Please add motivation for this sleep.".format(seconds))
        else:
            LOG.warning("Sleeping for {}s. {}.".format(seconds, msg))
        time.sleep(seconds)

    def assert_success_rate(self, expected_success_rate, actual_success_rate,
                            be_tolerant_for=0):
        if (actual_success_rate != expected_success_rate and
                be_tolerant_for > 0 and
                actual_success_rate >= (expected_success_rate -
                                        be_tolerant_for)):
            # hit a case of accepted failure tolerance
            self.skipTest('ATTENTION: success_rate is %d; skipping test' %
                          actual_success_rate)
        else:
            self.assertEqual(expected_success_rate, actual_success_rate,
                             'Success rate not met!')

    @classmethod
    def create_network_at_class_level(cls, network_name, client, **kwargs):
        body = client.create_network(name=network_name, **kwargs)
        network = body['network']
        cls.addClassResourceCleanup(client.delete_network, network['id'])
        return network

    def vsd_create_l2domain_template(
            self, name=None, enterprise=None,
            dhcp_managed=True, ip_type="IPV4",
            cidr4=None, gateway4=None,
            cidr6=None, gateway6=None, cleanup=True, **kwargs):
        l2domain_template = self.vsd.create_l2domain_template(
            name, enterprise, dhcp_managed, ip_type,
            cidr4, gateway4, cidr6, gateway6, **kwargs)
        self.assertIsNotNone(l2domain_template)
        if cleanup:
            self.addCleanup(l2domain_template.delete)
        return l2domain_template

    def vsd_create_l2domain(self, name=None, enterprise=None, template=None,
                            cleanup=True):
        vsd_l2domain = self.vsd.create_l2domain(name, enterprise, template)
        self.assertIsNotNone(vsd_l2domain)
        if cleanup:
            self.addCleanup(vsd_l2domain.delete)
        return vsd_l2domain

    def vsd_create_l3domain_template(
            self, name=None, enterprise=None, cleanup=True):
        l3domain_template = self.vsd.create_l3domain_template(
            name, enterprise)
        self.assertIsNotNone(l3domain_template)
        if cleanup:
            self.addCleanup(l3domain_template.delete)
        return l3domain_template

    def vsd_create_l3domain(
            self, name=None, enterprise=None, template_id=None, cleanup=True):
        vsd_domain = self.vsd.create_l3domain(
            name, enterprise, template_id)
        self.assertIsNotNone(vsd_domain)
        if cleanup:
            self.addCleanup(vsd_domain.delete)
        return vsd_domain

    def vsd_create_zone(self, name=None, domain=None, cleanup=False):
        vsd_zone = self.vsd.create_zone(name, domain)
        self.assertIsNotNone(vsd_zone)
        if cleanup:
            self.addCleanup(vsd_zone.delete)
        return vsd_zone

    def create_vsd_subnet(self, name=None, zone=None, ip_type="IPV4",
                          cidr4=None, gateway4=None,
                          cidr6=None, gateway6=None, cleanup=True, **kwargs):
        vsd_subnet = self.vsd.create_subnet(name, zone, ip_type,
                                            cidr4, gateway4, cidr6, gateway6,
                                            **kwargs)
        self.assertIsNotNone(vsd_subnet)
        if cleanup:
            self.addCleanup(vsd_subnet.delete)
        return vsd_subnet

    def create_network(self, network_name=None, client=None,
                       cleanup=True, **kwargs):
        """Wrapper utility that returns a test network."""
        network_name = network_name or data_utils.rand_name('test-network')

        if not client:
            client = self.manager

        body = client.networks_client.create_network(
            name=network_name, **kwargs)
        network = body['network']

        self.assertIsNotNone(network)

        if cleanup:
            self.addCleanup(
                client.networks_client.delete_network, network['id'])
        return network

    def update_network(self, network_id, client=None,
                       **kwargs):
        """Wrapper utility that updates a test network."""
        if not client:
            client = self.manager

        body = client.networks_client.update_network(network_id, **kwargs)
        network = body['network']
        return network

    def get_network(self, network_id, client=None, **kwargs):
        """Wrapper utility that gets a test network."""
        if not client:
            client = self.manager

        body = client.networks_client.show_network(network_id, **kwargs)
        network = body['network']
        return network

    def create_subnet(self, network, subnet_name=None, gateway='', cidr=None,
                      mask_bits=None,
                      ip_version=None, client=None, cleanup=True,
                      no_net_partition=False,
                      **kwargs):
        """Wrapper utility that returns a test subnet."""
        # allow tests to use admin client
        if not client:
            client = self.manager

        subnet_name = subnet_name or data_utils.rand_name('test-subnet-')

        # The cidr and mask_bits depend on the ip version.
        ip_version = ip_version if ip_version is not None else self._ip_version
        gateway_not_set = gateway == ''

        # fill in cidr and mask_bits if not set -- note that mask_bits is
        # not optional when cidr is set !  ( ~ upstream method behavior )
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
                if not no_net_partition and 'net_partition' not in kwargs:
                    kwargs['net_partition'] = self.default_netpartition_name

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
            raise ValueError(message)

        subnet = body['subnet']

        dhcp_enabled = subnet['enable_dhcp']
        if self.is_dhcp_agent_present() and dhcp_enabled:
            current_time = time.time()
            LOG.info("Waiting for dhcp port resolution")
            dhcp_subnets = []
            while subnet['id'] not in dhcp_subnets:
                if time.time() - current_time > 30:
                    raise lib_exc.NotFound("DHCP port not resolved within"
                                           " allocated time.")
                time.sleep(0.5)
                filters = {
                    'device_owner': 'network:dhcp',
                    'network_id': subnet['network_id']
                }
                dhcp_ports = client.ports_client.list_ports(**filters)['ports']
                if not dhcp_ports:
                    continue
                dhcp_port = dhcp_ports[0]
                dhcp_subnets = [x['subnet_id'] for x in dhcp_port['fixed_ips']]
            LOG.info("DHCP port resolved")

        self.assertIsNotNone(subnet)

        if cleanup:
            self.addCleanup(client.subnets_client.delete_subnet, subnet['id'])

        # add parent network
        subnet['parent_network'] = network

        # add me to network
        if ip_version == 4:
            network['v4_subnet'] = subnet  # keeps last created only
        else:
            network['v6_subnet'] = subnet  # keeps last created only

        return subnet

    def update_subnet(self, subnet, client=None, **kwargs):
        """Wrapper utility that updates a test subnet."""
        if not client:
            client = self.manager
        body = client.subnets_client.update_subnet(subnet['id'],
                                                   **kwargs)
        return body['subnet']

    def create_l2_vsd_managed_subnet(self, network, vsd_l2domain, ip_version=4,
                                     dhcp_managed=True, dhcp_option_3=None,
                                     **subnet_kwargs):
        if not isinstance(vsd_l2domain, self.vsd.vspk.NUL2Domain):
            self.fail("Must have an VSD L2 domain")

        if ip_version == 4:
            cidr = IPNetwork(vsd_l2domain.address + "/" +
                             vsd_l2domain.netmask)
            gateway = dhcp_option_3
        elif ip_version == 6:
            gateway = None
            cidr = IPNetwork(vsd_l2domain.ipv6_address)
        else:
            self.fail("IP version {} is not supported".format(ip_version))

        subnet = self.create_subnet(
            network,
            enable_dhcp=dhcp_managed,
            ip_version=ip_version,
            cidr=cidr,
            mask_bits=cidr.prefixlen,
            gateway=gateway,
            nuagenet=vsd_l2domain.id,
            net_partition=vsd_l2domain.parent_object.name,
            **subnet_kwargs)

        # add vsd mgd info to network
        subnet['parent_network']['vsd_l2_domain'] = vsd_l2domain

        return subnet

    def create_l3_vsd_managed_subnet(self, network, vsd_domain, vsd_subnet,
                                     dhcp_managed=True, ip_version=4,
                                     gateway=None,
                                     **subnet_kwargs):
        if not isinstance(vsd_subnet, self.vsd.vspk.NUSubnet):
            self.fail("Must have an VSD L3 subnet")

        if ip_version == 4:
            cidr = IPNetwork(vsd_subnet.address + "/" + vsd_subnet.netmask)
            gateway = (None if gateway and gateway == ''
                       else gateway if gateway else vsd_subnet.gateway)
        elif ip_version == 6:
            gateway = (None if gateway and gateway == ''
                       else gateway if gateway else vsd_subnet.ipv6_gateway)
            cidr = IPNetwork(vsd_subnet.ipv6_address)
        else:
            self.fail("IP version {} is not supported".format(ip_version))

        # subnet -> zone -> domain -> enterprise
        net_partition = \
            vsd_subnet.parent_object.parent_object.parent_object.name

        subnet = self.create_subnet(
            network,
            enable_dhcp=dhcp_managed,
            ip_version=ip_version,
            cidr=cidr,
            mask_bits=cidr.prefixlen,
            gateway=gateway,
            nuagenet=vsd_subnet.id,
            net_partition=net_partition,
            **subnet_kwargs)

        # add vsd mgd info to network
        subnet['parent_network']['vsd_l3_domain'] = vsd_domain
        subnet['parent_network']['vsd_l3_subnet'] = vsd_subnet

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

        # add parent network
        port['parent_network'] = network

        return port

    def update_port(self, port, client=None, **kwargs):
        """Wrapper utility that updates a test port."""
        if not client:
            client = self.manager
        body = client.ports_client.update_port(port['id'],
                                               **kwargs)
        return body['port']

    def delete_port(self, port, client=None):
        """Wrapper utility that deletes a test port."""
        if not client:
            client = self.manager
        client.ports_client.delete_port(port['id'])

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
        for key, value in iteritems(kwargs):
            if isinstance(value, dict):
                # compare dict
                raise NotImplementedError
            if isinstance(value, list):
                self.assertItemsEqual(port[key], value)
            else:
                self.assertThat(port, ContainsDict({key: Equals(value)}))

    def _verify_vport_in_l2_domain(self, port, vsd_l2domain):
        vport = self.vsd.get_vport(l2domain=vsd_l2domain,
                                   by_port_id=port['id'])
        self.assertEqual(port['id'], vport.name)

    def _verify_vport_in_l3_subnet(self, port, vsd_l3_subnet):
        vport = self.vsd.get_vport(subnet=vsd_l3_subnet,
                                   by_port_id=port['id'])
        self.assertEqual(port['id'], vport.name)

    def create_open_ssh_security_group(self):
        if not self.ssh_security_group:
            self.ssh_security_group = self._create_security_group(
                namestart='tempest-open-ssh')
        return self.ssh_security_group

    def create_test_router(self, client=None):
        if Topology.access_to_l2_supported():
            return self.create_router(client=client)  # can be isolated router
        else:
            return self.create_public_router(client=client)  # needs FIP access

    def create_public_router(self, client=None, retry_on_router_delete=False):
        return self.create_router(
            external_network_id=CONF.network.public_network_id,
            client=client, retry_on_router_delete=retry_on_router_delete)

    def create_router(self, router_name=None, admin_state_up=True,
                      external_network_id=None, enable_snat=None,
                      external_gateway_info_on=True,
                      client=None, cleanup=True,
                      retry_on_router_delete=None,
                      no_net_partition=False,
                      **kwargs):
        """Wrapper utility that creates a router."""
        ext_gw_info = {}
        router_name = router_name or data_utils.rand_name('test-router-')
        if not client:
            client = self.manager
        if not no_net_partition and 'net_partition' not in kwargs:
            kwargs['net_partition'] = self.default_netpartition_name
        if external_gateway_info_on:
            if external_network_id:
                ext_gw_info['network_id'] = external_network_id
            if enable_snat is not None:
                ext_gw_info['enable_snat'] = enable_snat
            body = client.routers_client.create_router(
                name=router_name, external_gateway_info=ext_gw_info,
                admin_state_up=admin_state_up, **kwargs)
        else:
            body = client.routers_client.create_router(
                name=router_name, admin_state_up=admin_state_up, **kwargs)

        router = body['router']
        if cleanup:
            self.addCleanup(self.delete_router, router, client,
                            retry_on_router_delete)
        return router

    # TODO(TEAM) - VSD-21337 : DELETE ROUTER OFTEN FAILS WHEN
    # TODO(TEAM) - DONE TOO SOON AFTER SUBNET DETACH. MEANWHILE THIS IS A
    # TODO(TEAM) - WORK-AROUND, BY GIVING DELAY TO THIS METHOD
    def delete_router(self, router, client=None,
                      retry_on_router_delete=None):
        if retry_on_router_delete is None:
            retry_on_router_delete = self.is_dhcp_agent_present()
        if not client:
            client = self.manager
        if retry_on_router_delete:
            for attempt in range(Topology.nbr_retries_for_test_robustness):
                try:
                    client.routers_client.delete_router(router['id'])
                    return
                except Exception as e:
                    if ('Nuage API: vPort has VMInterface network interfaces '
                            'associated with it.' not in str(e)):
                        raise e
                    LOG.error('VSD-21337: Domain deletion failed (%d)',
                              attempt + 1)
                    self.sleep(msg='Give time for VSD-21337')

        client.routers_client.delete_router(router['id'])

    def update_router(self, router,
                      external_network_id=None, enable_snat=None, client=None,
                      external_gateway_info_on=True, **kwargs):
        if not client:
            client = self.manager
        if external_gateway_info_on:
            ext_gw_info = {}
            if external_network_id:
                ext_gw_info['network_id'] = external_network_id
            if enable_snat is not None:
                ext_gw_info['enable_snat'] = enable_snat
            body = client.routers_client.update_router(
                router["id"], external_gateway_info=ext_gw_info, **kwargs)
        else:
            body = client.routers_client.update_router(
                router["id"], **kwargs)
        router = body["router"]
        return router

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

    def delete_floatingip(self, floatingip_id=None,
                          client=None):
        """Wrapper utility that deletes a floating IP."""
        if not client:
            client = self.manager
        client.floating_ips_client.delete_floatingip(
            floatingip_id)

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
        shared_network_resource_id = self.vsd.get_shared_network_resource(
            by_fip_subnet_id=floatingip_subnet_id).id

        # Create floating ip
        floating_ip = self.vsd.create_floating_ip(
            vsd_domain,
            shared_network_resource_id=shared_network_resource_id)
        self.addCleanup(floating_ip.delete)

        # Associate floating ip
        vport = self.vsd.get_vport(subnet=vsd_subnet, by_port_id=port_id)
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
            floatingip['id'], **kwargs)
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

    def router_attach(self, router, subnet, client=None, cleanup=True):
        self.create_router_interface(router['id'], subnet['id'],
                                     client=client, cleanup=cleanup)

        # mark network as L3
        subnet['parent_network']['is_l3'] = True

    def router_detach(self, router, subnet):
        self.remove_router_interface(router['id'], subnet['id'])

        # unmark network as l3
        subnet['parent_network']['is_l3'] = False

    @staticmethod
    def osc_get_database_table_row(db_name, db_username, db_password,
                                   table_name, row=0,
                                   assert_table_size=None):
        db_cmd = 'SELECT * FROM ' + table_name

        db_connection = pymysql.connect(host='localhost',
                                        user=db_username,
                                        passwd=db_password,
                                        db=db_name)
        cursor = db_connection.cursor()
        cursor.execute(db_cmd)
        db_row_cnt = cursor.rowcount
        db_row = cursor.fetchone() if row == 0 else cursor.fetchall()[row]
        db_connection.close()

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
        image_id = None
        for image in images['images']:
            # add them all
            self.image_name_to_id_cache[image['name']] = image['id']

            if image_name == image['name']:
                image_id = image['id']

        return image_id

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
                               ports=None, security_groups=None,
                               wait_until='ACTIVE',
                               volume_backed=False, name=None, flavor=None,
                               image_id=None, cleanup=True,
                               deploy_attempt_count=1,
                               return_none_on_failure=False,
                               **kwargs):
        """Common wrapper utility returning a test server.

        :param client: Client manager which provides OpenStack Tempest clients.
        :param tenant_networks: Tenant networks used for creating the server.
        :param security_groups: Tenant security groups for the server.
        :param ports: Tenant ports used for creating the server.
        :param wait_until: Server status to wait for the server to reach after
        its creation.
        :param volume_backed: Whether the instance is volume backed or not.
        :param name: Instance name.
        :param flavor: Instance flavor.
        :param image_id: Instance image ID.
        :param cleanup: Flag for cleanup (leave True for auto-cleanup).
        :param deploy_attempt_count: max deploy attempt count
        :param return_none_on_failure: if True, return None on failure instead
        of failing the test case
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
                if 'id' in network:
                    params['networks'].append({'uuid': network['id']})
        if ports:
            params.update({"networks": []})
            for port in ports:
                if 'id' in port:
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

            bd_map_v2 = [{'uuid': volume['volume']['id'],
                          'source_type': 'volume',
                          'destination_type': 'volume',
                          'boot_index': 0,
                          'delete_on_termination': True}]
            kwargs['block_device_mapping_v2'] = bd_map_v2

            # Since this is boot from volume an image does not need
            # to be specified.
            image_id = ''

        vm = None

        if security_groups:
            sg_name_dicts = []  # nova requires sg names in dicts
            for sg in security_groups:
                sg_name_dicts.append({'name': sg['name']})
            kwargs['security_groups'] = sg_name_dicts

        def cleanup_server():
            client.servers_client.delete_server(vm['id'])
            waiters.wait_for_server_termination(
                client.servers_client, vm['id'])

        for attempt in range(deploy_attempt_count):

            LOG.info("Deploying server %s (attempt %d)", name, attempt + 1)

            body = client.servers_client.create_server(name=name,
                                                       imageRef=image_id,
                                                       flavorRef=flavor,
                                                       **kwargs)

            vm = rest_client.ResponseBody(body.response, body['server'])
            LOG.info("Id of vm %s", vm['id'])

            if wait_until:

                LOG.info("Waiting for server %s to be %s", name, wait_until)
                try:
                    waiters.wait_for_server_status(client.servers_client,
                                                   vm['id'], wait_until)

                    break

                except Exception as e:

                    if ('preserve_server_on_error' not in kwargs or
                            kwargs['preserve_server_on_error'] is False):

                        LOG.error("Deploying server %s failed (%s). "
                                  "Destroying.", name, str(e))

                        # for convenience, define equal
                        undeploy_attempt_count = deploy_attempt_count

                        for delete_attempt in range(undeploy_attempt_count):

                            try:
                                cleanup_server()
                                vm = None  # mark deletion success
                                break

                            except Exception as e:
                                LOG.exception(
                                    'Destroying server %s failed (%s)',
                                    name, str(e))

                        if vm is not None:
                            if return_none_on_failure:
                                LOG.error('Destroying server %s failed', name)
                                return None
                            else:
                                self.fail('Destroying server %s failed' % name)

            else:
                break

        if vm:
            if cleanup:
                self.addCleanup(cleanup_server)

            return vm

        else:

            # FAILED TO DEPLOY SERVER

            if return_none_on_failure:
                LOG.error('Deploying server %s failed', name)
                return None

            else:
                self.fail('Deploying server %s failed' % name)

    @staticmethod
    def is_l2_network(network):
        return not network.get('is_l3') and not network.get('vsd_l3_subnet')

    def create_tenant_server(self, client=None, networks=None,
                             ports=None, security_groups=None,
                             wait_until='ACTIVE',
                             volume_backed=False, name=None, flavor=None,
                             image_profile='default', cleanup=True,
                             make_reachable=False,
                             configure_dualstack_itf=False,
                             wait_until_initialized=True,
                             **kwargs):

        assert not (wait_until_initialized and wait_until != 'ACTIVE')
        assert not (networks and ports)  # one of both, not both
        assert networks or ports  # but one at least
        assert not (ports and security_groups)  # one of both, not both
        assert not (configure_dualstack_itf and not make_reachable)

        # the 1st network/port determines for l2/l3
        first_network = (networks[0] if networks
                         else ports[0].get('parent_network'))
        l2_deployment = self.is_l2_network(first_network)

        name = name or data_utils.rand_name('test-server')
        data_interface = 'eth0'

        server = TenantServer(self, client, self.admin_manager.servers_client,
                              name, networks, ports, security_groups,
                              image_profile, flavor, volume_backed)

        for attempt in range(3):  # retrying seems to pay off (CI evidence)

            if l2_deployment and make_reachable:
                LOG.info("create_tenant_server %s: PREPARE FOR L2 -> L3 "
                         "(attempt %d)", name, attempt + 1)

                server.networks = None
                server.ports = self.prepare_l3_topology_for_l2_network(
                    networks, ports, security_groups)
                server.security_groups = None
                data_interface = 'eth1'

            LOG.info("create_tenant_server %s: START (attempt %d)", name,
                     attempt + 1)

            if server.boot(wait_until, cleanup, True, **kwargs):
                networks = server.networks
                ports = server.ports
                break

        assert server.did_deploy()

        LOG.info("create_tenant_server %s: server is %s", name, wait_until)

        if wait_until_initialized:
            self.sleep(5, 'Give time for server to initialize')

        if make_reachable:
            LOG.info("create_tenant_server %s: make reachable", name)

            # make reachable over the 1st port
            first_port = (self.osc_get_server_port_in_network(
                server, networks[0]) if networks else ports[0])

            if networks and networks[0].get('vsd_l3_subnet'):
                # vsd managed l3
                self.create_fip_to_server(
                    server, first_port,
                    vsd_domain=networks[0].get('vsd_l3_domain'),
                    vsd_subnet=networks[0].get('vsd_l3_subnet'),
                    client=client)
            else:
                # os mgd or vsd managed l2
                self.create_fip_to_server(server, first_port)

        if configure_dualstack_itf:
            LOG.info("create_tenant_server %s: configure dualstack", name)

            configured_dualstack = False

            if not networks:
                networks = []
                for port in ports:
                    if port.get('parent_network'):
                        networks.append(port['parent_network'])

            for network in networks:
                server_ipv6 = server.get_server_ip_in_network(
                    network['name'], ip_type=6)

                if network.get('v6_subnet'):
                    server.configure_dualstack_interface(
                        server_ipv6, subnet=network['v6_subnet'],
                        device=data_interface)
                    configured_dualstack = True

            assert configured_dualstack  # assert we did the job

        LOG.info("create_tenant_server %s: DONE!", name)
        return server

    def prepare_l3_topology_for_l2_network(
            self, networks, ports, security_groups=None, client=None):

        # L2 (existing)
        l2_network = (networks[0] if networks
                      else ports[0]['parent_network'])
        if security_groups:
            l2_sgs = []
            for sg in security_groups:
                l2_sgs.append(sg['id'])
            l2_port = self.create_port(l2_network, client,
                                       security_groups=l2_sgs)
        else:
            l2_port = self.create_port(l2_network, client)

        # L3 (new)
        fip_network = self.create_network(client=client)
        subnet = self.create_subnet(
            fip_network, cidr=IPNetwork("192.168.0.0/24"),
            client=client)
        router = self.create_test_router(client=client)
        self.router_attach(router, subnet, client=client)

        # l3 port
        open_ssh_sg = self.create_open_ssh_security_group()
        l3_port = self.create_port(fip_network, client,
                                   security_groups=[open_ssh_sg['id']])
        return [l3_port, l2_port]

    def create_fip_to_server(self, server, port=None, validate_access=False,
                             vsd_domain=None, vsd_subnet=None, client=None):
        """Create a fip and connect it to the given server

        :param server:
        :param port:
        :param validate_access:
        :param vsd_domain: L3Domain VSPK object
        :param vsd_subnet: L3Subnet VSPK object
        :param client: os client
        :return:
        """
        LOG.info("create_fip_to_server: vsd_domain=%s, vsd_subnet=%s",
                 str(vsd_domain), str(vsd_subnet))

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
                    port_id=port['id'] if port else None, client=client
                )['floating_ip_address']

            server.associate_fip(fip)
            LOG.info("create_fip_to_server: fip associated: %s", str(fip))

            if validate_access:
                assert server.check_connectivity(3)
                LOG.info("create_fip_to_server: server connectivity verified")

        return server.associated_fip

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

    def stop_tenant_server(self, server_id, wait_until='SHUTOFF'):
        self.servers_client.stop_server(server_id)  # changed for dev ci
        if wait_until:
            try:
                waiters.wait_for_server_status(
                    self.servers_client, server_id, wait_until)
            except Exception:
                LOG.exception('Stopping server %s failed', server_id)

    def assert_ping(self, server1, server2, network, ip_type=4,
                    should_pass=True, interface=None, ping_count=3,
                    return_boolean_to_indicate_success=False):
        if not server1.console():
            self.skipTest('This test cannot complete assert_ping request '
                          'as it has no console access.')

        address2 = server2.get_server_ip_in_network(
            network['name'], ip_type)
        ping_pass = None  # keeps pycharm happy

        for attempt in range(1, Topology.nbr_retries_for_test_robustness + 1):
            LOG.info('assert_ping: ping attempt %d start', attempt)

            ping_result = server1.ping(address2, ping_count, interface,
                                       ip_type, should_pass)
            ping_pass = 'PASSED' if ping_result else 'FAILED'
            if ping_result == should_pass:
                LOG.info('assert_ping: ping attempt %d %s', attempt, ping_pass)
                return True

            LOG.error('assert_ping: ping attempt %d %s', attempt, ping_pass)
            self.sleep(msg='reattempting ping in 1 sec')

        LOG.error(
            'Ping from server {} to server {} on IP address {} {}.'
            .format(server1.id(), server2.id(), address2, ping_pass))

        server1.echo_debug_info()

        if return_boolean_to_indicate_success:
            LOG.error('Ping unexpectedly ' + ping_pass)
            return False
        else:
            self.fail('Ping unexpectedly ' + ping_pass)

    def assert_ping6(self, server1, server2, network,
                     should_pass=True, interface=None, ping_count=3,
                     return_boolean_to_indicate_success=False):
        return self.assert_ping(server1, server2, network, 6,
                                should_pass, interface, ping_count,
                                return_boolean_to_indicate_success)

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
        stack_owner_role = CONF.heat_plugin.admin_username or 'admin'
        cls.os = cls.get_client_manager(roles=[stack_owner_role])

    @classmethod
    def setup_clients(cls):
        super(NuageBaseOrchestrationTest, cls).setup_clients()

        # add ourselves for now as was removed upstream
        cls.orchestration_client = orchestration.OrchestrationClient(
            cls.os_admin.auth_provider,
            CONF.heat_plugin.catalog_type,
            CONF.heat_plugin.region or CONF.identity.region,
            build_interval=CONF.heat_plugin.build_interval,
            build_timeout=CONF.heat_plugin.build_timeout,
            **cls.os_admin.default_params)

        cls.admin_networks_client = cls.os_admin.networks_client
        cls.admin_routers_client = cls.os_admin.routers_client

    @classmethod
    def resource_setup(cls):
        super(NuageBaseOrchestrationTest, cls).resource_setup()

        cls.build_timeout = CONF.heat_plugin.build_timeout
        cls.build_interval = CONF.heat_plugin.build_interval

        cls.net_partition_name = CONF.def_netpartition
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


class NuageAdminNetworksTest(base.BaseAdminNetworkTest):

    dhcp_agent_present = None

    @classmethod
    def is_dhcp_agent_present(cls):
        if cls.dhcp_agent_present is None:
            agents = cls.admin_agents_client.list_agents().get('agents')
            if agents:
                cls.dhcp_agent_present = any(
                    agent for agent in agents if agent['alive'] and
                    agent['binary'] == 'neutron-dhcp-agent')
            else:
                cls.dhcp_agent_present = False

        return cls.dhcp_agent_present
