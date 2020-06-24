# Copyright 2017 Alcatel-Lucent
# All Rights Reserved.

import functools
import os.path
from six import iteritems
import socket
import subprocess
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
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc
from tempest.scenario import manager as scenario_manager
from tempest.services import orchestration

from testtools.matchers import ContainsDict
from testtools.matchers import Equals

from nuage_tempest_plugin.lib.test.tenant_server import TenantServer
from nuage_tempest_plugin.lib.test import vsd_helper
from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.lib.utils import data_utils as utils
from nuage_tempest_plugin.services.nuage_network_client \
    import NuageNetworkClientJSON


CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


def skip_because(*args, **kwargs):
    """A decorator useful to skip tests hitting known bugs

    @param condition: optional condition to be True for the skip to have place
    @param bug: bug number causing the test to skip
    @param reason: (other) reason causing the test to skip
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(self, *func_args, **func_kwargs):
            skip = kwargs.get('condition', True)

            if 'bug' in kwargs and skip is True:
                msg = 'Skipped until Bug: {} is resolved'.format(kwargs['bug'])
                raise testtools.TestCase.skipException(msg)

            elif 'reason' in kwargs and skip is True:
                msg = 'Skipped because {}'.format(kwargs["reason"])
                raise testtools.TestCase.skipException(msg)

            return f(self, *func_args, **func_kwargs)
        return wrapper
    return decorator


def unstable_test(*args, **kwargs):
    """A decorator useful to run tests hitting known bugs and skip it if fails

    This decorator can be used in cases like:

    * We have skipped tests with some bug and now bug is claimed to be fixed.
      Now we want to check the test stability so we use this decorator.
      The number of skipped cases with that bug can be counted to mark test
      stable again.
    * There is test which is failing often, but not always. If there is known
      bug related to it, and someone is working on fix, this decorator can be
      used instead of "skip_because". That will ensure that test is still run
      so new debug data can be collected from jobs' logs but it will not make
      life of other developers harder by forcing them to recheck jobs more
      often.

    :param bug: bug causing the test to skip (jira)
    :raises: testtools.TestCase.skipException if test actually fails,
        and ``bug`` is included
    """
    def decor(f):
        @functools.wraps(f)
        def inner(self, *func_args, **func_kwargs):
            try:
                return f(self, *func_args, **func_kwargs)
            except Exception as e:
                if "bug" in kwargs:
                    bug = kwargs['bug']
                    msg = ("Marked as unstable and skipped because of bug: "
                           "%s, failure was: %s") % (bug, e)
                    raise testtools.TestCase.skipException(msg)
                else:
                    raise e
        return inner
    return decor


class NuageBaseTest(scenario_manager.NetworkScenarioTest):

    """NuageBaseTest

    Base class for all test cases.
    This class will have all the common function and will initiate object
    of other class in setup_client rather then inheritance.
    """
    _ip_version = 4

    credentials = ['primary', 'admin']
    default_netpartition_name = Topology.def_netpartition
    shared_infrastructure = 'Shared Infrastructure'
    ext_net_id = CONF.network.public_network_id
    image_name_to_id_cache = {}
    dhcp_agent_present = None

    nuage_aggregate_flows = 'off'
    default_prepare_for_connectivity = False
    enable_aggregate_flows_on_vsd_managed = False
    ssh_security_group = None
    cls_name = None

    @classmethod
    def setup_clients(cls):
        super(NuageBaseTest, cls).setup_clients()
        cls.manager = cls.get_client_manager()
        cls.admin_manager = cls.get_client_manager(credential_type='admin')
        cls.vsd = vsd_helper.VsdHelper()
        cls.plugin_network_client = NuageNetworkClientJSON(
            cls.os_primary.auth_provider,
            **cls.os_primary.default_params)

    @classmethod
    def resource_setup(cls):
        super(NuageBaseTest, cls).resource_setup()
        cls.setup_network_resources(cls)

    @classmethod
    def setUpClass(cls):
        cls.long_cls_name = cls.__name__
        cls.cls_name = cls._shorten_name(cls.__name__)

        LOG.info('')
        LOG.info('========== [{}] Test setUpClass =========='.format(
            cls.long_cls_name))
        super(NuageBaseTest, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        LOG.info('[{}] Test {} tearDownClass'.format(cls.cls_name,
                                                     cls.long_cls_name))
        super(NuageBaseTest, cls).tearDownClass()

    @classmethod
    def _shorten_name(cls, name,
                      shorten_to_x_chars=32, pre_fill_with_spaces=True):
        if shorten_to_x_chars:
            if len(name) > shorten_to_x_chars:
                name = '...' + name[-(shorten_to_x_chars - 3):]
            elif pre_fill_with_spaces:
                name = ' ' * (shorten_to_x_chars - len(name)) + name
        return name

    @classmethod
    def setup_credentials(cls):
        # Create no network resources for these tests.
        cls.set_network_resources()
        super(NuageBaseTest, cls).setup_credentials()

    @classmethod
    def skip_checks(cls):
        super(NuageBaseTest, cls).skip_checks()
        if not CONF.service_available.neutron:
            # this check prevents this test to be run in unittests
            raise cls.skipException("Neutron support is required")

    def skipTest(self, reason):
        LOG.warn('TEST SKIPPED: ' + reason)
        super(NuageBaseTest, self).skipTest(reason)

    def setUp(self):
        self.long_test_name = self.get_long_test_name()
        self.test_name = self._shorten_name(self.long_test_name)

        LOG.info('')
        LOG.info('----- [{}] Test setUp -----'.format(self.long_test_name))
        super(NuageBaseTest, self).setUp()

    def tearDown(self):
        LOG.info('[{}] Test {} tearDown'.format(self.test_name,
                                                self.long_test_name))
        super(NuageBaseTest, self).tearDown()

    def get_long_test_name(self):
        name = self.id().split('.')[-1]
        for tag in ['[smoke]', '[negative]', '[slow]']:
            if name.endswith(tag):
                name = name[:-len(tag)]
        return name

    def fail(self, msg):
        self.preFailTest(msg)
        super(NuageBaseTest, self).fail(msg)

    def preFailTest(self, msg):
        # custom handling of a failed test
        LOG.info('[{}] FATAL ERROR: {}'.format(self.test_name, msg))
        # e.g. sleep statement can be added here, to pause the setup on failure

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
    def ip_to_hex(cls, ip):
        hex_ip = hex(int(IPAddress(ip)))[2:]
        if hex_ip.endswith('L'):
            hex_ip = hex_ip[:-1]
        if len(hex_ip) % 2:  # odd amount of characters
            return '0' + hex_ip  # make it even
        else:
            return hex_ip

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

    def assert_icmp_connectivity(self, from_server, to_server,
                                 network_name=None,
                                 is_connectivity_expected=True, ip_version=6):
        # TODO(glenn) investigate if we can replace this with upstream methods
        if network_name is None:
            network_name = to_server.get_server_networks()[0]['name']

        if to_server.needs_provisioning:
            to_server.provision()
        to = IPAddress(to_server.get_server_ip_in_network(
            network_name, ip_version))

        error_msg = ("Ping error: timed out waiting for {} to "
                     "become reachable".format(to)
                     if is_connectivity_expected
                     else ("Ping error: ip address {} is reachable while "
                           "it shouldn't be".format(to)))
        has_connectivity = from_server.ping(to)
        self.assertEqual(expected=is_connectivity_expected,
                         observed=has_connectivity,
                         message=error_msg)

    def assert_tcp_connectivity(self, from_server, to_server,
                                network_name=None,
                                is_connectivity_expected=True,
                                source_port=None,
                                destination_port=80, ip_version=6):
        # TODO(glenn) investigate if we can replace this with upstream methods

        if network_name is None:
            network_name = to_server.get_server_networks()[0]['name']

        if to_server.needs_provisioning:
            to_server.provision()
        to_ip = IPAddress(to_server.get_server_ip_in_network(
            network_name, ip_version))

        output = from_server.curl(destination_ip=to_ip,
                                  destination_port=destination_port,
                                  source_port=source_port)
        has_connectivity = output is not False

        error_msg = ("HTTP error: timed out waiting for {} to "
                     "become reachable".format(to_ip)
                     if is_connectivity_expected
                     else ("HTTP error: server [{}]:{} is reachable while "
                           "it shouldn't be".format(to_ip,
                                                    destination_port)))
        self.assertEqual(expected=is_connectivity_expected,
                         observed=has_connectivity,
                         message=error_msg)

    def validate_tcp_stateful_traffic(self, network, ip_version=None):
        ip_version = ip_version if ip_version is not None else self._ip_version
        # create open-ssh security group
        web_server_sg = self.create_open_ssh_security_group()
        client_sg = self.create_open_ssh_security_group()
        # Launch tenant servers in OpenStack network
        client_server = self.create_tenant_server(
            [network],
            security_groups=[client_sg],
            prepare_for_connectivity=True)
        web_server = self.create_tenant_server(
            [network],
            security_groups=[web_server_sg],
            prepare_for_connectivity=True)
        self.start_web_server(web_server, port=80)

        self.assert_tcp_connectivity(client_server, web_server,
                                     is_connectivity_expected=False,
                                     source_port=None,
                                     destination_port=80,
                                     ip_version=ip_version,
                                     network_name=network['name'])
        self.create_tcp_rule(client_sg,
                             direction='egress',
                             ip_version=ip_version)
        self.assert_tcp_connectivity(client_server, web_server,
                                     is_connectivity_expected=False,
                                     source_port=None,
                                     destination_port=80,
                                     ip_version=ip_version,
                                     network_name=network['name'])
        self.create_tcp_rule(web_server_sg,
                             direction='ingress',
                             ip_version=ip_version)
        self.assert_tcp_connectivity(client_server, web_server,
                                     is_connectivity_expected=True,
                                     source_port=None,
                                     destination_port=80,
                                     ip_version=ip_version,
                                     network_name=network['name'])

    def sleep(self, seconds=1, msg=None, tag=None):
        if tag is None:
            tag = self.test_name
        if not msg:
            LOG.error(
                "{}Added a {}s sleep without clarification. "
                "Please add motivation for this sleep.".format(
                    seconds, '[{}] '.format(tag) if tag else ''))
        else:
            LOG.warning("{}Sleeping for {}s. {}.".format(
                '[{}] '.format(tag) if tag else '', seconds, msg))
        time.sleep(seconds)

    def vsd_create_l2domain_template(
            self, name=None, enterprise=None, dhcp_managed=True,
            ip_type="IPV4", cidr4=None, gateway4=None, cidr6=None,
            gateway6=None, cleanup=True, enable_dhcpv4=True,
            enable_dhcpv6=False, **kwargs):
        l2domain_template = self.vsd.create_l2domain_template(
            name=name, enterprise=enterprise, dhcp_managed=dhcp_managed,
            ip_type=ip_type, cidr4=cidr4, gateway4=gateway4, cidr6=cidr6,
            gateway6=gateway6, enable_dhcpv4=enable_dhcpv4,
            enable_dhcpv6=enable_dhcpv6, **kwargs)
        self.assertIsNotNone(l2domain_template)
        if cleanup:
            self.addCleanup(l2domain_template.delete)
        return l2domain_template

    def vsd_create_l2domain(self, name=None, enterprise=None, template=None,
                            cleanup=True, **kwargs):
        vsd_l2domain = self.vsd.create_l2domain(name, enterprise,
                                                template, **kwargs)
        self.assertIsNotNone(vsd_l2domain)
        if cleanup:
            self.addCleanup(vsd_l2domain.delete)
        return vsd_l2domain

    def vsd_create_l3domain_template(self, name=None, enterprise=None,
                                     cleanup=True):
        l3domain_template = self.vsd.create_l3domain_template(
            name, enterprise)
        self.assertIsNotNone(l3domain_template)
        if cleanup:
            self.addCleanup(l3domain_template.delete)
        return l3domain_template

    def vsd_create_l3domain(
            self, name=None, enterprise=None, template_id=None, cleanup=True):
        kwargs = {}
        if self.enable_aggregate_flows_on_vsd_managed:
            kwargs = {
                'aggregate_flows_enabled': True,
                'aggregation_flow_type':
                    constants.AGGREGATE_FLOW_TYPE_ROUTE_BASED
            }
        vsd_domain = self.vsd.create_l3domain(
            name, enterprise, template_id, **kwargs)
        self.assertIsNotNone(vsd_domain)
        if cleanup:
            self.addCleanup(vsd_domain.delete)
        return vsd_domain

    def vsd_create_zone(self, name=None, domain=None, cleanup=False,
                        **kwargs):
        vsd_zone = self.vsd.create_zone(name, domain, **kwargs)
        self.assertIsNotNone(vsd_zone)
        if cleanup:
            self.addCleanup(vsd_zone.delete)
        return vsd_zone

    def create_vsd_subnet(self, name=None, zone=None, ip_type="IPV4",
                          cidr4=None, gateway4=None, enable_dhcpv4=True,
                          cidr6=None, gateway6=None, enable_dhcpv6=False,
                          cleanup=True, **kwargs):
        vsd_subnet = self.vsd.create_subnet(
            name=name, zone=zone, ip_type=ip_type, cidr4=cidr4,
            gateway4=gateway4, enable_dhcpv4=enable_dhcpv4, cidr6=cidr6,
            gateway6=gateway6, enable_dhcpv6=enable_dhcpv6, **kwargs)
        self.assertIsNotNone(vsd_subnet)
        if cleanup:
            self.addCleanup(vsd_subnet.delete)
        return vsd_subnet

    @classmethod
    def create_cls_network(cls, network_name, manager, cleanup=True, **kwargs):
        body = manager.networks_client.create_network(
            name=network_name, **kwargs)
        network = body['network']
        if cleanup:
            cls.addClassResourceCleanup(manager.networks_client.delete_network,
                                        network['id'])
        return network

    def create_network(self, network_name=None, manager=None,
                       cleanup=True, **kwargs):
        network_name = network_name or data_utils.rand_name('test-network')
        manager = manager or self.manager
        network = self.create_cls_network(
            network_name, manager, cleanup=False, **kwargs)
        self.assertIsNotNone(network)
        if cleanup:
            self.addCleanup(
                manager.networks_client.delete_network, network['id'])
        return network

    def update_network(self, network_id, manager=None, **kwargs):
        manager = manager or self.manager
        body = manager.networks_client.update_network(network_id, **kwargs)
        network = body['network']
        return network

    def is_l2_subnet(self, subnet, manager=None):
        if subnet['vsd_managed']:
            return self.vsd.get_l2domain(
                self.vsd.get_enterprise_by_id(subnet['net_partition']),
                by_id=subnet['nuagenet']) is not None
        else:
            router_ports = self.list_ports(
                device_owner='network:router_interface',
                network_id=subnet['network_id'],
                manager=manager)
            return len(router_ports) == 0

    def is_l3_subnet(self, subnet, manager=None):
        return not self.is_l2_subnet(subnet, manager=manager)

    def get_network(self, network_id, manager=None, **kwargs):
        manager = manager or self.manager
        body = manager.networks_client.show_network(network_id, **kwargs)
        network = body['network']
        return network

    def get_subnet(self, subnet_id, manager=None, **kwargs):
        manager = manager or self.manager
        body = manager.subnets_client.show_subnet(subnet_id, **kwargs)
        subnet = body['subnet']
        return subnet

    @classmethod
    def create_cls_subnet(cls, network, subnet_name=None,
                          gateway='', cidr=None, mask_bits=None,
                          ip_version=None, manager=None, cleanup=True,
                          no_net_partition=False, **kwargs):
        manager = manager or cls.manager
        subnet_name = subnet_name or data_utils.rand_name('test-subnet-')

        # The cidr and mask_bits depend on the ip version.
        ip_version = ip_version or cls._ip_version
        gateway_not_set = gateway == ''

        # fill in cidr and mask_bits if not set -- note that mask_bits is
        # not optional when cidr is set !  ( ~ upstream method behavior )
        if ip_version == 4:
            cidr = cidr or cls.cidr4
            if mask_bits is None:  # mind, can be 0
                mask_bits = cls.mask_bits4
        elif ip_version == 6:
            cidr = cidr or cls.cidr6
            if mask_bits is None:  # mind, can be 0
                mask_bits = cls.mask_bits6

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
                    kwargs['net_partition'] = cls.default_netpartition_name

                body = manager.subnets_client.create_subnet(
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

        if (cls.is_dhcp_agent_present() and dhcp_enabled and
                not network.get('router:external')):
            current_time = time.time()
            LOG.debug('[{}] Waiting for DHCP port resolution'.format(
                cls.cls_name))
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
                dhcp_ports = manager.ports_client.list_ports(
                    **filters)['ports']
                if not dhcp_ports:
                    continue
                dhcp_port = dhcp_ports[0]
                dhcp_subnets = [x['subnet_id'] for x in dhcp_port['fixed_ips']]
            LOG.debug('[{}] DHCP port resolved'.format(cls.cls_name))

        assert subnet
        if cleanup:
            cls.addClassResourceCleanup(
                manager.subnets_client.delete_subnet, subnet['id'])

        return subnet

    def create_subnet(self, network, subnet_name=None, gateway='', cidr=None,
                      mask_bits=None, ip_version=None, manager=None,
                      cleanup=True, no_net_partition=False, **kwargs):
        manager = manager or self.manager
        subnet = self.create_cls_subnet(
            network, subnet_name, gateway, cidr, mask_bits, ip_version,
            manager, cleanup=False, no_net_partition=no_net_partition,
            **kwargs)
        if cleanup:
            self.addCleanup(
                manager.subnets_client.delete_subnet, subnet['id'])
        return subnet

    def update_subnet(self, subnet, manager=None, **kwargs):
        manager = manager or self.manager
        body = manager.subnets_client.update_subnet(subnet['id'],
                                                    **kwargs)
        return body['subnet']

    def get_network_subnet(self, network, ip_version, manager=None):
        manager = manager or self.manager
        subnets = self.list_subnets(manager,
                                    network_id=network['id'],
                                    ip_version=ip_version)
        if len(subnets) == 0:
            return None
        elif len(subnets) == 1:
            return subnets[0]
        else:
            self.fail('Cannot return 1 arbitrary IPv{} subnet of network '
                      'as there are many ({})'.format(ip_version,
                                                      len(subnets)))

    def is_dhcp_enabled(self, network, require_all_subnets_to_match=True,
                        manager=None):
        """is_dhcp_enabled

        Checks whether dhcp is enabled on a network; the criterion for that
        defaults to all subnets to have dhcp enabled, by the
        require_all_subnets_to_match flag passed.
        When that flag is set False, only 1 subnet must have dhcp enabled
        in order to comply, though.
        """

        def is_dhcp_enabled_on_subnet(sub):
            return (sub['enable_dhcp'] and
                    (sub['ip_version'] == 4 or Topology.has_dhcp_v6_support()))

        subnets = self.list_subnets(network_id=network['id'],
                                    manager=manager)
        if require_all_subnets_to_match:
            for subnet in subnets:
                if not is_dhcp_enabled_on_subnet(subnet):
                    return False
            return True
        else:
            for subnet in subnets:
                if is_dhcp_enabled_on_subnet(subnet):
                    return True
            return False

    def create_l2_vsd_managed_subnet(self, network, vsd_l2domain, ip_version=4,
                                     dhcp_managed=True, dhcp_option_3=None,
                                     manager=None, cleanup=True,
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
            manager=manager,
            cleanup=cleanup,
            **subnet_kwargs)

        return subnet

    def create_l3_vsd_managed_subnet(self, network, vsd_subnet,
                                     dhcp_managed=True, ip_version=4,
                                     gateway=None,
                                     manager=None, cleanup=True,
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
            manager=manager,
            cleanup=cleanup,
            **subnet_kwargs)

        return subnet

    def create_port(self, network, manager=None, cleanup=True, **kwargs):
        manager = manager or self.manager

        if CONF.network.port_vnic_type and 'binding:vnic_type' not in kwargs:
            kwargs['binding:vnic_type'] = CONF.network.port_vnic_type
        if CONF.network.port_profile and 'binding:profile' not in kwargs:
            kwargs['binding:profile'] = CONF.network.port_profile

        body = manager.ports_client.create_port(network_id=network['id'],
                                                **kwargs)
        port = body['port']
        if cleanup:
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            manager.ports_client.delete_port,
                            port['id'])

        return port

    @staticmethod
    def is_offload_capable(port):
        return (port['binding:vnic_type'] == 'direct' and
                'switchdev' in port['binding:profile'].get('capabilities', []))

    def update_port(self, port, manager=None, **kwargs):
        manager = manager or self.manager
        body = manager.ports_client.update_port(port['id'], **kwargs)
        return body['port']

    def delete_port(self, port, manager=None):
        manager = manager or self.manager
        manager.ports_client.delete_port(port['id'])

    def get_ports(self, manager=None, **kwargs):
        manager = manager or self.manager
        body = manager.ports_client.list_ports(**kwargs)
        return body['ports']

    def _verify_port(self, port, subnet4=None, subnet6=None, **kwargs):
        testcase = kwargs.pop('testcase', 'unknown')
        message = 'testcase: %s' % testcase

        has_ipv4_ip = False
        has_ipv6_ip = False

        for fixed_ip in port['fixed_ips']:
            ip_address = fixed_ip['ip_address']
            if subnet4 and fixed_ip['subnet_id'] == subnet4['id']:
                start_ip_address = subnet4['allocation_pools'][0]['start']
                end_ip_address = subnet4['allocation_pools'][0]['end']
                ip_range = IPRange(start_ip_address, end_ip_address)
                self.assertIn(ip_address, ip_range, message=message)
                has_ipv4_ip = True

            if subnet6 and fixed_ip['subnet_id'] == subnet6['id']:
                start_ip_address = subnet6['allocation_pools'][0]['start']
                end_ip_address = subnet6['allocation_pools'][0]['end']
                ip_range = IPRange(start_ip_address, end_ip_address)
                self.assertIn(ip_address, ip_range, message=message)
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

    # --------- copy of upstream but added selective cleanup support ----------
    def _create_security_group(self, security_group_rules_client=None,
                               tenant_id=None,
                               namestart='secgroup-smoke',
                               security_groups_client=None,
                               stateful=True,
                               cleanup=True):
        if security_group_rules_client is None:
            security_group_rules_client = self.security_group_rules_client
        if security_groups_client is None:
            security_groups_client = self.security_groups_client
        if tenant_id is None:
            tenant_id = security_groups_client.tenant_id
        secgroup = self._create_empty_security_group(
            namestart=namestart, client=security_groups_client,
            tenant_id=tenant_id, stateful=stateful, cleanup=cleanup)

        # Add rules to the security group
        rules = self._create_loginable_secgroup_rule(
            security_group_rules_client=security_group_rules_client,
            secgroup=secgroup,
            security_groups_client=security_groups_client)
        for rule in rules:
            self.assertEqual(tenant_id, rule['tenant_id'])
            self.assertEqual(secgroup['id'], rule['security_group_id'])
        if not stateful:
            for direction in ['ingress', 'egress']:
                ruleset = {
                    'protocol': 'tcp',
                    'direction': direction,
                    'ethertype': 'IPv4'
                }
                self.create_security_group_rule(
                    security_group=secgroup,
                    **ruleset)
        return secgroup

    def _create_empty_security_group(self, client=None, tenant_id=None,
                                     namestart='secgroup-smoke',
                                     stateful=True, cleanup=True):
        """Create a security group without rules.

        Default rules will be created:
         - IPv4 egress to any
         - IPv6 egress to any

        :param tenant_id: secgroup will be created in this tenant
        :returns: the created security group
        """
        if client is None:
            client = self.security_groups_client
        if not tenant_id:
            tenant_id = client.tenant_id
        sg_name = data_utils.rand_name(namestart)
        sg_desc = sg_name + " description"
        sg_dict = dict(name=sg_name,
                       description=sg_desc)
        sg_dict['tenant_id'] = tenant_id
        sg_dict['stateful'] = stateful
        result = client.create_security_group(**sg_dict)

        secgroup = result['security_group']
        self.assertEqual(secgroup['name'], sg_name)
        self.assertEqual(tenant_id, secgroup['tenant_id'])
        self.assertEqual(secgroup['description'], sg_desc)

        if cleanup:
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            client.delete_security_group, secgroup['id'])
        return secgroup
    # -------------- copy of upstream but added cleanup support ---------------

    def create_open_ssh_security_group(self, sg_name=None, manager=None,
                                       stateful=True, cleanup=True):
        manager = manager or self.manager
        if not self.ssh_security_group:
            self.ssh_security_group = self._create_security_group(
                namestart=sg_name or 'tempest-open-ssh',
                security_group_rules_client=(
                    manager.security_group_rules_client),
                security_groups_client=manager.security_groups_client,
                stateful=stateful,
                cleanup=cleanup)
        return self.ssh_security_group

    def create_security_group_rule(self, security_group=None, manager=None,
                                   **kwargs):
        if 'security_group_id' not in kwargs:
            security_group = security_group or self.ssh_security_group
        if security_group:
            security_group_id = kwargs.setdefault('security_group_id',
                                                  security_group['id'])
            if security_group_id != security_group['id']:
                raise ValueError('Security group ID specified multiple times.')

        manager = manager or self.manager
        security_group_rules_client = manager.security_group_rules_client
        return self._create_security_group_rule(
            security_group, security_group_rules_client, **kwargs)

    def create_tcp_rule(self, sec_grp, direction, ip_version, manager=None):
        if direction == 'egress':
            port_range_min = 1
            port_range_max = 65535
        else:
            port_range_min = 80
            port_range_max = 80
        ruleset = {
            # for web server
            'protocol': 'tcp',
            'port_range_min': port_range_min,
            'port_range_max': port_range_max,
            'direction': direction,
            'ethertype': 'ipv' + str(ip_version)
        }
        self.create_security_group_rule(
            security_group=sec_grp,
            manager=manager,
            **ruleset)

    def create_public_router(self, manager=None, cleanup=True):
        return self.create_router(
            external_network_id=self.ext_net_id,
            manager=manager,
            cleanup=cleanup)

    def create_router(self, router_name=None, admin_state_up=True,
                      external_network_id=None, enable_snat=None,
                      external_gateway_info_on=True,
                      manager=None, cleanup=True,
                      no_net_partition=False,
                      **kwargs):
        ext_gw_info = {}
        router_name = router_name or data_utils.rand_name('test-router-')
        manager = manager or self.manager
        if not no_net_partition and 'net_partition' not in kwargs:
            kwargs['net_partition'] = self.default_netpartition_name
        if external_gateway_info_on:
            if external_network_id:
                ext_gw_info['network_id'] = external_network_id
            if enable_snat is not None:
                ext_gw_info['enable_snat'] = enable_snat
            body = manager.routers_client.create_router(
                name=router_name, external_gateway_info=ext_gw_info,
                admin_state_up=admin_state_up, **kwargs)
        else:
            body = manager.routers_client.create_router(
                name=router_name, admin_state_up=admin_state_up, **kwargs)

        router = body['router']
        if cleanup:
            self.addCleanup(self.delete_router, router, manager)
        return router

    def delete_router(self, router, manager=None):
        manager = manager or self.manager
        manager.routers_client.delete_router(router['id'])

    def update_router(self, router,
                      external_network_id=None, enable_snat=None, manager=None,
                      external_gateway_info_on=True, **kwargs):
        manager = manager or self.manager
        if external_gateway_info_on:
            ext_gw_info = {}
            if external_network_id:
                ext_gw_info['network_id'] = external_network_id
            if enable_snat is not None:
                ext_gw_info['enable_snat'] = enable_snat
            body = manager.routers_client.update_router(
                router["id"], external_gateway_info=ext_gw_info, **kwargs)
        else:
            body = manager.routers_client.update_router(
                router["id"], **kwargs)
        router = body["router"]
        return router

    def get_router(self, router_id, client=None, **kwargs):
        if not client:
            client = self.manager
        body = client.routers_client.show_router(router_id, **kwargs)
        router = body['router']
        return router

    def create_floatingip(self, server=None, external_network_id=None,
                          port_id=None, manager=None, cleanup=True, **kwargs):

        external_network_id = external_network_id or self.ext_net_id
        manager = manager or self.manager

        if server:
            if not port_id:
                port_id, ip4 = self._get_server_port_id_and_ip4(server)
            else:
                ip4 = None
            result = manager.floating_ips_client.create_floatingip(
                floating_network_id=external_network_id, port_id=port_id,
                tenant_id=server['tenant_id'], fixed_ip_address=ip4,
                **kwargs)
        else:
            result = manager.floating_ips_client.create_floatingip(
                floating_network_id=external_network_id, port_id=port_id,
                **kwargs)

        floating_ip = result['floatingip']

        if cleanup:
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            manager.floating_ips_client.delete_floatingip,
                            floating_ip['id'])

        return floating_ip

    def get_floatingip(self, floatingip_id=None, manager=None):
        manager = manager or self.manager
        return manager.floating_ips_client.show_floatingip(
            floatingip_id)['floatingip']

    def delete_floatingip(self, floatingip_id=None, manager=None):
        manager = manager or self.manager
        manager.floating_ips_client.delete_floatingip(floatingip_id)

    def get_vsd_shared_network_resource(self, external_network_id):
        floatingip_subnet_id = self.list_networks(
            id=external_network_id)[0]['subnets'][0]
        if Topology.is_v5:
            return self.vsd.get_shared_network_resource(
                by_fip_subnet_id=floatingip_subnet_id)
        else:
            return self.vsd.get_shared_network_resource(
                vspk_filter='name is "{}"'.format(
                    external_network_id + '_' + floatingip_subnet_id))

    def create_associate_vsd_managed_floating_ip(self, server, port_id=None,
                                                 vsd_domain=None,
                                                 vsd_subnet=None,
                                                 external_network_id=None,
                                                 ip_address=None,
                                                 cleanup=True):
        external_network_id = external_network_id or self.ext_net_id
        shared_network_resource_id = self.get_vsd_shared_network_resource(
            external_network_id).id

        # Create floating ip
        floating_ip = self.vsd.create_floating_ip(
            vsd_domain, shared_network_resource_id, address=ip_address)
        if cleanup:
            self.addCleanup(floating_ip.delete)

        # Associate floating ip
        if not port_id:
            port_id, _ = self._get_server_port_id_and_ip4(server)
        vport = self.vsd.get_vport(subnet=vsd_subnet, by_port_id=port_id)
        vport.associated_floating_ip_id = floating_ip.id
        vport.save()

        def cleanup_floatingip_vport(vport_):
            vport_.associated_floating_ip_id = None
            vport_.save()

        if cleanup:
            self.addCleanup(cleanup_floatingip_vport, vport)
        return floating_ip

    def update_floatingip(self, floatingip, manager=None, **kwargs):
        manager = manager or self.manager
        body = manager.floating_ips_client.update_floatingip(
            floatingip['id'], **kwargs)
        fip = body['floatingip']
        return fip

    def create_router_interface(self, router_id, subnet_id, manager=None,
                                cleanup=True):
        manager = manager or self.manager
        interface = manager.routers_client.add_router_interface(
            router_id, subnet_id=subnet_id)
        if cleanup:
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.remove_router_interface, router_id, subnet_id,
                            manager)
        return interface

    def remove_router_interface(self, router_id, subnet_id, manager=None):
        manager = manager or self.manager
        manager.routers_client.remove_router_interface(
            router_id, subnet_id=subnet_id)

    def router_attach(self, router, subnet, manager=None, cleanup=True):
        self.create_router_interface(router['id'], subnet['id'],
                                     manager=manager, cleanup=cleanup)

    def router_detach(self, router, subnet, manager=None):
        self.remove_router_interface(router['id'], subnet['id'],
                                     manager=manager)

    def create_router_interface_with_port_id(self, router_id, port_id,
                                             manager=None, cleanup=True):
        manager = manager or self.manager
        interface = manager.routers_client.add_router_interface(
            router_id, port_id=port_id)
        if cleanup:
            self.addCleanup(self.remove_router_interface_with_port_id,
                            router_id, port_id, manager)
        return interface

    def remove_router_interface_with_port_id(self, router_id,
                                             port_id, manager=None):
        manager = manager or self.manager
        manager.routers_client.remove_router_interface(
            router_id, port_id=port_id)

    def router_attach_with_port_id(self, router, port, manager=None,
                                   cleanup=True):
        self.create_router_interface_with_port_id(router['id'], port['id'],
                                                  manager=manager,
                                                  cleanup=cleanup)

    def router_detach_with_port_id(self, router, port, manager=None):
        self.remove_router_interface_with_port_id(router['id'], port['id'],
                                                  manager=manager)

    def get_router_interface(self, by_router_id, by_subnet_id, manager=None):
        ports = self.list_ports(
            manager,
            device_owner="network:router_interface",
            device_id=by_router_id)
        ri_port = next((port for port in ports if
                        port['fixed_ips'][0]['subnet_id'] == by_subnet_id),
                       None)
        return ri_port

    def create_trunk(self, port, subports=None, client=None,
                     cleanup=True, **kwargs):
        client = client or self.plugin_network_client
        body = client.create_trunk(port['id'], subports=subports,
                                   **kwargs)
        trunk = body['trunk']
        if cleanup:
            self.addCleanup(self.delete_trunk, trunk, client)
        return trunk

    def delete_trunk(self, trunk, client=None):
        """Delete network trunk

        :param trunk: dictionary containing trunk ID (trunk['id'])

        :param client: client to be used for connecting to networking service
        """
        client = client or self.plugin_network_client
        trunk.update(client.show_trunk(trunk['id'])['trunk'])

        if not trunk['admin_state_up']:
            # Cannot touch trunk before admin_state_up is True
            client.update_trunk(trunk['id'], admin_state_up=True)
        if trunk['sub_ports']:
            # Removes trunk ports before deleting it
            test_utils.call_and_ignore_notfound_exc(client.remove_subports,
                                                    trunk['id'],
                                                    trunk['sub_ports'])

        # we have to detach the interface from the server before
        # the trunk can be deleted.
        parent_port = {'id': trunk['port_id']}

        def is_parent_port_detached():
            parent_port.update(client.show_port(parent_port['id'])['port'])
            return not parent_port['device_id']

        if not is_parent_port_detached():
            # this could probably happen when trunk is deleted and parent port
            # has been assigned to a VM that is still running. Here we are
            # assuming that device_id points to such VM.
            self.manager.interfaces_client.delete_interface(
                parent_port['device_id'], parent_port['id'])
            utils.wait_until_true(is_parent_port_detached)

        client.delete_trunk(trunk['id'])

    def create_keypair(self, name=None, manager=None, cleanup=True,
                       **kwargs):
        manager = manager or self.manager
        name = name or data_utils.rand_name(self.__class__.__name__)
        # We don't need to create a keypair by pubkey in scenario
        body = manager.keypairs_client.create_keypair(name=name, **kwargs)
        if cleanup:
            self.addCleanup(manager.keypairs_client.delete_keypair, name)
        return body['keypair']

    def get_keypair(self, name=None, user_id=None, manager=None):
        manager = manager or self.manager
        keypair = manager.keypairs_client.show_keypair(
            name, user_id=user_id)['keypair']
        return keypair

    def list_networks(self, manager=None, *args, **kwargs):
        manager = manager or self.manager
        networks_list = manager.networks_client.list_networks(
            *args, **kwargs)
        return networks_list['networks']

    def get_network_by_name(self, name, manager=None):
        networks = self.list_networks(manager, name=name)
        self.assertEqual(1, len(networks))  # assert uniqueness
        return networks[0]

    def list_subnets(self, manager=None, *args, **kwargs):
        manager = manager or self.manager
        subnets_list = manager.subnets_client.list_subnets(
            *args, **kwargs)
        return subnets_list['subnets']

    def list_routers(self, manager=None, *args, **kwargs):
        manager = manager or self.manager
        routers_list = manager.routers_client.list_routers(*args, **kwargs)
        return routers_list['routers']

    def list_ports(self, manager=None, *args, **kwargs):
        manager = manager or self.manager
        ports_list = manager.ports_client.list_ports(*args, **kwargs)
        return ports_list['ports']

    def get_port_in_network(self, owner_id, network, manager=None):
        ports = self.list_ports(manager,
                                device_id=owner_id,
                                network_id=network['id'])
        self.assertEqual(1, len(ports))  # assert uniqueness
        return ports[0]

    def get_server_port_in_network(self, server, network, manager=None):
        return self.get_port_in_network(server.id, network, manager)

    def list_servers(self, manager=None, **kwargs):
        manager = manager or self.manager
        servers = manager.servers_client.list_servers(all_tenants=True,
                                                      **kwargs)
        return servers['servers']

    def get_server(self, server_id, manager=None):
        manager = manager or self.manager
        server = manager.servers_client.show_server(server_id)
        return server['server']

    def get_server_by_name(self, name, manager=None):
        servers = self.list_servers(manager, name=name)
        if len(servers) != 1:
            LOG.warn('{} servers are present, got {}'.format(
                self.list_servers(manager),
                self.list_servers(manager, name=name)))
        self.assertEqual(1, len(servers))  # assert uniqueness
        return servers[0]

    def list_floating_ips(self, manager, **kwargs):
        manager = manager or self.manager
        floating_ips = manager.floating_ips_client.list_floatingips(**kwargs)
        return floating_ips['floatingips']

    def get_floating_ip_by_port_id(self, port_id, assert_not_none=True,
                                   manager=None):
        floating_ips = self.list_floating_ips(manager, port_id=port_id)
        if assert_not_none:
            self.assertEqual(1, len(floating_ips))  # assert uniqueness
            return floating_ips[0]
        else:
            return floating_ips[0] if floating_ips else None

    def get_image_id(self, image_name, manager=None):
        # check cache first
        if image_name in self.image_name_to_id_cache:
            return self.image_name_to_id_cache[image_name]
        manager = manager or self.manager
        images = manager.image_client_v2.list_images()
        image_id = None
        for image in images['images']:
            # add them all
            self.image_name_to_id_cache[image['name']] = image['id']
            if image_name == image['name']:
                image_id = image['id']
        return image_id

    def server_add_interface(self, server, port, manager=None,
                             cleanup=True):
        manager = manager or self.manager
        port_id = port['id']
        iface = manager.interfaces_client.create_interface(
            server.server_details['id'],
            port_id=port_id)['interfaceAttachment']
        iface = waiters.wait_for_interface_status(
            manager.interfaces_client, server.server_details['id'],
            iface['port_id'], 'ACTIVE')
        if cleanup:
            self.addCleanup(
                manager.interfaces_client.delete_interface,
                server.server_details['id'],
                iface['port_id'])

    # TODO(Kris) refactor to eliminate this (or at least much reduce) in favor
    #            of upstream create_server method
    # This is the method called back from TenantServer 'boot' request, which
    # on its turn is invoked from this class's 'create_tenant_server'.
    #
    # ---  This method is for internal use only, don't use from test case;  ---
    #      use create_tenant_server instead                                 ---
    def _create_server(self, tag, tenant_networks=None, ports=None,
                       security_groups=None, wait_until='ACTIVE',
                       volume_backed=False, name=None, flavor=None,
                       image_id=None, keypair=None,
                       manager=None, cleanup=True,
                       return_none_on_failure=False,
                       **kwargs):
        """Common wrapper utility returning a server instance.

        :param tag: used for tagging at logging
        :param tenant_networks: Tenant networks used for creating the server.
        :param security_groups: Tenant security groups for the server.
        :param ports: Tenant ports used for creating the server.
        :param wait_until: Server status to wait for the server to reach after
        its creation.
        :param volume_backed: Whether the instance is volume backed or not.
        :param name: Instance name.
        :param flavor: Instance flavor.
        :param image_id: Instance image ID.
        :param keypair: Nova keypair for ssh access
        :param manager: Client manager providing OpenStack Tempest clients.
        :param cleanup: Flag for cleanup (leave True for auto-cleanup).
        :param return_none_on_failure: if True, return None on failure instead
        of failing the test case
        :returns: a tuple
        """
        manager = manager or self.manager
        name = name or data_utils.rand_name(__name__ + "-instance")
        flavor = flavor or CONF.compute.flavor_ref
        image_id = image_id or CONF.compute.image_ref

        vnic_type = CONF.network.port_vnic_type
        profile = CONF.network.port_profile

        if kwargs:
            networks = kwargs.pop('networks', [])
        else:
            networks = []

        # process ports and networks, ports take precedence
        port_network_id_list = []
        for p in ports or []:
            networks.append({'port': p})
            port_network_id_list.append(p['network_id'])
        for net in tenant_networks or []:
            if net['id'] not in port_network_id_list:  # don't process it twice
                networks.append(net)

        # If vnic_type or profile are configured create port for every network
        if vnic_type or profile:
            ports = []
            create_port_body = {}

            if vnic_type:
                create_port_body['binding:vnic_type'] = vnic_type

            if profile:
                create_port_body['binding:profile'] = profile
            if security_groups:
                security_groups_ids = []
                for sg in security_groups:
                    security_groups_ids.append(sg['id'])
                create_port_body['security_groups'] = security_groups_ids
            for network in networks:
                if 'port' in network:
                    ports.append({'port': network['port']['id']})
                else:
                    port = self.create_port(network,
                                            manager=manager,
                                            **create_port_body)
                    ports.append({'port': port['id']})
            if ports:
                kwargs['networks'] = ports
        else:
            nets = []
            for network in networks:
                if 'port' in network:
                    nets.append({'port': network['port']['id']})
                else:
                    nets.append({'uuid': network['id']})
            kwargs['networks'] = nets
            if security_groups:
                sg_name_dicts = []  # nova requires sg names in dicts
                for sg in security_groups:
                    sg_name_dicts.append({'name': sg['name']})
                kwargs['security_groups'] = sg_name_dicts

        if volume_backed:
            volume_name = data_utils.rand_name('volume')
            volumes_client = manager.volumes_v2_client
            if CONF.volume_feature_enabled.api_v1:
                volumes_client = manager.volumes_client
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

        if keypair:
            kwargs['key_name'] = keypair['name']

        vm = None

        def cleanup_server():
            test_utils.call_and_ignore_notfound_exc(
                manager.servers_client.delete_server, vm['id'])
            waiters.wait_for_server_termination(
                manager.servers_client, vm['id'])

        body = manager.servers_client.create_server(name=name,
                                                    imageRef=image_id,
                                                    flavorRef=flavor,
                                                    **kwargs)

        vm = rest_client.ResponseBody(body.response, body['server'])

        LOG.info('[{}] ID is {}'.format(tag, vm['id']))

        if wait_until:
            LOG.info('[{}] Waiting for to become {}'.format(tag,
                                                            wait_until))
            try:
                waiters.wait_for_server_status(manager.servers_client,
                                               vm['id'], wait_until)

            except Exception as e:

                if ('preserve_server_on_error' not in kwargs or
                        kwargs['preserve_server_on_error'] is False):

                    LOG.error('[{}] Deploy failed ({}). '
                              'Destroying.'.format(name, str(e)))

                    try:
                        cleanup_server()
                        vm = None  # mark deletion success

                    except Exception as e:
                        LOG.exception(
                            '[{}] Failed destroying ({})'.format(name, str(e)))

                    if vm is not None:
                        if return_none_on_failure:
                            LOG.error('[{}] Destroy failed'.format(name))
                            return None
                        else:
                            self.fail('[{}] Destroy failed'.format(name))

        if vm:
            if cleanup:
                self.addCleanup(cleanup_server)

            return vm

        else:

            # FAILED TO DEPLOY SERVER

            if return_none_on_failure:
                LOG.error('[{}] Deploying server {} failed'.format(
                    self.test_name, name))
                return None

            else:
                self.fail('Deploying server {} failed'.format(name))

    # create_tenant_server : creating a tenant server (nova instance)
    #
    # -- This is the reference method to use in nuage api/connectivity tests --
    #
    def create_tenant_server(self, networks=None, ports=None,
                             security_groups=None, keypair=None,
                             wait_until='ACTIVE',
                             volume_backed=False, name=None, flavor=None,
                             prepare_for_connectivity=None,
                             pre_prepared_fip=None,
                             start_web_server=False,
                             web_server_port=80,
                             force_dhcp_config=False,
                             manager=None, cleanup=True, **kwargs):

        assert not (networks and ports)  # one of both, not both
        assert networks or ports  # but one at least
        assert not (ports and security_groups)  # one of both, not both

        name = name or data_utils.rand_name('test-server')
        manager = manager or self.manager

        LOG.info('[{}] --- INITIATE:{} ---'.format(self.test_name, name))
        LOG.info('[{}] Got {}'.format(
            self.test_name,
            '{} network(s)'.format(len(networks)) if networks
            else '{} port(s)'.format(len(ports))))

        if prepare_for_connectivity is None:
            prepare_for_connectivity = self.default_prepare_for_connectivity
            if prepare_for_connectivity:
                LOG.info('[{}] prepare_for_connectivity is set as of test '
                         'class default'.format(self.test_name))

        def needs_provisioning(server_networks=None, server_ports=None):
            # we configure through cloudinit the interfaces for DHCP;
            # hence we only need provisioning for non-DHCP networks
            if force_dhcp_config:
                return False
            if server_networks:
                for net in server_networks:
                    if not self.is_dhcp_enabled(net):
                        return True
                return False
            else:
                server_networks = []
                for port in server_ports:
                    server_networks.append(self.get_network(
                        port['network_id'], manager=manager))
                return needs_provisioning(server_networks)

        provisioning_needed = (needs_provisioning(networks, ports)
                               if prepare_for_connectivity
                               else False)

        if prepare_for_connectivity:
            first_network = (
                networks[0] if networks
                else self.get_network(ports[0]['network_id'], manager=manager))
            first_v4_subnet = self.get_network_subnet(first_network, 4,
                                                      manager=manager)

            # fip is only supported on L3 v4, so in L2 or L3 pure v6 cases,
            # another L3 domain with v4 subnet will be created to associate FIP
            # - this is also done for L3 subnets that have v4 but no dhcpv4,
            #   as the nic won't obtain ip then

            if not first_v4_subnet:
                prepare = True

            # ----------------------- aggregate flows -------------------------
            # There is a limitation today of FIP 2 UL not working with
            # aggregate flows; therefore, treat vsd managed always as L2, such
            # that a new network will be created at which the FIP will be
            # applied; and as such overcome the limitation
            elif (first_v4_subnet['vsd_managed'] and
                    self.enable_aggregate_flows_on_vsd_managed):
                prepare = True
            elif self.nuage_aggregate_flows == 'route':
                prepare = True
            # ----------------------- aggregate flows -------------------------

            elif self.is_l2_subnet(first_v4_subnet, manager=manager):
                prepare = True
            else:
                prepare = not first_v4_subnet['enable_dhcp']

            if prepare:
                ports = self.prepare_fip_topology(
                    name, networks, ports, security_groups, manager, cleanup)
                networks = []
                security_groups = []
                provisioning_needed |= needs_provisioning(server_ports=ports)

        keypair = keypair or self.create_keypair(manager=manager,
                                                 cleanup=cleanup)

        LOG.info('[{}] Creating TenantServer {} ({})'.format(
            self.test_name, name,
            '{} network(s)'.format(len(networks)) if networks
            else '{} port(s)'.format(len(ports))))

        server = TenantServer(self, name, networks, ports,
                              security_groups, flavor, keypair, volume_backed)

        if start_web_server:
            kwargs['user_data'] = (kwargs.get('user_data', '') +
                                   self._get_start_web_server_cmd(
                                       web_server_port))

        server.boot(wait_until, manager, cleanup, **kwargs)
        server.force_dhcp = force_dhcp_config
        server.set_to_prepare_for_connectivity = prepare_for_connectivity
        server.needs_provisioning = provisioning_needed

        # Check need for provisioning interfaces statically ...
        if provisioning_needed:
            LOG.info('[{}] {} will need provisioning'.format(
                self.test_name, name))
            server.needs_provisioning = True

        # In both cases, the actual provisioning or the potential need for
        # making the server reachable is postponed, such that parallel booting
        # of servers is maximized (and test execution minimized)

        LOG.info('[{}] {} deployed SUCCESSFULLY'.format(
            self.test_name, name))

        # If to be prepared for connectivity, create/associate FIP now
        if prepare_for_connectivity:
            if pre_prepared_fip:
                server.associate_fip(pre_prepared_fip)
            else:
                self.make_fip_reachable(server, manager, cleanup)

        LOG.info('[{}] --- COMPLETE:{} ---'.format(
            self.test_name, server.name))
        LOG.info('[{}]'.format(self.test_name))

        return server

    def make_fip_reachable(self, server, manager=None, cleanup=True):
        LOG.info('[{}] Making {} FIP reachable'.format(
            self.test_name, server.name))

        # make reachable over the 1st port
        if server.networks:
            first_network = server.networks[0]
            if server.ports:
                first_port = server.ports[0]
            else:
                first_port = self.get_server_port_in_network(
                    server, first_network, manager=manager)
        else:
            assert server.ports
            first_port = server.ports[0]
            first_network = self.get_network(first_port['network_id'],
                                             manager=manager)

        v4_subnet = self.get_network_subnet(first_network, 4,
                                            manager=manager)
        if v4_subnet['vsd_managed']:
            if self.is_l3_subnet(v4_subnet, manager=manager):
                # vsd managed l3
                vsd_l3_subnet = self.vsd.get_subnet(
                    by_id=v4_subnet['nuagenet'])
                assert vsd_l3_subnet
                _, domain = self.vsd.get_zone_and_domain_parent_of_subnet(
                    vsd_l3_subnet)
                self.create_fip_to_server(
                    server, first_port, domain, vsd_l3_subnet,
                    manager=manager, cleanup=cleanup)
            else:
                # vsd managed l2
                raise NotImplementedError
        else:
            # OS managed
            self.create_fip_to_server(server, first_port,
                                      manager=manager, cleanup=cleanup)

    def prepare_fip_topology(
            self, server_name, networks, ports, security_groups=None,
            manager=None, cleanup=True):

        LOG.info('[{}] Preparing FIP topology for {}'.format(
            self.test_name, server_name))

        # Current network (L2 or L3 pure v6)
        if networks:
            ports = []
            sgs = []
            if security_groups:
                for sg in security_groups:
                    sgs.append(sg['id'])
            for network in networks:
                port = self.create_port(network,
                                        security_groups=sgs,
                                        # make sure this port does not
                                        # become the default port
                                        extra_dhcp_opts=[
                                            {'opt_name': 'router',
                                             'opt_value': '0'}],
                                        manager=manager,
                                        cleanup=cleanup)
                ports.append(port)

        # Create a jump (FIP) network (L3)
        fip_network = self.create_network(manager=manager, cleanup=cleanup)
        fip_cidr = IPNetwork("192.168.0.0/24")
        subnet = self.create_subnet(
            fip_network, cidr=fip_cidr, mask_bits=fip_cidr.prefixlen,
            ip_version=4, manager=manager, cleanup=cleanup)
        router = self.create_public_router(manager=manager, cleanup=cleanup)
        self.router_attach(router, subnet, manager=manager, cleanup=cleanup)

        open_ssh_sg = self.create_open_ssh_security_group(manager=manager,
                                                          cleanup=cleanup)

        # Avoid mixing virtio and switchdev port
        # On RHEL-7-7, interfaces are ordered. VIRTIO comes first, then
        # switchdev. We don't want this order to change since metadata
        # agent relies on DHCPv4 being executed on first interface and
        # this should be the fip_port interface.
        fip_kwargs = {'binding:vnic_type': ports[0]['binding:vnic_type']}
        if 'binding:profile' in ports[0]:
            fip_kwargs['binding:profile'] = ports[0]['binding:profile']

        fip_port = self.create_port(fip_network,
                                    security_groups=[open_ssh_sg['id']],
                                    manager=manager, cleanup=cleanup,
                                    **fip_kwargs)

        LOG.info('[{}] FIP topology for {} set up'.format(
            self.test_name, server_name))

        return [fip_port] + ports

    def create_fip_to_server(self, server, port=None,
                             vsd_domain=None, vsd_subnet=None, manager=None,
                             cleanup=True):
        """Create a fip and connect it to the given server

        :param server: the tenant server
        :param port: its first port
        :param vsd_domain: L3Domain VSPK object
        :param vsd_subnet: L3Subnet VSPK object
        :param manager: os manager
        :param cleanup: add automated cleanup
        :return: the associated FIP
        """
        if not server.associated_fip:
            if vsd_domain:
                LOG.info('[{}] Creating FIP for {} using VSD domain'.format(
                    self.test_name, server.name))
                fip = self.create_floatingip(
                    manager=manager,
                    cleanup=cleanup)
                self.create_associate_vsd_managed_floating_ip(
                    server.get_server_details(),
                    port_id=port['id'] if port else None,
                    vsd_domain=vsd_domain,
                    vsd_subnet=vsd_subnet,
                    ip_address=fip['floating_ip_address'],
                    cleanup=cleanup)
            else:
                LOG.info('[{}] Creating FIP for {}'.format(
                    self.test_name, server.name))
                fip = self.create_floatingip(
                    server.get_server_details(),
                    port_id=port['id'] if port else None,
                    manager=manager,
                    cleanup=cleanup)

            server.associate_fip(fip)

        return server.associated_fip

    def start_tenant_server(self, server, wait_until=None):
        self.servers_client.start_server(server.id)
        if wait_until:
            try:
                waiters.wait_for_server_status(
                    self.servers_client, server.id, wait_until)
            except Exception as e:
                LOG.exception('Starting server {} failed ({})'.format(
                    server.openstack_data['id'], e))

    def stop_tenant_server(self, server_id, wait_until='SHUTOFF'):
        self.servers_client.stop_server(server_id)
        if wait_until:
            try:
                waiters.wait_for_server_status(
                    self.servers_client, server_id, wait_until)
            except Exception as e:
                LOG.exception('Stopping server {} failed ({})'.format(
                    server_id, e))

    def assert_ping(self, server1, server2=None, network=None, ip_version=None,
                    should_pass=True, interface=None, address=None,
                    ping_count=3, ping_size=None, ping_timeout=10):
        LOG.info('[{}] Pinging {} > {}'.format(
            self.test_name,
            server1.name, server2.name if server2 else address))

        ip_version = ip_version if ip_version else self._ip_version

        if server2:
            if server2.set_to_prepare_for_connectivity:
                # this may be a reason alone to declare a server a to prepare
                # fip connectivity : making sure it completed on cloudinit
                server2.wait_for_cloudinit_to_complete()

                # furthermore, if provisioning is needed, provision
                if server2.needs_provisioning:
                    server2.provision()

            if address:
                dest = address
            else:
                assert network
                dest = server2.get_server_ip_in_network(
                    network['name'], ip_version)
        else:
            assert address
            dest = address

        if server1.needs_provisioning:
            server1.provision()

        def ping():

            timeout = ping_timeout or CONF.validation.ping_timeout
            count = ping_count or CONF.validation.ping_count
            size = ping_size or CONF.validation.ping_size

            def ping_cmd(source, nic=None):

                # Use 'ping6' for IPv6 addresses, 'ping' for IPv4 and hostnames

                cmd = 'ping6' if ip_version == 6 else 'ping'
                if nic:
                    cmd = '{cmd} -I {nic}'.format(cmd=cmd, nic=interface)
                cmd += ' -c{0} -w{0} -s{1} {2}'.format(count, size, dest)
                return source.send(cmd, as_sudo=False, one_off_attempt=True,
                                   assert_success=False) is not None

            def ping_address():

                LOG.info('[{}] Pinging {} from {}'.format(
                    self.test_name, dest, server1.get_fip_ip()))

                if ping_cmd(server1, interface):
                    success = True
                else:
                    msg = '[{}] Failed to ping IP {} from {} ({})'.format(
                        self.test_name, dest, server1.name,
                        server1.get_fip_ip())
                    if should_pass:
                        LOG.warning(msg)
                    else:
                        LOG.info(msg)
                    if ip_version == 4:
                        LOG.info('[{}] Clearing ARP cache for {}'.format(
                            self.test_name, dest))
                        cmd = 'arp -d {}'.format(dest)
                        if server1.send(cmd, one_off_attempt=True,
                                        assert_success=False) is None:
                            LOG.debug('[{}] Failed to execute command on'
                                      ' {}'.format(self.test_name, server1.id))
                    else:
                        if should_pass:
                            # TODO(OPENSTACK-2664) : CI test robustness:
                            #      include ip neigh in our cirros-ipv6 image
                            LOG.warn('[{}] Would need to clear IPv6 neighbors '
                                     'cache but need CI image support '
                                     '({})'.format(self.test_name, dest))
                    success = False

                LOG.info('[{}] Ping -{}- {}'.format(
                    self.test_name,
                    'expected' if success == should_pass else 'unexpected',
                    'SUCCESS' if success else 'FAIL'))

                return success

            return test_utils.call_until_true(ping_address, timeout, 1)

        try:
            self.assertEqual(should_pass, ping())

        except lib_exc.SSHTimeout as ssh_e:
            LOG.error('[{}] SSH Timeout! ({})'.format(self.test_name, ssh_e))
            raise

        except AssertionError:
            LOG.error('[{}] Ping {} > {} unexpectedly {}!'.format(
                self.test_name,
                server1.name, server2.name if server2 else address,
                'FAILED' if should_pass else 'PASSED'))

            # DEFINE ACTIONS HERE...
            # self.sleep(300, 'Pausing for giving means to debug...',
            #            tag=self.test_name)
            raise

    def assertDictEqual(self, d1, d2, ignore, msg):
        for k in d1:
            if k in ignore:
                continue
            self.assertIn(k, d2, "{} for key {}".format(msg, k))
            self.assertEqual(d1[k], d2[k], "{} for key {}".format(msg, k))

    @staticmethod
    def _get_start_web_server_cmd(tcp_port):
        return ("screen -d -m sh -c '"
                "while true; do echo -e \"HTTP/1.0 200 Ok\\n\\nHELLO\\n\" "
                "| nc -l -p {port}; done;'".format(port=tcp_port))

    @staticmethod
    def start_web_server(server, port):
        cmd = NuageBaseTest._get_start_web_server_cmd(port)
        server.send(cmd)

    def delete_server(self, vm_id, manager=None):
        manager = manager or self.manager
        manager.servers_client.delete_server(vm_id)
        waiters.wait_for_server_termination(manager.servers_client, vm_id)

    def delete_network(self, network, manager=None):
        manager = manager or self.manager
        manager.networks_client.delete_network(network['id'])

    def delete_router_interface(self, router, subnet, manager=None):
        manager = manager or self.manager
        manager.routers_client.remove_router_interface(router['id'],
                                                       subnet_id=subnet['id'])

    def delete_subnet(self, subnet, manager=None):
        manager = manager or self.manager
        manager.subnets_client.delete_subnet(subnet['id'])

    def verify_ip_in_allocation_pools(self, ip_address, allocation_pools):
        in_pool = False
        for pool in allocation_pools:
            start_ip_address = pool['start']
            end_ip_address = pool['end']
            ip_range = IPRange(start_ip_address, end_ip_address)
            if IPAddress(ip_address) in ip_range:
                in_pool = True
        self.assertTrue(in_pool, msg="IP address not in allocation pools")

    @staticmethod
    # ref: https://stackoverflow.com/a/28950776/6244487
    def get_local_ip():  # creates a socket to get the local ip
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't have to be reachable
            s.connect(('13.255.255.255', 1))
            ip = s.getsockname()[0]
        finally:
            s.close()
        LOG.debug("Local IP: {}".format(ip))
        return ip

    def create_redirection_target(self, **post_body):
        return self.plugin_network_client.create_redirection_target(
            **post_body)

    def delete_redirection_target(self, rt_id):
        return self.plugin_network_client.delete_redirection_target(rt_id)

    def create_redirection_target_rule(self, **post_body):
        return self.plugin_network_client.create_redirection_target_rule(
            **post_body)

    def check_dhcp_port(self, network_id, ip_types):
        if self.is_dhcp_agent_present():
            filters = {
                'device_owner': 'network:dhcp',
                'network_id': network_id
            }
            dhcp_port = self.ports_client.list_ports(**filters)['ports'][0]
            vm_interface = self.nuage_client.get_resource(
                'vms',
                filters='externalID',
                filter_values=self.nuage_client.get_vsd_external_id(
                    dhcp_port['id']),
                flat_rest_path=True)[0]['interfaces'][0]
            for idx, ip_type in enumerate(ip_types):
                if ip_type == 4:
                    self.assertEqual(
                        dhcp_port['fixed_ips'][idx]['ip_address'],
                        vm_interface['IPAddress'])
                else:
                    self.assertEqual(
                        dhcp_port['fixed_ips'][idx]['ip_address'] + '/64',
                        vm_interface['IPv6Address'])
            if len(ip_types) == 1:
                if ip_types[0] == 4:
                    self.assertIsNone(vm_interface['IPv6Address'])
                else:
                    self.assertIsNone(vm_interface['IPAddress'])

    def create_security_group(self, manager=None, cleanup=True, **kwargs):
        manager = manager or self.manager
        client = manager.security_groups_client
        sg = {'name': data_utils.rand_name('security-group')}
        sg.update(kwargs)
        sg = client.create_security_group(**sg)['security_group']
        if cleanup:
            self.addCleanup(self.delete_security_group, sg['id'],
                            manager=manager)
        return sg

    def delete_security_group(self, sg_id, ignore_not_found=True,
                              manager=None):
        manager = manager or self.manager
        client = manager.security_groups_client
        try:
            client.delete_security_group(sg_id)
        except lib_exc.NotFound:
            if not ignore_not_found:
                raise

    @staticmethod
    def execute_from_shell(command, success_expected=True, pause=None):
        output = None
        try:
            LOG.debug('Executing: {}'.format(command))
            output = (subprocess.check_output(
                command, shell=True)).decode('utf-8')
            LOG.debug('Output: {}'.format(output))
        except subprocess.CalledProcessError:
            if success_expected:
                raise
        if pause:
            time.sleep(pause)
        return output

    def create_segment(self, segment_name=None, cleanup=True,
                       manager=None, **kwargs):
        manager = manager or self.admin_manager
        segment_name = segment_name or data_utils.rand_name('test-segment')
        body = manager.segments_client.create_segment(
            name=segment_name, **kwargs)
        segment = body['segment']
        self.assertIsNotNone(segment)
        if cleanup:
            self.addCleanup(
                self.admin_manager.segments_client.delete_segment,
                segment['id'])
        return segment


class NuageBaseOrchestrationTest(NuageBaseTest):
    """Base test case class for all Nuage Orchestration API tests."""

    @classmethod
    def skip_checks(cls):
        super(NuageBaseOrchestrationTest, cls).skip_checks()
        if not hasattr(CONF, 'heat_plugin'):
            raise cls.skipException('heat_plugin is not configured '
                                    'in tempest.conf')

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

        cls.net_partition_name = Topology.def_netpartition
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


# TODO(KRIS) NEED TO INTEGRATE BELOW CLASS WITH NUAGEBASETEST SOMEHOW
class NuageAdminNetworksTest(base.BaseAdminNetworkTest):

    dhcp_agent_present = None
    ext_net_id = CONF.network.public_network_id

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

    @staticmethod
    def sleep(seconds=1, msg=None):
        if not msg:
            LOG.error(
                "Added a {}s sleep without clarification. "
                "Please add motivation for this sleep.".format(seconds))
        else:
            LOG.warning("Sleeping for {}s. {}.".format(seconds, msg))
        time.sleep(seconds)

    @classmethod
    def create_port(cls, network, **kwargs):
        if CONF.network.port_vnic_type and 'binding:vnic_type' not in kwargs:
            kwargs['binding:vnic_type'] = CONF.network.port_vnic_type
        if CONF.network.port_profile and 'binding:profile' not in kwargs:
            kwargs['binding:profile'] = CONF.network.port_profile
        return super(NuageAdminNetworksTest, cls).create_port(network,
                                                              **kwargs)
