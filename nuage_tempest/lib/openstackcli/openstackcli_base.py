# Copyright 2015 Alcatel-Lucent USA Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import json

import netaddr

from nuage_tempest.lib.openstackcli import openstack_cliclient
from nuage_tempest.lib.openstackcli import vpnaas_cliclient

from oslo_log import log as logging

from tempest import config
from tempest import exceptions
from tempest.lib.common.utils import data_utils

CONF = config.CONF

LOG = logging.getLogger(__name__)


class NetworkClient(openstack_cliclient.ClientTestBase):
    force_tenant_isolation = False

    def __init__(self, osc):
        super(NetworkClient, self).__init__(osc)

    def create_network_with_args(self, network_name, **kwargs):
        """Wrapper utility that returns a test network."""
        the_params = '{} '.format(network_name)
        for k, v in kwargs.iteritems():
            the_params += ('--{} {} '.format(k, v))

        response = self.cli.neutron('net-create', params=the_params)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Created a new network:')
        network = self.parser.details(response)
        response = {'network': network}
        return response

    def create_network(self, name=None):
        """Wrapper utility that returns a test network."""
        network_name = name or data_utils.rand_name('test-network')
        kwargs = {}
        return self.create_network_with_args(network_name, **kwargs)

    def delete_network(self, network_id):
        response = self._delete_network(network_id)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Deleted network')

    def show_network(self, network_id):
        response = self.cli.neutron('net-show', params=network_id)
        network = self.parser.details(response)
        # assert network['id'] == network_id
        response = {'network': network}
        return response

    def list_networks(self):
        response = self.cli.neutron('net-list')
        networks = self.parser.listing(response)
        return networks

    def update_network_with_args(self, net_id, **kwargs):
        """Wrapper utility that updates returns a test network."""
        the_params = '{} '.format(net_id)
        for k, v in kwargs.iteritems():
            the_params += ('--{} {} '.format(k, v))
        response = self.cli.neutron('net-update', params=the_params)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Updated network:')

    def _delete_network(self, network_id):
        response = self.cli.neutron('net-delete', params=network_id)
        return response


class SubnetClient(openstack_cliclient.ClientTestBase):
    force_tenant_isolation = False

    def __init__(self, osc):
        super(SubnetClient, self).__init__(osc)

    def show_subnet(self, subnet_id):
        response = self.cli.neutron('subnet-show', params=subnet_id)
        subnet = self.parser.details(response)
        # networks = self.parser.listing(response)
        # assert subnet['id'] == subnet_id
        response = {'subnet': subnet}
        return response

    def list_subnets(self):
        response = self.cli.neutron('subnet-list')
        subnets = self.parser.listing(response)
        return subnets

    def create_subnet_with_args(self, network_id, cidr,
                                gateway_ip,
                                **kwargs):
        """Wrapper utility that returns a test subnet."""
        the_params = '{} {} '.format(network_id, cidr)
        if gateway_ip:
            the_params += ('--gateway {} '.format(gateway_ip))
        for k, v in kwargs.iteritems():
            the_params += ('--{} {} '.format(k, v))

        response = self.cli.neutron('subnet-create', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Created a new subnet:')
        subnet = self.parser.details(response)
        response = {'subnet': subnet}
        return response

    def update_subnet_with_args(self, *args):
        """Wrapper utility that updates returns a test subnet."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('subnet-update', params=the_params)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Updated subnet:')

    def delete_subnet(self, subnet_id):
        response = self.cli.neutron('subnet-delete', params=subnet_id)
        return response


class RouterClient(openstack_cliclient.ClientTestBase):
    force_tenant_isolation = False

    _ip_version = 4

    def __init__(self, osc):
        super(RouterClient, self).__init__(osc)

    def create_router_with_args(self, router_name, **kwargs):
        """Wrapper utility that returns a test router."""
        the_params = '{}'.format(router_name)
        for k, v in kwargs.iteritems():
            the_params += ('--{} {} '.format(k, v))

        response = self.cli.neutron('router-create', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Created a new router:')
        router = self.parser.details(response)
        response = {'router': router}
        return response

    def create_router(self, router_name=None, **kwargs):
        """Wrapper utility that returns a test router."""
        router_name = router_name or data_utils.rand_name('test-router')
        return self.create_router_with_args(router_name, **kwargs)

    def update_router_with_args(self, *args):
        """Wrapper utility that returns a test router."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('router-update', params=the_params)
        self.assertFirstLineStartsWith(response.split('\n'), 'Updated router:')

    def show_router(self, router_id):
        response = self.cli.neutron('router-show', params=router_id)
        router = self.parser.details(response)
        # assert router['id'] == router_id
        response = {'router': router}
        return response

    def list_routers(self):
        response = self.cli.neutron('router-list')
        routers = self.parser.listing(response)
        return routers

    def set_router_gateway_with_args(self, *args):
        """Wrapper utility that sets the router gateway."""
        the_params = ''
        for arg in args:
            the_params += ' '
            the_params += arg

        response = self.cli.neutron('router-gateway-set', params=the_params)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Set gateway for router')

    def add_router_interface(self, router_id, subnet_id):
        """Wrapper utility that sets the router gateway."""
        the_params = '{} {} '.format(router_id, subnet_id)
        response = self.cli.neutron('router-interface-add', params=the_params)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Added interface')

    def remove_router_interface(self, router_id, subnet_id):
        response = self.cli.neutron('router-interface-delete',
                                    params=router_id + ' ' + subnet_id)
        return response

    def delete_router(self, router_id):
        self._clear_router_gateway(router_id)
        interfaces = self._list_router_ports(router_id)
        for i in interfaces:
            fixed_ips = i['fixed_ips']
            fixed_ips_dict = json.loads(fixed_ips)
            subnet_id = fixed_ips_dict['subnet_id']
            self.remove_router_interface(router_id, subnet_id)
        self._delete_router(router_id)

    def _clear_router_gateway(self, router_id):
        self.cli.neutron('router-gateway-clear', params=router_id)

    def _list_router_ports(self, router_id):
        response = self.cli.neutron('router-port-list', params=router_id)
        ports = self.parser.listing(response)
        return ports

    def _delete_router(self, router_id):
        self.cli.neutron('router-delete', params=router_id)


class PortClient(openstack_cliclient.ClientTestBase):
    force_tenant_isolation = False

    def __init__(self, osc):
        super(PortClient, self).__init__(osc)

    def create_port(self, network, **kwargs):
        """Wrapper utility that returns a test port."""
        the_params = '{} '.format(network['id'])
        for k, v in kwargs.iteritems():
            the_params += ('--{} {} '.format(k, v))

        response = self.cli.neutron('port-create', params=the_params)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Created a new port:')
        port = self.parser.details(response)

        port['allowed_address_pairs'] = self.parser.to_list_of_dict(
            port['allowed_address_pairs'])
        port['fixed_ips'] = self.parser.to_list_of_dict(port['fixed_ips'])

        response = {'port': port}
        return response

    def delete_port(self, port_id):
        response = self._delete_port(port_id)
        self.assertFirstLineStartsWith(response.split('\n'), 'Deleted port')

    def show_port(self, port_id):
        response = self.cli.neutron('port-show', params=port_id)
        port = self.parser.details(response)
        assert port['id'] == port_id
        response = {'port': port}
        return response

    def list_ports(self):
        response = self.cli.neutron('port-list')
        ports = self.parser.listing(response)
        return ports

    def update_port(self, port, **kwargs):
        """Wrapper utility that updates returns a test port."""
        the_params = '{} '.format(port['id'])
        for k, v in kwargs.iteritems():
            the_params += ('--{} {} '.format(k, v))
        response = self.cli.neutron('port-update', params=the_params)

        self.assertFirstLineStartsWith(response.split('\n'), 'Updated port:')

    def _delete_port(self, port_id):
        response = self.cli.neutron('port-delete', params=port_id)
        return response


class BgpVpnClient(openstack_cliclient.ClientTestBase):
    force_tenant_isolation = False

    def __init__(self, osc):
        super(BgpVpnClient, self).__init__(osc)

    def create_bgpvpn(self, **kwargs):
        params = ''
        for k, v in kwargs.iteritems():
            params = params + '--{} {} '.format(k, v)
        bgpvpn = self.cli.neutron('bgpvpn-create', params=params)
        self.assertFirstLineStartsWith(bgpvpn.split('\n'),
                                       'Created a new bgpvpn:')
        bgpvpn = self.parser.details(bgpvpn)
        response = {'bgpvpn': bgpvpn}
        return response

    def delete_bgpvpn(self, bgpvpn_id):
        self.cli.neutron('bgpvpn-delete {}'.format(bgpvpn_id))

    def show_bgpvpn(self, bgpvpn_id):
        response = self.cli.neutron('bgpvpn-show {}'.format(bgpvpn_id))
        item = self.parser.details(response)
        return item

    def list_bgpvpn(self):
        response = self.cli.neutron('bgpvpn-list')
        items = self.parser.listing(response)
        return items

    def bgpvpn_router_assoc_create(self, bgpvpnid, **kwargs):
        params = '{} '.format(bgpvpnid)
        for k, v in kwargs.iteritems():
            params = params + '--{} {} '.format(k, v)
        response = self.cli.neutron('bgpvpn-router-assoc-create',
                                    params=params)
        bgpvpn = self.parser.details(response)
        self.assertFirstLineStartsWith(response.split('\n'),
                                       'Created a new router_association:')
        return bgpvpn

    def bgpvpn_router_assoc_list(self, bgpvpnid):
        resp = self.cli.neutron('bgpvpn-router-assoc-list {}'.format(bgpvpnid))
        items = self.parser.listing(resp)
        return items

    def bgpvpn_net_assoc_create(self, bgpvpnid, fail_ok=True, **kwargs):
        params = '{} '.format(bgpvpnid)
        for k, v in kwargs.iteritems():
            params = params + '--{} {} '.format(k, v)
        response = self.cli.neutron('bgpvpn-net-assoc-create', params=params,
                                    fail_ok=fail_ok)
        if response[0].startswith('BGPVPN Nuage driver does not support'):
            assert()


class VPNaaSClient(vpnaas_cliclient.VPNaaSClient):
    force_tenant_isolation = False

    def __init__(self, osc):
        super(VPNaaSClient, self).__init__(osc)

    def delete_vpnaas(self, vpn_id):
        self.cli.neutron('vpnaas-delete {}'.format(vpn_id))


class OpenstackCliClient(object):
    """OpenstackCliClient

    Base class for the Neutron tests that use the remote CLI clients
    """

    def __init__(self, osc):
        self.networks = []
        self.subnets = []
        self.ports = []
        self.routers = []
        self.floating_ips = []
        self.security_groups = []
        self.security_group_rules = []
        self.vms = []
        self.bgpvpns = []
        self.vpnaas = []

        self.networks_client = NetworkClient(osc)
        self.subnets_client = SubnetClient(osc)
        self.routers_client = RouterClient(osc)
        self.ports_client = PortClient(osc)
        self.bgpvpn_client = BgpVpnClient(osc)
        self.vpnaas_client = VPNaaSClient(osc)
        self._ip_version = 4

    def resource_cleanup(self):
        # Clean up ports
        for port in self.ports:
            self.delete_port(port['id'])

        # Clean up routers
        for router in self.routers:
            self.delete_router(router['id'])
            self.routers.remove(router)

        # Clean up subnets
        for subnet in self.subnets:
            self.delete_subnet(subnet['id'])
            self.subnets.remove(subnet)

        # Clean up networks
        for network in self.networks:
            self.delete_network(network['id'])
            self.networks.remove(network)

        for bgpvpn in self.bgpvpns:
            self.delete_bgpvpn(bgpvpn['id'])
            self.bgpvpns.remove(bgpvpn)

        for vpnaas in self.vpnaas:
            self.delete_vpnaas(vpnaas['id'])
            self.vpnaas.remove(vpnaas)

    def __del__(self):
        self.resource_cleanup()

    def create_network(self, network_name=None, **kwargs):
        """Wrapper utility that returns a test network."""
        network_name = network_name or data_utils.rand_name('test-network-')
        if not kwargs:
            body = self.networks_client.create_network(name=network_name)
        else:
            body = self.networks_client.create_network_with_args(
                network_name=network_name, **kwargs)
        network = body['network']
        self.networks.append(network)
        return network

    def delete_network(self, network_id):
        """Wrapper utility that deletes a test network."""
        try:
            self.networks_client.delete_network(network_id)
        except Exception:
            raise

    def show_network(self, network_id):
        body = self.networks_client.show_network(network_id)
        return body['network']

    def update_network(self, network_id, **kwargs):
        self.networks_client.update_network_with_args(network_id, **kwargs)

    def create_port(self, network, port_name=None, **kwargs):
        """Wrapper utility that returns a test network."""
        port_name = port_name or data_utils.rand_name('test-port-')
        kwargs.update({'name': port_name})
        body = self.ports_client.create_port(network, **kwargs)
        port = body['port']
        self.ports.append(port)
        return port

    def delete_port(self, port_id):
        """Wrapper utility that deletes a test network."""
        try:
            self.ports_client.delete_port(port_id)
        except Exception:
            raise

    def show_port(self, port_id):
        body = self.ports_client.show_port(port_id)
        return body['port']

    def update_port(self, port, **kwargs):
        self.ports_client.update_port(port, **kwargs)

    def create_subnet(self, network, gateway='', cidr=None, mask_bits=None,
                      ip_version=None, client=None, **kwargs):
        """Wrapper utility that returns a test subnet."""

        # allow tests to use admin client
        if not client:
            client = self.subnets_client

        # The cidr and mask_bits depend on the ip version.
        ip_version = ip_version if ip_version is not None else self._ip_version
        gateway_not_set = gateway == ''
        if ip_version == 4:
            cidr = cidr or netaddr.IPNetwork(CONF.network.tenant_network_cidr)
            mask_bits = mask_bits or CONF.network.tenant_network_mask_bits
        elif ip_version == 6:
            cidr = (
                cidr or netaddr.IPNetwork(CONF.network.tenant_network_v6_cidr))
            mask_bits = mask_bits or CONF.network.tenant_network_v6_mask_bits
        # Find a cidr that is not in use yet and create a subnet with it
        for subnet_cidr in cidr.subnet(mask_bits):
            if gateway_not_set:
                gateway_ip = str(netaddr.IPAddress(subnet_cidr) + 1)
            else:
                gateway_ip = gateway
            try:
                body = client.create_subnet_with_args(
                    network_id=network['id'],
                    cidr=str(subnet_cidr),
                    ip_version=ip_version,
                    gateway_ip=gateway_ip,
                    **kwargs)
                break
            except Exception as e:
                is_overlapping_cidr = 'overlaps with another subnet' in str(e)
                if not is_overlapping_cidr:
                    raise
        else:
            message = 'Available CIDR for subnet creation could not be found'
            raise exceptions.BuildErrorException(message)
        subnet = body['subnet']
        self.subnets.append(subnet)
        return subnet

    def delete_subnet(self, subnet_id):
        try:
            self.subnets_client.delete_subnet(subnet_id)
        except Exception:
            raise

    def create_router(self, router_name=None, **kwargs):
        body = self.routers_client.create_router(
            router_name, **kwargs)
        router = body['router']
        self.routers.append(router)
        return router

    def delete_router(self, router_id):
        try:
            self.routers_client.delete_router(router_id)
        except Exception:
            raise

    def create_router_interface(self, router_id, subnet_id):
        try:
            self.routers_client.add_router_interface(router_id, subnet_id)
        except Exception:
            raise

    def remove_router_interface(self, router_id, subnet_id):
        try:
            self.routers_client.remove_router_interface(router_id, subnet_id)
        except Exception:
            raise

    def create_bgpvpn(self, **kwargs):
        body = self.bgpvpn_client.create_bgpvpn(**kwargs)
        bgpvpn = body['bgpvpn']
        self.bgpvpns.append(bgpvpn)
        return bgpvpn

    def delete_bgpvpn(self, bgpvpn_id):
        self.bgpvpn_client.delete_bgpvpn(bgpvpn_id)

    def delete_vpnaas(self, vpn_id):
        self.vpnaas_client.delete_vpnaas(vpn_id)
