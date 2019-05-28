# Copyright 2015 Alcatel-Lucent USA Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
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
#
#    -----------------------WARNING----------------------------
#     This file is present to support Legacy Test Code only.
#     DO not use this file for writing the new tests.
#    ----------------------------------------------------------
#

import json
from six.moves.urllib import parse as urlparse

from tempest.lib.common import rest_client as service_client
from tempest.lib.common.utils import data_utils
from tempest.lib.exceptions import ServerFault

from nuage_tempest_plugin.lib.topology import Topology
import nuage_tempest_plugin.lib.utils.constants as constants

CONF = Topology.get_conf()


class NuageNetworkClientJSON(service_client.RestClient):

    version = '2.0'
    uri_prefix = "v2.0"

    def __init__(self,
                 auth_provider,
                 service=CONF.network.catalog_type,
                 region=CONF.network.region or CONF.identity.region,
                 endpoint_type=CONF.network.endpoint_type,
                 build_interval=CONF.network.build_interval,
                 build_timeout=CONF.network.build_timeout,
                 disable_ssl_certificate_validation=False,
                 ca_certs=None,
                 trace_requests='',
                 name=None,
                 http_timeout=None,
                 proxy_url=None):
        super(NuageNetworkClientJSON, self).__init__(
            auth_provider, service, region, endpoint_type,
            build_interval, build_timeout,
            disable_ssl_certificate_validation, ca_certs,
            trace_requests, name, http_timeout, proxy_url)

    def post(self, url, body, headers=None, extra_headers=False,
             chunked=False):
        resp, body = super(NuageNetworkClientJSON, self).post(
            url, body, headers=headers, extra_headers=extra_headers,
            chunked=chunked)
        return resp, body.decode()

    def get(self, url, headers=None, extra_headers=False):
        resp, body = super(NuageNetworkClientJSON, self).get(
            url, headers=headers, extra_headers=extra_headers)
        return resp, body.decode()

    def delete(self, url, headers=None, body=None, extra_headers=False):
        resp, body = super(NuageNetworkClientJSON, self).delete(
            url, headers=headers, body=body, extra_headers=extra_headers)
        return resp, body.decode()

    def put(self, url, body, headers=None, extra_headers=False,
            chunked=False):
        resp, body = super(NuageNetworkClientJSON, self).put(
            url, body, headers=headers, extra_headers=extra_headers,
            chunked=chunked)
        return resp, body.decode()

    def _get_request(self, uri):
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    # for convenience added a few std resource methods

    def show_network(self, network_id):
        uri = ('%s/networks/%s' % (self.uri_prefix, network_id))
        return self._get_request(uri)

    def show_subnet(self, subnet_id):
        uri = ('%s/subnets/%s' % (self.uri_prefix, subnet_id))
        return self._get_request(uri)

    # end of convenience methods

    def get_nuage_plugin_stats(self):
        uri = '%s/nuage-plugin-stats' % self.uri_prefix
        return self._get_request(uri)

    def get_nuage_api_count(self):
        return self.get_nuage_plugin_stats()[
            'nuage_plugin_stats'][0]['api_count']

    def list_gateways(self):
        uri = '%s/nuage-gateways' % self.uri_prefix
        return self._get_request(uri)

    def show_gateway(self, gw_id):
        uri = ('%s/nuage-gateways/%s' % (self.uri_prefix, gw_id))
        return self._get_request(uri)

    def list_gateway_ports(self, gw_id):
        uri = '%s/nuage-gateway-ports?gateway=%s' % (self.uri_prefix, gw_id)
        return self._get_request(uri)

    def get_gateway_id_by_name(self, gw_name):
        uri = ('%s/nuage-gateways?name=%s' % (self.uri_prefix, gw_name))
        body = self._get_request(uri)
        gw_id = body['nuage_gateways'][0]['id']
        return gw_id

    def get_gateway_port_id_by_name(self, port_name, gw_name):
        gw_id = self.get_gateway_id_by_name(gw_name)
        uri = ('%s/nuage-gateway-ports?name=%s&gateway=%s' %
               (self.uri_prefix, port_name, gw_id))
        body = self._get_request(uri)
        return body['nuage_gateway_ports'][0]['id']

    def list_gateway_ports_by_gateway_name(self, gw_name):
        return self.list_gateway_ports(self.get_gateway_id_by_name(gw_name))

    def show_gateway_ports_by_gateway_name(self, port_name, gw_name):
        return self.show_gateway_port(
            self.get_gateway_port_id_by_name(port_name, gw_name))

    def list_gateway_vlans(self, gw_port_id):
        uri = '%s/nuage-gateway-vlans?gatewayport=%s' % (self.uri_prefix,
                                                         gw_port_id)
        return self._get_request(uri)

    def get_gateway_vlan_id_by_name(self, vlan_value, gw_port_id):
        uri = '%s/nuage-gateway-vlans?gatewayport=%s&name=%s' % \
              (self.uri_prefix, gw_port_id, vlan_value)
        body = self._get_request(uri)
        return body['nuage_gateway_vlans'][0]['id']

    def show_gateway_vlan_by_name(self, vlan_value, port_name, gw_name):
        gw_id = self.get_gateway_id_by_name(gw_name)
        gw_port_id = self.get_gateway_port_id_by_name(port_name, gw_name)
        gw_vlan_id = self.get_gateway_vlan_id_by_name(vlan_value, gw_port_id)
        uri = '%s/nuage-gateway-vlans/%s?gatewayport=%s&gateway=%s' % (
            self.uri_prefix, gw_vlan_id, gw_port_id, gw_id)
        return self._get_request(uri)

    def list_gateway_vlans_by_name(self, port_name, gw_name):
        gw_id = self.get_gateway_id_by_name(gw_name)
        gw_port_id = self.get_gateway_port_id_by_name(port_name, gw_name)
        uri = '%s/nuage-gateway-vlans?gatewayport=%s&gateway=%s' % (
            self.uri_prefix, gw_port_id, gw_id)
        return self._get_request(uri)

    def show_gateway_port(self, gw_port_id):
        uri = ('%s/nuage-gateway-ports/%s' % (self.uri_prefix, gw_port_id))
        return self._get_request(uri)

    def show_gateway_vlan(self, vlan_id):
        uri = ('%s/nuage-gateway-vlans/%s' % (self.uri_prefix, vlan_id))
        return self._get_request(uri)

    def create_gateway_vlan(self, **kwargs):
        post_body = {'nuage_gateway_vlan': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-gateway-vlans' % self.uri_prefix
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def create_gateway_vport(self, **kwargs):
        post_body = {'nuage_gateway_vport': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-gateway-vports' % self.uri_prefix
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_gateway_vlan(self, id):
        uri = '%s/nuage-gateway-vlans/%s' % (self.uri_prefix, id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    # Add redirect target
    def create_redirection_target(self, **kwargs):
        post_body = {'nuage_redirect_target': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-redirect-targets' % self.uri_prefix
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_redirection_target(self, id):
        uri = '%s/nuage-redirect-targets/%s' % (self.uri_prefix, id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_redirection_targets(self, id):
        uri = '%s/nuage-redirect-targets?subnet=%s' % (self.uri_prefix, id)
        return self._get_request(uri)

    def show_redirection_target(self, id):
        uri = ('%s/nuage-redirect-targets/%s' % (self.uri_prefix, id))
        return self._get_request(uri)

    def get_redirection_target_id_by_name(self, name):
        uri = ('%s/nuage-redirect-targets?name=%s' % (self.uri_prefix, name))
        body = self._get_request(uri)
        id = body['nuage-redirect-targets'][0]['id']
        return id

    # Add redirect target VIP
    def create_redirection_target_vip(self, **kwargs):
        post_body = {'nuage_redirect_target_vip': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-redirect-target-vips' % self.uri_prefix
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    # Add redirect target rules
    def create_redirection_target_rule(self, **kwargs):
        post_body = {'nuage_redirect_target_rule': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-redirect-target-rules' % self.uri_prefix
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_redirection_target_rule(self, id):
        uri = '%s/nuage-redirect-target-rules/%s' % (self.uri_prefix, id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def assign_gateway_vlan(self, id, **kwargs):
        post_body = {'nuage_gateway_vlan': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-gateway-vlans/%s' % (self.uri_prefix, id)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return resp, body

    def list_gateway_vport(self, subnet_id):
        uri = '%s/nuage-gateway-vports.json?subnet=%s' % (
            self.uri_prefix, subnet_id)
        return self._get_request(uri)

    def show_gateway_vport(self, vport_id, subnet_id):
        uri = '%s/nuage-gateway-vports/%s?subnet=%s' % (
            self.uri_prefix, vport_id, subnet_id)
        return self._get_request(uri)

    def create_netpartition(self, name, **kwargs):
        name = name or data_utils.rand_name('test-netpartition-')
        post_body = {'net_partition': kwargs}
        post_body['net_partition']['name'] = name
        body = json.dumps(post_body)
        uri = '%s/net-partitions' % self.uri_prefix
        try:
            resp, body = self.post(uri, body)
        except ServerFault:  # this probably should eventually be done
            #                  generically, inside the post method
            resp = {
                'status': 500
            }
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_netpartition(self, id):
        uri = '%s/net-partitions/%s' % (self.uri_prefix, id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_netpartition(self):
        uri = '%s/net-partitions' % self.uri_prefix
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_netpartition_by_name(self, name):
        uri = '{}/net-partitions?{}'.format(self.uri_prefix,
                                            urlparse.urlencode({'name': name}))
        body = self._get_request(uri)
        return body['net_partitions']

    def list_tiers(self, app_id):
        uri = '%s/tiers?app_id=%s' % (self.uri_prefix, app_id)
        return self._get_request(uri)

    def list_flows(self, app_id):
        uri = '%s/flows?app_id=%s' % (self.uri_prefix, app_id)
        return self._get_request(uri)

    def create_nuage_external_security_group(self, **kwargs):
        post_body = {'nuage_external_security_group': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-external-security-groups' % self.uri_prefix
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_nuage_external_security_group(self, security_group_id):
        uri = '%s/nuage-external-security-groups/%s' % (self.uri_prefix,
                                                        security_group_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def show_nuage_external_security_group(self, security_group_id):
        uri = '%s/nuage-external-security-groups/%s' % (self.uri_prefix,
                                                        security_group_id)
        return self._get_request(uri)

    def create_nuage_external_security_group_rule(self, **kwargs):
        post_body = {'nuage_external_security_group_rule': kwargs}
        body = json.dumps(post_body)
        uri = '%s/nuage-external-security-group-rules' % self.uri_prefix
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_nuage_external_security_group_rule(
            self, security_group_rule_id):
        uri = '%s/nuage-external-security-group-rules/%s' % \
              (self.uri_prefix, security_group_rule_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def show_nuage_external_security_group_rule(
            self, security_group_rule_id):
        uri = '%s/nuage-external-security-group-rules/%s' % \
              (self.uri_prefix, security_group_rule_id)
        return self._get_request(uri)

    def list_nuage_external_security_group(self, router_id):
        uri = '%s/nuage-external-security-groups.json?router=%s' % \
              (self.uri_prefix, router_id)
        return self._get_request(uri)

    def list_nuage_external_security_group_rule(self, remote_group_id):
        uri = '%s/nuage-external-security-group-rules.json?' \
              'external_group=%s' % (self.uri_prefix, remote_group_id)
        return self._get_request(uri)

    def list_nuage_external_security_group_l2domain(self, subnet_id):
        uri = '%s/nuage-external-security-groups.json?subnet=%s' % \
              (self.uri_prefix, subnet_id)
        return self._get_request(uri)

    def show_nuage_policy_group(self, pg_id):
        uri = '%s/nuage-policy-groups/%s' % (self.uri_prefix, pg_id)
        return self._get_request(uri)

    def list_nuage_policy_group_all(self):
        uri = '%s/nuage-policy-groups.json' % self.uri_prefix
        return self._get_request(uri)

    def list_nuage_policy_group_for_subnet(self, subnet_id):
        uri = '%s/nuage-policy-groups.json?for_subnet=%s' % \
              (self.uri_prefix, subnet_id)
        return self._get_request(uri)

    def list_nuage_policy_group_for_port(self, port_id):
        uri = '%s/nuage-policy-groups.json?for_port=%s' % \
              (self.uri_prefix, port_id)
        return self._get_request(uri)

    def list_nuage_floatingip_by_subnet(self, subnet_id):
        uri = '%s/nuage-floatingips.json?for_subnet=%s' % \
              (self.uri_prefix, subnet_id)
        # uri = '%s/nuage-floatingips' % (self.uri_prefix)
        return self._get_request(uri)

    # FloatingIp
    def create_floatingip(self, parent_id, shared_netid,
                          address, parent=None, externalId=None,
                          extra_params=None):
        data = {
            "associatedSharedNetworkResourceID": shared_netid,
            "address": address
        }
        if externalId:
            # TODO(team) - fix below - get_vsd_external_id is not resolved
            data['externalID'] = self.get_vsd_external_id(externalId)
        if extra_params:
            data.update(extra_params)
        if not parent:
            parent = constants.DOMAIN
        # TODO(team) - fix below - build_resource_path is not resolved
        res_path = self.build_resource_path(
            parent, parent_id, constants.FLOATINGIP)
        return self.post(res_path, data)

    def update_router_rdrt(self, router_id, **kwargs):
        uri = '/routers/%s' % router_id
        update_body = {'router': kwargs}
        return self.put(uri, update_body)

    def show_application_domain(self, domain_id):
        uri = ('%s/application-domains/%s' % (self.uri_prefix, domain_id))
        return self._get_request(uri)

    def show_application(self, id):
        uri = ('%s/applications/%s' % (self.uri_prefix, id))
        return self._get_request(uri)

    def show_service(self, id):
        uri = ('%s/services/%s' % (self.uri_prefix, id))
        return self._get_request(uri)

    def show_tier(self, id):
        uri = ('%s/tiers/%s' % (self.uri_prefix, id))
        return self._get_request(uri)

    def show_flow(self, id):
        uri = ('%s/flows/%s' % (self.uri_prefix, id))
        return self._get_request(uri)

    def show_appdport(self, id):
        uri = ('%s/appdports/%s' % (self.uri_prefix, id))
        return self._get_request(uri)

    def _update_router(self, router_id, set_enable_snat, **kwargs):
        uri = '%s/routers/%s' % (self.uri_prefix, router_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        update_body = {}
        update_body['name'] = kwargs.get('name', body['router']['name'])
        update_body['admin_state_up'] = kwargs.get(
            'admin_state_up', body['router']['admin_state_up'])
        cur_gw_info = body['router']['external_gateway_info']
        if cur_gw_info:
            # TODO(kevinbenton): setting the external gateway info is not
            # allowed for a regular tenant. If the ability to update is also
            # merged, a test case for this will need to be added similar to
            # the SNAT case.
            cur_gw_info.pop('external_fixed_ips', None)
            if not set_enable_snat:
                cur_gw_info.pop('enable_snat', None)
        update_body['external_gateway_info'] = kwargs.get(
            'external_gateway_info', body['router']['external_gateway_info'])
        if 'distributed' in kwargs:
            update_body['distributed'] = kwargs['distributed']
        update_body = dict(router=update_body)
        update_body = json.dumps(update_body)
        resp, body = self.put(uri, update_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def update_router_with_snat_gw_info(self, router_id, **kwargs):
        """Update a router passing also the enable_snat attribute.

        This method must be execute with admin credentials, otherwise the API
        call will return a 404 error.
        """
        return self._update_router(router_id, set_enable_snat=True, **kwargs)

    def update_extra_routes(self, router_id, nexthop, destination):
        uri = '%s/routers/%s' % (self.uri_prefix, router_id)
        put_body = {
            'router': {
                'routes': [{'nexthop': nexthop,
                            "destination": destination}]
            }
        }
        body = json.dumps(put_body)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_extra_routes(self, router_id):
        uri = '%s/routers/%s' % (self.uri_prefix, router_id)
        null_routes = None
        put_body = {
            'router': {
                'routes': null_routes
            }
        }
        body = json.dumps(put_body)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def create_trunk(self, parent_port_id, subports,
                     tenant_id=None, name=None, admin_state_up=None,
                     description=None):
        uri = '%s/trunks' % self.uri_prefix
        post_data = {
            'trunk': {
                'port_id': parent_port_id,
            }
        }
        if subports is not None:
            post_data['trunk']['sub_ports'] = subports
        if tenant_id is not None:
            post_data['trunk']['tenant_id'] = tenant_id
        if name is not None:
            post_data['trunk']['name'] = name
        if description is not None:
            post_data['trunk']['description'] = description
        if admin_state_up is not None:
            post_data['trunk']['admin_state_up'] = admin_state_up
        resp, body = self.post(uri, json.dumps(post_data))
        body = json.loads(body)
        self.expected_success(201, resp.status)
        return service_client.ResponseBody(resp, body)

    def update_trunk(self, trunk_id, **kwargs):
        put_body = {'trunk': kwargs}
        body = json.dumps(put_body)
        uri = '%s/trunks/%s' % (self.uri_prefix, trunk_id)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def show_trunk(self, trunk_id):
        uri = '%s/trunks/%s' % (self.uri_prefix, trunk_id)
        resp, body = self.get(uri)
        body = json.loads(body)
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def list_trunks(self, **kwargs):
        uri = '%s/trunks' % self.uri_prefix
        if kwargs:
            uri += '?' + urlparse.urlencode(kwargs, doseq=1)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_trunk(self, trunk_id):
        uri = '%s/trunks/%s' % (self.uri_prefix, trunk_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)

    def _subports_action(self, action, trunk_id, subports):
        uri = '%s/trunks/%s/%s' % (self.uri_prefix, trunk_id, action)
        resp, body = self.put(uri, json.dumps({'sub_ports': subports}))
        body = json.loads(body)
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def add_subports(self, trunk_id, subports):
        return self._subports_action('add_subports', trunk_id, subports)

    def remove_subports(self, trunk_id, subports):
        return self._subports_action('remove_subports', trunk_id, subports)

    def get_subports(self, trunk_id):
        uri = '%s/trunks/%s/%s' % (self.uri_prefix, trunk_id, 'get_subports')
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def show_port(self, port_id):
        uri = '%s/ports/%s' % (self.uri_prefix, port_id)
        resp, body = self.get(uri)
        body = json.loads(body)
        self.expected_success(200, resp.status)
        return service_client.ResponseBody(resp, body)

    def delete_port(self, port_id):
        uri = '%s/ports/%s' % (self.uri_prefix, port_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)

    def list_switchport_mappings(self, **kwargs):
        uri = '%s/net-topology/switchport_mappings' % self.uri_prefix
        if kwargs:
            uri += '?' + urlparse.urlencode(kwargs, doseq=1)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def list_switchport_binding(self, **kwargs):
        uri = '%s/net-topology/switchport_bindings' % self.uri_prefix
        if kwargs:
            uri += '?' + urlparse.urlencode(kwargs, doseq=1)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def create_nuage_l2bridge(self, name, **kwargs):
        name = name or data_utils.rand_name('test-l2bridge-')
        post_body = {'nuage_l2bridge': kwargs}
        post_body['nuage_l2bridge']['name'] = name
        body = json.dumps(post_body)
        uri = '%s/nuage-l2bridges' % self.uri_prefix
        resp, body = self.post(uri, body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def get_nuage_l2bridge(self, l2bridge_id):
        uri = '%s/nuage-l2bridges/%s' % (self.uri_prefix, l2bridge_id)
        return self._get_request(uri)

    def update_nuage_l2bridge(self, l2bridge_id, **kwargs):
        put_body = {'nuage_l2bridge': kwargs}
        body = json.dumps(put_body)
        uri = '%s/nuage-l2bridges/%s' % (self.uri_prefix, l2bridge_id)
        resp, body = self.put(uri, body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return service_client.ResponseBody(resp, body)

    def delete_nuage_l2bridge(self, l2bridge_id):
        uri = '%s/nuage-l2bridges/%s' % (self.uri_prefix, l2bridge_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
