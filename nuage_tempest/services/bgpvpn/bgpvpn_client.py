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

import abc
import json
import six
import urllib

from tempest import config
from tempest.lib.common import rest_client
from tempest.lib import exceptions as lib_exc


CONF = config.CONF


@six.add_metaclass(abc.ABCMeta)
class BaseNeutronResourceClient(rest_client.RestClient):
    URI_PREFIX = "v2.0"

    def __init__(self, auth_provider, resource, parent=None, path_prefix=None):
        self.resource = resource.replace('-', '_')
        self.parent = parent + '/%s/' if parent else ''
        prefix = self.URI_PREFIX + '/'
        if path_prefix:
            prefix = prefix + path_prefix + '/'
        self.resource_url = '%s%ss' % (prefix, self.parent + resource)
        self.single_resource_url = self.resource_url + '/%s'
        super(BaseNeutronResourceClient, self).__init__(
            auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout)

    def is_resource_deleted(self, id):
        try:
            self.show(id)
        except lib_exc.NotFound:
            return True
        return False

    def create(self, parent=None, **kwargs):
        if parent:
            uri = self.resource_url % parent
        else:
            uri = self.resource_url

        resource = kwargs
        req_post_data = json.dumps({self.resource: resource})
        resp, body = self.post(uri, req_post_data)
        body = json.loads(body)
        self.expected_success(201, resp.status)
        return rest_client.ResponseBody(resp, body)[self.resource]

    def list(self, parent=None, **filters):
        if parent:
            uri = self.resource_url % parent
        else:
            uri = self.resource_url
        if filters:
            uri += '?' + urllib.urlencode(filters, doseq=1)
        resp, body = self.get(uri)
        body = json.loads(body)
        self.expected_success(200, resp.status)
        return rest_client.ResponseBody(resp, body)['%ss' % self.resource]

    def show(self, id, parent=None, fields=None):
        if parent:
            uri = self.single_resource_url % (parent, id)
        else:
            uri = self.single_resource_url % id
        if fields:
            uri += '?' + urllib.urlencode(fields, doseq=1)
        resp, body = self.get(uri)
        body = json.loads(body)
        self.expected_success(200, resp.status)
        return rest_client.ResponseBody(resp, body)[self.resource]

    def update(self, id, parent=None, **kwargs):
        if parent:
            uri = self.single_resource_url % (parent, id)
        else:
            uri = self.single_resource_url % id
        resource = kwargs
        req_data = json.dumps({self.resource: resource})
        resp, body = self.put(uri, req_data)
        body = json.loads(body)
        self.expected_success(200, resp.status)
        return rest_client.ResponseBody(resp, body)[self.resource]

    def delete(self, id, parent=None):
        if parent:
            uri = self.single_resource_url % (parent, id)
        else:
            uri = self.single_resource_url % id
        resp, body = super(BaseNeutronResourceClient, self).delete(uri)
        self.expected_success(204, resp.status)
        rest_client.ResponseBody(resp, body)


class BGPVPNClient(BaseNeutronResourceClient):
    def __init__(self, auth_provider):
        super(BGPVPNClient, self).__init__(auth_provider, 'bgpvpn',
                                           path_prefix='bgpvpn')

    def create_bgpvpn(self, **kwargs):
        return super(BGPVPNClient, self).create(**kwargs)

    def show_bgpvpn(self, id, fields=None):
        return super(BGPVPNClient, self).show(id, fields)

    def list_bgpvpns(self, **filters):
        return super(BGPVPNClient, self).list(**filters)

    def update_bgpvpn(self, id, **kwargs):
        return super(BGPVPNClient, self).update(id, **kwargs)

    def delete_bgpvpn(self, id):
        super(BGPVPNClient, self).delete(id)


class BGPVPNNetworkAssociationClient(BaseNeutronResourceClient):
    def __init__(self, auth_provider):
        super(BGPVPNNetworkAssociationClient, self).__init__(
            auth_provider, 'network_association', parent='bgpvpns',
            path_prefix='bgpvpn')

    def create_network_association(self, bgpvpn_id, **kwargs):
        return super(BGPVPNNetworkAssociationClient, self).create(
            parent=bgpvpn_id, **kwargs)

    def show_network_association(self, id, bgpvpn_id, fields=None):
        return super(BGPVPNNetworkAssociationClient, self).show(
            id, parent=bgpvpn_id, fields=fields)

    def list_network_associations(self, bgpvpn_id, **filters):
        return super(BGPVPNNetworkAssociationClient, self).list(
            parent=bgpvpn_id, **filters)

    def update_network_association(self, id, bgpvpn_id, **kwargs):
        return super(BGPVPNNetworkAssociationClient, self).update(
            id, parent=bgpvpn_id, **kwargs)

    def delete_network_association(self, id, bgpvpn_id):
        super(BGPVPNNetworkAssociationClient, self).delete(
            id, parent=bgpvpn_id)


class BGPVPNRouterAssociationClient(BaseNeutronResourceClient):
    def __init__(self, auth_provider):
        super(BGPVPNRouterAssociationClient, self).__init__(
            auth_provider, 'router_association', parent='bgpvpns',
            path_prefix='bgpvpn')

    def create_router_assocation(self, bgpvpn_id, **kwargs):
        return super(BGPVPNRouterAssociationClient, self).create(
            parent=bgpvpn_id, **kwargs)

    def show_router_assocation(self, id, bgpvpn_id, fields=None):
        return super(BGPVPNRouterAssociationClient, self).show(
            id, parent=bgpvpn_id, fields=fields)

    def list_router_assocations(self, bgpvpn_id, **filters):
        return super(BGPVPNRouterAssociationClient, self).list(
            parent=bgpvpn_id, **filters)

    def update_router_assocation(self, id, bgpvpn_id, **kwargs):
        return super(BGPVPNRouterAssociationClient, self).update(
            id, parent=bgpvpn_id, **kwargs)

    def delete_router_assocation(self, id, bgpvpn_id):
        super(BGPVPNRouterAssociationClient, self).delete(id, parent=bgpvpn_id)
