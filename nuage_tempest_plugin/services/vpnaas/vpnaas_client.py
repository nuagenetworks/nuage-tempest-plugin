import abc
import json
import six
import urllib

from tempest.lib.common import rest_client
from tempest.lib import exceptions as lib_exc

from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()


@six.add_metaclass(abc.ABCMeta)
class BaseNeutronResourceClient(rest_client.RestClient):
    URI_PREFIX = "v2.0"

    def __init__(self, auth_provider, resource, parent=None, path_prefix=None):
        self.resource = resource.replace('-', '_')
        self.parent = parent + '/%s/' if parent else ''
        prefix = self.URI_PREFIX + '/'
        if path_prefix:
            prefix = prefix + path_prefix + '/'
        if resource[-1] == 'y':
            self.resource_url = (
                '%s%sies' % (prefix, self.parent + resource[:-1])
            )
        else:
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
        if self.resource[-1] == 'y':
            return rest_client.ResponseBody(
                resp, body
            )['%sies' % self.resource[:-1]]
        else:
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


class IKEPolicyClient(BaseNeutronResourceClient):

    """CRUD Operations for IKEPolicy """

    def __init__(self, auth_provider):
        super(IKEPolicyClient, self).__init__(auth_provider, 'ikepolicy',
                                              path_prefix='vpn')

    def create_ikepolicy(self, name, **kwargs):
        kwargs = {'name': name}
        return super(IKEPolicyClient, self).create(**kwargs)

    def show_ikepolicy(self, id, fields=None):
        return super(IKEPolicyClient, self).show(id, fields)

    def list_ikepolicy(self, **filters):
        return super(IKEPolicyClient, self).list(**filters)

    def update_ikepolicy(self, id, **kwargs):
        return super(IKEPolicyClient, self).update(id, **kwargs)

    def delete_ikepolicy(self, id):
        super(IKEPolicyClient, self).delete(id)


class IPSecPolicyClient(BaseNeutronResourceClient):

    """CRUD Operations for IPSecPolicy """

    def __init__(self, auth_provider):
        super(IPSecPolicyClient, self).__init__(auth_provider, 'ipsecpolicy',
                                                path_prefix='vpn')

    def create_ipsecpolicy(self, name, **kwargs):
        kwargs = {'name': name}
        return super(IPSecPolicyClient, self).create(**kwargs)

    def show_ipsecpolicy(self, id, fields=None):
        return super(IPSecPolicyClient, self).show(id, fields)

    def list_ipsecpolicy(self, **filters):
        return super(IPSecPolicyClient, self).list(**filters)

    def update_ipsecpolicy(self, id, **kwargs):
        return super(IPSecPolicyClient, self).update(id, **kwargs)

    def delete_ipsecpolicy(self, id):
        super(IPSecPolicyClient, self).delete(id)


class VPNServiceClient(BaseNeutronResourceClient):

    """CRUD Operations for VPNService """

    def __init__(self, auth_provider):
        super(VPNServiceClient, self).__init__(auth_provider, 'vpnservice',
                                               path_prefix='vpn')

    def create_vpnservice(self, router_id, subnet_id, **kwargs):
        kwargs['router_id'] = router_id
        kwargs['subnet_id'] = subnet_id
        return super(VPNServiceClient, self).create(**kwargs)

    def show_vpnservice(self, id, fields=None):
        return super(VPNServiceClient, self).show(id, fields)

    def list_vpnservice(self, **filters):
        return super(VPNServiceClient, self).list(**filters)

    def update_vpnservice(self, id, **kwargs):
        return super(VPNServiceClient, self).update(id, **kwargs)

    def delete_vpnservice(self, id):
        super(VPNServiceClient, self).delete(id)


class IPSecSiteConnectionClient(BaseNeutronResourceClient):

    """CRUD Operations for IPSecSiteConnection """

    def __init__(self, auth_provider):
        super(IPSecSiteConnectionClient, self).__init__(
            auth_provider, 'ipsec-site-connection', path_prefix='vpn')

    def create_ipsecsiteconnection(self, vpnservice_id, ikepolicy_id,
                                   ipsecpolicy_id, peer_address, peer_id,
                                   peer_cidrs, psk, **kwargs):
        kwargs['vpnservice_id'] = vpnservice_id
        kwargs['ikepolicy_id'] = ikepolicy_id
        kwargs['ipsecpolicy_id'] = ipsecpolicy_id
        kwargs['peer_address'] = peer_address
        kwargs['peer_id'] = peer_id
        kwargs['peer_cidrs'] = peer_cidrs
        kwargs['psk'] = psk
        return super(IPSecSiteConnectionClient, self).create(**kwargs)

    def show_ipsecsiteconnection(self, id, fields=None):
        return super(IPSecSiteConnectionClient, self).show(id, fields)

    def list_ipsecsiteconnection(self, **filters):
        return super(IPSecSiteConnectionClient, self).list(**filters)

    def update_ipsecsiteconnection(self, id, **kwargs):
        return super(IPSecSiteConnectionClient, self).update(id, **kwargs)

    def delete_ipsecsiteconnection(self, id):
        super(IPSecSiteConnectionClient, self).delete(id)
