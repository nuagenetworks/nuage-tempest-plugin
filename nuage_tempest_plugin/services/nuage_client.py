#
#
#    -----------------------WARNING----------------------------
#     This file is present to support Legacy Test Code only.
#     DO not use this file for writing the new tests.
#    ----------------------------------------------------------
#
#

import netaddr
import re
import six
import time

from tempest.lib.common.utils import test_utils as misc_utils
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.lib.utils import constants
from nuage_tempest_plugin.lib.utils import exceptions as n_exceptions
from nuage_tempest_plugin.lib.utils import restproxy

SERVERSSL = True
SERVERTIMEOUT = 30
RESPONSECHOICE = '?responseChoice=1'
CMS_ID = None

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


# convert a structure into a string safely
def safe_body(body, maxlen=5000):
    try:
        text = six.text_type(body)
    except UnicodeDecodeError:
        # if this isn't actually text, return marker that
        return "<BinaryData: removed>"
    if len(text) > maxlen:
        return text[:maxlen]
    else:
        return text


class NuageRestClient(object):

    def __init__(self):
        server = Topology.vsd_server
        self.def_netpart_name = (
            Topology.def_netpartition
        )
        global CMS_ID
        CMS_ID = Topology.cms_id
        if not CMS_ID:
            raise exceptions.InvalidConfiguration("Missing cms_id in "
                                                  "configuration.")
        base_uri = Topology.base_uri
        auth_resource = Topology.auth_resource
        server_auth = Topology.server_auth
        vsd_org = Topology.vsd_org

        self.restproxy = restproxy.RESTProxyServer(server, base_uri, SERVERSSL,
                                                   server_auth, auth_resource,
                                                   vsd_org, SERVERTIMEOUT)
        self.restproxy.generate_nuage_auth()

    @staticmethod
    def _error_checker(resp):
        if resp.status == 300:
            raise n_exceptions.MultipleChoices(resp.data)

        # It is not an error response
        if resp.status < 400:
            return

        if resp.status == 401 or resp.status == 403:
            raise n_exceptions.Unauthorized(resp.data)

        if resp.status == 404:
            raise n_exceptions.NotFound(resp.data)

        if resp.status == 400:
            raise n_exceptions.BadRequest(resp.data)

        if resp.status == 409:
            raise n_exceptions.Conflict(resp.data)

        if resp.status == 422:
            raise n_exceptions.UnprocessableEntity(resp.data)

        if resp.status in (500, 501):
            message = resp.data

            raise n_exceptions.ServerFault(message)

        if resp.status >= 400:
            raise n_exceptions.UnexpectedResponseCode(str(resp.status))

    def _log_request_start(self, method, req_url, req_headers=None,
                           req_body=None):
        if req_headers is None:
            req_headers = {}
        caller_name = misc_utils.find_test_caller()
        trace_regex = CONF.debug.trace_requests
        if trace_regex and re.search(trace_regex, caller_name):
            LOG.debug('Starting Request (%s): %s %s',
                      caller_name, method, req_url)

    def _log_request_full(self, method, req_url, resp,
                          secs="", req_headers=None,
                          req_body=None, resp_body=None,
                          caller_name=None, extra=None):
        if 'X-Auth-Token' in req_headers:
            req_headers['X-Auth-Token'] = '<omitted>'
        log_fmt = """Request (%s):
            HTTP %s %s %s%s
            Request - Headers: %s
                Body: %s
            Response - Headers: %s
                Body: %s"""

        LOG.debug(
            log_fmt, caller_name, resp.status, method, req_url, secs,
            str(req_headers), safe_body(req_body),
            resp.headers,
            safe_body(resp_body), extra=extra)

    def _log_request(self, method, req_url, resp,
                     secs="", req_headers=None,
                     req_body=None, resp_body=None):
        if req_headers is None:
            req_headers = {}

        # if we have the request id, put it in the right part of the log
        # extra = dict(request_id=self._get_request_id(resp))
        extra = {}

        # NOTE(sdague): while we still have 6 callers to this function
        # we're going to just provide work around on who is actually
        # providing timings by gracefully adding no content if they don't.
        # Once we're down to 1 caller, clean this up.
        caller_name = misc_utils.find_test_caller()
        if secs:
            secs = " %.3fs" % secs
        LOG.info(
            'Request (%s): %s %s %s%s', caller_name, resp.status, method,
            req_url, secs, extra=extra)

        # Also look everything at DEBUG if you want to filter this
        # out, don't run at debug.
        self._log_request_full(method, req_url, resp, secs, req_headers,
                               req_body, resp_body, caller_name, extra)

    def request(self, method, url, body=None, extra_headers=None):
        self._log_request_start(method, url)

        start = time.time()
        resp = self.restproxy.rest_call(
            method, url, data=body, extra_headers=extra_headers)
        end = time.time()

        self._log_request(method, url, resp, secs=(end - start),
                          req_headers=extra_headers, req_body=body,
                          resp_body=resp.data)

        # Verify HTTP response codes
        self._error_checker(resp)
        return resp

    def delete(self, url, body=None, extra_headers=None):
        return self.request('DELETE', url, body, extra_headers)

    def get(self, url, extra_headers=None, body=None):
        resp = self.request('GET', url, extra_headers=extra_headers)
        if not resp.data:
            return ''
        return resp.data

    def post(self, url, body, extra_headers=None):
        resp = self.request('POST', url, body, extra_headers)
        if not resp.data:
            return ''
        return resp.data

    def put(self, url, body, extra_headers=None):
        return self.request('PUT', url, body, extra_headers)

    @staticmethod
    def get_extra_headers(attr, attr_value):
        headers = {}
        if not (isinstance(attr, list) and isinstance(attr_value, list)):
            attr = [attr]
            attr_value = [attr_value]
        headers['X-NUAGE-FilterType'] = 'predicate'
        headers['X-Nuage-Filter'] = ""
        for attribute, value in zip(attr, attr_value):
            if headers.get('X-Nuage-Filter'):
                headers['X-Nuage-Filter'] += " and "
            if attribute == 'externalID':
                value = NuageRestClient.get_vsd_external_id(value)
            if attribute == 'address' and '/' in value:
                # extracts the address from the cidr
                value = value.split('/')[0]
            if isinstance(attr_value, int):
                headers['X-Nuage-Filter'] += "{} IS {}".format(
                    attribute, value)
            else:
                headers['X-Nuage-Filter'] += "{} IS '{}'".format(
                    attribute, value)
        return headers

    @staticmethod
    def build_resource_path(resource=None, resource_id=None,
                            child_resource=None):
        res_path = None
        if resource:
            res_path = ("/%s" % resource +
                        (resource_id and "/%s" % resource_id or '') +
                        (child_resource and "/%s" % child_resource or ''))
        return res_path

    def get_global_resource(self, resource, filters=None,
                            filter_value=None):
        extra_headers = None
        res_path = "/%s" % resource
        if filters:
            extra_headers = self.get_extra_headers(filters, filter_value)
        return self.get(res_path, extra_headers)

    def get_resource(self, resource, filters=None,
                     filter_value=None,
                     netpart_name=None,
                     flat_rest_path=False):
        extra_headers = None
        if flat_rest_path:
            res_path = '/' + resource
        else:
            if not netpart_name:
                netpart_name = self.def_netpart_name
            net_part = self.get_net_partition(netpart_name)
            res_path = self.build_resource_path(
                resource=constants.NET_PARTITION,
                resource_id=net_part[0]['ID'],
                child_resource=resource)
        if filters:
            extra_headers = self.get_extra_headers(filters, filter_value)
        return self.get(res_path, extra_headers)

    def get_child_resource(self, resource, resource_id, child_resource,
                           filters=None, filter_value=None):
        extra_headers = None
        res_path = self.build_resource_path(
            resource, resource_id,
            child_resource)
        if filters:
            extra_headers = self.get_extra_headers(filters, filter_value)
        return self.get(res_path, extra_headers)

    def delete_resource(self, resource, resource_id, responseChoice=False):
        res_path = self.build_resource_path(resource, resource_id)
        if responseChoice:
            res_path = res_path + RESPONSECHOICE
        return self.delete(res_path)

    # Net Partition
    def create_net_partition(self, name, fip_quota, extra_params):
        data = {
            'name': name,
            'floatingIPsQuota': fip_quota,
            'allowedForwardingClasses': ['E', 'F', 'G', 'H']
        }
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(constants.NET_PARTITION)
        return self.post(res_path, data)

    def delete_net_partition(self, np_id):
        return self.delete_resource(constants.NET_PARTITION, np_id)

    def get_net_partition(self, net_part_name):
        res_path = self.build_resource_path(constants.NET_PARTITION)
        extra_headers = self.get_extra_headers('name', net_part_name)
        return self.get(res_path, extra_headers)

    # Network
    # EnterpriseNetworkMacro
    def get_enterprise_net_macro(self, filters=None, filter_value=None,
                                 netpart_name=None):
        return self.get_resource(constants.ENTERPRISE_NET_MACRO,
                                 filters, filter_value, netpart_name)

    def list_enterprises(self):
        res_path = self.build_resource_path(constants.NET_PARTITION,
                                            None, None)
        extra_headers = {}
        result = self.get(res_path, extra_headers)
        return result

    # Public Network Macro
    def get_public_net_macro(self, filters=None, filter_value=None,
                             netpart_name=None):
        return self.get_resource(constants.PUBLIC_NET_MACRO,
                                 filters, filter_value, netpart_name)

    # DomainTemplates
    def create_l3domaintemplate(self, name, extra_params=None,
                                netpart_name=None):
        data = {
            'name': name
        }
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)

        res_path = self.build_resource_path(
            constants.NET_PARTITION, net_part[0]['ID'],
            constants.DOMAIN_TEMPLATE)
        return self.post(res_path, data)

    def get_l3domaintemplate(self, filters=None,
                             filter_value=None, netpart_name=None):
        return self.get_resource(constants.DOMAIN_TEMPLATE,
                                 filters, filter_value,
                                 netpart_name)

    def delete_l3domaintemplate(self, l3dom_tid):
        return self.delete_resource(constants.DOMAIN_TEMPLATE, l3dom_tid)

    # Domain
    def create_domain(self, name, templateId, externalId=None,
                      netpart_name=None, extra_params=None):
        data = {
            'name': name,
            'templateID': templateId
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)
        res_path = self.build_resource_path(
            constants.NET_PARTITION, net_part[0]['ID'],
            constants.DOMAIN)
        return self.post(res_path, data)

    # If filters is not set, returns /enterprises/%s/domains
    def get_l3domain(self, filters=None, filter_value=None, netpart_name=None):
        return self.get_resource(constants.DOMAIN,
                                 filters, filter_value, netpart_name)

    def delete_domain(self, dom_id):
        for attempt in range(1, Topology.nbr_retries_for_test_robustness + 1):
            try:
                return self.delete_resource(constants.DOMAIN, dom_id)

            except Exception as e:
                if attempt == Topology.nbr_retries_for_test_robustness:
                    raise
                elif ('domain is in use' in str(e) or
                      'Policy Group cannot be deleted as it is attached '
                      'to VPort' in str(e)):
                    LOG.error('Got {} (attempt {})'.format(str(e), attempt))
                    time.sleep(0.2)  # same wait time as plugin
                else:
                    raise

    # Zone Template
    def create_zonetemplate(self, parent_id, name, extra_params=None):
        data = {
            'name': name
        }
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            constants.DOMAIN_TEMPLATE, parent_id, constants.ZONE_TEMPLATE)
        return self.post(res_path, data)

    def get_zonetemplate(self, parent_id, filters=None, filter_value=None):
        return self.get_child_resource(constants.DOMAIN_TEMPLATE, parent_id,
                                       constants.ZONE_TEMPLATE, filters,
                                       filter_value)

    # Zone
    def create_zone(self, parent_id, name, externalId=None, extra_params=None):
        data = {
            'name': name
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            constants.DOMAIN, parent_id, constants.ZONE)
        return self.post(res_path, data)

    def get_zone(self, parent_id, filters=None, filter_value=None):
        return self.get_child_resource(constants.DOMAIN, parent_id,
                                       constants.ZONE, filters, filter_value)

    def delete_zone(self, zone_id):
        return self.delete_resource(constants.ZONE, zone_id)

    # Domain Subnet
    def create_domain_subnet(self, parent_id, name, net_address, netmask,
                             gateway, externalId=None, extra_params=None):
        data = {
            "name": name,
            "address": net_address,
            "netmask": netmask,
            "gateway": gateway
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            constants.ZONE, parent_id, constants.SUBNETWORK)
        return self.post(res_path, data)

    def create_domain_unmanaged_subnet(self, parent_id, name,
                                       extra_params=None):
        data = {
            "name": name
        }
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            constants.ZONE, parent_id, constants.SUBNETWORK)
        return self.post(res_path, data)

    def get_domain_subnet(self, parent, parent_id, filters=None,
                          filter_value=None):
        if parent:
            return self.get_child_resource(
                parent, parent_id, constants.SUBNETWORK, filters, filter_value)
        else:
            return self.get_global_resource(constants.SUBNETWORK, filters,
                                            filter_value)

    def get_l3_subnet_vports(self, subnet_id, filters=None,
                             filter_value=None):
        # TODO(team) implement filters and filter_value
        res_path = self.build_resource_path(
            constants.SUBNETWORK, subnet_id, "vports")
        return self.get(res_path)

    def update_domain_subnet(self, subnet_id, externalId=None,
                             update_params=None, netpart_name=None):
        data = {}
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if update_params:
            data.update(update_params)
        res_path = self.build_resource_path(constants.SUBNETWORK,
                                            subnet_id, None)
        return self.put(res_path, data)

    def delete_domain_subnet(self, subnet_id):
        return self.delete_resource(constants.SUBNETWORK, subnet_id)

    # DHCPOptions
    def create_dhcpoption(self, parent_type, parent,
                          option_number, option_values):
        data = {
            'actualType': option_number,
            'actualValues': option_values
        }
        res_path = self.build_resource_path(parent_type, parent,
                                            constants.DHCPOPTION)
        return self.post(res_path, data)

    def create_dhcpoption_on_l2dom(self, parent, option_number, option_values):
        return self.create_dhcpoption(constants.L2_DOMAIN, parent,
                                      option_number, option_values)

    def create_dhcpoption_on_shared(self, parent,
                                    option_number, option_values):
        return self.create_dhcpoption(constants.SHARED_NET_RES, parent,
                                      option_number, option_values)

    def get_dhcpoption(self, parent, parent_id, ip_version=4):
        return self.get_child_resource(
            parent, parent_id,
            constants.DHCPOPTION if ip_version == 4
            else constants.DHCPV6OPTION, None, None)

    # Sharedresource
    def get_sharedresource(self, filters=None, filter_value=None):
        return self.get_global_resource(constants.SHARED_NET_RES,
                                        filters, filter_value)

    def create_vsd_shared_resource(self, name, externalId=None,
                                   extra_params=None, type=None):
        if type is None:
            type = 'L2DOMAIN'
        data = {
            "name": name,
            "type": type
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            constants.SHARED_NET_RES, None, None)
        return self.post(res_path, data)

    def delete_vsd_shared_resource(self, shared_resource_id):
        try:
            self.delete_resource(constants.SHARED_NET_RES, shared_resource_id)
        except n_exceptions.MultipleChoices:
            # Temporary fix to unblock CI, will need investigation on
            # VSD behavior of asking for response choice although its
            # child objects were deleted.
            self.delete_resource(constants.SHARED_NET_RES, shared_resource_id,
                                 responseChoice=True)

    # FloatingIp
    def create_floatingip(self, parent_id, shared_netid,
                          address, parent=None, externalId=None,
                          extra_params=None):
        data = {
            "associatedSharedNetworkResourceID": shared_netid,
            "address": address
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if self.extra_params:
            data.update(extra_params)
        if not parent:
            parent = constants.DOMAIN
        res_path = self.build_resource_path(
            parent, parent_id, constants.FLOATINGIP)
        return self.post(res_path, data)

    def get_floatingip(self, parent, parent_id):
        return self.get_child_resource(
            parent, parent_id, constants.FLOATINGIP, None, None)

    def create_floatingip_pool(self, name, address, gateway, netmask,
                               extra_params=None):
        data = {
            "type": "FLOATING",
            "netmask": netmask,
            "name": name,
            "gateway": gateway,
            "address": address
        }
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            constants.SHARED_NET_RES, None, None)
        return self.post(res_path, data)

    def claim_floatingip(self, l3domain_id, vsd_fip_pool_id):
        data = {
            "associatedSharedNetworkResourceID": vsd_fip_pool_id
        }
        res_path = self.build_resource_path(
            constants.DOMAIN, l3domain_id, constants.FLOATINGIP)
        return self.post(res_path, data)

    # Static Route
    def create_staticroute(self, parent, parent_id, netaddr, nexthop,
                           externalId=None, extra_params=None):
        data = {
            'address': netaddr.ip,
            'netmask': netaddr.netmask,
            'nextHopIp': nexthop
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if self.extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            parent, parent_id, constants.STATIC_ROUTE)
        return self.post(res_path, data)

    def get_staticroute(self, parent, parent_id, filters=None,
                        filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.STATIC_ROUTE, None, None)

    # L2Domain Template
    def create_l2domaintemplate(self, name, extra_params=None,
                                netpart_name=None):
        data = {
            'name': name
        }
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)

        res_path = self.build_resource_path(
            constants.NET_PARTITION, net_part[0]['ID'],
            constants.L2_DOMAIN_TEMPLATE)
        return self.post(res_path, data)

    def get_l2domaintemplate(self, filters=None, filter_value=None,
                             netpart_name=None):
        return self.get_resource(constants.L2_DOMAIN_TEMPLATE,
                                 filters, filter_value, netpart_name)

    def delete_l2domaintemplate(self, l2dom_tid):
        for attempt in range(1, Topology.nbr_retries_for_test_robustness + 1):
            try:
                return self.delete_resource(constants.L2_DOMAIN_TEMPLATE,
                                            l2dom_tid)
            except Exception as e:
                if attempt == Topology.nbr_retries_for_test_robustness:
                    raise
                elif 'l2domaintemplate is in use' in str(e):
                    LOG.error('Got {} (attempt {})'.format(str(e), attempt))
                    time.sleep(0.2)  # same wait time as plugin
                else:
                    raise

    def apply_l2domaintemplate_policies(self, l2dom_tid):
        data = {"command": "APPLY_POLICY_CHANGES"}
        res_path = self.build_resource_path(
            constants.L2_DOMAIN_TEMPLATE, l2dom_tid,
            constants.APPLY_JOBS)
        return self.post(res_path, data)

    # L2Domain
    def create_l2domain(self, name, templateId=None, externalId=None,
                        extra_params=None, netpart_name=None):
        if not templateId:
            l2dom_template = self.create_l2domaintemplate(
                name + '-l2domtemplate')
            templateId = l2dom_template[0]['ID']
        data = {
            'name': name,
            'templateID': templateId
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)

        res_path = self.build_resource_path(
            constants.NET_PARTITION, net_part[0]['ID'],
            constants.L2_DOMAIN)
        return self.post(res_path, data)

    def update_l2domain(self, l2domain_id, externalId=None,
                        update_params=None):
        data = {}
        #     'name': name,
        # }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if update_params:
            data.update(update_params)

        res_path = self.build_resource_path(
            constants.L2_DOMAIN, l2domain_id,
            None)
        return self.put(res_path, data)

    def delete_l2domain(self, l2dom_id):
        for attempt in range(1, Topology.nbr_retries_for_test_robustness + 1):
            try:
                return self.delete_resource(constants.L2_DOMAIN, l2dom_id)

            except Exception as e:
                if attempt == Topology.nbr_retries_for_test_robustness:
                    raise
                elif ('l2domain is in use' in str(e) or
                      'Policy Group cannot be deleted as it is attached '
                      'to VPort' in str(e)):
                    LOG.error('Got {} (attempt {})'.format(str(e), attempt))
                    time.sleep(0.2)  # same wait time as plugin
                else:
                    raise

    def get_l2domain(self, filters=None, filter_value=None, netpart_name=None):
        return self.get_resource(constants.L2_DOMAIN,
                                 filters, filter_value, netpart_name)

    def get_l2domain_vports(self, l2domain_id):
        res_path = self.build_resource_path(
            constants.L2_DOMAIN, l2domain_id, "vports")
        return self.get(res_path)

    def get_bridge_port_gateway_vlan(self, port):
        res_path2 = self.build_resource_path("vlans", port['VLANID'])
        return self.get(res_path2)

    # Policy
    # Policygroup
    def create_policygroup(self, parent, parent_id, name, type,
                           externalId=None, extra_params=None):
        data = {
            'description': name,
            'type': type
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
            data['name'] = externalId
        else:
            data['name'] = name
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            parent, parent_id, constants.POLICYGROUP)
        return self.post(res_path, data)

    def delete_policygroup(self, id):
        return self.delete_resource(constants.POLICYGROUP, id)

    def get_policygroup(self, parent, parent_id, filters=None,
                        filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.POLICYGROUP, filters, filter_value)

    def begin_l2_policy_changes(self, l2domain_id):
        data = {"command": "BEGIN_POLICY_CHANGES"}
        res_path = self.build_resource_path(
            resource=constants.L2_DOMAIN,
            resource_id=l2domain_id,
            child_resource=constants.APPLY_JOBS)
        return self.post(res_path, data)

    def apply_l2_policy_changes(self, l2domain_id):
        data = {"command": "APPLY_POLICY_CHANGES"}
        res_path = self.build_resource_path(
            resource=constants.L2_DOMAIN,
            resource_id=l2domain_id,
            child_resource=constants.APPLY_JOBS)
        return self.post(res_path, data)

    def begin_l3_policy_changes(self, l3domain_id):
        data = {"command": "BEGIN_POLICY_CHANGES"}
        res_path = self.build_resource_path(
            resource=constants.DOMAIN,
            resource_id=l3domain_id,
            child_resource=constants.APPLY_JOBS)
        return self.post(res_path, data)

    def apply_l3_policy_changes(self, l3domain_id):
        data = {"command": "APPLY_POLICY_CHANGES"}
        res_path = self.build_resource_path(
            resource=constants.DOMAIN,
            resource_id=l3domain_id,
            child_resource=constants.APPLY_JOBS)
        return self.post(res_path, data)

    # Redirection Target
    def get_redirection_target(self, parent, parent_id,
                               filters=None, filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.REDIRECTIONTARGETS,
            filters, filter_value)

    def create_l2_redirect_target(self, domain_id, name, extra_params=None):
        data = {
            "endPointType": "VIRTUAL_WIRE",
            "name": name,
        }
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=constants.L2_DOMAIN,
            resource_id=domain_id,
            child_resource=constants.REDIRECTIONTARGETS)
        return self.post(res_path, data)

    def update_redirect_target(self, rt_id, update_params=None):
        data = {}
        if update_params:
            data.update(update_params)
        res_path = self.build_resource_path(
            resource=constants.REDIRECTIONTARGETS,
            resource_id=rt_id,
            child_resource=None)
        return self.put(res_path, data)

    def create_l3_redirect_target(self, domain_id, name, extra_params=None):
        data = {
            "endPointType": "L3",
            "name": name,
        }
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=constants.DOMAIN,
            resource_id=domain_id,
            child_resource=constants.REDIRECTIONTARGETS)
        return self.post(res_path, data)

    def delete_redirect_target(self, id):
        res_path = self.build_resource_path(
            resource=constants.REDIRECTIONTARGETS,
            resource_id=id)
        return self.delete(res_path)

    def get_redirection_target_vports(self, parent, parent_id,
                                      filters=None, filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.VPORT, filters, filter_value)

    def get_redirection_target_vips(self, parent, parent_id,
                                    filters=None, filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.VIRTUAL_IP, filters, filter_value)

    # ADVFWDTemplate
    def create_advfwd_entrytemplate(self, parent, parent_id,
                                    filters=None, filter_value=None):
        data = {
            'name': "nameke",
            'active': True,
            "priorityType": "NONE",
            "priority": None,
            "statsLoggingEnabled": False,
            "policyState": None,
            "flowLoggingEnabled": False,
            "defaultAllowNonIP": False,
            "defaultAllowIP": False}

        res_path = self.build_resource_path(
            resource=parent,
            resource_id=parent_id,
            child_resource=constants.INGRESS_ADV_FWD_TEMPLATE)
        return self.post(res_path, data)

    def get_advfwd_entrytemplate(self, parent, parent_id,
                                 filters=None, filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.INGRESS_ADV_FWD_ENTRY_TEMPLATE,
            filters, filter_value)

    def get_advfwd_template(self, parent, parent_id,
                            filters=None, filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.INGRESS_ADV_FWD_TEMPLATE,
            filters, filter_value)

    # ACLTemplate
    def create_ingress_acl_template(self, name, parent, parent_id,
                                    extra_params=None):
        data = {"name": name}
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=parent,
            resource_id=parent_id,
            child_resource=constants.INGRESS_ACL_TEMPLATE)
        result = self.post(res_path, data)
        return result

    def create_l2domain_ingress_acl_template(self, name, domain_id,
                                             extra_params=None):
        data = {
            "name": name
        }
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=constants.L2_DOMAIN,
            resource_id=domain_id,
            child_resource=constants.INGRESS_ACL_TEMPLATE)
        result = self.post(res_path, data)
        return result

    def get_ingressacl_template(self, parent, parent_id):
        return self.get_child_resource(parent, parent_id,
                                       constants.INGRESS_ACL_TEMPLATE, None,
                                       None)

    def get_egressacl_template(self, parent, parent_id):
        return self.get_child_resource(parent, parent_id,
                                       constants.EGRESS_ACL_TEMPLATE, None,
                                       None)

    def update_egress_acl_template(self, eacl_template_id, extra_params=None):
        data = {}
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=constants.EGRESS_ACL_TEMPLATE,
            resource_id=eacl_template_id,
            child_resource=None)
        self.put(res_path, data)

    def update_ingress_acl_template(self, eacl_template_id, extra_params=None):
        data = {}
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=constants.INGRESS_ACL_TEMPLATE,
            resource_id=eacl_template_id,
            child_resource=None)
        self.put(res_path, data)

    def create_egress_acl_template(self, name, parent, parent_id,
                                   extra_params=None):
        data = {"name": name}
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=parent,
            resource_id=parent_id,
            child_resource=constants.EGRESS_ACL_TEMPLATE)
        result = self.post(res_path, data)
        return result

    def create_l2domain_egress_acl_template(self, name, domain_template_id,
                                            extra_params=None):
        data = {
            "name": name
        }
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=constants.L2_DOMAIN,
            resource_id=domain_template_id,
            child_resource=constants.EGRESS_ACL_TEMPLATE)
        result = self.post(res_path, data)
        return result

    def create_ingress_security_group_entry(self, name_description,
                                            iacl_template_id,
                                            extra_params=None,
                                            responseChoice=False):
        data = {
            "description": name_description
        }

        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=constants.INGRESS_ACL_TEMPLATE,
            resource_id=iacl_template_id,
            child_resource=constants.INGRESS_ACL_ENTRY_TEMPLATE)

        if responseChoice:
            res_path = res_path + RESPONSECHOICE

        result = self.post(res_path, data)
        return result

    # ACLRule
    def create_ingress_acl(self):
        pass

    def get_ingressacl_entrytemplate(self, parent, parent_id,
                                     filters=None, filter_value=None):
        return self.get_child_resource(parent, parent_id,
                                       constants.INGRESS_ACL_ENTRY_TEMPLATE,
                                       filters, filter_value)

    def get_egressacl_entrytemplate(self, parent, parent_id,
                                    filters=None, filter_value=None):
        return self.get_child_resource(parent, parent_id,
                                       constants.EGRESS_ACL_ENTRY_TEMPLATE,
                                       filters, filter_value)

    # User Mgmt
    # User
    def get_user(self, filters=None, filter_value=None, netpart_name=None):
        return self.get_resource(constants.USER, filters,
                                 filter_value, netpart_name)

    # Group
    def get_usergroup(self, parent, parent_id, filters=None,
                      filter_value=None, netpart_name=None):
        if parent:
            return self.get_child_resource(parent, parent_id, constants.GROUP,
                                           filters, filter_value)
        else:
            return self.get_resource(constants.GROUP, filters,
                                     filter_value, netpart_name)

    # Permissions
    def get_permissions(self, parent, parent_id, filters=None,
                        filter_value=None):
        return self.get_child_resource(parent, parent_id,
                                       constants.PERMIT_ACTION,
                                       filters,
                                       filter_value)

    # VM Interface
    def get_vm_iface(self, parent, parent_id, filters=None, filter_value=None):
        return self.get_child_resource(parent, parent_id,
                                       constants.VM_IFACE, filters,
                                       filter_value)

    # VM
    def get_vm(self, parent, parent_id, filters=None,
               filter_value=None, netpart_name=None):
        if parent:
            return self.get_child_resource(parent, parent_id, constants.VM,
                                           filters, filter_value)
        else:
            return self.get_resource(constants.VM, filters,
                                     filter_value, netpart_name)

    # Vport
    # Bridge Interface
    def get_bridge_iface(self, parent, parent_id, filters=None,
                         filter_value=None):
        return self.get_child_resource(parent, parent_id,
                                       constants.BRIDGE_IFACE, filters,
                                       filter_value)

    # Vport
    def get_vport(self, parent, parent_id, filters=None, filter_value=None):
        return self.get_child_resource(parent, parent_id, constants.VPORT,
                                       filters, filter_value)

    # VirtualIP
    def get_virtual_ip(self, parent, parent_id, filters=None,
                       filter_value=None):
        return self.get_child_resource(parent, parent_id, constants.VIRTUAL_IP,
                                       filters, filter_value)

    # Gateway
    def create_gateway(self, name, system_id, personality,
                       np_id=None, extra_params=None):
        data = {
            'systemID': system_id,
            'name': name,
            'personality': personality
        }

        if extra_params:
            data.update(extra_params)

        if np_id:
            res_path = self.build_resource_path(
                resource=constants.NET_PARTITION, resource_id=np_id,
                child_resource=constants.GATEWAY)
        else:
            res_path = self.build_resource_path(resource=constants.GATEWAY)
        return self.post(res_path, data)

    def delete_gateway(self, gw_id):
        return self.delete_resource(constants.GATEWAY, gw_id)

    def get_global_gateways(self, filters=None, filter_value=None):
        res_path = self.build_resource_path(constants.GATEWAY)
        if filters:
            extra_headers = self.get_extra_headers(filters, filter_value)
            return self.get(res_path, extra_headers)
        return self.get(res_path)

    def get_gateway(self, filters=None, filter_value=None, netpart_name=None):
        return self.get_resource(constants.GATEWAY,
                                 filters, filter_value, netpart_name)

    # Gateway redundancy group
    def create_redundancy_group(self, name, gateway_id_1,
                                gateway_id_2, extra_params=None):
        data = {
            'name': name,
            'gatewayPeer1ID': gateway_id_1,
            'gatewayPeer2ID': gateway_id_2
        }

        if extra_params:
            data.update(extra_params)

        res_path = self.build_resource_path(
            resource=constants.REDUNDANCY_GROUPS)
        return self.post(res_path, data)

    def delete_redundancy_group(self, grp_id):
        return self.delete_resource(constants.REDUNDANCY_GROUPS, grp_id)

    # GatewayPort
    def create_gateway_port(self, name, userMnemonic, type, gw_id,
                            extra_params=None):
        data = {
            'userMnemonic': userMnemonic,
            'name': name,
            'physicalName': name,
            'portType': type,
            'VLANRange': '0-4094'
        }

        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=constants.GATEWAY,
            resource_id=gw_id, child_resource=constants.GATEWAY_PORT)
        return self.post(res_path, data)

    def delete_gateway_port(self, port_id):
        return self.delete_resource(constants.GATEWAY_PORT, port_id)

    def get_gateway_port(self, filters=None, filter_value=None,
                         netpart_name=None):
        return self.get_resource(constants.GATEWAY_PORT,
                                 filters, filter_value, netpart_name)

    # GatewayVlan
    def create_gateway_vlan(self, gw_port_id, userMnemonic, value,
                            extra_params=None):
        data = {
            'userMnemonic': userMnemonic,
            'value': value
        }

        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=constants.GATEWAY_PORT,
            resource_id=gw_port_id, child_resource=constants.VLAN)
        return self.post(res_path, data)

    def delete_gateway_vlan(self, vlan_id):
        return self.delete_resource(constants.VLAN, vlan_id,
                                    responseChoice=True)

    def get_gateway_vlan(self, parent, parent_id, filters=None,
                         filter_value=None):
        return self.get_child_resource(
            parent, parent_id, constants.VLAN, filters, filter_value)

    def get_gateway_vlan_by_id(self, vlan_id):
        return self.get_global_resource(constants.VLAN + '/' + vlan_id)[0]

    @staticmethod
    def is_hw_gateway_personality(personality):
        return personality not in constants.SW_GW_TYPES

    def create_vsg_redundancy_ports(self, name, userMnemonic, type,
                                    gw_1_port_id, gw_2_port_id, rdn_grp,
                                    extra_params=None):
        data = {
            'userMnemonic': userMnemonic,
            'name': name,
            'physicalName': name,
            'portType': type,
            'VLANRange': '0-4094',
            'portPeer1ID': gw_1_port_id,
            'portPeer2ID': gw_2_port_id
        }
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=constants.REDUNDANCY_GROUPS,
            resource_id=rdn_grp[0]['ID'],
            child_resource=constants.VSG_REDUNDANT_PORTS)
        return self.post(res_path, data)

    def create_vrsg_redundancy_ports(self, name, userMnemonic, type, grp_id,
                                     extra_params=None):
        data = {
            'userMnemonic': userMnemonic,
            'name': name,
            'physicalName': name,
            'portType': type,
            'VLANRange': '0-4094'
        }

        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=constants.REDUNDANCY_GROUPS,
            resource_id=grp_id, child_resource=constants.GATEWAY_PORT)
        return self.post(res_path, data)

    def delete_vsg_redundancy_ports(self, rd_port_id):
        return self.delete_resource(constants.VSG_REDUNDANT_PORTS, rd_port_id)

    def create_vsg_redundancy_vlans(self, rd_port_id, userMnemonic, value,
                                    extra_params=None):
        data = {
            'userMnemonic': userMnemonic,
            'value': value
        }

        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=constants.VSG_REDUNDANT_PORTS,
            resource_id=rd_port_id, child_resource=constants.VLAN)
        return self.post(res_path, data)

    def get_host_vport(self, vport_id):
        res_path = self.build_resource_path(constants.VPORT, vport_id)
        return self.get(res_path)

    def delete_host_interface(self, intf_id):
        return self.delete_resource(constants.HOST_IFACE, intf_id, True)

    def delete_bridge_interface(self, intf_id):
        return self.delete_resource(constants.BRIDGE_IFACE, intf_id, True)

    def delete_host_vport(self, vport_id):
        return self.delete_resource(constants.VPORT, vport_id, True)

    def create_gateway_redundancy_group(self, name,
                                        peer1, peer2, extra_params=None):
        data = {
            'name': name,
            'gatewayPeer1ID': peer1,
            'gatewayPeer2ID': peer2
        }

        if extra_params:
            data.update(extra_params)

        res_path = self.build_resource_path(resource=constants.REDCY_GRP)
        return self.post(res_path, data)

    def create_vsg_redundant_port(self, name, userMnemonic, type, gw_id,
                                  extra_params=None):
        data = {
            'userMnemonic': userMnemonic,
            'name': name,
            'physicalName': name,
            'portType': type,
            'VLANRange': '0-4094'
        }

        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=constants.REDCY_GRP,
            resource_id=gw_id, child_resource=constants.GATEWAY_VSG_REDCY_PORT)
        return self.post(res_path, data)

    def list_ports_by_redundancy_group(self, gw_id, personality):
        if self.is_hw_gateway_personality(personality):
            child_resource = constants.GATEWAY_VSG_REDCY_PORT
        else:
            child_resource = constants.GATEWAY_PORT
        res_path = self.build_resource_path(
            resource=constants.REDCY_GRP,
            resource_id=gw_id,
            child_resource=child_resource)
        return self.get(res_path)

    def delete_gateway_redundancy_group(self, grp_id):
        return self.delete_resource(constants.REDCY_GRP, grp_id)

    def create_gateway_vlan_redundant_port(self, gw_port_id,
                                           userMnemonic, value,
                                           personality,
                                           extra_params=None):
        data = {
            'userMnemonic': userMnemonic,
            'value': value
        }
        if self.is_hw_gateway_personality(personality):
            resource = constants.GATEWAY_VSG_REDCY_PORT
        else:
            resource = constants.GATEWAY_PORT
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            resource=resource,
            resource_id=gw_port_id,
            child_resource=constants.VLAN)
        return self.post(res_path, data)

    # QOS
    def get_qos(self, parent, parent_id, filters=None, filter_value=None):
        return self.get_child_resource(parent, parent_id, constants.QOS,
                                       filters, filter_value)

    def create_vlan_permission(self, vlan_id, enterprise_id):
        res_path = self.build_resource_path(
            resource=constants.VLAN,
            resource_id=vlan_id,
            child_resource=constants.ENTERPRISE_PERMS)
        return self.post(res_path, {'permittedAction': 'USE',
                                    'permittedEntityID': enterprise_id})

    def delete_vlan_permission(self, vlan_id):
        res_path = self.build_resource_path(
            resource=constants.VLAN,
            resource_id=vlan_id,
            child_resource=constants.PERMIT_ACTION)
        perm = self.get(res_path)
        if perm:
            return self.delete_resource(constants.PERMIT_ACTION,
                                        perm[0]['ID'], True)

    def get_vlan_permission(self, parent, parent_id, permission_type):
        return self.get_child_resource(
            parent, parent_id, permission_type)

    def create_default_appdomain_template(self, name, extra_params=None,
                                          netpart_name=None):
        data = {
            'name': name
        }
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)

        res_path = self.build_resource_path(
            constants.NET_PARTITION, net_part[0]['ID'],
            constants.DOMAIN_TEMPLATE)
        return self.post(res_path, data)

    def create_app_domain(self, name, templateId, externalId=None,
                          netpart_name=None, extra_params=None):
        data = {
            'name': name,
            'templateID': templateId
        }
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)
        res_path = self.build_resource_path(
            constants.NET_PARTITION, net_part[0]['ID'],
            constants.DOMAIN)
        return self.post(res_path, data)

    def delete_app_domain(self, app_dom_id):
        return self.delete_resource(constants.DOMAIN, app_dom_id, True)

    def create_application(self, name, domain_id,
                           netpart_name=None, extra_params=None):
        data = {
            'name': name,
            'associatedDomainID': domain_id,
            'associatedDomainType': "DOMAIN"
        }
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)
        res_path = self.build_resource_path(
            constants.NET_PARTITION,
            resource_id=net_part[0]['ID'],
            child_resource=constants.APPLICATION)
        return self.post(res_path, data)

    def delete_application(self, app):
        return self.delete_resource(constants.APPLICATION, app, True)

    def create_tier(self, name, app_id, type, cidr=None,
                    externalId=None, extra_params=None):
        data = {
            'name': name,
            'type': type,
        }
        if type == 'STANDARD':
            net = netaddr.IPNetwork(cidr)
            data.update({'address': str(net.ip)})
            data.update({'netmask': str(net.netmask)})
        if externalId:
            data['externalID'] = self.get_vsd_external_id(externalId)
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            constants.APPLICATION,
            resource_id=app_id,
            child_resource=constants.TIER)
        return self.post(res_path, data)

    def delete_tier(self, tier):
        return self.delete_resource(constants.TIER, tier, True)

    def create_flow(self, name, app_id, originTierID,
                    destinationTierID, extra_params=None):
        data = {
            'name': name,
            'originTierID': originTierID,
            'destinationTierID': destinationTierID
        }
        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(
            constants.APPLICATION,
            resource_id=app_id,
            child_resource=constants.FLOW)
        return self.post(res_path, data)

    def delete_flow(self, flow):
        return self.delete_resource(constants.FLOW, flow, True)

    def create_service(self, name, netpart_name=None,
                       protocol=constants.PROTO_NAME_TO_NUM['tcp'],
                       etherType=constants.PROTO_NAME_TO_NUM['IPv4'],
                       direction='REFLEXIVE',
                       src_port='*', dscp='*',
                       dest_port='*',
                       extra_params=None):
        data = {
            'name': name,
            'description': direction,
            'sourcePort': src_port,
            'destinationPort': dest_port,
            'etherType': etherType,
            'DSCP': dscp,
            'protocol': protocol,
            'direction': direction,
        }
        if extra_params:
            data.update(extra_params)
        if not netpart_name:
            netpart_name = self.def_netpart_name
        net_part = self.get_net_partition(netpart_name)
        res_path = self.build_resource_path(
            constants.NET_PARTITION, net_part[0]['ID'],
            constants.SERVICE)
        return self.post(res_path, data)

    def delete_service(self, svc):
        return self.delete_resource(constants.SERVICE, svc, True)

    @staticmethod
    def get_vsd_external_id(neutron_id):
        if neutron_id and '@' not in neutron_id and CMS_ID:
            return neutron_id + '@' + CMS_ID
        return neutron_id

    # System configs
    def get_system_configuration(self):
        res_path = self.build_resource_path(
            resource=constants.SYSTEM_CONFIGS)
        return self.get(res_path)

    def update_system_configuration(self, configuration_id, configuration):
        res_path = self.build_resource_path(
            resource=constants.SYSTEM_CONFIGS,
            resource_id=configuration_id)
        return self.put(res_path, configuration)

    def create_uplink_subnet(self, extra_params=None, **kwargs):
        data = {'netmask': kwargs['netmask'],
                'uplinkGWVlanAttachmentID':
                    str(kwargs['uplinkGWVlanAttachmentID']),
                'name': kwargs['name'],
                'sharedResourceParentID':
                    str(kwargs['sharedResourceParentID']),
                'address': kwargs['address'],
                'uplinkVPortName': kwargs['uplinkVportName'],
                'uplinkInterfaceMAC': kwargs['uplinkInterfaceMAC'],
                'type': 'UPLINK_SUBNET',
                'gateway': kwargs['gateway'],
                'uplinkInterfaceIP': kwargs['uplinkInterfaceIP']}

        if extra_params:
            data.update(extra_params)
        res_path = self.build_resource_path(resource=constants.SHARED_NET_RES)
        return self.post(res_path, data)

    def delete_uplink_subnet(self, subnet_id):
        return self.delete_resource(constants.SHARED_NET_RES, subnet_id)
