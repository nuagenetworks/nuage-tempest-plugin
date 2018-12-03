from tempest.lib.common import rest_client as service_client
from tempest.lib.services.network import base


class NetworkingSfcClient(base.BaseNetworkClient):

    def create_port_pair(self, name, ingress_port, egress_port):
        uri = '/sfc/port_pairs'
        post_data = {'port_pair':
                     {"name": name,
                      "ingress": ingress_port,
                      "egress": egress_port}}
        return self.create_resource(uri, post_data)

    def create_port_pair_group(self, name, port_pair):
        uri = '/sfc/port_pair_groups'
        post_data = {'port_pair_group':
                     {'port_pairs': [port_pair['port_pair']['id']],
                      'name': name}}
        return self.create_resource(uri, post_data)

    def create_flow_classifier(self, **kwargs):
        uri = '/sfc/flow_classifiers'
        post_data = {'flow_classifier': kwargs}
        return self.create_resource(uri, post_data)

    def create_port_chain(self, **kwargs):
        uri = '/sfc/port_chains'
        post_data = {'port_chain': kwargs}
        return self.create_resource(uri, post_data)

    def delete_port_pair(self, port_pair_id):
        uri = '/v2.0/sfc/port_pairs/%s' % port_pair_id
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def delete_port_pair_group(self, port_pair_group_id):
        uri = '/v2.0/sfc/port_pair_groups/%s' % port_pair_group_id
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def delete_flow_classifier(self, flow_classifier_id):
        uri = '/v2.0/sfc/flow_classifiers/%s' % flow_classifier_id
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def delete_port_chain(self, port_chain_id):
        uri = '/v2.0/sfc/port_chains/%s' % port_chain_id
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return service_client.ResponseBody(resp, body)

    def update_port_pair_group(self, port_pair_group_id, port_pair):
        uri = '/sfc/port_pair_groups/%s' % port_pair_group_id
        post_data = {'port_pair_group':
                     {'port_pairs': [port_pair['port_pair']['id']]}}
        return self.update_resource(uri, post_data)

    def update_port_chain(self, port_chain_id, **kwargs):
        uri = '/sfc/port_chains/%s' % port_chain_id
        post_data = {'port_chain': kwargs}
        return self.update_resource(uri, post_data)
