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

from nuage_tempest.lib.openstackcli import openstack_cliclient
from oslo_log import log as logging
from tempest import config

CONF = config.CONF

LOG = logging.getLogger(__name__)


class VPNaaSClient(openstack_cliclient.ClientTestBase):

    force_tenant_isolation = False

    _ip_version = 4

    @classmethod
    def skip_checks(self):
        if not CONF.service_available.neutron:
            raise self.skipException("Neutron support is required")

    def __init__(self, osc):
        super(VPNaaSClient, self).__init__(osc)

    def create_ikepolicy(self, name, **kwargs):
        params = ''
        params += '{} '.format(name)
        for k, v in kwargs.iteritems():
            params = params + '--{} {} '.format(k, v)
        ikepolicy = self.cli.neutron('vpn-ikepolicy-create', params=params)
        self.assertFirstLineStartsWith(ikepolicy.split('\n'),
                                       'Created a new ikepolicy:')
        ikepolicy = self.parser.details(ikepolicy)
        response = {'ikepolicy': ikepolicy}
        return response

    def delete_ikepolicy(self, id):
        response = self.cli.neutron('vpn-ikepolicy-delete {}'.format(id))
        return response

    def show_ikepolicy(self, id):
        response = self.cli.neutron('vpn-ikepolicy-show {}'.format(id))
        item = self.parser.details(response)
        return item

    def list_ikepolicy(self):
        response = self.cli.neutron('vpn-ikepolicy-list')
        items = self.parser.listing(response)
        return items

    def create_ipsecpolicy(self, name, **kwargs):
        params = ''
        params += '{} '.format(name)
        for k, v in kwargs.iteritems():
            params = params + '--{} {} '.format(k, v)
        ipsecpolicy = self.cli.neutron('vpn-ipsecpolicy-create', params=params)
        self.assertFirstLineStartsWith(ipsecpolicy.split('\n'),
                                       'Created a new ipsecpolicy:')
        ipsecpolicy = self.parser.details(ipsecpolicy)
        response = {'ipsecpolicy': ipsecpolicy}
        return response

    def delete_ipsecpolicy(self, id):
        response = self.cli.neutron('vpn-ipsecpolicy-delete {}'.format(id))
        return response

    def show_ipsecpolicy(self, id):
        response = self.cli.neutron('vpn-ipsecpolicy-show {}'.format(id))
        item = self.parser.details(response)
        return item

    def list_ipsecpolicy(self):
        response = self.cli.neutron('vpn-ipsecpolicy-list')
        items = self.parser.listing(response)
        return items

    def create_vpnservice(self, routerid, subnetid, name, positive=True,
                          **kwargs):
        params = '{} '.format(routerid)
        params += '{} '.format(subnetid)
        params += '--{} {} '.format('name', name)
        for k, v in kwargs.iteritems():
            params = params + '--{} {} '.format(k, v)
        vpnservice = self.cli.neutron('vpn-service-create', params=params)
        if positive:
            self.assertFirstLineStartsWith(vpnservice.split('\n'),
                                           'Created a new vpnservice:')
            vpnservice = self.parser.details(vpnservice)
            response = {'vpnservice': vpnservice}
        else:
            if vpnservice != '':
                LOG.error('DUPLICATE VPNSERVCICE CREATED')
            response = ''
        return response

    def delete_vpnservice(self, id):
        response = self.cli.neutron('vpn-service-delete {}'.format(id))
        return response

    def show_vpnservice(self, id):
        response = self.cli.neutron('vpn-service-show {}'.format(id))
        item = self.parser.details(response)
        return item

    def list_vpnservice(self):
        response = self.cli.neutron('vpn-service-list')
        items = self.parser.listing(response)
        return items

    def create_ipsecsiteconnection(self, vpnservice_id, ikepolicy_id,
                                   ipsecpolicy_id, peer_address, peer_id,
                                   peer_cidrs, psk, name, **kwargs):

        params = '--{} {} '.format('vpnservice-id', vpnservice_id)
        params += '--{} {} '.format('ikepolicy-id', ikepolicy_id)
        params += '--{} {} '.format('ipsecpolicy-id', ipsecpolicy_id)
        params += '--{} {} '.format('peer-address', peer_address)
        params += '--{} {} '.format('peer-id', peer_id)
        params += '--{} {} '.format('peer-cidr', peer_cidrs)
        params += '--{} {} '.format('psk', psk)
        params += '--{} {} '.format('name', name)

        for k, v in kwargs.iteritems():
            params = params + '--{} {} '.format(k, v)
        ipsecsiteconnection = self.cli.neutron(
            'ipsec-site-connection-create', params=params)
        self.assertFirstLineStartsWith(ipsecsiteconnection.split('\n'),
                                       'Created a new ipsec_site_connection:')
        ipsecsiteconnection = self.parser.details(ipsecsiteconnection)
        response = {'ipsecsiteconnection': ipsecsiteconnection}
        return response

    def delete_ipsecsiteconnection(self, id):
        response = self.cli.neutron(
            'ipsec-site-connection-delete {}'.format(id))
        return response

    def show_ipsecsiteconnection(self, id):
        response = self.cli.neutron('ipsec-site-connection-show {}'.format(id))
        item = self.parser.details(response)
        return item

    def list_ipsecsiteconnection(self):
        response = self.cli.neutron('ipsec-site-connection-list')
        items = self.parser.listing(response)
        return items
