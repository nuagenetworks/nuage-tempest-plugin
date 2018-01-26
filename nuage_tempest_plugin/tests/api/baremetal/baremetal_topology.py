# Copyright 2017 NOKIA
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

from nuage_tempest_plugin.lib.utils import constants


class Topology(object):
    def __init__(self, vsd_client, network, subnet,
                 router, port, security_group):
        super(Topology, self).__init__()
        self.vsd_client = vsd_client
        self.network = network
        self.subnet = subnet
        self.router = router
        self.normal_port = port
        self.baremetal_port = None
        self.security_group = security_group

    @property
    def vsd_vport_parent(self):
        if not getattr(self, '_vsd_vport_parent', False):
            self._vsd_vport_parent = self.vsd_client.get_global_resource(
                self.vsd_vport_parent_resource,
                filters='externalID',
                filter_value=self.subnet['id'])[0]
        return self._vsd_vport_parent

    @property
    def vsd_vport_parent_resource(self):
        if not getattr(self, '_vsd_vport_parent_resource', False):
            if self.router:
                self._vsd_vport_parent_resource = constants.SUBNETWORK
            else:
                self._vsd_vport_parent_resource = constants.L2_DOMAIN
        return self._vsd_vport_parent_resource

    @property
    def vsd_baremetal_vport(self):
        if not getattr(self, '_vsd_baremetal_vport', False):
            vsd_vports = self.vsd_client.get_vport(
                self.vsd_vport_parent_resource,
                self.vsd_vport_parent['ID'],
                filters='externalID',
                filter_value=self.baremetal_port['id'])
            self._vsd_baremetal_vport = vsd_vports[0]
        return self._vsd_baremetal_vport

    @property
    def vsd_domain(self):
        if not getattr(self, '_vsd_domain', False):
            if self.router:
                zone = self.vsd_client.get_global_resource(
                    constants.ZONE + '/' +
                    self.vsd_vport_parent['parentID'])[0]
                self._vsd_domain = self.vsd_client.get_global_resource(
                    constants.DOMAIN + '/' + zone['parentID'])[0]
            else:
                self._vsd_domain = self.vsd_vport_parent
        return self._vsd_domain

    @property
    def vsd_domain_resource(self):
        if not getattr(self, '_vsd_domain_resource', False):
            if self.router:
                self._vsd_domain_resource = constants.DOMAIN
            else:
                self._vsd_domain_resource = constants.L2_DOMAIN
        return self._vsd_domain_resource

    @property
    def vsd_policygroups(self):
        return self.get_vsd_policygroups()

    def get_vsd_policygroups(self, force_read=False):
        if force_read or not getattr(self, '_vsd_policygroups', False):
            self._vsd_policygroups = self.vsd_client.get_policygroup(
                self.vsd_domain_resource,
                self.vsd_domain['ID'])
        return self._vsd_policygroups

    @property
    def vsd_baremetal_interface_resource(self):
        if not getattr(self, '_vsd_baremetal_interface_resource', False):
            if self.vsd_baremetal_vport['type'] == constants.VPORT_TYPE_HOST:
                self._vsd_baremetal_interface_resource = constants.HOST_IFACE
            else:
                self._vsd_baremetal_interface_resource = constants.BRIDGE_IFACE
        return self._vsd_baremetal_interface_resource

    @property
    def vsd_baremetal_interface(self):
        if not getattr(self, '_vsd_baremetal_interface', False):
            self._vsd_baremetal_interface = self.vsd_client.get_child_resource(
                constants.VPORT,
                self.vsd_baremetal_vport['ID'],
                self.vsd_baremetal_interface_resource)[0]
        return self._vsd_baremetal_interface

    @property
    def vsd_egress_acl_template(self):
        if not getattr(self, '_vsd_egress_acl_templates', False):
            self._vsd_egress_acl_templates = \
                self.vsd_client.get_egressacl_template(
                    self.vsd_domain_resource,
                    self.vsd_domain['ID'])[0]
        return self._vsd_egress_acl_templates

    @property
    def vsd_egress_acl_entries(self):
        if not getattr(self, '_vsd_egress_acl_entries', False):
            self._vsd_egress_acl_entries = \
                self.vsd_client.get_egressacl_entytemplate(
                    constants.EGRESS_ACL_TEMPLATE,
                    self.vsd_egress_acl_template['ID'])
        return self._vsd_egress_acl_entries

    @property
    def vsd_baremetal_dhcp_opts(self):
        if not getattr(self, '_vsd_baremetal_dhcp_opts', False):
            self._vsd_baremetal_dhcp_opts = self.vsd_client.get_dhcpoption(
                self.vsd_baremetal_interface_resource,
                self.vsd_baremetal_interface['ID'])
        return self._vsd_baremetal_dhcp_opts
