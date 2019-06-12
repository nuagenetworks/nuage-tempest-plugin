# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class NuageFeatures(object):
    """Provides information on supported features per release.

    ml2_limited_exceptions: Up till Newton, ML2 driver prevented the Nuage ML2
    driver to raise the exact exception and exception message.
    The driver could only raise exceptions like
        'update_port_postcommit failed'
        'update_port_precommit failed'
    """

    def _set_features(self):

        if Topology.nuage_release.major_release == '4.0':
            self.full_external_id_support = Topology.from_nuage('4.0R5')
            self.vsd_managed_dualstack_subnets = Topology.from_nuage('4.0VZ')

        else:
            self.full_external_id_support = True
            self.ml2_limited_exceptions = False
            self.full_os_networking = True
            self.vsd_managed_dualstack_subnets = Topology.is_ml2
            self.os_managed_dualstack_subnets = (
                Topology.from_nuage('5.1') and self.ipv6_enabled)
            self.project_name_in_vsd = Topology.from_nuage('5.1')
            self.stateless_security_groups = Topology.from_nuage('5.2')
            self.route_to_underlay = Topology.from_nuage('5.2')
            self.switchdev_offload = (Topology.from_nuage('5.4') and
                                      Topology.from_openstack('queens'))

    def _log_features(self):

        LOG.info('')
        LOG.info('RELEASES:')
        LOG.info('NUAGE release                    : {}'.
                 format(Topology.nuage_release_qualifier))
        LOG.info('OpenStack version                : {}'.
                 format(Topology.openstack_version_qualifier))
        LOG.info('')
        LOG.info('FEATURES:')
        LOG.info('full_external_id_support         : {}'.
                 format(self.full_external_id_support))
        LOG.info('ml2_limited_exceptions           : {}'.
                 format(self.ml2_limited_exceptions))
        LOG.info('full_os_networking               : {}'.
                 format(self.full_os_networking))
        LOG.info('vsd_managed_dualstack_subnets    : {}'.
                 format(self.vsd_managed_dualstack_subnets))
        LOG.info('os_managed_dualstack_subnets     : {}'.
                 format(self.os_managed_dualstack_subnets))
        LOG.info('stateless_security_groups        : {}'.
                 format(self.stateless_security_groups))
        LOG.info('route_to_underlay                : {}'.
                 format(self.route_to_underlay))
        LOG.info('switchdev_offload                : {}'.
                 format(self.switchdev_offload))

    def __init__(self):
        super(NuageFeatures, self).__init__()

        self.ipv6_enabled = CONF.network_feature_enabled.ipv6

        self.full_external_id_support = False
        self.ml2_limited_exceptions = Topology.is_ml2
        self.full_os_networking = not Topology.is_ml2
        self.vsd_managed_dualstack_subnets = False
        self.os_managed_dualstack_subnets = False
        self.ipv6_enabled = CONF.network_feature_enabled.ipv6
        self.stateless_security_groups = False
        self.route_to_underlay = False
        self._set_features()
        self._log_features()


NUAGE_FEATURES = NuageFeatures()
