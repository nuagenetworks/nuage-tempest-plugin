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

from nuage_tempest_lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)


class NuageFeatures(object):
    """Provides information on supported features per release.

    """

    def log_features(self):
        LOG.info('RELEASES:')
        LOG.info('NUAGE release                    : {}'.
                 format(Topology.nuage_release_qualifier))
        LOG.info('OpenStack version                : {}'.
                 format(Topology.openstack_version_qualifier))
        LOG.info('')
        LOG.info('FEATURES:')
        LOG.info('full_external_id_support         : {}'.
                 format(self.full_external_id_support))
        LOG.info('full_os_networking               : {}'.
                 format(self.full_os_networking))
        LOG.info('stateless_security_groups        : {}'.
                 format(self.stateless_security_groups))
        LOG.info('route_to_underlay                : {}'.
                 format(self.route_to_underlay))

    def __init__(self):

        self.full_external_id_support = True
        self.full_os_networking = True
        self.ipv6_enabled = CONF.network_feature_enabled.ipv6
        self.stateless_security_groups = Topology.from_nuage('5.2')
        self.route_to_underlay = Topology.from_nuage('5.2')

        self.log_features()


NUAGE_FEATURES = NuageFeatures()
