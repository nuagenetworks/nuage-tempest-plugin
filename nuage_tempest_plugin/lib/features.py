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

from oslo_log import log as logging
from tempest import config

from nuage_tempest_plugin.lib.release import Release
from nuage_tempest_plugin.lib.topology import Topology

CONF = config.CONF
LOG = logging.getLogger(__name__)


# this should never be called outside of this class
class NuageFeatures(object):
    """Provides information on supported features per release.

    ml2_limited_exceptions: Up till Newton, ML2 driver prevented the Nuage ML2
    driver to raise the exact exception and exception message.
    The driver could only raise exceptions like
        "update_port_postcommit failed"
        "update_port_precommit failed"
    """

    def _set_features(self):
        if self.current_release.major_release == "3.2":
            self.bidirectional_fip_rate_limit = \
                self.current_release >= Release('3.2R10')

        elif self.current_release.major_release == "4.0":
            self.full_external_id_support = \
                self.current_release >= Release('4.0R5')
            self.bidirectional_fip_rate_limit = \
                self.current_release >= Release('4.0R6')
            self.vsd_managed_dualstack_subnets = \
                self.current_release == Release('4.0VZ')

        else:
            self.full_external_id_support = True
            self.bidirectional_fip_rate_limit = True
            self.ml2_limited_exceptions = False
            self.full_os_networking = True
            self.vsd_managed_dualstack_subnets = Topology.is_ml2
            self.os_managed_dualstack_subnets = (
                self.current_release >= Release('5.1') and
                self.ipv6_enabled)
            self.project_name_in_user_group_description = (
                self.current_release >= Release('5.1'))
            self.vsd_shared_infrastructure = True

    def _log_features(self):
        LOG.info("FEATURES:")
        LOG.info("full_external_id_support         : {}".
                 format(self.full_external_id_support))
        LOG.info("bidirectional_fip_rate_limit     : {}".
                 format(self.bidirectional_fip_rate_limit))
        LOG.info("ml2_limited_exceptions           : {}".
                 format(self.ml2_limited_exceptions))
        LOG.info("full_os_networking               : {}".
                 format(self.full_os_networking))
        LOG.info("vsd_managed_dualstack_subnets    : {}".
                 format(self.vsd_managed_dualstack_subnets))
        LOG.info("os_managed_dualstack_subnets     : {}".
                 format(self.os_managed_dualstack_subnets))
        LOG.info("vsd_shared_infrastructure        : {}".
                 format(self.vsd_shared_infrastructure))

    def __init__(self):
        """Initialize a feature set"""
        super(NuageFeatures, self).__init__()
        self.current_release = Release(Topology.nuage_release)

        self.full_external_id_support = False
        self.bidirectional_fip_rate_limit = False
        self.ml2_limited_exceptions = Topology.is_ml2
        self.full_os_networking = not Topology.is_ml2
        self.vsd_managed_dualstack_subnets = False
        self.os_managed_dualstack_subnets = False
        self.vsd_shared_infrastructure = False
        self.ipv6_enabled = CONF.network_feature_enabled.ipv6

        self._set_features()
        self._log_features()


NUAGE_FEATURES = NuageFeatures()
