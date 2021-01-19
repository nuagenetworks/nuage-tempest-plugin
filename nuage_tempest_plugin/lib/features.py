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
    def __init__(self):
        self.ipv6_enabled = CONF.network_feature_enabled.ipv6

        self.full_external_id_support = True
        self.ml2_limited_exceptions = False
        self.full_os_networking = True
        self.vsd_managed_dualstack_subnets = True
        self.os_managed_dualstack_subnets = self.ipv6_enabled
        self.project_name_in_vsd = True
        self.stateless_security_groups = True
        self.route_to_underlay = True
        self.switchdev_offload = Topology.from_nuage('6.0')

        LOG.info('')
        LOG.info('RELEASES:')
        LOG.info('Nuage version                    : {}'.
                 format(Topology.nuage_release_qualifier))
        LOG.info('OpenStack version                : {}'.
                 format(Topology.openstack_version_qualifier))
        LOG.info('Python version                   : {}.{}.{}'.
                 format(Topology.python_version.major,
                        Topology.python_version.minor,
                        Topology.python_version.micro))


NUAGE_FEATURES = NuageFeatures()
