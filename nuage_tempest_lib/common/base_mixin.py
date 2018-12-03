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

from tempest import config

CONF = config.CONF


class NuageBaseMixin(object):

    # common base Nuage mixing
    # - this can grow over time -

    def_netpartition = CONF.nuage.nuage_default_netpartition
    cms_id = CONF.nuage.nuage_cms_id
    public_network_id = CONF.network.public_network_id

    nuage_config = CONF.nuage

    nbr_retries_for_test_robustness = 10
