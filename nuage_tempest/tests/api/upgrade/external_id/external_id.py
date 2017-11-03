# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import re

from tempest import config

CONF = config.CONF


class ExternalId(object):
    external_id_regex = re.compile("^([a-zA-Z0-9\-_]*)(?:@)?([a-zA-Z0-9\-]*)")

    def __init__(self, id_string):
        self.cms = ""
        self.uuid = ""
        self._parse(id_string)

    def _parse(self, id_string):
        if not id_string:
            self.uuid = ""
            self.cms = ""
        else:
            parsed = ExternalId.external_id_regex.search(id_string)

            if parsed is None:
                raise Exception("Can not parse External ID'%s'" % id_string)
            self.uuid = parsed.group(1)
            self.cms = parsed.group(2) if parsed.group(2) else ""

    def _build(self):
        return self.uuid + '@' + self.cms

    def at(self, cms_string):
        self.cms = cms_string
        return self._build()

    def at_cms_id(self):
        self.cms = CONF.nuage.nuage_cms_id
        return self._build()

    def at_openstack(self):
        self.cms = 'openstack'
        return self._build()
