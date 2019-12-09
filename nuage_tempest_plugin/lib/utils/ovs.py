# All Rights Reserved.
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

import re


class FlowQuery(object):
    """Filter flows based on criteria"""

    def __init__(self, flows):
        """Constructor

        :param flows: A list of strings
        """
        self.flows = flows

    def _matches(self, regex):
        matcher = re.compile(regex)
        self.flows = [flow for flow in self.flows if matcher.match(flow)]

    def _not_matches(self, regex):
        matcher = re.compile(regex)
        self.flows = [flow for flow in self.flows if not matcher.match(flow)]

    def src_mac(self, mac):
        """Flows must have src mac equal to input"""

        self._matches(r'.*eth\(src={},dst=[^\)]+\).*'.format(mac))
        return self

    def dst_mac(self, mac):
        """Flows must have dst mac equal to input"""

        self._matches(r'.*eth\(src=[^\)]+,dst={}\).*'.format(mac))
        return self

    def action_set_tunnel_vxlan(self):
        """Flows with action tunnel"""

        self._matches(r'.*actions:set\(tunnel.*')
        return self

    def vxlan(self):
        """Flows from vxlan tunnel"""

        self._matches('.*tunnel.*actions.*')
        return self

    def icmp(self):
        """Flows must be icmp"""

        self._matches('.*icmp.*')
        return self

    def tcp(self):
        """Flows must be tcp"""

        self._matches('.*tcp.*')
        return self

    def wildcard_protocol(self):
        """Flow allows any protocol"""

        self._matches('.*proto=0/0.*actions.*')
        return self

    def ip_version(self, version):
        """Flow with specific ip version"""

        self._matches('.*ipv{}.*actions.*'.format(version))
        return self

    def offload(self):
        """Flows must be offloaded"""

        self._matches('.*offloaded:yes.*')
        return self

    def no_offload(self):
        """Flows must not be offloaded"""

        self._not_matches('.*offloaded:yes.*')
        return self

    def result(self):
        """Get the resulting flows"""

        return list(self.flows)
