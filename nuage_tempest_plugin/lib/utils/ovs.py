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

import abc
import re
import six


def filter(input_func):
    def wrapper(*args, **kwargs):
        self = args[0]
        result = input_func(*args, **kwargs)
        cnt_after = len(self.flows)
        arg_str = (', '.join(map(str, args[1:])) +
                   ', '.join(['{}={}'.format(k, v) for k, v in kwargs]))

        self.filter_history.append(
            {'filter': input_func.__name__,
             'args': arg_str,
             'cnt_after': cnt_after})
        return result
    return wrapper


@six.add_metaclass(abc.ABCMeta)
class FlowQuery(object):
    """Filter flows based on criteria"""

    def __init__(self, flows):
        """Constructor

        :param flows: A list of strings
        """
        self.flows = []
        self.filter_history = []
        self.load(flows)

    @filter
    def load(self, flows):
        self.flows = flows

    @abc.abstractmethod
    def src_mac(self, mac):
        """Flows must have src mac equal to input"""
        pass

    @abc.abstractmethod
    def dst_mac(self, mac):
        """Flows must have dst mac equal to input"""
        pass

    @abc.abstractmethod
    def action_set_tunnel_vxlan(self):
        """Flows with action tunnel"""
        pass

    @abc.abstractmethod
    def vxlan(self):
        """Flows from vxlan tunnel"""
        pass

    @abc.abstractmethod
    def icmp(self):
        """Flows must be icmp"""
        pass

    @abc.abstractmethod
    def no_icmpv6(self):
        """Flows must not be icmpv6"""
        pass

    @abc.abstractmethod
    def tcp(self):
        """Flows must be tcp"""
        pass

    @abc.abstractmethod
    def wildcard_protocol(self):
        """Flow allows any protocol"""
        pass

    @abc.abstractmethod
    def ip_version(self, version):
        """Flow with specific ip version"""
        pass

    @abc.abstractmethod
    def no_ip(self, ip):
        pass

    @abc.abstractmethod
    def offload(self):
        """Flows must be offloaded"""
        pass

    @abc.abstractmethod
    def no_offload(self):
        """Flows must not be offloaded"""
        pass

    @abc.abstractmethod
    def no_arp(self):
        """No arp flows"""
        pass

    def trace(self):
        return (' -> '.join('{}({}) ({} flows)'
                            .format(item['filter'],
                                    item['args'],
                                    item['cnt_after'])
                            for item in self.filter_history))

    def result(self):
        """Get the resulting flows"""
        return list(self.flows)


class OvrsFlowQuery(FlowQuery):
    """Filter flows based on criteria"""

    def _matches(self, regex):
        matcher = re.compile(regex)
        self.flows = [flow for flow in self.flows if matcher.match(flow)]

    def _not_matches(self, regex):
        matcher = re.compile(regex)
        self.flows = [flow for flow in self.flows if not matcher.match(flow)]

    @filter
    def src_mac(self, mac):
        """Flows must have src mac equal to input"""

        self._matches(r'.*eth\(src={},dst=[^\)]+\).*'
                      .format(mac.lower()))
        return self

    @filter
    def dst_mac(self, mac):
        """Flows must have dst mac equal to input"""

        self._matches(r'.*eth\(src=[^\)]+,dst={}\).*'
                      .format(mac.lower()))
        return self

    @filter
    def action_set_tunnel_vxlan(self):
        """Flows with action tunnel"""

        self._matches(r'.*actions:set\(tunnel.*')
        return self

    @filter
    def vxlan(self):
        """Flows from vxlan tunnel"""

        self._matches('.*tunnel.*actions.*')
        return self

    @filter
    def icmp(self):
        """Flows must be icmp"""

        self._matches('.*icmp.*')
        return self

    @filter
    def no_icmpv6(self):
        """Flows must not be icmpv6"""

        self._not_matches('.*icmpv6.*')
        return self

    @filter
    def tcp(self):
        """Flows must be tcp"""

        self._matches('.*tcp.*')
        return self

    @filter
    def wildcard_protocol(self):
        """Flow allows any protocol"""

        self._matches('.*proto=0/0.*actions.*')
        return self

    @filter
    def ip_version(self, version):
        """Flow with specific ip version"""

        self._matches('.*ipv{}.*actions.*'.format(version))
        return self

    @filter
    def no_ip(self, ip):
        """Flows excluding the ip"""

        self._not_matches('.*{}.*'.format(ip.replace('.', '\\.')))
        return self

    @filter
    def offload(self):
        """Flows must be offloaded"""

        self._matches('.*offloaded:yes.*')
        return self

    @filter
    def no_offload(self):
        """Flows must not be offloaded"""

        self._not_matches('.*offloaded:yes.*')
        return self

    @filter
    def no_arp(self):
        """No arp flows"""
        self._not_matches('.*arp.*')
        return self


class AvrsFlowQuery(FlowQuery):

    @filter
    def src_mac(self, mac):
        """Flows must have src mac equal to input"""

        self.flows = [flow for flow in self.flows
                      if flow['flow.key']['eth']['src'] == mac.lower()]
        return self

    @filter
    def dst_mac(self, mac):
        """Flows must have dst mac equal to input"""
        self.flows = [flow for flow in self.flows
                      if flow['flow.key']['eth']['dst'] == mac.lower()]
        return self

    @filter
    def action_set_tunnel_vxlan(self):
        """Flows with action tunnel"""
        raise NotImplementedError

    @filter
    def vxlan(self):
        """Flows from vxlan tunnel"""
        raise NotImplementedError

    @filter
    def icmp(self):
        """Flows must be icmp"""
        self.flows = [flow for flow in self.flows if 'ip' in flow['flow.key']
                      and flow['flow.key']['ip']['proto'] == 1]
        return self

    @filter
    def no_icmpv6(self):
        """Flows must not be icmpv6"""
        raise NotImplementedError

    @filter
    def tcp(self):
        """Flows must be tcp"""
        self.flows = [flow for flow in self.flows if 'ip' in flow['flow.key']
                      and flow['flow.key']['ip']['proto'] == 6]
        return self

    @filter
    def wildcard_protocol(self):
        """Flow allows any protocol"""
        raise NotImplementedError

    @filter
    def ip_version(self, version):
        """Flow with specific ip version"""
        if version == 4:
            self.flows = [flow for flow in self.flows if
                          'ip' in flow['flow.key']]
        else:
            self.flows = [flow for flow in self.flows if
                          'ipv6' in flow['flow.key']]
        return self

    @filter
    def no_ip(self, ip):
        """Flows excluding the ip"""
        raise NotImplementedError

    @filter
    def offload(self):
        """Flows must be offloaded"""
        raise NotImplementedError

    @filter
    def no_offload(self):
        """Flows must not be offloaded"""
        raise NotImplementedError

    @filter
    def no_arp(self):
        """No arp flows"""
        raise NotImplementedError
