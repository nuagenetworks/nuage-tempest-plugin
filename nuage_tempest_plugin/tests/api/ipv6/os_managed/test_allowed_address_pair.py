# Copyright 2014 OpenStack Foundation
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
#    under the License.

from tempest.api.network import test_allowed_address_pair as base_tempest
from tempest import config

CONF = config.CONF


class AllowedAddressPairIpV6NuageTest(base_tempest.AllowedAddressPairTestJSON):
    _ip_version = 6

    @classmethod
    def resource_setup(cls):
        super(base_tempest.AllowedAddressPairTestJSON, cls).resource_setup()
        cls.network = cls.create_network()
        cls.subnet4 = cls.create_subnet(
            cls.network, ip_version=4, enable_dhcp=True)
        cls.subnet6 = cls.create_subnet(
            cls.network, ip_version=6, enable_dhcp=False)

        port = cls.create_port(cls.network)
        cls.ip_address = port['fixed_ips'][1]['ip_address']
        cls.mac_address = port['mac_address']
