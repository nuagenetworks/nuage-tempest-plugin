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
"""
These mixins extend BaseTestCase, so your testclass should only extend the
mixins it needs. The reason for this design is that now every mixin a test
extends will have 'setup_clients' called automagically for you. A test class'
structure would look like:
     BaseTestCase
         |
     BaseMixin
    /    |    \
mixin1 mixin2  mixin3
    \    |    /
     TestClass
"""
from tempest import test


class BaseMixin(test.BaseTestCase):

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(BaseMixin, cls).setup_credentials()

    @classmethod
    def setup_clients(cls):
        super(BaseMixin, cls).setup_clients()
        cls.has_primary = getattr(cls, 'os_primary', None) is not None
        cls.has_admin = getattr(cls, 'os_admin', None) is not None
