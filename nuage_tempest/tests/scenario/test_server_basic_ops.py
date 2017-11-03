
from tempest.scenario import test_server_basic_ops
from tempest import test
from tempest.test import decorators

from nuage_tempest.tests import nuage_ext


class TestServerBasicOps(test_server_basic_ops.TestServerBasicOps):

    def setUp(self):
        super(TestServerBasicOps, self).setUp()

    @decorators.attr(type='smoke')
    @test.services('compute', 'network')
    def test_server_basic_ops(self):
        # self.add_keypair() not supported upstream - changed to create_keypair

        self.security_group = self._create_security_group()

        security_groups = [{'name': self.security_group['name']}]
        self.instance = self.create_server(
            security_groups=security_groups,
            wait_until='ACTIVE')

        nuage_ext.nuage_extension.nuage_components(
            nuage_ext._generate_tag('verify_vm', self.__class__.__name__),
            self)

        self.servers_client.delete_server(self.instance['id'])
