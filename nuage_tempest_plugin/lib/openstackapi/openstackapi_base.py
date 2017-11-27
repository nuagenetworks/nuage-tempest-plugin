from nuage_tempest_plugin.services.vpnaas import vpnaas_mixins
from tempest.api.compute import base as basecompute
from tempest.api.network import base
from tempest.api.network import base_security_groups
from tempest import config

CONF = config.CONF


class OpenstackAPIClient(base_security_groups.BaseSecGroupTest,
                         base.BaseAdminNetworkTest,
                         base.BaseNetworkTest,
                         vpnaas_mixins.VPNMixin,
                         basecompute.BaseV2ComputeTest):
    """Base API Client:

     Openstack API Client which will be inherited
     from base classes for networking resources
     (neutron). Also any new clients that need to
     be used should be added here
    """

    def __init__(cls):
        cls.resource_setup()

    @classmethod
    def resource_setup(cls):
        super(OpenstackAPIClient, cls).setup_credentials()
        super(OpenstackAPIClient, cls).setup_clients()
        super(OpenstackAPIClient, cls).resource_setup()

    def runTest(cls):
        pass

    def __del__(cls):
        super(OpenstackAPIClient, cls).resource_cleanup()
        super(OpenstackAPIClient, cls).clear_credentials()

    def delete_network(self, network_id):
        self._try_delete_resource(self.networks_client.delete_network,
                                  network_id)

    def delete_router(self, router_id, routers_client=None):
        client = routers_client or self.routers_client
        client.delete_router(router_id)
