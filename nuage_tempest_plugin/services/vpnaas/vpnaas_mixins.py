"""
Similar to mixins in bgpvpn folder
"""

import contextlib

from tempest.lib.common.utils import data_utils
from tempest.test import BaseTestCase

from nuage_tempest_plugin.services.vpnaas import vpnaas_client


class BaseMixin(BaseTestCase):
    """BaseMixin

    Base class for all Mixins.
    This class exists because calling get_client_manager() in every mixin would
    reinitialize all the clients over and over again. So don't use
    get_client_manager in the mixins, but cls.manager and cls.admin_manager
    instead.
    """
    @classmethod
    def setup_clients(cls):
        super(BaseMixin, cls).setup_clients()
        cls.manager = cls.get_client_manager()
        cls.admin_manager = cls.get_client_manager(credential_type='admin')
        cls.manager.ikepolicy_client = vpnaas_client.IKEPolicyClient(
            cls.manager.auth_provider)
        cls.admin_manager.ikepolicy_client = vpnaas_client.IKEPolicyClient(
            cls.manager.auth_provider)
        cls.manager.ipsecpolicy_client = vpnaas_client.IPSecPolicyClient(
            cls.manager.auth_provider)
        cls.admin_manager.ipsecpolicy_client = vpnaas_client.IPSecPolicyClient(
            cls.manager.auth_provider)
        cls.manager.vpnservice_client = vpnaas_client.VPNServiceClient(
            cls.manager.auth_provider)
        cls.admin_manager.vpnservice_client = vpnaas_client.VPNServiceClient(
            cls.manager.auth_provider)
        cls.manager.ipsecsiteconnection_client = (
            vpnaas_client.IPSecSiteConnectionClient(
                cls.manager.auth_provider
            )
        )
        cls.admin_manager.ipsecsiteconnection_client = (
            vpnaas_client.IPSecSiteConnectionClient(
                cls.manager.auth_provider
            )
        )


class VPNMixin(BaseMixin):

    @classmethod
    def setup_clients(cls):
        super(VPNMixin, cls).setup_clients()
        cls.ikepolicy_client = cls.manager.ikepolicy_client
        cls.ikepolicy_client_admin = cls.admin_manager.ikepolicy_client
        cls.ipsecpolicy_client = cls.manager.ipsecpolicy_client
        cls.ipsecpolicy_client_admin = cls.admin_manager.ipsecpolicy_client
        cls.vpnservice_client = cls.manager.vpnservice_client
        cls.vpnservice_client_admin = cls.admin_manager.vpnservice_client
        cls.ipsecsiteconnection_client = cls.manager.ipsecsiteconnection_client
        cls.ipsecsiteconnection_client_admin = (
            cls.admin_manager.ipsecsiteconnection_client
        )
        cls.networks_client = cls.manager.networks_client
        cls.networks_client_admin = cls.admin_manager.networks_client
        cls.subnets_client = cls.manager.subnets_client
        cls.subnets_client_admin = cls.admin_manager.subnets_client
        cls.routers_client = cls.manager.routers_client
        cls.routers_client_admin = cls.admin_manager.routers_client

    @contextlib.contextmanager
    def ikepolicy(self, do_delete=True, as_admin=True, **kwargs):
        client = (
            self.ikepolicy_client_admin if as_admin else self.ikepolicy_client
        )
        ikepolicy = {'name': data_utils.rand_name('ikepolicy')}
        ikepolicy.update(kwargs)
        ikepolicy = client.create_ikepolicy(**ikepolicy)
        try:
            yield ikepolicy
        finally:
            if do_delete:
                client.delete_ikepolicy(ikepolicy['id'])

    @contextlib.contextmanager
    def ipsecpolicy(self, do_delete=True, as_admin=True, **kwargs):
        client = self.ipsecpolicy_client_admin \
            if as_admin else self.ipsecpolicy_client
        ipsecpolicy = {'name': data_utils.rand_name('ipsecpolicy')}
        ipsecpolicy.update(kwargs)
        ipsecpolicy = client.create_ipsecpolicy(**ipsecpolicy)
        try:
            yield ipsecpolicy
        finally:
            if do_delete:
                client.delete_ipsecpolicy(ipsecpolicy['id'])

    @contextlib.contextmanager
    def vpnservice(self, router_id, subnet_id, do_delete=True,
                   as_admin=False, **kwargs):
        client = (self.vpnservice_client_admin if as_admin
                  else self.vpnservice_client)
        vpnservice = {'name': data_utils.rand_name('vpnservice')}
        vpnservice.update(kwargs)
        vpnservice = client.create_vpnservice(
            router_id, subnet_id, **vpnservice)
        try:
            yield vpnservice
        finally:
            if do_delete:
                client.delete_vpnservice(vpnservice['id'])

    @contextlib.contextmanager
    def ipsecsiteconnection(self, vpnservice_id, ikepolicy_id,
                            ipsecpolicy_id, peer_address, peer_id,
                            peer_cidrs, psk, do_delete=True,
                            as_admin=False, **kwargs):
        client = (self.ipsecsiteconnection_client_admin if as_admin
                  else self.ipsecsiteconnection_client)
        ipsecsiteconnection = {
            'name': data_utils.rand_name('ipsecsiteconnection')}
        ipsecsiteconnection.update(kwargs)
        ipsecsiteconnection = (
            client.create_ipsecsiteconnection(
                vpnservice_id, ikepolicy_id,
                ipsecpolicy_id, peer_address,
                peer_id, peer_cidrs, psk,
                **ipsecsiteconnection)
        )
        try:
            yield ipsecsiteconnection
        finally:
            if do_delete:
                client.delete_ipsecsiteconnection(ipsecsiteconnection['id'])
