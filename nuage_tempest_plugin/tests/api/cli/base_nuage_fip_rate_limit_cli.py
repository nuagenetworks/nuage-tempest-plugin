# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

from oslo_log import log as logging

from tempest.common import utils
from tempest import config

from nuage_tempest_plugin.lib.remote_cli import remote_cli_base_testcase
from nuage_tempest_plugin.lib.utils import constants
import nuage_tempest_plugin.services.nuage_client as nuage_client

CONF = config.CONF


class BaseNuageFipRateLimit(
        remote_cli_base_testcase.RemoteCliBaseTestCase):

    """FipRateLimit tests using Neutron CLI client.

    """
    LOG = logging.getLogger(__name__)
    configured_default_fip_rate = None
    expected_default_fip_rate = constants.UNLIMITED
    ext_net_id = CONF.network.public_network_id

    @classmethod
    def skip_checks(cls):
        super(BaseNuageFipRateLimit, cls).skip_checks()
        if not CONF.service_available.neutron:
            msg = 'Skipping all Neutron cli tests because it is not available'
            raise cls.skipException(msg)

        if not utils.is_extension_enabled('nuage-floatingip', 'network'):
            msg = 'Extension nuage_floatingip not enabled.'
            raise cls.skipException(msg)

    @classmethod
    def setup_clients(cls):
        super(BaseNuageFipRateLimit, cls).setup_clients()
        cls.nuage_vsd_client = nuage_client.NuageRestClient()
        cls.assure_nuage_fip_rate_limit_configs()

    @classmethod
    def assure_nuage_fip_rate_limit_configs(cls):
        pass

    @staticmethod
    def fip_rate_config_value_matches(a, b):
        if a is None and b is None:
            return True
        if a is None and b == constants.UNLIMITED:
            return True
        if b is None and a == constants.UNLIMITED:
            return True
        return False

    @staticmethod
    def convert_mbps_to_kbps(value):
        if value == 'INFINITY':
            return value
        else:
            return float(value) * 1000

    def assertEqualFiprate(self, os_fip_rate, vsd_fip_rate):
        if os_fip_rate == constants.UNLIMITED or os_fip_rate == 'INFINITY':
            self.assertEqual('INFINITY', vsd_fip_rate)
        else:
            self.assertEqual(float(os_fip_rate), float(vsd_fip_rate))
