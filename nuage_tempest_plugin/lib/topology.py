from oslo_log import log as logging
import sys

from tempest import config

from nuage_tempest_plugin.lib.release import Release
from nuage_tempest_plugin.lib.utils.console_logging import ConsoleLogging

CONF = config.CONF


class Topology(object):

    nuage_release_qualifier = CONF.nuage_sut.release
    nuage_release = Release(nuage_release_qualifier)
    openstack_version_qualifier = CONF.nuage_sut.openstack_version
    openstack_version = Release(openstack_version_qualifier)
    python_version = sys.version_info

    is_ml2 = True
    api_workers = int(CONF.nuage_sut.api_workers)
    console_logging = CONF.nuage_sut.console_logging
    nuage_baremetal_driver = CONF.nuage_sut.nuage_baremetal_driver

    vsd_server = CONF.nuage.nuage_vsd_server
    vsd_org = CONF.nuage.nuage_vsd_org
    base_uri = CONF.nuage.nuage_base_uri
    auth_resource = CONF.nuage.nuage_auth_resource
    server_auth = (CONF.nuage.nuage_vsd_user + ":" +
                   CONF.nuage.nuage_vsd_password)
    def_netpartition = CONF.nuage.nuage_default_netpartition
    cms_id = CONF.nuage.nuage_cms_id

    # - - - - - -

    def __init__(self):
        assert False  # you don't need to instantiate a topology

    # - - - - - -

    @staticmethod
    def get_logger(name, console_logging=None):
        if console_logging is None:
            console_logging = Topology.console_logging
        return (ConsoleLogging(name) if console_logging
                else logging.getLogger(name))

    @staticmethod
    def get_conf():
        return CONF

    # - - - - - -

    @staticmethod
    def at_nuage(nuage_release):
        return Topology.nuage_release == Release(nuage_release)

    @staticmethod
    def at_openstack(openstack_version):
        return Topology.openstack_version == Release(openstack_version)

    @staticmethod
    def beyond_nuage(nuage_release):
        return Topology.nuage_release > Release(nuage_release)

    @staticmethod
    def beyond_openstack(openstack_version):
        return Topology.openstack_version > Release(openstack_version)

    @staticmethod
    def from_nuage(nuage_release):
        return Topology.nuage_release >= Release(nuage_release)

    @staticmethod
    def from_openstack(openstack_version):
        return Topology.openstack_version >= Release(openstack_version)

    @staticmethod
    def before_nuage(nuage_release):
        return Topology.nuage_release < Release(nuage_release)

    @staticmethod
    def before_openstack(openstack_version):
        return Topology.openstack_version < Release(openstack_version)

    @staticmethod
    def up_to_nuage(nuage_release):
        return Topology.nuage_release <= Release(nuage_release)

    @staticmethod
    def up_to_openstack(openstack_version):
        return Topology.openstack_version <= Release(openstack_version)

    # - - - - - -

    nbr_retries_for_test_robustness = 5  # same as plugin

    @staticmethod
    def single_worker_run():
        return Topology.api_workers == 1

    @staticmethod
    def telnet_console_access_to_vm_enabled():
        return bool(CONF.nuage_sut.console_access_to_vm)

    @staticmethod
    def access_to_l2_supported():
        return Topology.telnet_console_access_to_vm_enabled()

    @staticmethod
    def neutron_restart_supported():
        return False  # assumed as non-applicable capability, which is correct
        #               for the standard jobs that run in CI

    @staticmethod
    def nuage_fip_rate_limit_configs():
        return None, None  # egress & ingress rate limit configured in neutron
        #                    Defaulting to None, None, according CI settings

    @staticmethod
    def is_existing_flat_vlan_allowed():
        """Whether nuage sriov option allow_existing_flat_vlan is set to True

        See neutron setting [nuage_sriov] allow_existing_flat_vlan
        """
        return bool(CONF.nuage_sut.nuage_sriov_allow_existing_flat_vlan)

    @staticmethod
    def has_default_switchdev_port_profile():
        """This condition is True for OVRS setups"""
        return (CONF.network.port_vnic_type == 'direct' and
                'switchdev' in CONF.network.port_profile.get('capabilities',
                                                             []))
