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
    tempest_concurrency = int(CONF.nuage_sut.tempest_concurrency)
    console_logging = CONF.nuage_sut.console_logging

    vsd_server = CONF.nuage.nuage_vsd_server
    vsd_org = CONF.nuage.nuage_vsd_org
    base_uri = CONF.nuage.nuage_base_uri
    auth_resource = CONF.nuage.nuage_auth_resource
    server_auth = (CONF.nuage.nuage_vsd_user + ":" +
                   CONF.nuage.nuage_vsd_password)
    def_netpartition = CONF.nuage.nuage_default_netpartition
    cms_id = CONF.nuage.nuage_cms_id

    is_v5 = nuage_release < Release('6.0.0')

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

    @classmethod
    def at_nuage(cls, nuage_release):
        return cls.nuage_release == Release(nuage_release)

    @classmethod
    def at_openstack(cls, openstack_version):
        return cls.openstack_version == Release(openstack_version)

    @classmethod
    def beyond_nuage(cls, nuage_release):
        return cls.nuage_release > Release(nuage_release)

    @classmethod
    def beyond_openstack(cls, openstack_version):
        return cls.openstack_version > Release(openstack_version)

    @classmethod
    def from_nuage(cls, nuage_release, within_stream=None):
        # e.g use as :
        # from_nuage('6.0.12', within_stream='6.0')
        match = cls.nuage_release >= Release(nuage_release)
        if within_stream:
            match = match and cls.up_to_nuage(within_stream)
        return match

    @classmethod
    def from_openstack(cls, openstack_version):
        return cls.openstack_version >= Release(openstack_version)

    @classmethod
    def before_nuage(cls, nuage_release):
        return cls.nuage_release < Release(nuage_release)

    @classmethod
    def before_openstack(cls, openstack_version):
        return cls.openstack_version < Release(openstack_version)

    @classmethod
    def up_to_nuage(cls, nuage_release):
        return cls.nuage_release <= Release(nuage_release)

    @classmethod
    def up_to_openstack(cls, openstack_version):
        return cls.openstack_version <= Release(openstack_version)

    # - - - - - -

    nbr_retries_for_test_robustness = 5  # same as plugin

    @classmethod
    def neutron_restart_supported(cls):
        return False  # assumed as non-applicable capability, which is correct
        #               for the standard jobs that run in CI

    @classmethod
    def nuage_fip_rate_limit_configs(cls):
        return None, None  # egress & ingress rate limit configured in neutron
        #                    Defaulting to None, None, according CI settings

    @classmethod
    def is_existing_flat_vlan_allowed(cls):
        """Whether nuage sriov option allow_existing_flat_vlan is set to True

        See neutron setting [nuage_sriov] allow_existing_flat_vlan
        """
        return bool(CONF.nuage_sut.nuage_sriov_allow_existing_flat_vlan)

    @classmethod
    def has_default_switchdev_port_profile(cls):
        """This condition is True for OVRS setups"""
        return (CONF.network.port_vnic_type == 'direct' and
                'switchdev' in CONF.network.port_profile.get('capabilities',
                                                             []))

    @classmethod
    def has_single_stack_v6_support(cls):
        return not cls.is_v5

    @classmethod
    def has_full_dhcp_control_in_vsd(cls):
        return not cls.is_v5

    @classmethod
    def has_dhcp_v6_support(cls):
        return not cls.is_v5

    @classmethod
    def has_fwaas_v6_support(cls):
        return not cls.is_v5

    @classmethod
    def has_full_dhcp_options_support(cls):
        return not cls.is_v5

    @classmethod
    def has_domain_template_description_configured_support(cls):
        return not cls.is_v5

    @classmethod
    def has_utf8_netpartition_names_support(cls):
        return not cls.is_v5

    @classmethod
    def has_unified_pg_for_all_support(cls):
        return not cls.is_v5

    @classmethod
    def has_aggregate_flows_support(cls):
        return not cls.is_v5

    @classmethod
    def has_secured_netpartitions_support(cls):
        return cls.from_openstack('queens')

    @classmethod
    def has_vlan_transparency_support(cls):
        return ('vlan-transparent' in
                CONF.network_feature_enabled.api_extensions and
                CONF.nuage_sut.image_is_advanced)
