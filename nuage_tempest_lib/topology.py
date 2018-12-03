from oslo_log import log as logging

from tempest import config

from nuage_commons.data_utils import Singleton
from nuage_tempest_lib.release import Release

CONF = config.CONF


class Topology(Singleton):

    nuage_release_qualifier = CONF.nuage_sut.release
    nuage_release = Release(nuage_release_qualifier)
    openstack_version_qualifier = CONF.nuage_sut.openstack_version
    openstack_version = Release(openstack_version_qualifier)
    is_ml2 = True
    api_workers = int(CONF.nuage_sut.api_workers)

    vsd_server = CONF.nuage.nuage_vsd_server
    vsd_org = CONF.nuage.nuage_vsd_org
    base_uri = CONF.nuage.nuage_base_uri
    auth_resource = CONF.nuage.nuage_auth_resource
    server_auth = (CONF.nuage.nuage_vsd_user + ":" +
                   CONF.nuage.nuage_vsd_password)
    def_netpartition = CONF.nuage.nuage_default_netpartition
    cms_id = CONF.nuage.nuage_cms_id

    # - - - - - -

    @staticmethod
    def get_logger(name):
        return logging.getLogger(name)

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
    def from_nuage_sub_release(nuage_release, sub_release=1):
        this = Topology.nuage_release
        spec = Release(nuage_release)
        # TODO(team)
        # below comparison is hacky and should be replaced - problem is
        # Release class still assumes nuage release formats in form of x.yRz
        return (this > spec and
                Release.nuage_part(this) != (
                    Release.nuage_part(spec) + '.' + str(sub_release)))

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

    @staticmethod
    def is_devstack():
        return True  # hardcoded now ; next step is take out all checks (later)

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
        return not Topology.is_devstack()

    @staticmethod
    def assume_fip_to_underlay_as_enabled_by_default():
        return Topology.is_devstack()

    @staticmethod
    def assume_pat_to_underlay_as_disabled_by_default():
        return Topology.is_devstack()

    @staticmethod
    def assume_default_fip_rate_limits():
        return Topology.is_devstack()

    @staticmethod
    def new_route_to_underlay_model_enabled():
        return CONF.nuage_sut.nuage_pat_legacy.lower() == 'disabled'
