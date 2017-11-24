from oslo_log import log as logging

from tempest import config

LOG = logging.getLogger(__name__)

CONF = config.CONF


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(
                *args, **kwargs)
        return cls._instances[cls]


class Topology(object):
    __metaclass__ = Singleton  # noqa H236

    nuage_release = CONF.nuage_sut.release
    openstack_version = CONF.nuage_sut.openstack_version
    is_ml2 = CONF.nuage_sut.nuage_plugin_mode.lower() == 'ml2'
    controller_user = CONF.nuage_sut.controller_user
    controller_password = CONF.nuage_sut.controller_password
    database_user = CONF.nuage_sut.database_user
    database_password = CONF.nuage_sut.database_password
    api_workers = int(CONF.nuage_sut.api_workers) \
        if CONF.nuage_sut.api_workers is not None else 0
    def_netpartition = CONF.nuage.nuage_default_netpartition
    public_network_id = CONF.network.public_network_id

    @staticmethod
    def is_devstack():
        return (hasattr(CONF.nuage_sut, 'sut_deployment') and
                CONF.nuage_sut.sut_deployment is not None and
                CONF.nuage_sut.sut_deployment.lower() == 'devstack')

    @staticmethod
    def run_connectivity_tests():
        # temporary exclusion of connectivity tests if api workers > 1
        return Topology.api_workers == 1

    @staticmethod
    def enable_snat_default_is_enabled():
        # on devstack enable_snat defaults to True
        return Topology.is_devstack()

    @staticmethod
    def telnet_console_access_to_vm_enabled():
        return (hasattr(CONF.nuage_sut, 'console_access_to_vm') and
                CONF.nuage_sut.console_access_to_vm and
                CONF.nuage_sut.console_access_to_vm.lower() == 'true')

    @staticmethod
    def access_to_l2_supported():
        return Topology.telnet_console_access_to_vm_enabled()

    @staticmethod
    def neutron_restart_supported():
        return not Topology.is_devstack()

    @staticmethod
    def use_alpine_for_advanced_image():
        return not Topology.is_devstack()  # not available on stock devstack
