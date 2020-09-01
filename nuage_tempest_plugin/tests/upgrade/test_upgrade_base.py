# Copyright 2020 NOKIA
# All Rights Reserved.

import getpass
import inspect

from nuage_tempest_plugin.lib.topology import Topology

from vspk import v5_0 as vspk5
try:
    from vspk import v6 as vspk6
except ImportError as e:
    if Topology.before_nuage('6.0'):
        pass  # be tolerant
    else:
        raise

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# CAUTION : THIS SUITE IS HIGHLY INTRUSIVE
#           - it relies heavily on devstack env
#           - it installs new packages in the tox env (like neutron)
#           - it changes the neutron branch out of which neutron runs
#           - it restarts neutron
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class NuageUpgradeSubTestMixin(object):

    def __init__(self, parent):
        self.parent = parent  # the parent test than encloses this subtest
        self.cls_name = self.__class__.__name__  # used for logging purposes
        self._log_date = None  # cache

        # convenience members
        self._vsd = self.parent.vsd
        self._vsd_client = self.parent.vsd_client
        self._network_client = self.parent.plugin_network_client
        self._network_client_admin = self.parent.plugin_network_client_admin
        self._cms_id = self.parent._cms_id
        self._ip_version = self.parent._ip_version
        self._ext_net_id = self.parent.ext_net_id
        self._is_large_setup = self.parent._is_large_setup

    def _get_external_id(self, neutron_id):
        return neutron_id + '@' + self._cms_id

    def _get_log_data(self):
        if self._log_date is None:
            self.log_data = self.parent._fetch_upgrade_log_data()
        return self.log_data

    @property
    def _vspk(self):
        return self.parent._vspk   # mind, this toggles


class NuageUpgradeMixin(object):

    _cms_id = Topology.cms_id
    _openstack_version = str(Topology.openstack_version_qualifier)
    _vspk = vspk5

    _neutron_conf = '/etc/neutron/neutron.conf'
    _plugin_conf = '/etc/neutron/plugins/nuage/plugin.ini'
    _user = getpass.getuser()
    _as_tempest = _user == 'tempest'
    _home = '/home/' + _user
    _log_dir = _home + '/nuageupgrade'

    _is_large_setup = False

    # ---- these must be set when using this mixin : -----------------------
    _from_release = 'changeme'
    _to_release = 'changeme'
    # ----------------------------------------------------------------- ----

    @classmethod
    def _get_from_branch(cls):
        # !! CHANGE ME ONCE STABLE BRANCHES REFER TO 21.x !!
        rel = 'stable' if cls._from_release == '20.10' else cls._from_release
        return rel + '/' + cls._openstack_version

    @classmethod
    def _get_to_branch(cls):
        # !! CHANGE ME ONCE STABLE BRANCHES REFER TO 21.x !!
        rel = 'stable' if cls._to_release == '20.10' else cls._to_release
        return rel + '/' + cls._openstack_version

    @staticmethod
    def _branch_to_api_version(branch):
        if branch.startswith('5'):
            return 'v5_0'
        else:
            return 'v6'

    @classmethod
    def _get_from_api_version(cls):
        return cls._branch_to_api_version(cls._get_from_branch())

    @classmethod
    def _get_to_api_version(cls):
        return cls._branch_to_api_version(cls._get_to_branch())

    @classmethod
    def _get_upgrade_script_name(cls):
        # mind, the name of the script WITHOUT .py
        return 'nuage_upgrade_to_' + cls._to_release.replace('.', '_')

    @classmethod
    def _get_upgrade_script_path(cls):
        return ('/opt/stack/nuage-openstack-upgrade-scripts/' +
                cls._get_upgrade_script_name() + '.py')

    @classmethod
    def _upgrade_skip_check(cls):
        if not Topology.at_nuage(cls._to_release):

            # -- Mind --
            # E.g. take upgrade from 5.4 to 6.0
            # -> The SUT is deployed with 6.0 Nuage (VSD/VSC/VRS) but with
            #    5.4 OpenStack Nuage plugin branch
            # -> The (no-)skip verification is testing for the Nuage version
            #    to be 6.0
            # -> I.e. the OpenStack plugin branch version is not at play in
            #    the check (!)

            msg = ('Upgrade tests to {} are applicable only when the deployed '
                   'Nuage version (i.e. version of VSD/VSC/VRS) is set '
                   'accordingly').format(cls.cls_name, cls._from_release)
            raise cls.skipException(msg)

    @classmethod
    def _set_up(cls):
        cls.assert_path_exists(cls._get_upgrade_script_path())
        cls.assert_path_exists(cls._neutron_conf)
        cls.assert_path_exists(cls._plugin_conf)
        cls.assert_path_exists(cls._log_dir, create_if_not=True)

        cls._install_dependencies()

    @classmethod
    def _install_dependencies(cls):
        LOG.info('[{}] _install_dependencies:start'.format(cls.cls_name))
        cls.execute_from_shell('{}/bash/install_dependencies.sh'.format(
            cls.get_local_path(__file__)), return_output=False)
        LOG.info('[{}] _install_dependencies:end'.format(cls.cls_name))

    @classmethod
    def _set_vspk(cls, vspk_lib):
        cls.vsd.default_enterprise = None
        cls.vsd.enterprise_name_to_enterprise = {}
        cls.vsd._session = None
        cls.vsd.vspk = vspk_lib

        cls._vspk = vspk_lib

    def _get_test_instances(self):
        # get all the subclasses that end with 'Test'
        nested_test_classes = self._get_nested_classes(ends_with='Test')

        # instantiate them
        nested_test_instances = []
        for c in nested_test_classes:
            nested_test_instances.append(c(self))

        return nested_test_instances

    def _test_upgrade(self, alembic_expected):
        test_instances = self._get_test_instances()

        # start of upgrade scenario
        self._switch_plugin_branch(
            self._get_from_branch(),
            from_api_version=self._get_to_api_version(),  # mind the inversion
            to_api_version=self._get_from_api_version())

        setup_complete = False
        try:
            # run negative upgrade tests first
            self._test_pre_upgrade_neg()

            # set up all nested test instances
            for test_instance in test_instances:
                LOG.info('')
                LOG.info('=========== {}:setup:start ==========='.format(
                    test_instance.__class__.__name__))
                test_instance.setup()
                LOG.info('=========== {}:setup:end ==========='.format(
                    test_instance.__class__.__name__))
                LOG.info('')

            setup_complete = True

        finally:
            if not setup_complete:
                LOG.warn('FATAL ERROR occurred during test setup, '
                         'winding down')

            # always set back, also on failure
            self._switch_plugin_branch(
                self._get_to_branch(),
                from_api_version=self._get_from_api_version(),
                to_api_version=self._get_to_api_version())

        # run alembic
        self._run_neutron_alembic(running_upgrade_expected=alembic_expected)

        # run the script under test
        # self._execute_the_upgrade_script(dryrun=True)  # TODO(Kris)
        self._execute_the_upgrade_script()

        # verify all nested test instances
        for test_instance in test_instances:
            LOG.info('')
            LOG.info('=========== {}:verify:start ==========='.format(
                test_instance.__class__.__name__))
            test_instance.verify()
            LOG.info('=========== {}:verify:end ==========='.format(
                test_instance.__class__.__name__))
            LOG.info('')

    def _test_pre_upgrade_neg(self):
        pass  # implement me, if applicable

    @classmethod
    def _get_nested_classes(cls, starts_with=None, ends_with=None):
        return [cls_attribute for cls_attribute in cls.__dict__.values()
                if inspect.isclass(cls_attribute) and
                (not starts_with or cls_attribute.__name__.startswith(
                    starts_with)) and
                (not ends_with or cls_attribute.__name__.endswith(ends_with))]

    def _switch_plugin_branch(self, branch, from_api_version, to_api_version):
        LOG.info('[{}] _switch_plugin_branch:start ({})'.format(
            self.cls_name, branch))
        self.execute_from_shell(
            '{}/bash/set_plugin_version.sh {} {} {}'.format(
                self.get_local_path(__file__),
                branch, from_api_version, to_api_version), return_output=False)
        LOG.info('[{}] _switch_plugin_branch:end'.format(
            self.cls_name))

        is_v5 = branch.startswith('5')
        Topology.is_v5 = is_v5
        self._set_vspk(vspk5 if is_v5 else vspk6)

    def _run_neutron_alembic(self, running_upgrade_expected):
        LOG.info('[{}] _run_neutron_alembic:start'.format(self.cls_name))
        out = self.execute_from_shell('{}/bash/run_alembic.sh'.format(
            self.get_local_path(__file__)))
        if running_upgrade_expected:
            self.assertIn(
                'INFO  [alembic.runtime.migration] Running upgrade', out)
        LOG.info('[{}] _run_neutron_alembic:end'.format(self.cls_name))

    def _execute_the_upgrade_script(self, expected_exit_code=0, dryrun=False):
        LOG.info('[{}] _execute_the_upgrade_script:start{}'.format(
            self.cls_name, ' (dry-run)' if dryrun else ''))

        cmd = 'python {} --neutron-conf {} --nuage-conf {}'.format(
            self._get_upgrade_script_path(),
            self._neutron_conf, self._plugin_conf)
        if dryrun:
            cmd += ' --dry-run'
        errcode = self.execute_from_shell(cmd, success_expected=False,
                                          return_output=False)
        self.assertEqual(expected_exit_code, errcode)
        log_data = self._fetch_upgrade_log_data()
        self.assertNotIn('ERROR ', log_data)
        LOG.info('[{}] _execute_the_upgrade_script:end'.format(
            self.cls_name))

    def _fetch_upgrade_log_data(self, log_file_matcher=None):
        LOG.info('[{}] _fetch_upgrade_log_data:start'.format(self.cls_name))
        log_file_matcher = (log_file_matcher or
                            'upgrade_{}.*.log'.format(
                                self._get_upgrade_script_name()))
        file_name = self.execute_from_shell(
            "ls -lt {}/{}".format(self._log_dir, log_file_matcher) +
            " | (head -1; dd of=/dev/null 2>/dev/null)"  # fix broken pipe
            " | awk '{ print $9 }'").strip()
        LOG.info('[{}] _fetch_upgrade_log_data:reading {}'.format(
            self.cls_name, file_name))
        with open(file_name, 'r') as log_file:
            data = log_file.read()
        LOG.info('[{}] _fetch_upgrade_log_data:end'.format(self.cls_name))
        return data
