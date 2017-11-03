import itertools
import re
import sys
import threading
import traceback

import libVSD

from oslo_log import log as logging

from nuage_tempest.lib.openstackapi import openstackapi_base
from nuage_tempest.lib.openstackcli import openstackcli_base

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

    openstack_version = CONF.nuage_sut.openstack_version
    is_ml2 = CONF.nuage_sut.nuage_plugin_mode.lower() == 'ml2'
    controller_user = CONF.nuage_sut.controller_user
    controller_password = CONF.nuage_sut.controller_password
    database_user = CONF.nuage_sut.database_user
    database_password = CONF.nuage_sut.database_password
    api_workers = int(CONF.nuage_sut.api_workers) \
        if CONF.nuage_sut.api_workers is not None else 0

    def __init__(self):
        self.nuage_components = CONF.nuagext.nuage_components
        self.topology_file = CONF.nuagext.topologyfile
        self.duts_list = self.parse_topology_file()
        self.make_testbed()

    @property
    def _vrs(self):
        vrs = {}
        for dutname, dut in self.duts.iteritems():
            if self._is_vrs(dut):
                vrs[dutname] = dut

    def open_session(self):
        def _open_ssh_session(dut):
            try:
                dut.ssh.open()
            except Exception:
                exc = ''.join(traceback.format_exception(*sys.exc_info()))
                dut.ssh.log.error(exc)
                failed.append(dut)

        threads = []
        failed = []
        for dut in dir(self):
            if dut.split('_')[0] in CONF.nuagext.nuage_components + ['osc']:
                if dut.split('_')[0] == 'vsd':
                    obj = getattr(self, dut)
                    obj.api.new_session()
                    obj.update_vsd_session()
                else:
                    adut = getattr(self, dut)
                    t = threading.Thread(target=_open_ssh_session,
                                         args=(adut,))
                    t.is_daemon = True
                    t.start()
                    threads.append(t)

                    [thread.join() for thread in threads]

    def parse_topology_file(self):
        def parse_line(line):
            line = line.split()
            try:
                if line[0] == 'None':
                    return (None, None, None, None, None, None)
                elif '-component' in line and '-username' in line and \
                     '-password' in line:
                    idx = line.index('-component') + 1
                    idx_u = line.index('-username') + 1
                    idx_p = line.index('-password') + 1
                    return (line[0], line[1], line[2], line[idx], line[idx_u],
                            line[idx_p])
                return line[0], line[1], line[2], None, None, None
            except Exception:
                return None, None, None, None, None, None

        duts_list = []
        try:
            topo_file = open(self.topology_file, 'r')
            content = topo_file.readlines()
        except IOError:
            if any(comp in CONF.nuagext.nuage_components
                   for comp in ('vsc', 'vrs')):
                raise Exception(
                    'Testbed topo file or exec server is not provided')
            elif 'vsd' in CONF.nuagext.nuage_components:
                vsd_dut = {'component': 'VSD', 'name': 'vsd-1', 'ip': 'vsd-1'}
                duts_list.append(vsd_dut)
            else:
                raise Exception(
                    'Testbed topo file or exec server is not provided')
        else:
            with topo_file:
                for line in content:
                    dut_type, dut_name, dut_ip, component, username, password \
                        = parse_line(line)
                    if dut_type in ['LINUX', 'ESR']:
                        duts_list.append({
                            'name': dut_name,
                            'type': dut_type,
                            'ip': dut_ip,
                            'component': component,
                            'username': username,
                            'password': password
                        })
        return duts_list

    def get_dut_from_topologyfile(self, name):
        for d in self.duts_list:
            if d['name'] == name:
                return d
        raise Exception('{} not found in {}'.format(name, self.topology_file))

    @staticmethod
    def _is_vrs(dut):
        from libduts.linux.vrs import VRS
        return isinstance(dut, VRS)

    @staticmethod
    def _is_sros(component):
        if re.match('7750', component):
            return True
        return False

    @staticmethod
    def _is_vsc(component):
        if re.match('VSC', component):
            return True
        return False

    @staticmethod
    def _is_7750(component):
        if re.match('7750', component):
            return True
        return False

    @staticmethod
    def _is_vsd(component):
        if re.match('VSD', component):
            return True
        return False

    @staticmethod
    def _is_ovs(component):
        if re.match('VRS', component):
            return True
        return False

    @staticmethod
    def _is_osc(component):
        if re.match('OSC', component):
            return True
        return False

    @staticmethod
    def _is_util(component):
        if re.match('UTILS', component):
            return True
        return False

    @staticmethod
    def _is_vsg(component):
        if re.match('VSG', component):
            return True
        return False

    @staticmethod
    def _is_nsg(component):
        if re.match('NSG', component):
            return True
        return False

    @staticmethod
    def _is_traffic(component):
        if component == 'TRAFFIC':
            return True
        return False

    @staticmethod
    def _base_uri_to_version(base_uri):
        pattern = re.compile(r'(\d+_\d+)')
        match = pattern.search(base_uri)
        version = match.group()
        version = str(version).replace('_', '.')
        return version

    def make_dut(self, name):

        dut = self.get_dut_from_topologyfile(name)
        ip = dut['ip']
        component = dut['component']

        if self._is_ovs(component):
            from libduts.linux.vrs import VRS

            return VRS(ip, id=name, password=dut['password'],
                       user=dut['username'])

        if self._is_vsd(component):
            vsd_ip = CONF.nuage.nuage_vsd_server.split(':')[0]
            vsd_port = CONF.nuage.nuage_vsd_server.split(':')[1]

            vsd_api_version = self._base_uri_to_version(
                CONF.nuage.nuage_base_uri)

            api = libVSD.client.ApiClient(vsd_ip, port=vsd_port,
                                          version=vsd_api_version)
            helper = libVSD.helpers.VSDHelpers(api)
            setattr(helper, 'api', api)
            return helper

        if self._is_7750(component):
            from libduts.sros import SROS
            return SROS(ip, name, id=name, password=dut['password'],
                        user=dut['username'])

        if self._is_vsg(component):
            from libduts.sros.vsg import VSG
            return VSG(ip, name, id=name, password=dut['password'],
                       user=dut['username'])

        if self._is_vsc(component):
            from libduts.sros.vsc import VSC
            return VSC(ip, name, id=name, password=dut['password'],
                       user=dut['username'])

        if self._is_osc(component):
            from libduts.linux import OSC
            osc = OSC(ip, id=name, password=dut['password'],
                      user=dut['username'])
            setattr(osc, 'cli', openstackcli_base.OpenstackCliClient(osc))
            setattr(osc, 'api', openstackapi_base.OpenstackAPIClient())
            return osc

        err = 'Cannot find a class corresponding to {}'.format(name)
        raise Exception(err)

    def make_testbed(self):
        vrs_counter = itertools.count()
        vrs_counter.next()
        vsc_counter = itertools.count()
        vsc_counter.next()
        vsd_counter = itertools.count()
        vsd_counter.next()
        osc_counter = itertools.count()
        osc_counter.next()
        testbed = CONF.nuagext.exec_server

        if not self.is_devstack():
            from libduts.linux import Linux
            self.testbed = Linux(testbed, id='testbed')
        self.duts = {}
        for dut in self.duts_list:
            if (dut['component'] == "VRS" and
                    'vrs' in CONF.nuagext.nuage_components):
                dutobjname = 'vrs_' + str(vrs_counter.next())
                dutobj = self.make_dut(dut['name'])
                setattr(self, dutobjname, dutobj)
                self.duts[dutobjname] = getattr(self, dutobjname)
            elif (dut['component'] == "VSC" and
                    'vsc' in CONF.nuagext.nuage_components):
                dutobjname = 'vsc_' + str(vsc_counter.next())
                dutobj = self.make_dut(dut['name'])
                setattr(self, dutobjname, dutobj)
                self.duts[dutobjname] = getattr(self, dutobjname)
            elif (dut['component'] == "VSD" and
                    'vsd' in CONF.nuagext.nuage_components):
                dutobjname = 'vsd_' + str(vsd_counter.next())
                dutobj = self.make_dut(dut['name'])
                setattr(self, dutobjname, dutobj)
                self.duts[dutobjname] = getattr(self, dutobjname)
            elif dut['component'] == "OSC":
                dutobjname = 'osc_' + str(osc_counter.next())
                dutobj = self.make_dut(dut['name'])
                setattr(self, dutobjname, dutobj)
                self.duts[dutobjname] = getattr(self, dutobjname)

    @staticmethod
    def is_devstack():
        return (hasattr(CONF.nuage_sut, 'sut_deployment') and
                CONF.nuage_sut.sut_deployment is not None and
                CONF.nuage_sut.sut_deployment.lower() == 'devstack')

    @staticmethod
    def enable_snat_default_is_enabled():
        # in a devstack SUT, enable_snat is defaulting to True
        return Topology.is_devstack()

    @staticmethod
    def telnet_console_access_to_vm_enabled():
        return (hasattr(CONF.nuage_sut, 'console_access_to_vm') and
                CONF.nuage_sut.console_access_to_vm and
                CONF.nuage_sut.console_access_to_vm.lower() == 'true')
