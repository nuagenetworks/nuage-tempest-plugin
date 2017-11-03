import logging

from nuage_tempest.tests import conf

LOG = logging.getLogger(__name__)


def get_external_id(id):
    return (id + '@' + conf.nuage.nuage_cms_id) \
        if conf.nuage.nuage_cms_id else id


def get_filter_str(key, value):
    return key + '  == "{}"'.format(value)


def poll_for_vm_boot(vrs, vm_ip, max_tries):
    vrs_data = vrs.appctl.port_show('vm')
    for vm in vrs_data:
        for each_try in (0, max_tries):
            if vm['ip'] != '0':
                break
        if vm['ip'] == vm_ip:
                return vm
    return None
