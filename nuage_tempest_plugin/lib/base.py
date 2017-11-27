import logging
import re
import time

LOG = logging.getLogger(__name__)


def setup_tempest_public_network(osc):

    # TODO(team) why is this here?
    osc.cmd("source ~/admin_rc;neutron net-list", timeout=30, strict=False)

    cmds = [
        'source ~/admin_rc',
        'neutron net-create tempestPublicNw --router:external',
        'neutron subnet-create tempestPublicNw 10.10.1.0/24 '
        '--allocation-pool start=10.10.1.5,end=10.10.1.253 '
        '--name tempestPublicSubnet --underlay true',
        'neutron net-list',
        'neutron subnet-list'
    ]
    osc.cmd(' ; '.join(cmds), timeout=60)

    out = osc.cmd("source ~/admin_rc;neutron net-list",
                  timeout=30, strict=False)
    m = re.search(r"(\w+\-\w+\-\w+\-\w+\-\w+)", out[0][3])
    if m:
        net_id = m.group(0)
    else:
        LOG.warn('Network id not found')
        return None

    return net_id


def get_glance_image_id(osc, imagename):

    cmd = "source ~/admin_rc;glance image-list | grep "
    cmd = cmd + imagename + " | awk '{print $2}'"
    out = osc.cmd(cmd, timeout=30, strict=False)
    if re.search(r"(\w+\-\w+\-\w+\-\w+\-\w+)", out[0][0]):
        image_id = out[0][0]
    else:
        LOG.info('Unable to find image ID for' + imagename)
        return None

    return image_id


def setup_tempest_tenant_user(osc, tenant, user, password, role):

    def ks_cmd(cmd):
        ks_base_cmd = 'source ~/admin_rc ; keystone'
        awk_cmd = 'awk "/ id / {print $4}"'
        command = '{} {} | {}'.format(ks_base_cmd, cmd, awk_cmd)
        return osc.cmd(command, timeout=30, strict=False)

    tenantid = ks_cmd('tenant-get {}'.format(tenant))
    if not tenantid[0]:
        tenantid = ks_cmd('tenant-create --name {}'.format(tenant))
    tenantid = tenantid[0][0]
    LOG.info('Tenant: {}  ID: {}'.format(tenant, tenantid))

    userid = ks_cmd('user-get {}'.format(user))
    if not userid[0]:
        cmd = 'user-create --name {} --pass {} --tenant {}'
        userid = ks_cmd(cmd.format(user, password, tenant))
    userid = userid[0][0]
    LOG.info('User: {} ID: {}'.format(user, userid))

    roleid = ks_cmd('role-get {}'.format(role))
    if not roleid[0]:
        cmd = 'role create {}'
        ks_cmd(cmd.format(role))
        cmd = 'user-role-add --name {} --pass {} --tenant {} --role {}'
        ks_cmd(cmd.format(user, password, tenant, role))
    roleid = userid[0][0]
    LOG.info('Role: {} ID: {}'.format(role, roleid))


def setup_tempest_tenant_user_openstack_cli(osc, project, user, password,
                                            role):

    def ks_cmd(cmd):
        ks_base_cmd = 'source ~/admin_rc ; openstack'
        awk_cmd = "awk '/ id / {print $4}'"
        command = '{} {} | {}'.format(ks_base_cmd, cmd, awk_cmd)
        return osc.cmd(command, timeout=30, strict=False)

    tenantid = ks_cmd('project create {} --or-show'.format(project))
    tenantid = tenantid[0][0]
    LOG.info('Project: {}  ID: {}'.format(project, tenantid))

    cmd = 'user create {} --password {} --project {} --or-show'
    userid = ks_cmd(cmd.format(user, password, project))
    userid = userid[0][0]
    LOG.info('User: {} ID: {}'.format(user, userid))

    cmd = 'role create {} --or-show'
    roleid = ks_cmd(cmd.format(role))
    roleid = roleid[0][0]
    LOG.info('Role: {} ID: {}'.format(role, roleid))

    # get role assignments
    ks_cmd = 'source ~/admin_rc ; openstack role assignment list ' \
             '--project {} --user {} | grep {}'.format(project, user, roleid)
    awk_cmd = " awk '/ id / {print $2}'"
    command = '{} | {}'.format(ks_cmd, awk_cmd)
    role_assignment_id = osc.cmd(command, timeout=30, strict=False)

    if not role_assignment_id:
        cmd = 'role add --user {} --project {} {}'
        # TODO(team) fix this - str object is not callable
        role_assignment_id = ks_cmd(cmd.format(user, project, role))
        role_assignment_id = role_assignment_id[0][0]
        LOG.info('Role Assignment created for role: {} ID: {}'.
                 format(role, role_assignment_id))
    else:
        LOG.info('Role Assignment existed for role: {} ID: {}'.
                 format(role, role_assignment_id))


def setup_tempest_tenant_user_v3(osc, tenant, user, password, role):

    def ks_cmd(cmd):
        ks_base_cmd = 'source ~/admin_rc ; openstack'
        awk_cmd = 'awk "/ id / {print $4}"'
        command = '{} {} | {}'.format(ks_base_cmd, cmd, awk_cmd)
        return osc.cmd(command, timeout=30, strict=False)

    tenantid = ks_cmd('project show {}'.format(tenant))
    if not tenantid[0]:
        tenantid = ks_cmd('project create {} --domain default'.format(tenant))
    tenantid = tenantid[0][0]
    LOG.info('Project: {}  ID: {}'.format(tenant, tenantid))

    userid = ks_cmd('user show {}'.format(user))
    if not userid[0]:
        cmd = 'user create {} --password {} --project {} --domain default'
        userid = ks_cmd(cmd.format(user, password, tenant))
    userid = userid[0][0]
    LOG.info('User: {} ID: {}'.format(user, userid))

    roleid = ks_cmd('role show {}'.format(role))
    if not roleid[0]:
        cmd = 'role create {}'
        ks_cmd(cmd.format(role))
        cmd = 'role add --user {} --project {} {}'
        ks_cmd(cmd.format(user, tenant, role))
    roleid = userid[0][0]
    LOG.info('Role: {} ID: {}'.format(role, roleid))


def setup_cmsid(osc):
    plugin_file = "/etc/neutron/plugins/nuage/plugin.ini"
    audit_cmd = ('python generate_cms_id.py --config-file ' + plugin_file)
    path = '/opt/upgrade-script/upgrade-scripts'
    cmd = 'cd {} ; {}'.format(path, audit_cmd)
    osc.cmd(cmd, timeout=30, strict=False)

    osc.cmd('service neutron-server restart', strict=False, timeout=120)
    time.sleep(5)
    osc.cmd('service neutron-server status', strict=False, timeout=20)

    cmd = "cat {} | grep cms_id".format(plugin_file)
    out = osc.cmd(cmd, timeout=30, strict=False)
    m = re.search(r"cms_id = (\w+\-\w+\-\w+\-\w+\-\w+)", out[0][0])
    if m:
        cms_id = m.group(1)
    else:
        raise Exception('Could not retrieve CMS ID')
    return cms_id


def add_csproot_to_cms(vsd_api, vspk):

    global_ent_id = vsd_api.session.user.enterprise_id
    global_ent = vspk.NUEnterprise(id=global_ent_id)
    grp_filter = 'name IS "CMS Group"'
    usr_filter = 'userName IS "csproot"'
    global_ent.add_user_to_group(global_ent, usr_filter=usr_filter,
                                 grp_filter=grp_filter)
