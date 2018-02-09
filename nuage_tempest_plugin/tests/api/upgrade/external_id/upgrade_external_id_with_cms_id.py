# Copyright 2015 OpenStack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import urlparse

from tempest.lib.common import ssh
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)

SET_EXTERNAL_ID_UPGRADE_SCRIPT = "set_externalid_with_cmsid.py"
SCRIPT_PATH = "/opt/upgrade-script/upgrade-scripts/"


def execute(cmd):
    """Executes specified command for the given action."""
    LOG.info("Executing: '%s", cmd)

    ssh_timeout = 10
    ssh_channel_timeout = 10

    uri = CONF.identity.uri

    uri_object = urlparse.urlparse(uri)
    netloc_parts = uri_object.netloc.rsplit(':')
    ip_address = netloc_parts[0]

    username = Topology.controller_user
    password = Topology.controller_password

    ssh_client = ssh.Client(ip_address, username, password,
                            ssh_timeout,
                            channel_timeout=ssh_channel_timeout)

    response = ssh_client.exec_command(cmd)
    LOG.debug("Response: \n'%s'", response)

    return response


def do_run_upgrade_script():
    script_cmd = SCRIPT_PATH + SET_EXTERNAL_ID_UPGRADE_SCRIPT
    script_args = "--config-file /etc/neutron/neutron.conf " \
                  "/etc/neutron/plugin.ini"

    try:
        response = execute("python " + script_cmd + " " + script_args)
        return response
    except exceptions.SSHExecCommandFailed as e:
        LOG.error("Failed. Exception %s", e)
        raise e
