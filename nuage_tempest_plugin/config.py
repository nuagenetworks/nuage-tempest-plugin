# Copyright 2015
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg

from nuage_tempest_plugin.lib.utils import constants

NuageVsdGroup = [
    cfg.StrOpt('nuage_vsd_server',
               default="vsd.example.com",
               help="Nuage vsd server"),
    cfg.StrOpt('nuage_default_netpartition',
               default="OpenStackDefaultNetPartition",
               help="default nuage netpartition name"),
    cfg.StrOpt('nuage_auth_resource',
               default="/me",
               help="api path to authenticate for nuage vsd"),
    cfg.StrOpt('nuage_base_uri',
               default="/nuage/api/v5_0",
               help="base nuage vsd api url"),
    cfg.StrOpt('nuage_vsd_user',
               default='csproot',
               help="nuage vsd user"),
    cfg.StrOpt('nuage_vsd_password',
               default='csproot',
               help='nuage vsd user password'),
    cfg.StrOpt('nuage_vsd_org',
               default='csp',
               help='nuage vsd organization name'),
    cfg.StrOpt('nuage_cms_id', default=None,
               help=('ID of a Cloud Management System on the VSD which '
                     'identifies this OpenStack instance'))
]

nuage_vsd_group = cfg.OptGroup(name='nuage',
                               title='Nuage VSD config options')

nuage_tempest_group = cfg.OptGroup(name='nuagext',
                                   title='Nuage Tempest config options')

NuageTempestGroup = [
    cfg.ListOpt('nuage_components',
                default=['vsd'],
                help="VSD/VSC/VRS"),
    cfg.StrOpt('nuage_ext_mode',
               default='api',
               help="api/scenario"),
    cfg.StrOpt('topologyfile',
               default='',
               help="Full path of topology file"),
    cfg.StrOpt('exec_server_user',
               default='',
               help="User name of execution server"),
    cfg.StrOpt('exec_server',
               default='',
               help="Host name of execution server")
]

nuage_sut_group = cfg.OptGroup(name='nuage_sut',
                               title='Nuage SUT config options')

NuageSutGroup = [
    cfg.StrOpt('nuage_plugin_configuration',
               default='/etc/neutron/plugins/nuage/plugin.ini',
               help="Full path for the Nuage plugin configuration file."),
    cfg.StrOpt('openstack_version',
               default='kilo',
               choices=['kilo', 'liberty', 'mitaka', 'newton', 'ocata', 'pike',
                        'queens', 'master'],
               help="The mode for controlling services on controller node."),
    cfg.StrOpt('nuage_plugin_mode',
               default='monolithic',
               choices=['monolithic', 'ml2'],
               help="The mode for controlling services on controller node."),
    cfg.StrOpt('sut_deployment',
               default='distro',
               choices=['distro', 'devstack'],
               help="The type of SUT deployment."),
    cfg.StrOpt('nuage_baremetal_driver',
               default=constants.BAREMETAL_DRIVER_BRIDGE,
               choices=[constants.BAREMETAL_DRIVER_BRIDGE,
                        constants.BAREMETAL_DRIVER_HOST],
               help="The driver being used by the baremetal mechanism "
                    "driver."),
    cfg.IntOpt('nuage_baremetal_segmentation_id',
               default=4095,
               help="The segmentation ID which the baremetal mechanism "
                    "driver will use."),
    cfg.StrOpt('release',
               default='0.0',
               help="The release of the sut. "
                    "Valid examples: 3.2R1, 4.0, 4.0r2"),
    cfg.StrOpt('controller_service_management_mode',
               default='devstack',
               choices=['devstack', 'ubuntu', 'rhel'],
               help="The mode for controlling services on controller node."),
    cfg.StrOpt('controller_user',
               default='root',
               help="A sudo user on controller node."),
    cfg.StrOpt('controller_password',
               default='password',
               help='The password for controller_user.'),
    cfg.StrOpt('database_user',
               default='root',
               help="The neutron DB username."),
    cfg.StrOpt('database_password',
               default='tigris',
               help="The neutron DB password."),
    cfg.StrOpt('console_access_to_vm',
               default='False',
               help='Whether console access to vm is enabled in topology.'),
    cfg.StrOpt('api_workers',
               default='1',
               help='Number of neutron api workers deployed.')
]
