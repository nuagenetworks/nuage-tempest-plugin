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

nuage_vsd_group = cfg.OptGroup(name='nuage',
                               title='Nuage VSD config options')

NuageVsdGroup = [
    cfg.StrOpt('nuage_vsd_server',
               default="localhost:8443",
               help="Nuage vsd server"),
    cfg.StrOpt('nuage_default_netpartition',
               default="OpenStackDefaultNetPartition",
               help="default nuage netpartition name"),
    cfg.StrOpt('nuage_auth_resource',
               default="/me",
               help="api path to authenticate for nuage vsd"),
    cfg.StrOpt('nuage_base_uri',
               default="/nuage/api/v6",
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

nuage_sut_group = cfg.OptGroup(name='nuage_sut',
                               title='Nuage SUT config options')

NuageSutGroup = [
    cfg.StrOpt('openstack_version',
               default='master',
               help="The OpenStack version run. Can be 'queens', 'rocky', "
                    "etc, or 'master'"),
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
               default='20.10',
               help="The Nuage release of the sut"),
    cfg.BoolOpt('console_access_to_vm',
                default=False,
                help='Whether console access to vm is enabled in topology.'),
    cfg.IntOpt('tempest_concurrency',
               default=1,
               help='The tempest concurrency the current run is using.'),
    cfg.BoolOpt('image_is_advanced',
                default=False,
                help='Whether image supports advanced features like 8021q'),
    cfg.BoolOpt('nuage_sriov_allow_existing_flat_vlan',
                default=False,
                help='Set to true to enable driver to complete port '
                     'binding on a flat network, when corresponding'
                     'GW port has vlan 0 provisioned by external entity'),
    cfg.BoolOpt('nuage_fip_underlay',
                default=False,
                help='System under test underlay setting for FIP subnets'),
    cfg.StrOpt('ipam_driver',
               default='nuage_internal',
               help="Currently active ipam driver. "
                    "Valid examples: nuage_internal, nuage_vsd_managed"),
    cfg.BoolOpt('nuage_hybrid_mpls_enabled',
                default=False,
                help="Indicating whether nuage_hybrid_mpls is enabled."),
    cfg.BoolOpt('use_network_scripts',
                default=False,
                help="Whether to use /etc/sysconfig/network-scripts "
                     "for network interface configuration in VM's. "
                     "This is needed e.g. when using DHCPv6 with RHEL VM's"
                     "Not supported for cirros."),
    cfg.StrOpt('compute_login_username',
               default='heat-admin',
               help='Compute login username'),
    cfg.BoolOpt('identify_hypervisors_by_flavor',
                default=True,
                help='Whether E2E tests should pick compute by aggregate '
                     'flavor'),
    cfg.DictOpt('hypervisors_connectivity_override',
                default={},
                help="A dict of hypervisor names to their ip's via which they "
                     "can be accessed from where tempest tests are run, "
                     "as override to the OS hypervisor-list command. "
                     "(Context: the fastpath verification E2E tests need "
                     "hypervisor access.) "
                     "E.g.: hypervisors_connectivity_overwrite = "
                     "overcloud-avrscompute-0.localdomain:172.31.0.16, "
                     "overcloud-avrscompute-1.localdomain:172.31.0.28"),
    cfg.StrOpt('gateway_type',
               default='wbx',
               choices=['wbx', 'cisco'],
               help="The type of VTEP gateway"),
    cfg.StrOpt('undercloud_name',
               default='boreas',
               help='Name of the undercloud where the hypervisors of the'
                    'openstack SUT are running. This is used by openstacksdk'
                    'to connect to the undercloud controller and '
                    'manage the hypervisor lifecycle.'),

    # TEST EXECUTION RELATED SETTINGS
    cfg.IntOpt('max_cloudinit_polling_time',
               default=200,
               help='Time (in secs) for end-of-cloudinit to be polled for'),
    cfg.IntOpt('time_to_debug_on_failure',
               default=0,
               help='Time to debug (in secs) on failure, before running the '
                    'test cleanup'),
    cfg.BoolOpt('console_logging',
                default=False,
                help='Enable for console logging')
]

nuage_feature_group = cfg.OptGroup(name='nuage-feature-enabled',
                                   title='Enabled nuage service features on '
                                         'the system under test')

NuageFeaturesGroup = [
    cfg.BoolOpt('proprietary_fip_rate_limiting',
                default=True,
                help='Does the test environment support Nuage proprietary'
                     ' floating ip rate limiting for all computes.'),
    cfg.BoolOpt('nova_qos',
                default=True,
                help='Does the test environment support nova/libvirt qos for '
                     'all computes'),
]
