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
import json

from tempest.lib.common.utils import data_utils

from nuage_tempest_plugin.lib.test.nuage_test import NuageBaseTest
from nuage_tempest_plugin.lib.topology import Topology


CONF = Topology.get_conf()
LOG = Topology.get_logger(__name__)

# Allow to spin up instance across the numa node
FLAVOR_PROPERTIES = {'hw:pci_numa_affinity_policy': 'preferred'}


class NUMATest(NuageBaseTest):
    """NUMA Tests

    @pre on the computes, configure vcpu_pin_set in nova.conf,
     assign the same amount of VCPUS from every NUMA node.
     E.g. if lscpu shows NUMA node 0: 0-9, 20-29, NUMA node 1: 10-19, 30-39
     then set in
    /var/lib/config-data/puppet-generated/nova_libvirt/etc/nova/nova.conf
    vcpu_pin_set=0-9,10-19 so there are an equal amount (10 in this case)
    of vcpus from each node available to nova.
    @pre don't run in parallel with other tests that spawn VM's
    """

    @classmethod
    def setup_clients(cls):
        super(NuageBaseTest, cls).setup_clients()
        cls.hv_client = cls.admin_manager.hypervisor_client
        cls.flavor_client = cls.admin_manager.flavors_client

    def get_hypervisors(self):
        hypervisors = self.hv_client.list_hypervisors()['hypervisors']
        for hv in hypervisors:
            show = self.hv_client.show_hypervisor(hv['id'])['hypervisor']

            # TODO() UPSTREAM BUG
            # for some idiotic reason, upstream passes json formatted
            # attribute that we need as a string.. fix it here..
            show['cpu_info'] = json.loads(show['cpu_info'])

            yield show

    @staticmethod
    def get_numa_node_count(hypervisor):
        # look at this gerrit post for why cells equal NUMA nodes
        # https://review.opendev.org/#/c/223869/
        return hypervisor['cpu_info']['topology']['cells']

    def test_use_all_vcpus(self):
        """Make sure that all vcpus can be used on a NUMA hypervisor

        check that when hw:pci_numa_affinity_policy == 'preferred',
        the remote NUMA can also be used
        """

        # select a hypervisor with more than one numa node
        numa_hv = next((hv for hv in self.get_hypervisors()
                        if self.get_numa_node_count(hv) > 1), None)

        # assert that the selected hypervisor is good
        if not numa_hv:
            self.skipTest('Skipping test as it only applies to NUMA setups')

        self.assertEqual(observed=numa_hv['vcpus_used'],
                         expected=0,
                         message='hypervisor should be empty')

        # prepare to fill up each NUMA node with one VM,
        # we assume that all NUMA nodes have equal amount of vCPUs here
        vm_count = self.get_numa_node_count(numa_hv)
        vcpus_per_vm = numa_hv['vcpus'] // self.get_numa_node_count(numa_hv)

        LOG.info('Hypervisor: {hv} has {vcpus} vCPUs divided over {cells} '
                 'NUMA nodes so I will boot {vm_count} VMs that use '
                 '{vcpus_per_vm} vcpus each in order to use all NUMA nodes.'
                 .format(hv=numa_hv['service']['host'], vcpus=numa_hv['vcpus'],
                         cells=self.get_numa_node_count(numa_hv),
                         vm_count=vm_count, vcpus_per_vm=vcpus_per_vm))

        # create a flavor that is like the default one but occupies
        # one NUMA node entirely
        default_flavor = self.flavor_client.show_flavor(
            flavor_id=CONF.compute.flavor_ref)['flavor']

        new_flavor = self.flavor_client.create_flavor(
            name=data_utils.rand_name('flavor'),
            ram=default_flavor['ram'],
            vcpus=vcpus_per_vm,
            disk=default_flavor['disk'])['flavor']
        self.addCleanup(self.flavor_client.delete_flavor, new_flavor['id'])

        self.flavor_client.set_flavor_extra_spec(
            new_flavor['id'], **FLAVOR_PROPERTIES)

        # launch VM's on the NUMA nodes and make sure they become active
        network = self.create_network()
        self.create_subnet(network)

        for i in range(vm_count):
            LOG.info('Starting VM {current}/{total}'.format(current=i + 1,
                                                            total=vm_count))
            self.create_tenant_server(
                flavor=new_flavor['id'],
                ports=[self.create_port(network, manager=self.admin_manager)],
                availability_zone=(
                    'nova:{host}'.format(host=numa_hv['hypervisor_hostname'])),
                wait_until='ACTIVE',
                manager=self.admin_manager)
