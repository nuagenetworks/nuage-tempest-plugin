# Copyright 2017 NOKIA
# All Rights Reserved.

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions


from nuage_tempest_plugin.lib.cli.client_testcase \
    import CLIClientTestCase
from nuage_tempest_plugin.lib.cli.client_testcase import Role
from nuage_tempest_plugin.lib.topology import Topology

CONF = Topology.get_conf()


class TestNuageNetpartitionProjectMappingCLI(CLIClientTestCase):

    """Nuage Underlay tests using Neutron CLI client.

    """

    @classmethod
    def resource_setup(cls):
        super(TestNuageNetpartitionProjectMappingCLI, cls).resource_setup()
        cls.ext_net_id = CONF.network.public_network_id
        cls.me = Role.admin

    def _verify_mapping(self, mapping, netpartition, project_id):
        self.assertEqual(project_id, mapping['project'])
        self.assertEqual(netpartition['id'],
                         mapping['associated_netpartition_id'])
        self.assertEqual(netpartition['name'],
                         mapping['associated_netpartition_name'])

    @decorators.attr(type='smoke')
    def test_cli_create_show_list_delete_mapping(self):
        name = data_utils.rand_name('test-proj-np-mapping')
        netpartition = self.create_nuage_netpartition_cli(name)
        self.addCleanup(self.delete_nuage_netpartition_cli, netpartition['id'])
        project_id = self.creds_client.projects_client.tenant_id
        # Create
        mapping = self.create_nuage_project_netpartition_mapping_cli(
            netpartition['id'], project_id)
        self._verify_mapping(mapping, netpartition, project_id)
        # Show
        mapping = self.show_nuage_project_netpartition_mapping_cli(project_id)
        self._verify_mapping(mapping, netpartition, project_id)
        # List
        mappings = self.list_nuage_project_netpartition_mapping_cli()
        found = False
        for mapping in mappings:
            if mapping['project'] == project_id:
                self._verify_mapping(mapping, netpartition, project_id)
                found = True
                break
        self.assertTrue(found, ('Could not find assigned project {} in '
                                'list of nuage project netpartition '
                                'mapping').format(project_id))
        # Delete
        self.delete_nuage_project_netpartition_mapping_cli(project_id)

        # Show to make sure it is deleted
        self.assertRaises(
            exceptions.CommandFailed,
            self.show_nuage_project_netpartition_mapping_cli, project_id)
        # List again
        mappings = self.list_nuage_project_netpartition_mapping_cli()
        found = False
        for mapping in mappings:
            if mapping['project'] == project_id:
                found = True
                break
        self.assertFalse(found, ('Could find deleted mapping {} in '
                                 'list of nuage project netpartition '
                                 'mapping').format(project_id))
