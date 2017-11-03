# Copyright 2015 Alcatel-Lucent
# All Rights Reserved.

import logging

from tempest import config

import nuage_base

from nuage_tempest.lib.test import nuage_test

CONF = config.CONF

LOG = logging.getLogger(__name__)


class OrchestrationSecurityGroupTest(nuage_base.NuageBaseOrchestrationTest):

    @classmethod
    def resource_setup(cls):
        super(OrchestrationSecurityGroupTest, cls).resource_setup()

    @nuage_test.header()
    def test_security_groups(self):
        # launch a heat stack
        stack_file_name = 'security_groups'
        stack_parameters = {
            # 'public_net': self.ext_net_id,
        }
        self.launch_stack(stack_file_name, stack_parameters)

        # Verifies created resources
        expected_resources = ['security_group_default',
                              'security_group_default_with_remote_group',
                              'security_group_with_rules']

        self.verify_stack_resources(expected_resources,
                                    self.template_resources,
                                    self.test_resources)

        # Test minimal
        self.verify_created_security_group(
            'security_group_default')
        # TODO(team) test rules

        # Test remote groups
        self.verify_created_security_group(
            'security_group_default_with_remote_group')
        # TODO(team) test rules

        # Test rules
        self.verify_created_security_group(
            'security_group_with_rules')
        # TODO(team) test rules
