import testtools

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from nuage_tempest_plugin.lib.topology import Topology
from nuage_tempest_plugin.tests.api.ipv6.vsd_managed.base_nuage_networks \
    import BaseVSDManagedNetworksIPv6Test


class VSDManagedIPv6L2DomainDHCPManagedTest(BaseVSDManagedNetworksIPv6Test):
    dhcp_managed = True

    @testtools.skipIf(not Topology.has_single_stack_v6_support(),
                      'There is no single-stack v6 support in current release')
    @decorators.attr(type='smoke')
    def test_create_vsd_managed_ipv6_l2domain_with_ipv4_cidr_neg(self):
        vsd_l2domain_template = self.vsd_create_l2domain_template(
            dhcp_managed=True,
            ip_type="IPV6",
            cidr6=self.cidr6)

        self._verify_vsd_l2domain_template(vsd_l2domain_template,
                                           dhcp_managed=self.dhcp_managed,
                                           ip_type='IPV6',
                                           cidr6=self.cidr6)
        vsd_l2domain = self.vsd_create_l2domain(
            template=vsd_l2domain_template)

        self._verify_vsd_l2domain_with_template(vsd_l2domain,
                                                vsd_l2domain_template)
        # create OpenStack network
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        msg = ("Subnet with ip_version %(ip_version)s can't be linked to vsd "
               "subnet with IPType %(ip_type)s.") % {
            'ip_version': 4,
            'ip_type': vsd_l2domain.ip_type}
        kwargs = {
            'cidr': self.cidr4,
            'enable_dhcp': self.dhcp_managed,
            'nuagenet': vsd_l2domain.id,
            'net_partition': self.net_partition
        }
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_subnet,
                               network,
                               **kwargs)
