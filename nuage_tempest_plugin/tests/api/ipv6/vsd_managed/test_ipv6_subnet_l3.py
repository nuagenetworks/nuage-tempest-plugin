from netaddr import IPAddress
from netaddr import IPNetwork
from nuage_tempest_plugin.tests.api.ipv6.vsd_managed.base_nuage_networks \
    import BaseVSDManagedNetworksIPv6Test

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions


class VSDManagedIPv6SubnetL3Test(BaseVSDManagedNetworksIPv6Test):
    dhcp_managed = True

    @decorators.attr(type='smoke')
    def test_create_vsd_managed_ipv6_subnet_with_ipv4_cidr_neg(self):
        name = data_utils.rand_name('l3domain-')
        vsd_l3domain_template = self.vsd_create_l3domain_template(
            name=name)
        vsd_l3domain = self.vsd_create_l3domain(
            name=name, template_id=vsd_l3domain_template.id)

        self.assertEqual(vsd_l3domain.name, name)
        zone_name = data_utils.rand_name('zone-')
        vsd_zone = self.vsd_create_zone(name=zone_name,
                                        domain=vsd_l3domain)

        subnet_name = data_utils.rand_name('l3domain-subnet-')

        subnet_ipv6_cidr = IPNetwork("2001:5f74:c4a5:b82e::/64")
        subnet_ipv6_gateway = str(IPAddress(subnet_ipv6_cidr) + 1)

        vsd_l3domain_subnet = self.create_vsd_subnet(
            name=subnet_name,
            zone=vsd_zone,
            ip_type="IPV6",
            cidr6=subnet_ipv6_cidr,
            gateway6=subnet_ipv6_gateway)

        # create OpenStack network
        net_name = data_utils.rand_name('network-')
        network = self.create_network(network_name=net_name)

        msg = ("Subnet with ip_version %(ip_version)s can't be linked to vsd "
               "subnet with IPType %(ip_type)s.") % {
            'ip_version': 4,
            'ip_type': vsd_l3domain_subnet.ip_type}
        kwargs = {
            'cidr': self.cidr4,
            'enable_dhcp': self.dhcp_managed,
            'nuagenet': vsd_l3domain_subnet.id,
            'net_partition': self.net_partition[0]['name']
        }
        self.assertRaisesRegex(exceptions.BadRequest,
                               msg,
                               self.create_subnet,
                               network,
                               **kwargs)
