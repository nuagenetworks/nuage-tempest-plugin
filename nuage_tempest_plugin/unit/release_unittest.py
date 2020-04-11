import testtools

from nuage_tempest_plugin.lib.release import Release

# run me as :
# $ python -m testtools.run nuage_tempest_plugin/unit/release_unittest.py

r_5_4 = Release('5.4')
r_6_0 = Release('6.0')
r_0_0 = Release('0.0')

kilo = Release('kilo')
ocata = Release('ocata')
queens = Release('queens')
master = Release('master')


class ReleaseUnitTest(testtools.TestCase):

    @staticmethod
    def test_release_comparison():
        assert r_6_0 == r_6_0
        assert r_5_4 < r_6_0 < r_0_0
        assert r_0_0 > r_6_0 > r_5_4
        assert not r_6_0 > r_6_0
        assert not r_6_0 < r_6_0

    @staticmethod
    def test_os_flavor_comparison():
        assert kilo < ocata < queens < master
        assert master > queens > ocata > kilo
