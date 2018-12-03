import testtools

from nuage_tempest_lib.release import Release

# run me as :
# $ python -m testtools.run nuage_tempest_lib/unit/release_unittest.py

# ( TODO(team) - integrate in unit testing from tox )

r5_2 = Release('5.2')
r5_2_1 = Release('5.2.1')
r5_2_2 = Release('5.2.2')
r5_3_1 = Release('5.3.1')

kilo = Release('kilo')
ocata = Release('ocata')
queens = Release('queens')
master = Release('master')


class ReleaseUnitTest(testtools.TestCase):

    @staticmethod
    def test_release_comparison():
        assert r5_2 != r5_2_1
        assert r5_2_1 != r5_2_2

        assert r5_2 < r5_2_2
        assert r5_2_1 < r5_2_2
        assert r5_2_2 > r5_2
        assert r5_2_2 > r5_2_1

    @staticmethod
    def test_os_flavor_comparison():
        assert kilo < ocata < queens < master
        assert master > queens > ocata > kilo

    @staticmethod
    def test_from_tock():
        def from_tock(this, spec):
            return (this > spec and
                    Release.nuage_part(this) !=
                    Release.nuage_part(spec) + '.1')

        assert from_tock(r5_2_2, r5_2)
        assert not from_tock(r5_2_1, r5_2)
        assert from_tock(r5_3_1, r5_2)
