import testtools

from nuage_tempest_plugin.lib.release import Release

# run me as :
# $ python -m testtools.run nuage_tempest_plugin/unit/release_unittest.py


class ReleaseUnitTest(testtools.TestCase):

    def test_nuage_release_comparison(self):
        self.assertTrue(Release('0.0') == Release('20.10'))
        self.assertTrue(Release('0.0') > Release('20.10R1'))
        self.assertTrue(Release('0.0') != Release('20.10R1'))
        self.assertTrue(not Release('0.0') == Release('20.10R1'))
        self.assertTrue(not Release('0.0') < Release('20.10R1'))

        self.assertTrue(Release('20.10') == Release('20.10'))
        self.assertTrue(Release('20.10') > Release('20.10R1'))
        self.assertTrue(Release('20.10R2') > Release('20.10R1'))
        self.assertTrue(Release('20.10R1') < Release('20.10R2'))

        self.assertTrue(Release('20.10.R2') == Release('20.10R2'))

        self.assertTrue(Release('6.0') > Release('6.0.9'))
        self.assertTrue(Release('6.0') < Release('6.0.99'))

        self.assertTrue(Release('5.4') > Release('5.4.1U9'))
        self.assertTrue(Release('5.4') < Release('5.4.1U99'))
        self.assertTrue(Release('5.4.1') > Release('5.4.1U9'))
        self.assertTrue(Release('5.4.1') < Release('5.4.1U99'))

        self.assertTrue(Release('5.4.1.U9') == Release('5.4.1U9'))

        self.assertTrue(Release('5.3') == Release('5.3'))
        self.assertTrue(Release('5.3') > Release('5.3.1'))

        self.assertTrue(Release('5.2') == Release('5.2'))
        self.assertTrue(Release('5.2') > Release('5.2.1'))

        self.assertTrue(Release('5.1') == Release('5.1'))
        self.assertTrue(Release('5.1') > Release('5.1.1'))

        self.assertTrue(Release('20.10') > Release('6.0') > Release('5.4'))
        self.assertTrue(Release('5.4') < Release('6.0') < Release('20.10'))
        self.assertTrue(Release('20.10') > Release('6.0.9'))
        self.assertTrue(Release('20.10R1') > Release('5.4.1.U12'))

        # verify integer comparison, not alphanumerical
        self.assertTrue(Release('20.10R12') > Release('20.10R2'))
        self.assertTrue(Release('6.0.12') > Release('6.0.2'))

    def test_os_release_comparison(self):
        self.assertTrue(
            Release('queens') < Release('train') < Release('master'))
        self.assertTrue(
            Release('master') > Release('train') > Release('queens'))

        self.assertTrue(
            Release('Train') == Release('train') == Release('trAin'))

    def test_mixed_comparison(self):
        self.assertTrue(Release('train 6.0.9') == Release('train 6.0.9'))
        self.assertTrue(Release('train 6.0.9') > Release('train 6.0.8'))

        # the nuage release takes precedence
        self.assertTrue(Release('queens 6.0.9') > Release('train 6.0.8'))

        # no openstack version is greater than any openstack version
        self.assertTrue(Release('6.0.9') > Release('train 6.0.9'))
