import functools
import os
import re
import sys

from tempest import config

if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

CONF = config.CONF


def nuage_load_tests(loader, pattern, test_dir='nuage_tempest_plugin/tests'):
    suite = unittest.TestSuite()
    base_path = os.path.split(os.path.dirname(os.path.abspath(__file__)))[0]
    base_path = os.path.split(base_path)[0]
    # Load local tempest tests
    full_test_dir = os.path.join(base_path, test_dir)
    if not pattern:
        suite.addTests(loader.discover(full_test_dir,
                                       top_level_dir=base_path))
    else:
        suite.addTests(loader.discover(full_test_dir, pattern=pattern,
                                       top_level_dir=base_path))
    _filter_suite_by_nuage_release(suite)
    return suite


def _filter_suite_by_nuage_release(suite):
    conf_release = CONF.nuage_sut.release
    current_release = Release(conf_release)
    for test_file in suite._tests:
        for test_class in test_file._tests:
            _filter_test_class_by_release(test_class, current_release)


def _filter_test_class_by_release(test_class, current_release):
    try:
        test_class._tests
    except AttributeError:
        return

    invalid = []
    for i, test in enumerate(test_class._tests):
        if unittest.suite._isnotsuite(test):
            test_method = test._get_test_method()
            if getattr(test_method, "_since", False):
                since_release = Release(test_method._since)
                if since_release > current_release:
                    invalid.append(i)
                    continue
            if getattr(test_method, "_until", False):
                until_release = Release(test_method._until)
                if until_release <= current_release:
                    invalid.append(i)
    for index in reversed(invalid):
        del test_class._tests[index]


@functools.total_ordering
class Release(object):
    release_regex = re.compile("^([a-zA-Z]+)?[\D]*"
                               "((\d+(\.(?=\d))?){2,})?[\D]*"
                               "((\d+(\.(?=\d))?)*)$")

    def __init__(self, release_string):
        self._parse_release(release_string)

    def _parse_release(self, release):
        parsed = Release.release_regex.search(release)
        if parsed is None:
            raise Exception("Can not parse release String '%s'" % release)
        self.openstack_release = (parsed.group(1) or 'master').lower()
        if self.openstack_release == 'master':
            self._openstack_release = '{'  # first character after 'z' in ascii
        else:
            self._openstack_release = self.openstack_release
        self.major_release = parsed.group(2) or '0.0'
        self.labelled = "R" in release.upper()
        self.sub_release = parsed.group(5) or ''
        self.major_list = self.major_release.split('.')
        self.sub_list = self.sub_release.split('.')

    def __eq__(self, other):
        """__eq__

        Compares self with another Release object.
        Releases are considered equal when the major part of the release is
        equal and the sub-release is equal. With 1 exception: if any of the sub
        releases is empty, two releases are still equal. Meaning 4.0R1 == 4.0
        evaluates to True.
        :param other: Release object to compare with
        :return: True when the releases are considered equal else False.
        """
        equal = True
        equal &= self._openstack_release == other._openstack_release
        equal &= self.major_release == other.major_release
        equal &= self.labelled == other.labelled
        equal &= self.sub_release == other.sub_release
        return equal

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        """__lt__

        Compares self with another Release object to be 'less than'
        If both releases (3.2, 4.0, 3.2R1, 0.0, ...) are equal, it will compare
        the openstack release names (kilo, liberty, ...)
        In any other case it will be based of the release. Meaning Kilo 3.2
        will evaluate to greater than Liberty 3.0.
        :param other: Release object to compare with
        :return: True when self is less than other..
        """
        if (self.major_release == other.major_release and
                self.sub_release == other.sub_release):
            # eg. kilo 3.2R5 < liberty 3.2R5
            if self._openstack_release and other._openstack_release and \
                    self._openstack_release[0] < other._openstack_release[0]:
                return True
            return False

        if self.major_release == '0.0' and other.major_release != '0.0':
            return False
        if other.major_release == '0.0':
            return True

        if other.major_list and self.major_list:
            comparison = cmp(other.major_list, self.major_list)
            if comparison == 0:
                if self.labelled:
                    if other.labelled:
                        return cmp(other.sub_list, self.sub_list) > 0
                    else:
                        return True
                else:
                    if other.labelled:
                        return False
                    else:
                        return cmp(other.sub_list, self.sub_list) > 0

            return comparison > 0
        else:
            if self.sub_release == other.sub_release:
                return self._openstack_release is None

    def __str__(self):
        if self.labelled:
            sub = 'R'
        else:
            sub = '-'

        return ("%s %s%s" % (self.openstack_release or "",
                             self.major_release or "",
                             (sub + str(self.sub_release))
                             if self.sub_release != '' else "")
                ).strip()

    def __repr__(self):
        return self.__str__()
