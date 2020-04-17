import functools
import re


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
        self.major_list = [int(rel) for rel in self.major_release.split('.')]
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
        return not self == other

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
        def cmp(a, b):
            return (a > b) - (a < b)

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
                return cmp(other.sub_list, self.sub_list) > 0
            return comparison > 0
        else:
            if self.sub_release == other.sub_release:
                return self._openstack_release is None

    def __gt__(self, other):
        return not self <= other

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

    def nuage_part(self):
        return ("%s%s" % (self.major_release or "",
                          (str(self.sub_release))
                          if self.sub_release != '' else "")
                ).strip()
