import functools
import re


@functools.total_ordering
class Release(object):
    release_regex = re.compile(r'^([a-zA-Z]+)?[\D]*'
                               r'((\d+(\.(?=\d))?){2,})?[\D]*'
                               r'((\d+(\.(?=\d))?)*)$')

    current_release = {
        '5.4': '1.17',  # 5.4.1.U17
        '6.0': '12',  # 6.0.12
        '20.10': '3',  # 20.10.R3
        '21.4': '1'  # 21.4.1
    }

    current_rel_to_str = {float(x): x for x in current_release.keys()}

    def __init__(self, release_string):
        self.openstack_release = ''
        self.major_release = ''
        self.sub_release = ''
        self.major_list = []
        self.sub_list = []
        self._parse_release(release_string)

    def _parse_release(self, release):
        parsed = Release.release_regex.search(release)
        if parsed is None:
            raise Exception("Can not parse release String '%s'" % release)

        first_non_numerical_part = parsed.group(1)
        middle_part = parsed.group(2)
        last_numerical_part = parsed.group(5)

        self.openstack_release = (first_non_numerical_part or 'master').lower()
        if self.openstack_release == 'master':
            self.openstack_release = '{none}'  # { is first ascii character
            #                                  # after 'z'

        if middle_part:
            self.major_release = self.normalize_major_release(middle_part)

            if self.major_release.count('.') == 1:
                # this is a x.y type of release, e.g. 20.10R2
                self.sub_release = (last_numerical_part or
                                    self.current_release.get(
                                        self.major_release))
            else:
                assert self.major_release.count('.') == 2
                # this is a x.y.z type of release; the z becomes the substring
                if last_numerical_part:
                    # e.g. 5.4.1U12
                    s = self.major_release.rsplit('.', 1)
                    self.major_release = s[0]  # 5.4
                    self.sub_release = '{}.{}'.format(  # 1.12
                        s[1], last_numerical_part)
                else:
                    # e.g. 6.0.10, or 5.4.1
                    s = self.major_release.rsplit('.', 1)
                    self.major_release = s[0]
                    self.sub_release = s[1]
                    if '.' not in self.sub_release:
                        # check whether to expand to full digits
                        # e.g. in order to make 5.4.1 == 5.4.1.U16
                        curr_sub_rel = self.current_release.get(
                            self.major_release)
                        if (curr_sub_rel and '.' in curr_sub_rel and
                                self.sub_release ==
                                curr_sub_rel.strip('.')[0]):
                            # expand
                            self.sub_release = curr_sub_rel

            self.major_list = [int(rel)
                               for rel in self.major_release.split('.')]
            self.sub_list = ([int(rel) for rel in self.sub_release.split('.')
                              if rel] if self.sub_release else [999])

    def __eq__(self, other):
        """__eq__

        Compares self with another Release object.
        :param other: Release object to compare with
        :return: True when the releases are considered equal else False.
        """
        return (self.openstack_release == other.openstack_release and
                self.major_release == other.major_release and
                self.sub_release == other.sub_release)

    def __ne__(self, other):
        return not self == other

    def __lt__(self, other):
        """__lt__

        Compares self with another Release object to be 'less than'
        :param other: Release object to compare with
        :return: True when self is less than other.
        """
        def cmp(a, b):
            return (a > b) - (a < b)

        comparison = cmp(other.major_list, self.major_list)
        if comparison == 0:
            comparison = cmp(other.sub_list, self.sub_list)
            if comparison == 0:
                comparison = cmp(other.openstack_release,
                                 self.openstack_release)
        return comparison > 0

    def __gt__(self, other):
        return not self <= other

    def __str__(self):
        return ('%s %s%s' % (self.openstack_release,
                             self.major_release,
                             ('.' + str(self.sub_release))
                             if self.sub_release else '')
                ).strip()

    def __repr__(self):
        return self.__str__()

    @classmethod
    def highest_major_release(cls):
        return cls.current_rel_to_str[max(
            float(e) for e in cls.current_release.keys())]

    @classmethod
    def normalize_major_release(cls, rel):
        return cls.highest_major_release() if rel == '0.0' else rel
