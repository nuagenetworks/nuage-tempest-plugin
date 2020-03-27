# Copyright 2017 NOKIA

from netaddr import IPNetwork
import random
import time


def gimme_a_cidr_address(ip_version=4, netmask=None):
    """Get random IPv4 or IPv6 cidr

    This method was copied from neutron_lib since we cannot add it as a
    dependency at the moment due to python version issues
    """
    if ip_version == 4:
        netmask = netmask or 24
        return '10.%d.%d.0/%d' % (random.randint(3, 254),
                                  random.randint(3, 254),
                                  netmask)
    else:
        netmask = netmask or 64
        return '2001:db8:%x::/%d' % (random.getrandbits(16), netmask)


def gimme_a_cidr(ip_version=4, netmask=None):
    return IPNetwork(gimme_a_cidr_address(ip_version, netmask))


def get_cidr_attributes(ip_network):
    address = str(ip_network.ip)
    netmask = str(ip_network.netmask)
    gateway = str(ip_network.ip + 1)
    return address, netmask, gateway


# for py2 and py3 compatibility using next()
class Iterable(object):
    def __init__(self, iterable):
        self._iter = iter(iterable)

    def __next__(self):      # Py3-style iterator interface
        return next(self._iter).upper()  # builtin next() function calls

    def __iter__(self):
        return self


# works in Python 2 & 3
class _Singleton(type):
    """A metaclass that creates a Singleton base class when called."""
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(_Singleton, cls).__call__(
                *args, **kwargs)
        return cls._instances[cls]


class Singleton(_Singleton('SingletonMeta', (object,), {})):
    def __init__(self):
        pass
    pass


class WaitTimeout(Exception):
    """Default exception coming from wait_until_true() function."""


def wait_until_true(predicate, timeout=60, sleep=1, exception=None):
    """Wait until callable predicate is evaluated as True

    :param predicate: Callable deciding whether waiting should continue.
    Best practice is to instantiate predicate with functools.partial()
    :param timeout: Timeout in seconds how long should function wait.
    :param sleep: Polling interval for results in seconds.
    :param exception: Exception instance to raise on timeout. If None is passed
                      (default) then WaitTimeout exception is raised.
    """
    start = int(time.time())
    while int(time.time()) - start < timeout:
        if not predicate():
            time.sleep(sleep)
        else:
            return
    if exception is not None:
        # pylint: disable=raising-bad-type
        raise exception
    raise WaitTimeout("Timed out after %d seconds" % timeout)
