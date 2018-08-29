# Copyright 2017 NOKIA

from netaddr import IPAddress
from netaddr import IPNetwork

import random


def gimme_a_cidr_str(mask_bits=24):
    return '1%s.%s.%s.0/%s' % (random.randint(0, 9),
                               random.randint(0, 255),
                               random.randint(0, 255),
                               str(mask_bits))


def gimme_a_cidr(mask_bits=24):
    cidr = IPNetwork(gimme_a_cidr_str(mask_bits))
    gateway = str(IPAddress(cidr) + 1)
    return cidr, gateway, mask_bits


# for py2 and py3 compatibility using next()
class Iterable(object):
    def __init__(self, iterable):
        self._iter = iter(iterable)

    def __next__(self):      # Py3-style iterator interface
        return next(self._iter).upper()  # builtin next() function calls

    def __iter__(self):
        return self


def nextitem(iterable):
    return next(Iterable(iterable))  # eventually can become next(iterable)


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
    pass
