# Copyright 2017 NOKIA

from netaddr import IPAddress
from netaddr import IPNetwork

import random


def gimme_a_cidr(mask_bits=24):
    cidr = IPNetwork('1%s.%s.%s.0/%s' % (random.randint(0, 9),
                                         random.randint(0, 255),
                                         random.randint(0, 255),
                                         str(mask_bits)))
    gateway = str(IPAddress(cidr) + 1)
    return cidr, gateway, mask_bits
