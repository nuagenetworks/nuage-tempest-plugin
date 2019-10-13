# Copyright 2019 NOKIA
# All Rights Reserved.

from __future__ import print_function
import sys

from oslo_log import log as logging


class Console(object):

    RED = '\033[91m'  # light red (red is 31)
    GREEN = '\033[92m'  # light green (green is 32)
    YELLOW = '\033[93m'  # light yellow (yellow is 33)
    BLUE = '\033[94m'  # light blue (blue is 34)
    MAGENTA = '\033[95m'  # light magenta (magenta is 35)
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    HEADER = MAGENTA
    DEBUG = BLUE
    EMPHASIS = GREEN
    WARNING = YELLOW
    FAIL = RED

    post_py_3_3 = sys.version_info[:2] >= (3, 3)

    @classmethod
    def stdout(cls, msg='', *args, **kwargs):
        if cls.post_py_3_3:
            kwargs['flush'] = True
        if args:
            print(msg % tuple(args), **kwargs)
        else:
            print(msg, **kwargs)
        if not cls.post_py_3_3:
            sys.stdout.flush()

    @classmethod
    def newline(cls):
        cls.stdout()

    @classmethod
    def coloured(cls, color, msg, *args, **kwargs):
        cls.stdout('{}{}{}'.format(
            color, msg, cls.ENDC), *args, **kwargs)

    @classmethod
    def fail(cls, msg, *args, **kwargs):
        cls.coloured(cls.FAIL, msg, *args, **kwargs)

    @classmethod
    def error(cls, msg, *args, **kwargs):
        cls.coloured(cls.FAIL, 'ERROR: {}'.format(
            msg), *args, **kwargs)

    @classmethod
    def warn(cls, msg, *args, **kwargs):
        cls.coloured(cls.WARNING, ' WARN: {}'.format(
            msg), *args, **kwargs)

    @classmethod
    def info(cls, msg, *args, **kwargs):
        cls.coloured(cls.EMPHASIS, ' INFO: {}'.format(
            msg), *args, **kwargs)

    @classmethod
    def debug(cls, msg, *args, **kwargs):
        cls.coloured(cls.DEBUG, 'DEBUG: {}'.format(
            msg), *args, **kwargs)


class ConsoleLogging(object):

    def __init__(self, name=None):
        self.log = logging.getLogger(name or __name__)
        self.console = Console()

    def exception(self, msg, *args, **kwargs):
        if self.log.isEnabledFor(logging.ERROR):
            self.console.error(msg, *args, **kwargs)
        self.log.exception(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        if self.log.isEnabledFor(logging.ERROR):
            self.console.error(msg, *args, **kwargs)
        self.log.error(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        if self.log.isEnabledFor(logging.WARNING):
            self.console.warn(msg, *args, **kwargs)
        self.log.warn(msg, *args, **kwargs)

    warn = warning

    def info(self, msg, *args, **kwargs):
        if self.log.isEnabledFor(logging.INFO):
            self.console.info(msg, *args, **kwargs)
        self.log.info(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        if self.log.isEnabledFor(logging.DEBUG):
            self.console.debug(msg, *args, **kwargs)
        self.log.debug(msg, *args, **kwargs)
