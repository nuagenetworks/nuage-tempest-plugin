import importlib
from oslo_log import log as logging
import re
from tempest import config

CONF = config.CONF

LOG = logging.getLogger(__name__)


def skip_checks(fn):
    """Stub for skipping nuage extension"""
    def wrapped(*args, **kwargs):
        if not CONF.nuagext.nuage_components:
            LOG.info("Nuage Components not provided for verification")
            return
        else:
            try:
                return fn(*args, **kwargs)
            except ImportError as ex:
                if re.search('test_', ex.message):
                    LOG.info("Nuage Module not present for this tag")
                    return
                else:
                    raise ex
            return
    return wrapped


class NuageExtension(object):

    @skip_checks
    def nuage_components(self, tag, cls):
        m = re.search(r"(.*)\.(\w+)\.(\w+)\.(\w+)", tag)
        for comp in CONF.nuagext.nuage_components:
            base_path = 'nuage_tempest.%s' % comp
            module_name = base_path + '.' + m.group(1)
            vendor_module = importlib.import_module(module_name)
            if re.search(CONF.nuagext.nuage_ext_mode,
                         tag) or re.search(CONF.nuagext.nuage_ext_mode,
                                           'all'):
                module_class = getattr(vendor_module, m.group(2))
                verification_class = getattr(module_class, m.group(3))
                verification_object = verification_class()
                verify_function = getattr(verification_object, m.group(4))
                verify_function(cls)
            else:
                LOG.info("Enabled mode and tag don't match")
