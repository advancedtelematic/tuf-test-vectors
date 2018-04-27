# -*- coding: utf-8 -*-

import sys

from tempfile import TemporaryDirectory
from tuf_vectors import subclasses
from tuf_vectors.uptane import Uptane


for sub in subclasses(Uptane):
    def gen_test():
        def test_it(self):
            with TemporaryDirectory(prefix='tuf-test-vectors') as tempdir:
                sub = self.CLS(output_dir=tempdir,
                               key_type='ed25519',
                               signature_scheme='ed25519',
                               signature_encoding='hex',
                               compact=True,
                               cjson_strategy='olpc',
                               ecu_identifier='123',
                               hardware_id='abc')
                sub.persist()
        return test_it

    name = 'Test' + sub.__name__
    cls = type(name, (object,), {'test_it': gen_test(),
                                 'CLS': sub})
    setattr(sys.modules[__name__], name, cls)
