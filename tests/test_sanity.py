# -*- coding: utf-8 -*-

import sys

from tempfile import TemporaryDirectory
from tuf_vectors import subclasses
from tuf_vectors.tuf import Tuf, SimpleTuf
from tuf_vectors.uptane import Uptane


for base_cls in [Tuf, Uptane]:
    for sub in subclasses(base_cls):
        def gen_test():
            def test_it(self):
                with TemporaryDirectory(prefix='tuf-test-vectors') as tempdir:
                    sub = self.CLS(tempdir, key_type='ed25519', signature_scheme='ed25519',
                                   signature_encoding='hex', compact=True,
                                   cjson_strategy='olpc')
                    sub.generate_meta()
                    sub.write_static()
                    sub.write_meta()
                    sub.self_test()
            return test_it

        name = 'Test' + sub.__name__
        cls = type(name, (object,), {'test_it': gen_test(),
                                     'CLS': sub})
        setattr(sys.modules[__name__], name, cls)


for key_type, signature_scheme in [('ed25519', 'ed25519'),
                                   ('rsa-2048', 'rsassa-pss-sha256'),
                                   ('rsa-2048', 'rsassa-pss-sha512'),
                                   ('rsa-4096', 'rsassa-pss-sha256'),
                                   ('rsa-4096', 'rsassa-pss-sha512'),
                                   ('rsa-8192', 'rsassa-pss-sha256'),
                                   ('rsa-8192', 'rsassa-pss-sha512')]:
    for signature_encoding in ['hex', 'base64']:
        for compact in [True, False]:
            for cjson_strategy in ['olpc', 'json-subset']:
                def gen_test():
                    def test_it(self):
                        with TemporaryDirectory(prefix='tuf-test-vectors') as tempdir:
                            t = SimpleTuf(tempdir,
                                          key_type=key_type,
                                          signature_scheme=signature_scheme,
                                          signature_encoding=signature_encoding,
                                          compact=compact,
                                          cjson_strategy=cjson_strategy)
                            t.self_test()
                    return test_it

                name = 'Test_{}_{}_{}_{}'.format(signature_scheme,
                                                 signature_encoding,
                                                 'compact' if compact else 'pretty_print',
                                                 cjson_strategy) \
                    .replace('-', '_')
                cls = type(name, (object,), {'test_it': gen_test()})
                setattr(sys.modules[__name__], name, cls)
