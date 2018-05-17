# -*- coding: utf-8 -*-

import pytest

from tempfile import TemporaryDirectory
from tuf_vectors import subclasses
from tuf_vectors.uptane import Uptane, SimpleUptane


@pytest.mark.parametrize("cls", subclasses(Uptane))
def test_basic(cls):
    with TemporaryDirectory(prefix='tuf-test-vectors') as tempdir:
        sub = cls(output_dir=tempdir,
                  key_type='ed25519',
                  signature_scheme='ed25519',
                  signature_encoding='hex',
                  compact=True,
                  cjson_strategy='olpc',
                  ecu_identifier='123',
                  hardware_id='abc')
        sub.meta()
        sub.persist()


@pytest.mark.parametrize(
    "key_type,signature_scheme,signature_encoding,compact,cjson_strategy",
    [(k, s, e, c, j)
     for (k, s) in (('ed25519', 'ed25519'),
                    ('rsa-2048', 'rsassa-pss-sha256'),
                    ('rsa-2048', 'rsassa-pss-sha512'),
                    ('rsa-4096', 'rsassa-pss-sha256'),
                    ('rsa-4096', 'rsassa-pss-sha512'),
                    ('rsa-8192', 'rsassa-pss-sha256'),
                    ('rsa-8192', 'rsassa-pss-sha512'))
     for e in ('hex', 'base64')
     for c in (True, False)
     for j in ('olpc', 'json-subset')])
def test_options(key_type, signature_scheme, signature_encoding, compact, cjson_strategy):
    with TemporaryDirectory(prefix='tuf-test-vectors') as tempdir:
        SimpleUptane(output_dir=tempdir,
                     key_type=key_type,
                     signature_scheme=signature_scheme,
                     signature_encoding=signature_encoding,
                     compact=compact,
                     cjson_strategy=cjson_strategy,
                     ecu_identifier='123',
                     hardware_id='abc')
