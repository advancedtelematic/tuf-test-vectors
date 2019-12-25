# -*- coding: utf-8 -*-

import pytest
import fnmatch
import json
from os import path, walk

from tempfile import TemporaryDirectory
from tuf_vectors import subclasses
from tuf_vectors.uptane import Uptane, SimpleUptane


@pytest.mark.parametrize("cls", subclasses(Uptane))
def test_basic(cls):

    ''' This test case using parametrization mechanism will go through all of the sub classes of
    class Uptane, create instances for them and generate meta data, and write meta to files.
    '''

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

        case_dir = path.join(tempdir, sub.name())
        for root, dirs, files in walk(case_dir):
            for filename in files:
                if fnmatch.fnmatch(filename, '*.json'):
                    full_path = path.join(root, filename)
                    with open(full_path, 'rb') as f:
                        content = f.read()
                        assert json.loads(content)


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

    ''' This test case using parametrization mechanism will use every possible combination
        of parameters above to try to create the object of class SimpleUptane.
    '''

    with TemporaryDirectory(prefix='tuf-test-vectors') as tempdir:
        SimpleUptane(output_dir=tempdir,
                     key_type=key_type,
                     signature_scheme=signature_scheme,
                     signature_encoding=signature_encoding,
                     compact=compact,
                     cjson_strategy=cjson_strategy,
                     ecu_identifier='123',
                     hardware_id='abc')
