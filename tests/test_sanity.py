# -*- coding: utf-8 -*-

import pytest

from tempfile import TemporaryDirectory
from tuf_vectors import subclasses
from tuf_vectors.uptane import Uptane


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
        sub.persist()
