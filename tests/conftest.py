# -*- coding: utf-8 -*-

import pytest

from tuf_vectors.server import init_app


@pytest.fixture(scope='function')
def app():
    app = init_app(key_type='ed25519',
                   compact=True,
                   cjson_strategy='olpc',
                   signature_scheme='ed25519',
                   signature_encoding='base64',
                   hardware_id='abc',
                   ecu_identifier='123')
    app.testing = True
    return app.test_client()
