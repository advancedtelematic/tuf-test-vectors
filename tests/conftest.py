# -*- coding: utf-8 -*-

import pytest


from os import path
from tuf_vectors.server import init_app


@pytest.fixture(scope='function')
def tuf_app():
    app = init_app('tuf', key_type='ed25519',
                   compact=True, cjson_strategy='olpc', signature_scheme='ed25519',
                   signature_encoding='base64')
    app.testing = True
    return app.test_client()


@pytest.fixture(scope='function')
def uptane_app():
    app = init_app('uptane', key_type='ed25519',
                   compact=True, cjson_strategy='olpc', signature_scheme='ed25519',
                   signature_encoding='base64')
    app.testing = True
    return app.test_client()
