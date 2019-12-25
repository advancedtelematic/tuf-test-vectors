# -*- coding: utf-8 -*-

import pytest

from tuf_vectors.server import init_app


@pytest.fixture(scope='function')
def app():

    ''' This fixture function could create a server instance as pre-condition of your test case.
        For example: def test_yourcase(app)
        And then you will have a Flask instance named as "app"
    '''

    app = init_app(key_type='ed25519',
                   compact=True,
                   cjson_strategy='olpc',
                   signature_scheme='ed25519',
                   signature_encoding='base64',
                   hardware_id='abc',
                   ecu_identifier='123')
    app.testing = True
    return app.test_client()
