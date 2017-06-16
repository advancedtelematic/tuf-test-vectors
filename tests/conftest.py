# -*- coding: utf-8 -*-

import pytest


from os import path
from tuf_vectors.server import init_app


@pytest.fixture(scope='function')
def tuf_app():
    app = init_app('tuf', path.join(path.dirname(path.abspath(__file__)),
                                    '..', 'vectors', 'tuf'))
    app.testing = True
    return app.test_client()
