# -*- coding: utf-8 -*-


class TestServer:

    def test_server(self, tuf_app):
        resp = tuf_app.get('/')
        assert resp.status_code == 200
