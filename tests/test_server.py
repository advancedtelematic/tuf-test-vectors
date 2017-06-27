# -*- coding: utf-8 -*-

import json


class TestTufServer:

    def test_index(self, tuf_app):
        resp = tuf_app.get('/')
        assert resp.status_code == 200

        jsn = json.loads(resp.data.decode('utf-8'))
        assert isinstance(jsn, list)

    def test_simple(self, tuf_app):
        resp = tuf_app.post('/simple/step')
        assert resp.status_code == 200

        meta = json.loads(resp.data.decode('utf-8'))

        for m in ['root', '1.root', 'timestamp', 'targets', 'snapshot']:
            resp = tuf_app.get('/simple/{}.json'.format(m))
            assert resp.status_code == 200, m

            jsn = json.loads(resp.data.decode('utf-8'))
            assert isinstance(jsn, dict), m
            assert 'signed' in jsn, m
            assert 'signatures' in jsn, m

        for t in meta['targets'].keys():
            resp = tuf_app.get('/simple/{}'.format(t))
            assert resp.status_code == 200, t

        resp = tuf_app.post('/simple/step')
        assert resp.status_code == 204

        for p in ['root.json', '1.root.json', list(meta['targets'].keys())[0]]:
            resp = tuf_app.get('/simple/{}'.format(p))
            assert resp.status_code == 400, p

        resp = tuf_app.post('/simple/step')
        assert resp.status_code == 204

        resp = tuf_app.post('/simple/reset')
        assert resp.status_code == 204

        for p in ['root.json', '1.root.json', list(meta['targets'].keys())[0]]:
            resp = tuf_app.get('/simple/{}'.format(p))
            assert resp.status_code == 400, p

        resp = tuf_app.post('/simple/step')
        assert resp.status_code == 200

        for p in ['root.json', '1.root.json', list(meta['targets'].keys())[0]]:
            resp = tuf_app.get('/simple/{}'.format(p))
            assert resp.status_code == 200, p


class TestUptaneServer:

    def test_test_index(self, uptane_app):
        resp = uptane_app.get('/')
        assert resp.status_code == 200

        jsn = json.loads(resp.data.decode('utf-8'))
        assert isinstance(jsn, list)

    def test_simple(self, uptane_app):
        resp = uptane_app.post('/simple/step')
        assert resp.status_code == 200

        meta = json.loads(resp.data.decode('utf-8'))

        for m in ['root', '1.root', 'timestamp', 'targets', 'snapshot']:
            resp = uptane_app.get('/simple/image_repo/{}.json'.format(m))
            assert resp.status_code == 200, m

            jsn = json.loads(resp.data.decode('utf-8'))
            assert isinstance(jsn, dict), m
            assert 'signed' in jsn, m
            assert 'signatures' in jsn, m

        for m in ['root', '1.root', 'targets']:
            resp = uptane_app.get('/simple/director/{}.json'.format(m))
            assert resp.status_code == 200, m

            jsn = json.loads(resp.data.decode('utf-8'))
            assert isinstance(jsn, dict), m
            assert 'signed' in jsn, m
            assert 'signatures' in jsn, m

        for t in meta['image_repo']['targets'].keys():
            resp = uptane_app.get('/simple/image_repo/{}'.format(t))
            assert resp.status_code == 200, t

        resp = uptane_app.post('/simple/step')
        assert resp.status_code == 204

        for p in ['root.json', '1.root.json', list(meta['image_repo']['targets'].keys())[0]]:
            resp = uptane_app.get('/simple/image_repo/{}'.format(p))
            assert resp.status_code == 400, p

        for p in ['root.json', '1.root.json']:
            resp = uptane_app.get('/simple/director/{}'.format(p))
            assert resp.status_code == 400, p

        resp = uptane_app.post('/simple/step')
        assert resp.status_code == 204

        resp = uptane_app.post('/simple/reset')
        assert resp.status_code == 204

        for p in ['root.json', '1.root.json', list(meta['image_repo']['targets'].keys())[0]]:
            resp = uptane_app.get('/simple/image_repo/{}'.format(p))
            assert resp.status_code == 400, p

        for p in ['root.json', '1.root.json']:
            resp = uptane_app.get('/simple/director/{}'.format(p))
            assert resp.status_code == 400, p

        resp = uptane_app.post('/simple/step')
        assert resp.status_code == 200

        for p in ['root.json', '1.root.json', list(meta['image_repo']['targets'].keys())[0]]:
            resp = uptane_app.get('/simple/image_repo/{}'.format(p))
            assert resp.status_code == 200, p
