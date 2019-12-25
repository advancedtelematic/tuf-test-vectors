# -*- coding: utf-8 -*-

import json
import pytest


def test_index(app):
    resp = app.get('/')
    assert resp.status_code == 200

    jsn = json.loads(resp.data.decode('utf-8'))
    assert isinstance(jsn, list)


def test_simple(app):
    resp = app.post('/simple/step')
    assert resp.status_code == 200

    meta = json.loads(resp.data.decode('utf-8'))

    for m in ['root', '1.root', 'timestamp', 'targets', 'snapshot']:
        resp = app.get('/simple/image_repo/{}.json'.format(m))
        assert resp.status_code == 200, m

        jsn = json.loads(resp.data.decode('utf-8'))
        assert isinstance(jsn, dict), m
        assert 'signed' in jsn, m
        assert 'signatures' in jsn, m

    for m in ['root', '1.root', 'targets']:
        resp = app.get('/simple/director/{}.json'.format(m))
        assert resp.status_code == 200, m

        jsn = json.loads(resp.data.decode('utf-8'))
        assert isinstance(jsn, dict), m
        assert 'signed' in jsn, m
        assert 'signatures' in jsn, m

    for m in ['timestamp', 'snapshot']:
        resp = app.get('/simple/director/{}.json'.format(m))
        assert resp.status_code == 404, m

    for t in meta['image_repo']['targets'].keys():
        resp = app.get('/simple/image_repo/targets/{}'.format(t))
        assert resp.status_code == 200, t

    resp = app.post('/simple/step')
    assert resp.status_code == 204

    for p in ['root.json', '1.root.json', 'targets/{}'.format(
            list(meta['image_repo']['targets'].keys())[0])]:
        resp = app.get('/simple/image_repo/{}'.format(p))
        assert resp.status_code == 400, p

    for p in ['root.json', '1.root.json']:
        resp = app.get('/simple/director/{}'.format(p))
        assert resp.status_code == 400, p

    resp = app.post('/simple/step')
    assert resp.status_code == 204

    resp = app.post('/simple/reset')
    assert resp.status_code == 204

    for p in ['root.json', '1.root.json', 'targets/{}'.format(
            list(meta['image_repo']['targets'].keys())[0])]:
        resp = app.get('/simple/image_repo/{}'.format(p))
        assert resp.status_code == 400, p

    for p in ['root.json', '1.root.json']:
        resp = app.get('/simple/director/{}'.format(p))
        assert resp.status_code == 400, p

    resp = app.post('/simple/step')
    assert resp.status_code == 200

    for p in ['root.json', '1.root.json', 'targets/{}'.format(
            list(meta['image_repo']['targets'].keys())[0])]:
        resp = app.get('/simple/image_repo/{}'.format(p))
        assert resp.status_code == 200, p


@pytest.mark.skip(reason='TODO')
def test_root_rotation(app):
    resp = app.post('/image_repo_root_rotation/step')
    assert resp.status_code == 200

    for m in ['', '1.']:
        resp = app.get(
            '/image_repo_root_rotation/image_repo/{}root.json'.format(m))
        assert resp.status_code == 200, 'Prefix "{}"'.format(m)

        jsn = json.loads(resp.data.decode('utf-8'))
        assert jsn['signed']['version'] == 1, 'Prefix "{}"'.format(m)

    resp = app.post('/image_repo_root_rotation/step')
    assert resp.status_code == 200

    for m in ['', '2.']:
        resp = app.get(
            '/image_repo_root_rotation/image_repo/{}root.json'.format(m))
        assert resp.status_code == 200, 'Prefix "{}"'.format(m)

        jsn = json.loads(resp.data.decode('utf-8'))
        assert jsn['signed']['version'] == 2, 'Prefix "{}"'.format(m)

    resp = app.post('/image_repo_root_rotation/step')
    assert resp.status_code == 204
