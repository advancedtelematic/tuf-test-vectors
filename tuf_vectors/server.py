# -*- coding: utf-8 -*-

import json

from flask import Flask, Response, abort, make_response
from functools import wraps
from os import path
from tuf_vectors import subclasses
from tuf_vectors.tuf import Tuf
from tuf_vectors.uptane import Uptane


def json_response(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        out = f(*args, **kwargs)
        resp = make_response(json.dumps(out, separators=(',', ':')))
        resp.headers['Content-Type'] = 'application/json'
        return resp
    return decorated_function

def init_app(
        repo_type,
        key_type,
        signature_scheme,
        signature_encoding,
        compact,
        cjson_strategy):
    app = Flask(__name__, static_folder=None, template_folder=None)

    repos = {}
    counter = {}

    for repo in subclasses(Tuf if repo_type == 'tuf' else Uptane):
        repo = repo('/tmp/', key_type=key_type, signature_scheme=signature_scheme,
                    signature_encoding=signature_encoding,
                    compact=compact, cjson_strategy=cjson_strategy)
        repos[repo.name()] = repo

    @app.route('/')
    @json_response
    def index():
        return list(repos.keys())

    @app.route('/<string:repo>/step', methods=['POST'])
    @json_response
    def step(repo):
        current = counter.get(repo, 0)
        try:
            step_meta = repos[repo].steps[current].generate_meta()
        except KeyError:
            abort(400)
        except IndexError:
            return '', 204

        counter[repo] = current + 1
        # TODO if current step == 0, include root keys for pinning
        return {
            'update': step_meta['update'],
            'targets': step_meta['targets'],
        }

    @app.route('/<string:repo>/reset', methods=['POST'])
    def reset(repo):
        counter.pop(repo, None)
        return '', 204

    if repo_type == 'tuf':
        @app.route('/<string:repo>/<int:root_version>.root.json')
        def root(repo, root_version):
            current = counter.get(repo)
            if current is None:
                abort(400)

            root_idx = root_version - 1
            if current >= root_idx:
                try:
                    return repos[repo].steps[root_idx].root
                except (IndexError, ValueError):
                    abort(400)
            else:
                return abort(404)

        @app.route('/<string:repo>/<path:content_path>')
        def repo(repo, content_path):
            try:
                current = counter[repo]
                repo = repos[repo].steps[current - 1]
            except (IndexError, KeyError) as e:
                abort(400)

            for target in repo.TARGETS:
                if target[0] == content_path:
                    return target[1]

            abort(404)
    else:
        pass # TODO

    return app
