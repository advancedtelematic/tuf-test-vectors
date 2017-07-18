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
        resp = make_response(f(*args, **kwargs))
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
        return json.dumps(list(repos.keys()))

    @app.route('/<string:repo>/reset', methods=['POST'])
    def reset(repo):
        try:
            counter.pop(repo, None)
        except KeyError:
            pass
        return '', 204

    if repo_type == 'tuf':
        @app.route('/<string:repo>/step', methods=['POST'])
        @json_response
        def step(repo):
            current = counter.get(repo, 0)
            counter[repo] = current + 1
            try:
                step_meta = repos[repo].steps[current].generate_meta()
            except KeyError:
                abort(400)
            except IndexError:
                return '', 204

            # TODO if current step == 0, include root keys for pinning
            return json.dumps({
                'update': step_meta['update'],
                'targets': step_meta['targets'],
            })

        @app.route('/<string:repo>/<int:root_version>.root.json')
        @json_response
        def root(repo, root_version):
            current = counter.get(repo)
            if current is None:
                abort(400)

            root_idx = root_version - 1
            if current >= root_idx:
                try:
                    if current > len(repos[repo].steps):
                        abort(400)
                    repo = repos[repo]
                    return repo.jsonify(repo.steps[root_idx].root)
                except (IndexError, KeyError) as e:
                    app.logger.warn(e)
                    abort(400)
            else:
                return abort(404)

        @app.route('/<string:repo>/<string:metadata>.json')
        @json_response
        def meta(repo, metadata):
            current = counter.get(repo)
            if current is None:
                abort(400)

            if metadata not in ['root', 'timestamp', 'targets', 'snapshot']:
                abort(404)

            try:
                repo = repos[repo]
                return repo.jsonify(getattr(repo.steps[current - 1], metadata))
            except (IndexError, KeyError) as e:
                app.logger.warn(e)
                abort(400)
            except AttributeError as e:
                app.logger.warn(e)
                abort(404)

        @app.route('/<string:repo>/targets/<path:content_path>')
        def repo(repo, content_path):
            try:
                current = counter[repo]
                repo = repos[repo].steps[current - 1]
            except (IndexError, KeyError) as e:
                app.logger.warn(e)
                abort(400)

            for target in repo.TARGETS:
                if target[0] == content_path:
                    return target[1]

            abort(404)
    else:
        @app.route('/<string:repo>/step', methods=['POST'])
        @json_response
        def step(repo):
            current = counter.get(repo, 0)
            counter[repo] = current + 1
            try:
                step_meta = repos[repo].generate_meta()['steps'][current]
            except KeyError:
                abort(400)
            except IndexError:
                return '', 204

            # TODO if current step == 0, include root keys for pinning
            return json.dumps({
                'director': {
                    'update': step_meta['director']['update'],
                },
                'image_repo': {
                    'update': step_meta['image_repo']['update'],
                    'targets': step_meta['image_repo']['targets'],
                }
            })

        @app.route('/<string:repo>/<string:uptane>/<int:root_version>.root.json')
        @json_response
        def root(repo, uptane, root_version):
            current = counter.get(repo)
            if current is None:
                abort(400)

            if uptane not in ['director', 'image_repo']:
                abort(404)

            root_idx = root_version - 1
            if current >= root_idx:
                try:
                    if current > len(getattr(repos[repo], uptane).steps):
                        abort(400)

                    repo = repos[repo]
                    return repo.jsonify(getattr(repo, uptane).steps[root_idx].root)
                except (IndexError, KeyError) as e:
                    app.logger.warn(e)
                    abort(400)
            else:
                return abort(404)

        @app.route('/<string:repo>/<string:uptane>/<string:metadata>.json')
        @json_response
        def meta(repo, uptane, metadata):
            current = counter.get(repo)
            if current is None:
                abort(400)

            if uptane == 'director':
                if metadata not in ['root', 'targets']:
                    abort(404)
            else:
                if metadata not in ['root', 'targets', 'timestamp', 'snapshot']:
                    abort(404)

            try:
                repo = repos[repo]
                return repo.jsonify(
                    getattr(
                        getattr(
                            repo,
                            uptane).steps[
                            current -
                            1],
                        metadata))
            except (IndexError, KeyError) as e:
                app.logger.warn(e)
                abort(400)
            except AttributeError as e:
                app.logger.warn(e)
                abort(404)

        @app.route('/<string:repo>/image_repo/targets/<path:content_path>')
        def repo(repo, content_path):
            try:
                current = counter[repo]
                repo = repos[repo].image_repo.steps[current - 1]
            except (IndexError, KeyError) as e:
                app.logger.warn(e)
                abort(400)

            for target in repo.TARGETS:
                if target[0] == content_path:
                    return target[1]

            abort(404)

    return app
