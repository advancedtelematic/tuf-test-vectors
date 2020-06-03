# -*- coding: utf-8 -*-

import fnmatch

from flask import Flask, abort, make_response
from functools import wraps
from tuf_vectors import subclasses
from tuf_vectors.uptane import Uptane


def json_response(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        resp = make_response(f(*args, **kwargs))
        resp.headers['Content-Type'] = 'application/json'
        return resp
    return decorated_function


def init_app(
        key_type,
        signature_scheme,
        signature_encoding,
        compact,
        cjson_strategy,
        ecu_identifier,
        hardware_id):
    app = Flask(__name__, static_folder=None, template_folder=None)

    repos = {}
    counter = {}

    for repo in subclasses(Uptane):
        repo = repo(output_dir='/tmp/',
                    key_type=key_type,
                    signature_scheme=signature_scheme,
                    signature_encoding=signature_encoding,
                    compact=compact,
                    cjson_strategy=cjson_strategy,
                    hardware_id=hardware_id,
                    ecu_identifier=ecu_identifier)
        repos[repo.name()] = repo

    @app.route('/')
    @json_response
    def index():
        # hack to get jsonify function
        jsonify = list(repos.values())[0].steps[0][0].roots[0].jsonify
        return jsonify(sorted(list(repos.keys())))

    @app.route('/<string:repo>/reset', methods=['POST'])
    def reset(repo):
        try:
            counter.pop(repo, None)
        except KeyError:
            pass
        return '', 204

    @app.route('/<string:repo>/step', methods=['POST'])
    @json_response
    def step(repo):
        current = counter.get(repo, 0)
        counter[repo] = current + 1
        try:
            step_meta = repos[repo].meta()['steps'][current]
        except KeyError:
            abort(400)
        except IndexError:
            return '', 204

        # hack to get jsonify function
        jsonify = repos[repo].steps[0][0].roots[0].jsonify

        # TODO if current step == 0, include root keys for pinning
        return jsonify(step_meta)

    @app.route('/<string:repo>/<string:uptane>/<int:root_version>.root.json')
    @json_response
    def root(repo, uptane, root_version):
        current = counter.get(repo)
        if current is None:
            abort(400)

        if uptane not in ['director', 'image_repo']:
            abort(404)

        repo = repos.get(repo, None)
        if repo is None:
            abort(404)

        if current > len(repo.steps):
            abort(400)

        # this is a hack
        jsonify = repo.steps[0][0].roots[0].jsonify

        try:
            step = repo.steps[current - 1]
        except IndexError:
            abort(404)

        step_repo = step[0 if uptane == 'director' else 1]

        # Make sure the version we've fetched matches the version requested.
        try:
            root, = [r for r in step_repo.roots if r.version == root_version]
        except Exception:
            abort(404)

        return jsonify(root.value)

    # TODO: prevent fetching unversioned root.json?
    @app.route('/<string:repo>/<string:uptane>/<string:metadata>.json')
    @app.route('/<string:repo>/<string:uptane>/delegations/<string:metadata>.json')
    @json_response
    def meta(repo, uptane, metadata):
        current = counter.get(repo)
        if current is None:
            abort(400)

        if uptane == 'director':
            if metadata not in ['root', 'targets']:
                abort(404)

        repo = repos.get(repo, None)
        if repo is None:
            abort(404)

        # this is a hack
        jsonify = repo.steps[0][0].roots[0].jsonify

        try:
            step = repo.steps[current - 1]
        except IndexError:
            abort(400)

        step_repo = step[0 if uptane == 'director' else 1]

        data = getattr(step_repo, metadata, None)
        if data is None:
            data = step_repo.delegations.get(metadata, None)
            if data is None:
                abort(400)

        return jsonify(data.value)

    @app.route('/<string:repo>/image_repo/targets/<path:content_path>')
    def repo(repo, content_path):
        try:
            current = counter[repo]
            repo = repos[repo].steps[current - 1][1]
        except (IndexError, KeyError) as e:
            app.logger.warning(e)
            abort(400)

        # Check top-level targets
        for target in repo.targets.targets:
            if target.name == content_path:
                return target.content

        # Check first-order delegations.
        # TODO: does not work for nested delegations yet.
        for delegation in repo.targets.value['signed']['delegations']['roles']:
            for path in delegation['paths']:
                if fnmatch.fnmatch(content_path, path):
                    role_name = delegation['name']
                    for target in repo.delegations[role_name].targets:
                        if target.name == content_path:
                            return target.content

        abort(404)

    return app
