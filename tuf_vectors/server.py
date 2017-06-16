# -*- coding: utf-8 -*-

import json

from flask import Flask, send_from_directory,  Response, abort
from os import path
from tuf_vectors import subclasses
from tuf_vectors.tuf import Tuf
from tuf_vectors.uptane import Uptane


def init_app(repo_type, vector_dir):
    print(vector_dir)
    app = Flask(__name__, static_folder=None, template_folder=None)

    repos = {}
    counter = {}

    for repo in subclasses(Tuf if repo_type == 'tuf' else Uptane):
        repos[repo.name()] = repo

    @app.route('/')
    def index():
        out = json.dumps(list(repos.keys()), separators=(',', ':'))
        return Response(response=out, headers={'Content-Type': 'application/json'})

    @app.route('/<string:repo>/step', methods=['POST'])
    def step(repo):
        current = counter.get(repo, 0)
        step_meta = repos[repo].STEPS[current].generate_meta()

        # TODO if current step == 0, include root keys for pinning
        out = {
            'update': step_meta['update'],
            'targets': step_meta['targets'],
        }

        out = json.dumps(out, separators=(',', ':'))
        counter[repo] = current + 1
        return Response(response=out, headers={'Content-Type': 'application/json'})

    @app.route('/<string:repo>/reset', methods=['POST'])
    def reset(repo):
        counter.pop(repo, None)
        return '', 204

    @app.route('/<string:repo>/<int:root_version>.root.json')
    def root(repo, root_version):
        root_idx = root_version - 1
        current = counter.get(repo, 0)
        if current >= root_idx:
            return send_from_directory(vector_dir,
                                       path.join(repo,
                                                 str(root_idx),
                                                 'root.json'))
        else:
            return abort(404)

    @app.route('/<string:repo>/<path:content_path>')
    def repo(repo, content_path):
        current = counter.get(repo, 0)
        return send_from_directory(vector_dir,
                                   path.join(repo,
                                             str(current),
                                             *content_path.split('/')))

    return app
