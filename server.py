#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from os import path

# activate the virtual environment
if __name__ == '__main__':
    try:
        activate_this = path.join(path.abspath(path.dirname(__file__)),
                                  path.join('venv', 'bin', 'activate_this.py'))
        with open(activate_this) as f:
            code = compile(f.read(), activate_this, 'exec')
            exec(code, dict(__file__=activate_this))
    except FileNotFoundError:
        pass

import gzip
from argparse import ArgumentParser
from flask import Flask, send_from_directory, safe_join, Response


def init_app(vector_dir):
    app = Flask(__name__, static_folder=None, template_folder=None)

    @app.route('/<path:path>')
    def static(path):
        if path.endswith('.gz'):
            path = safe_join(vector_dir, path[:-3])
            with open(path, 'rb') as f:
                out = gzip.compress(f.read())
            return Response(response=out, headers={'Content-Type': 'application/gzip'})
        else:
            return send_from_directory(vector_dir, path)

    return app


def main(vector_dir):
    app = init_app(vector_dir)
    app.run(host='127.0.0.1', port=8080, debug=True)

if __name__ == '__main__':
    parser = ArgumentParser(path.basename(__file__),
                            description='Runs a TUF repo HTTP server')
    parser.add_argument('-p', '--path', help='The path to serve content from',
                        default=path.dirname(path.abspath(__file__)))
    args = parser.parse_args()
    main(args.path)
