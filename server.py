#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from argparse import ArgumentParser
from os import path
from tuf_vectors.server import init_app


def main(repo_type, vector_dir, port):
    app = init_app(repo_type, vector_dir)
    app.run(host='127.0.0.1', port=port, debug=True)

if __name__ == '__main__':
    parser = ArgumentParser(path.basename(__file__),
                            description='Runs a TUF repo HTTP server')
    parser.add_argument('-p', '--path', help='The path to serve content from.', required=True)
    parser.add_argument('-P', '--port', help='The port to bind the app to',
                        type=int, default=8080)
    parser.add_argument('-t', '--type', help='The type of repo to serve',
                        default='tuf', choices=['tuf', 'uptane'])
    args = parser.parse_args()

    main(args.type, path.abspath(args.path), args.port)
