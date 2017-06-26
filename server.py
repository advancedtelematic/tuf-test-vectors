#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from argparse import ArgumentParser
from os import path
from tuf_vectors.server import init_app


def main(
        repo_type,
        port,
        key_type,
        signature_scheme,
        signature_encoding,
        compact,
        cjson_strategy):
    app = init_app(repo_type, key_type=key_type, signature_scheme=signature_scheme,
            signature_encoding=signature_encoding, compact=compact, cjson_strategy=cjson_strategy)
    app.run(host='127.0.0.1', port=port, debug=True)

if __name__ == '__main__':
    parser = ArgumentParser(path.basename(__file__),
                            description='Runs a TUF repo HTTP server')
    parser.add_argument('-P', '--port', help='The port to bind the app to',
                        type=int, default=8080)
    parser.add_argument('-t', '--type', help='The type of repo to serve',
                        default='tuf', choices=['tuf', 'uptane'])
    parser.add_argument('--signature-encoding', help='The encoding for cryptographic signatures',
                        default='hex', choices=['hex', 'base64'])
    parser.add_argument('--compact', help='Write JSON in compact format', action='store_true')
    parser.add_argument('--cjson', help='The formatter to use for canonical JSON',
                        default='olpc', choices=['olpc', 'json-subset'])
    parser.add_argument('--key-type', help='The key type to use',
                        default='ed25519', choices=['ed25519', 'rsa-2048', 'rsa-4096', 'rsa-8192'])
    parser.add_argument(
        '--signature-scheme',
        help='The signature scheme to use',
        default='ed25519',
        choices=[
            'ed25519',
            'rsassa-pss-sha256',
            'rsassa-pss-sha512'])
    args = parser.parse_args()

    main(args.type, args.port,
         args.key_type, args.signature_scheme,
         args.signature_encoding, args.compact, args.cjson)
