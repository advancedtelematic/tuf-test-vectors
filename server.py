#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

from argparse import ArgumentParser
from os import path
from tuf_vectors.server import init_app


def main():
    args = arg_parser().parse_args()

    app = init_app(
        key_type=args.key_type,
        signature_scheme=args.signature_scheme,
        signature_encoding=args.signature_encoding,
        compact=args.compact,
        cjson_strategy=args.cjson,
        ecu_identifier=args.ecu_identifier,
        hardware_id=args.hardware_id)
    app.run(host=args.host, port=args.port, debug=args.debug)


def arg_parser():
    parser = ArgumentParser(path.basename(__file__),
                            description='Runs a TUF repo HTTP server')
    parser.add_argument('-H', '--host', help='Interface to bind the app to',
                        default='127.0.0.1')
    parser.add_argument('-P', '--port', help='The port to bind the app to',
                        type=int, default=8080)
    parser.add_argument('--debug', help='Run the server in debug mode',
                        action='store_true')

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
    parser.add_argument('--hardware-id', help="The ECU's hardware ID", required=True)
    parser.add_argument('--ecu-identifier', help="The ECU's unique identifier", required=True)

    return parser


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('')  # to get prompt on a newline
        sys.exit(1)
