#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from argparse import ArgumentParser
from os import path
from tuf_vectors import subclasses
from tuf_vectors.tuf import Tuf
from tuf_vectors.uptane import Uptane


def main(
        repo_type,
        output_dir,
        repo,
        key_type,
        signature_scheme,
        signature_encoding,
        compact,
        cjson_strategy):
    for sub in subclasses(Tuf if repo_type == 'tuf' else Uptane):
        if repo is None or sub.name == repo:
            sub = sub(output_dir, key_type=key_type, signature_scheme=signature_scheme,
                      signature_encoding=signature_encoding,
                      compact=compact, cjson_strategy=cjson_strategy)
            sub.write_static()


if __name__ == '__main__':
    parser = ArgumentParser(path.basename(__file__))
    parser.add_argument('-t', '--type', help='The type of test vectors to create',
                        default='tuf', choices=['tuf', 'uptane'])
    parser.add_argument('-o', '--output-dir', help='The path to write the repos',
                        required=True)
    parser.add_argument('-r', '--repo', help='The repo to generate', default=None)
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

    main(args.type, args.output_dir, args.repo, args.key_type, args.signature_scheme,
         args.signature_encoding, args.compact, args.cjson)
