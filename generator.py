#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from argparse import ArgumentParser
from os import path
from tuf_vectors import subclasses
from tuf_vectors.uptane import Uptane


def main(output_dir,
         key_type,
         signature_scheme,
         signature_encoding,
         compact,
         cjson_strategy,
         ecu_identifier,
         hardware_id):
    for sub in subclasses(Uptane):
        sub = sub(output_dir=output_dir,
                  key_type=key_type,
                  signature_scheme=signature_scheme,
                  signature_encoding=signature_encoding,
                  compact=compact,
                  cjson_strategy=cjson_strategy,
                  ecu_identifier=ecu_identifier,
                  hardware_id=hardware_id)
        sub.persist()


if __name__ == '__main__':
    parser = ArgumentParser(path.basename(__file__))
    parser.add_argument('-o', '--output-dir', help='The path to write the repos',
                        required=True)
    parser.add_argument('--ecu-identifier', help='An ECU identifier for the update')
    parser.add_argument('--hardware-id', help='A hardware identifier for the update')
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

    main(args.output_dir,
         args.key_type,
         args.signature_scheme,
         args.signature_encoding,
         args.compact,
         args.cjson,
         args.ecu_identifier,
         args.hardware_id)
