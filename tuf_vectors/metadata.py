# -*- coding: utf-8 -*-

import base64
import binascii
import ed25519
import json
import os

from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from os import path
from securesystemslib.formats import encode_canonical as olpc_cjson

from tuf_vectors import sha256, sha512, _cjson_subset_check, short_key_type


class Target:

    def __init__(
            self,
            name: str,
            content: bytes,
            do_write: bool=True,
            alteration: str=None,
            ) -> None:
        self.name = name
        self.content = content
        self.do_write = do_write
        self.meta = {
            'size': len(content),
            'hashes': {
                'sha256': sha256(content, bad_hash=False),
                'sha512': sha512(content, bad_hash=False),
            },
        }

    def persist(self, output_dir: str) -> None:
        if self.do_write:
            full_path = path.join(output_dir, self.name)
            with open(full_path, 'wb') as f:
                f.write(self.content)


class Metadata:

    def __init__(
            self,
            step_index,
            output_dir,
            key_type,
            signature_scheme,
            signature_encoding,
            compact,
            cjson_strategy,
            uptane_role,
            ecu_identifier,
            hardware_id) -> None:

        self.step_index = step_index

        p = path.join(output_dir, str(step_index))
        os.makedirs(p, exist_ok=True)
        self.output_dir = p

        self.key_type = key_type
        self.signature_scheme = signature_scheme
        self.signature_encoding = signature_encoding
        self.compact = compact
        self.cjson_strategy = cjson_strategy
        self.uptane_role = uptane_role
        self.ecu_identifier = ecu_identifier
        self.hardware_id = hardware_id

        self.key_store = {}

    def get_key(self, key_idx) -> (str, str):
        '''Returns 2-tuple of priv/pub key'''
        try:
            (priv, pub) = self.key_store[key_idx]
        except KeyError:
            path_base = path.join(path.dirname(__file__), os.pardir, 'keys',
                                  '{}-{}.'.format(self.key_type, key_idx))
            with open('{}priv'.format(path_base)) as f:
                priv = f.read()

            with open('{}pub'.format(path_base)) as f:
                pub = f.read()

            self.key_store[key_idx] = (priv, pub)

        return (priv, pub)

    def key_id(self, pub: str, bad_id: bool) -> str:
        return sha256(self.cjson(pub).encode('utf-8'), bad_id)

    def cjson(self, jsn) -> str:
        if self.cjson_strategy == 'olpc':
            return olpc_cjson(jsn)
        elif self.cjson_strategy == 'json-subset':
            _cjson_subset_check(jsn)
            return json.dumps(jsn, sort_keys=True, separators=(',', ':'))
        else:
            raise ValueError('{} is not a valid CJSON strategy'.format(self.cjson_strategy))

    def jsonify(self, jsn):
        kwargs = {'sort_keys': True, }

        if not self.compact:
            kwargs['indent'] = 2
        else:
            kwargs['separators'] = (',', ':')

        out = json.dumps(jsn, **kwargs)

        if not self.compact:
            out += '\n'

        return out

    def sign(self, sig_directives, signed) -> list:
        data = self.cjson(signed).encode('utf-8')

        sigs = []
        for (priv, pub), bad_sig in sig_directives:
            if self.signature_scheme == 'ed25519':
                priv = ed25519.SigningKey(binascii.unhexlify(priv))
                sig = priv.sign(data)
            elif self.signature_scheme.startswith('rsa'):
                if self.signature_scheme == 'rsassa-pss-sha256':
                    h = SHA256.new(data)
                elif self.signature_scheme == 'rsassa-pss-sha512':
                    h = SHA512.new(data)
                else:
                    raise Exception('Unknown signature scheme: {}'.format(self.signature_scheme))

                rsa = RSA.importKey(priv)
                signer = PKCS1_PSS.new(rsa)
                sig = signer.sign(h)
            else:
                raise Exception('Unknow signature scheme: {}'.format(self.signature_scheme))

            if bad_sig:
                sig[0] ^= 0x01

            sig_data = {
                'keyid': self.key_id(pub, bad_id=False),
                'method': self.signature_scheme,
                'sig': self.encode_signature(sig),
            }
            sigs.append(sig_data)

        return sigs

    def encode_signature(self, sig) -> str:
        if self.signature_encoding == 'hex':
            return binascii.hexlify(sig).decode('utf-8')
        elif self.signature_encoding == 'base64':
            return base64.b64encode(sig).decode('utf-8')
        else:
            raise ValueError('Invalid signature encoding: {}'.format(self.signature_encoding))

    def persist(self) -> None:
        full_path = path.join(self.output_dir, self.uptane_role, self.role_name + '.json')
        os.makedirs(path.dirname(full_path), exist_ok=True)
        with open(full_path, 'w') as f:
            f.write(self.jsonify(self.value))


class Root(Metadata):

    def __init__(
            self,
            version: int,
            is_expired: bool,
            root_keys_idx: list,
            targets_keys_idx: list,
            snapshot_keys_idx: list=None,
            timestamp_keys_idx: list=None,
            root_threshold: int=None,
            targets_threshold: int=None,
            snapshot_threshold: int=None,
            timestamp_threshold: int=None,
            **kwargs) -> None:
        self.role_name = 'root'
        super().__init__(**kwargs)

        if root_threshold is None:
            root_threshold = len(root_keys_idx)

        if targets_threshold is None:
            targets_threshold = len(targets_keys_idx)

        if self.uptane_role == 'image_repo':
            if snapshot_threshold is None:
                snapshot_threshold = len(snapshot_keys_idx)

            if timestamp_threshold is None:
                timestamp_threshold = len(timestamp_keys_idx)

        if self.uptane_role == 'image_repo':
            if not snapshot_keys_idx:
                raise ValueError('image_repo needs snapshot keys')
            if not timestamp_keys_idx:
                raise ValueError('image_repo needs timestamp keys')

        signed = {
            '_type': 'Root',
            'version': version,
            'expires': '2017-01-01T00:00:00Z' if is_expired else '2038-01-19T03:14:06Z',
            'consistent_snapshot': False,
            'keys': {},
            'roles': {
                'root': {
                    'keyids': [self.key_id(self.get_key(i)[1], bad_id=False)
                               for i in root_keys_idx],
                    'threshold': root_threshold,
                },
                'targets': {
                    'keyids': [self.key_id(self.get_key(i)[1], bad_id=False)
                               for i in targets_keys_idx],
                    'threshold': targets_threshold,
                },
            },
        }

        all_keys = root_keys_idx + targets_keys_idx

        if self.uptane_role == 'image_repo':
            # TODO
            signed['roles']['snapshot'] = {
                'keyids': [self.key_id(self.get_key(i)[1], bad_id=False)
                           for i in root_keys_idx],
                'threshold': root_threshold,
            }
            signed['roles']['timestamp'] = {
                'keyids': [self.key_id(self.get_key(i)[1], bad_id=False)
                           for i in timestamp_keys_idx],
                'threshold': timestamp_threshold,
            }
            all_keys.extend(snapshot_keys_idx + timestamp_keys_idx)

        for key_idx in all_keys:
            _, pub = self.get_key(key_idx)
            signed['keys'][self.key_id(pub, bad_id=False)] = {
                'keytype': short_key_type(self.key_type),
                'keyval': {
                    'public': pub,
                },
            }

        sig_directives = [(self.get_key(i), False) for i in root_keys_idx]

        self.value = {'signed': signed, 'signatures': self.sign(sig_directives, signed)}


class Timestamp(Metadata):

    def __init__(
            self,
            snapshot: dict,
            timestamp_keys_idx: list,
            timestamp_keys_bad_sign_idx: list,
            timestamp_version: int,
            is_expired: bool,
            snapshot_version: int,
            **kwargs) -> None:
        super().__init__(**kwargs)
        self.role_name = 'timestamp'

        if snapshot_version is None:
            snapshot_version = snapshot['signed']['version']

        snapshot_json = self.jsonify(snapshot)

        signed = {
            '_type': 'Timestamp',
            'version': 1,  # TODO
            'expires': '2017-01-01T00:00:00Z' if is_expired else '2038-01-19T03:14:06Z',
            'meta': {
                'snapshot.json': {
                    'version': snapshot_version,
                    'length': len(snapshot_json),
                    'hashes': {
                        'sha256': sha256(snapshot_json, bad_hash=False),
                        'sha512': sha512(snapshot_json, bad_hash=False),
                    },
                },
            },
        }

        sig_directives = [(self.get_key(i), i in timestamp_keys_bad_sign_idx)
                          for i in timestamp_keys_idx]
        self.value = {'signed': signed, 'signatures': self.sign(sig_directives, signed)}


class Snapshot(Metadata):

    def __init__(
            self,
            version: int,
            is_expired: bool,
            snapshot_keys_idx: list,
            targets: dict,
            delegations: dict,
            **kwargs) -> None:
        super().__init__(**kwargs)
        self.role_name = 'snapshot'

        # TODO manipulate version
        targets_version = targets['signed']['version']
        targets_json = self.jsonify(targets)

        signed = {
            '_type': 'Snapshot',
            'version': version,
            'expires': '2017-01-01T00:00:00Z' if is_expired else '2038-01-19T03:14:06Z',
            'meta': {
                'targets.json': {
                    'hashes': {
                        'sha256': sha256(targets_json, bad_hash=False),
                        'sha512': sha512(targets_json, bad_hash=False),
                    },
                    'length': len(targets_json),
                    'version': targets_version,
                },
            },
        }

        for (name, meta) in delegations.items():
            delegation_json = self.jsonify(meta)
            signed['meta'][name] = {
                'hashes': {
                    'sha256': sha256(delegation_json, bad_hash=False),
                    'sha512': sha512(delegation_json, bad_hash=False),
                },
                'length': len(delegation_json),
                'version': meta['signed']['version'],  # TODO manipulate version
             }

        sig_directives = [(self.get_key(i), False) for i in snapshot_keys_idx]

        self.value = {'signed': signed, 'signatures': self.sign(sig_directives, signed)}


class Targets(Metadata):

    def __init__(
            self,
            version: int,
            is_expired: bool,
            targets_keys_idx: list,
            targets: list,
            role_name: str='targets',
            **kwargs) -> None:
        super().__init__(**kwargs)
        self.role_name = role_name
        self.targets = targets
        self.__uptane_role = kwargs['uptane_role']

        signed = {
            '_type': 'Targets',
            'expires': '2017-01-01T00:00:00Z' if is_expired else '2038-01-19T03:14:06Z',
            'version': version,
            'targets': {},
        }

        for target in targets:
            signed['targets'][target.name] = target.meta

        sig_directives = [(self.get_key(i), False) for i in targets_keys_idx]

        self.value = {'signed': signed, 'signatures': self.sign(sig_directives, signed)}

    def persist(self) -> None:
        super().persist()
        if self.__uptane_role == 'image_repo':
            for target in self.targets:
                target.persist(path.join(self.output_dir, 'image_repo'))