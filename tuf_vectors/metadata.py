# -*- coding: utf-8 -*-

import base64
import binascii
import ed25519
import json
import os
import types

from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from os import path
from securesystemslib.formats import encode_canonical as olpc_cjson

from tuf_vectors import sha256, sha512, _cjson_subset_check, short_key_type

SKIPPED_DELEGATION_NAME = 'skipped'


class Helper:

    def __init__(self, key_type: str, cjson_strategy: str, **kwargs) -> None:
        self.key_type = key_type
        self.cjson_strategy = cjson_strategy
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


class Delegation(Helper):
    # Delegatation metadata as specified in the delegation's parent Targets
    # object.

    def __init__(
            self,
            keys_idx: list = None,
            bad_key_ids: list = None,
            role: list = None,
            **kwargs) -> None:
        super().__init__(**kwargs)
        self.value = {
            'keys': keys_idx,
            'bad_key_ids': bad_key_ids,
            'role': role,
        }


class Role(Helper):
    # Delegated role as specified in Targets metadata.

    def __init__(
            self,
            keys_idx: list,
            name: str,
            paths: list,
            terminating: bool = False,
            threshold: int = None,
            **kwargs) -> None:
        super().__init__(**kwargs)
        self.name = name
        self.value = {
            'keyids': [self.key_id(self.get_key(i)[1], bad_id=False) for i in keys_idx],
            'name': name,
            'paths': paths,
            'terminating': terminating,
            'threshold': threshold if threshold is not None else len(keys_idx),
        }


class Target:

    def __init__(
            self,
            name: str,
            content: bytes,
            hardware_id: str,
            do_write: bool = True,
            alteration: str = None,
            ecu_identifier: str = None,
            ) -> None:
        self.name = name
        self.content = content
        self.do_write = do_write

        bad_hash = False
        size_mod = 0
        bad_ecu_id = False
        bad_hw_id = False

        if alteration is None:
            pass
        elif alteration == 'bad-hash':
            bad_hash = True
        elif alteration == 'oversized':
            size_mod = -1
        elif alteration == 'bad-ecu-id':
            if ecu_identifier is None:
                raise ValueError('Tried to modify ECU ID with no ECU ID')
            bad_ecu_id = True
        elif alteration == 'bad-hw-id':
            bad_hw_id = True
        else:
            raise ValueError('Unknown alteration: {}'.format(alteration))

        self.meta = {
            'length': len(content) + size_mod,
            'hashes': {
                'sha256': sha256(content, bad_hash=bad_hash),
                'sha512': sha512(content, bad_hash=bad_hash),
            },
            'custom': {},
        }

        if ecu_identifier is None:
            # Only used by Image repo metadata.
            self.meta['custom'] = {
                'hardwareIds': [hardware_id + ('-XXX' if bad_hw_id else ''), ],
            }
        else:
            # Only used by Director metadata.
            ecu_identifier = ecu_identifier + ('-XXX' if bad_ecu_id else '')
            self.meta['custom']['ecuIdentifiers'] = {
                ecu_identifier: {
                    'hardwareId': hardware_id + ('-XXX' if bad_hw_id else ''),
                },
            }

    def persist(self, output_dir: str) -> None:
        if self.do_write:
            full_path = path.join(output_dir, self.name)
            with open(full_path, 'wb') as f:
                f.write(self.content)


class Metadata(Helper):

    def __init__(
            self,
            step_index: int,
            output_dir: str,
            signature_scheme: str,
            signature_encoding: str,
            compact: bool,
            uptane_role: str,
            ecu_identifier: str,
            hardware_id: str,
            is_delegation: bool = False,
            **kwargs
            ) -> None:
        super().__init__(**kwargs)
        self.step_index = step_index

        p = path.join(output_dir, str(step_index))
        os.makedirs(p, exist_ok=True)
        self.output_dir = p

        self.signature_scheme = signature_scheme
        self.signature_encoding = signature_encoding
        self.compact = compact
        self.uptane_role = uptane_role
        self.ecu_identifier = ecu_identifier
        self.hardware_id = hardware_id
        self.is_delegation = is_delegation

    def jsonify(self, jsn) -> str:
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
        if self.is_delegation:
            full_path = path.join(self.output_dir, self.uptane_role, 'delegations', self.role_name + '.json')
        elif self.role_name == 'root':
            full_path = path.join(self.output_dir, self.uptane_role, str(self.version) + '.' + self.role_name + '.json')
        else:
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
            root_sign_keys_idx: list = None,
            targets_keys_idx: list = None,
            snapshot_keys_idx: list = None,
            timestamp_keys_idx: list = None,
            root_threshold: int = None,
            targets_threshold: int = None,
            snapshot_threshold: int = None,
            timestamp_threshold: int = None,
            root_bad_key_ids: list = None,
            targets_bad_key_ids: list = None,
            snapshot_bad_key_ids: list = None,
            timestamp_bad_key_ids: list = None,
            stated_version: int = None,
            **kwargs) -> None:
        super().__init__(is_delegation=False, **kwargs)
        self.role_name = 'root'
        self.version = version
        if stated_version is None:
            stated_version = version

        if root_sign_keys_idx is None:
            root_sign_keys_idx = root_keys_idx

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
            '_type': kwargs.get('_type', 'Root'),
            'version': stated_version,
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
            signed['roles']['snapshot'] = {
                'keyids': [self.key_id(self.get_key(i)[1], bad_id=False)
                           for i in snapshot_keys_idx],
                'threshold': snapshot_threshold,
            }
            signed['roles']['timestamp'] = {
                'keyids': [self.key_id(self.get_key(i)[1], bad_id=False)
                           for i in timestamp_keys_idx],
                'threshold': timestamp_threshold,
            }
            all_keys.extend(snapshot_keys_idx + timestamp_keys_idx)

        bad_key_ids = ((root_bad_key_ids or []) +
                       (targets_bad_key_ids or []) +
                       (snapshot_bad_key_ids or []) +
                       (timestamp_bad_key_ids or []))

        for key_idx in all_keys:
            _, pub = self.get_key(key_idx)
            bad_id = key_idx in bad_key_ids
            signed['keys'][self.key_id(pub, bad_id=bad_id)] = {
                'keytype': short_key_type(self.key_type),
                'keyval': {
                    'public': pub,
                },
            }

        sig_directives = [(self.get_key(i), False) for i in root_sign_keys_idx]

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
            timestamp_sign_keys_idx: list = None,
            **kwargs) -> None:
        super().__init__(is_delegation=False, **kwargs)
        self.role_name = 'timestamp'

        if timestamp_sign_keys_idx is None:
            timestamp_sign_keys_idx = timestamp_keys_idx

        if snapshot_version is None:
            snapshot_version = snapshot['signed']['version']

        snapshot_json = self.cjson(snapshot)

        signed = {
            '_type': kwargs.get('_type', 'Timestamp'),
            'version': 1,  # TODO
            'expires': '2017-01-01T00:00:00Z' if is_expired else '2038-01-19T03:14:06Z',
            'meta': {
                'snapshot.json': {
                    'version': snapshot_version,
                    'length': len(self.jsonify(snapshot)),  # Server returns snapshot.json with self.jsonify
                    'hashes': {
                        'sha256': sha256(snapshot_json, bad_hash=False),
                        'sha512': sha512(snapshot_json, bad_hash=False),
                    },
                },
            },
        }

        sig_directives = [(self.get_key(i), i in timestamp_keys_bad_sign_idx)
                          for i in timestamp_sign_keys_idx]
        self.value = {'signed': signed, 'signatures': self.sign(sig_directives, signed)}


class Snapshot(Metadata):

    def __init__(
            self,
            version: int,
            is_expired: bool,
            snapshot_keys_idx: list,
            targets: dict,
            delegations: dict,  # role_name -> contents_dict
            snapshot_sign_keys_idx: list = None,
            targets_version: int = None,
            add_targets_hash_and_length: bool = False,
            **kwargs) -> None:
        super().__init__(is_delegation=False, **kwargs)
        self.role_name = 'snapshot'

        if snapshot_sign_keys_idx is None:
            snapshot_sign_keys_idx = snapshot_keys_idx

        if targets_version:
            targets_version = targets_version
        else:
            targets_version = targets['signed']['version']

        signed = {
            '_type': kwargs.get('_type', 'Snapshot'),
            'version': version,
            'expires': '2017-01-01T00:00:00Z' if is_expired else '2038-01-19T03:14:06Z',
            'meta': {
                'targets.json': {
                    'version': targets_version,
                },
            },
        }

        if add_targets_hash_and_length:
            targets_content = self.cjson(targets).encode('utf-8')
            signed['meta']['targets.json']['hashes'] = {
                'sha256': sha256(targets_content, False),
            }
            signed['meta']['targets.json']['length'] = len(targets_content)

        for (name, meta) in delegations.items():
            if name == SKIPPED_DELEGATION_NAME:
                continue

            if meta.snapshot_version:
                delegation_version = meta.snapshot_version
            else:
                delegation_version = meta.value['signed']['version']

            signed['meta'][name + '.json'] = {
                'version': delegation_version,
            }

        sig_directives = [(self.get_key(i), False) for i in snapshot_sign_keys_idx]

        self.value = {'signed': signed, 'signatures': self.sign(sig_directives, signed)}


class Targets(Metadata):

    def __init__(
            self,
            version: int,
            is_expired: bool,
            targets_keys_idx: list,
            targets: types.FunctionType,
            hardware_id: str,
            targets_sign_keys_idx: list = None,
            role_name: str = 'targets',
            ecu_identifier: str = None,
            delegations: types.FunctionType = None,  # -> list
            is_delegation: bool = False,
            snapshot_version: int = None,  # only works for delegations
            **kwargs) -> None:
        # add these back in for Metadata
        kwargs.update(hardware_id=hardware_id, ecu_identifier=ecu_identifier, is_delegation=is_delegation)
        super().__init__(**kwargs)

        if delegations is not None:
            delegations = delegations(**kwargs)
        else:
            delegations = []

        if targets_sign_keys_idx is None:
            targets_sign_keys_idx = targets_keys_idx

        self.role_name = role_name
        self.targets = targets(hardware_id, ecu_identifier)
        self.__uptane_role = kwargs['uptane_role']
        self.snapshot_version = snapshot_version

        signed = {
            '_type': kwargs.get('_type', 'Targets'),
            'expires': '2017-01-01T00:00:00Z' if is_expired else '2038-01-19T03:14:06Z',
            'version': version,
            'targets': {},
        }

        for target in self.targets:
            signed['targets'][target.name] = target.meta

        too_large = kwargs.get('too_large', None)
        if too_large == 'TRUE':
            for i in range(1, 1024*30):
                signed['targets'][target.name + str(i)] = target.meta

        if delegations:
            signed['delegations'] = {}
            signed['delegations']['keys'] = {}
            signed['delegations']['roles'] = []
            for delegation in delegations:
                signed['delegations']['roles'].append(delegation.value['role'].value)

                if delegation.value['keys']:
                    for key_idx in delegation.value['keys']:
                        _, pub = self.get_key(key_idx)
                        bad_id = delegation.value['bad_key_ids'] and key_idx in delegation.value['bad_key_ids']
                        signed['delegations']['keys'][self.key_id(pub, bad_id=bad_id)] = {
                            'keytype': short_key_type(self.key_type),
                            'keyval': {
                                'public': pub,
                            },
                        }

        sig_directives = [(self.get_key(i), False) for i in targets_sign_keys_idx]

        self.value = {'signed': signed, 'signatures': self.sign(sig_directives, signed)}

    def persist(self) -> None:
        super().persist()
        if self.__uptane_role == 'image_repo':
            for target in self.targets:
                target.persist(path.join(self.output_dir, 'image_repo'))
