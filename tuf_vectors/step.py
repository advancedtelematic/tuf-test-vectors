# -*- coding: utf-8 -*-

import json
import os
import sys

from os import path
from tuf_vectors import Generator, sha256, sha512, short_key_type, human_message, ALL_ROLES


class Step(Generator):

    CLASS_SUFFIX = 'Step'

    ROOT_VERSION = 1
    ROOT_EXPIRED = False
    ROOT_KEYS = [0]
    ROOT_KEYS_BAD_IDS = []
    ROOT_KEYS_SIGN = [0]
    ROOT_KEYS_BAD_SIGN = []
    ROOT_THRESHOLD_MOD = 0

    TARGETS_VERSION = 1
    TARGETS_EXPIRED = False
    TARGETS_KEYS = [1]
    TARGETS_KEYS_BAD_IDS = []
    TARGETS_KEYS_SIGN = [1]
    TARGETS_KEYS_BAD_SIGN = []
    TARGETS_THRESHOLD_MOD = 0

    TIMESTAMP_VERSION = 1
    TIMESTAMP_EXPIRED = False
    TIMESTAMP_KEYS = [2]
    TIMESTAMP_KEYS_BAD_IDS = []
    TIMESTAMP_KEYS_SIGN = [2]
    TIMESTAMP_KEYS_BAD_SIGN = []
    TIMESTAMP_THRESHOLD_MOD = 0

    SNAPSHOT_VERSION = 1
    SNAPSHOT_EXPIRED = False
    SNAPSHOT_KEYS = [3]
    SNAPSHOT_KEYS_BAD_IDS = []
    SNAPSHOT_KEYS_SIGN = [3]
    SNAPSHOT_KEYS_BAD_SIGN = []
    SNAPSHOT_THRESHOLD_MOD = 0

    UPDATE_ERROR = None
    TARGETS = [('targets/file.txt', b'wat wat wat', None)]

    def __init__(
            self,
            output_dir,
            step_index,
            key_type,
            signature_scheme,
            signature_encoding,
            compact,
            cjson_strategy,
            uptane_role=None):
        self.index = step_index

        p = path.join(output_dir, str(step_index))
        os.makedirs(p, exist_ok=True)
        self.output_dir = p

        self.key_type = key_type
        self.signature_scheme = signature_scheme
        self.signature_encoding = signature_encoding
        self.compact = compact
        self.cjson_strategy = cjson_strategy
        self.uptane_role = uptane_role

        self.key_store = {}

        self.generate_root()
        self.generate_targets()
        if self.uptane_role != 'director':
            self.generate_snapshot()
            self.generate_timestamp()

        # TODO delegations

    def generate_meta(self) -> dict:
        root_meta = {
            'signatures': [],
            'signed': {
                'consistent_snapshot': False,  # TODO configure
                'version': self.ROOT_VERSION,
                'keys': [],
                'roles': {
                    'root': {
                        'keys': [{'key_index': i} for i in self.ROOT_KEYS],
                        'threshold': len(self.ROOT_KEYS) + self.ROOT_THRESHOLD_MOD
                    },
                    'targets': {
                        'keys': [{'key_index': i} for i in self.TARGETS_KEYS],
                        'threshold': len(self.TARGETS_KEYS) + self.TARGETS_THRESHOLD_MOD
                    },
                },
            },
        }

        if self.uptane_role != 'director':
            root_meta['signed']['roles']['timestamp'] = {
                'keys': [{'key_index': i} for i in self.TIMESTAMP_KEYS],
                'threshold': len(self.TIMESTAMP_KEYS) + self.TIMESTAMP_THRESHOLD_MOD
            }
            root_meta['signed']['roles']['snapshot'] = {
                'keys': [{'key_index': i} for i in self.SNAPSHOT_KEYS],
                'threshold': len(self.SNAPSHOT_KEYS) + self.SNAPSHOT_THRESHOLD_MOD
            }

        keys = []
        keys.extend([{'key_index': i, 'bad_id': i in self.ROOT_KEYS_BAD_IDS}
                     for i in self.ROOT_KEYS])
        keys.extend([{'key_index': i, 'bad_id': i in self.TARGETS_KEYS_BAD_IDS}
                     for i in self.TARGETS_KEYS])
        if self.uptane_role != 'director':
            keys.extend([{'key_index': i, 'bad_id': i in self.TIMESTAMP_KEYS_BAD_IDS}
                         for i in self.TIMESTAMP_KEYS])
            keys.extend([{'key_index': i, 'bad_id': i in self.TARGETS_KEYS_BAD_IDS}
                         for i in self.TARGETS_KEYS])

        root_meta['signed']['keys'] = keys

        targets_meta = {
            'signatures': [],
            'signed': {
                'version': self.TARGETS_VERSION,
                'targets': {
                },
            },
        }

        if self.uptane_role != 'director':
            timestamp_meta = {
                'signatures': [],
                'signed': {
                    'version': self.TIMESTAMP_VERSION,
                    'meta': {
                        'snapshot': {
                            'has_hash': True,
                            'bad_hash': False,
                            'has_length': True,
                            'bad_length': False,
                            'has_version': True,
                            'bad_version': False,
                        },
                    },
                },
            }
            snapshot_meta = {
                'signatures': [],
                'signed': {
                    'version': self.SNAPSHOT_VERSION,
                    'meta': {
                        'root': {
                            'has_hash': True,
                            'bad_hash': False,
                            'has_length': True,
                            'bad_length': False,
                            'has_version': True,
                            'bad_version': False,
                        },
                        'targets': {
                            'has_hash': False,
                            'bad_hash': False,
                            'has_length': False,
                            'bad_length': False,
                            'has_version': True,
                            'bad_version': False,
                        },
                    },
                },
            }

        meta_meta = {
            'root': root_meta,
            'targets': targets_meta,
        }

        if self.uptane_role != 'director':
            meta_meta['timestamp'] = timestamp_meta
            meta_meta['snapshot'] = snapshot_meta

        meta = {
            'server': {
                # TODO directives on how to slow traffic, etc
            },
            'meta': meta_meta,
            # TODO directives for renaming _type
            'update': {
                'is_success': self.UPDATE_ERROR is None,
            },
            'targets': {},
        }

        for meta_key, keys, bads in [('root', self.ROOT_KEYS_SIGN, self.ROOT_KEYS_BAD_SIGN),
                                     ('targets', self.TARGETS_KEYS_SIGN, self.TARGETS_KEYS_BAD_SIGN),
                                     ('timestamp', self.TIMESTAMP_KEYS_SIGN, self.TIMESTAMP_KEYS_BAD_SIGN),
                                     ('snapshot', self.SNAPSHOT_KEYS_SIGN, self.SNAPSHOT_KEYS_BAD_SIGN)]:
            for key_idx in keys:
                key_meta = {
                    'key_index': key_idx,
                    'bad_signature': key_idx in bads,
                }
                meta['meta'][meta_key]['signatures'].append(key_meta)

        for role in ['root', 'targets', 'timestamp', 'snapshot']:
            meta['meta'][role]['signed']['expired'] = \
                bool(getattr(self, '{}_EXPIRED'.format(role.upper())))

        if self.UPDATE_ERROR is not None:
            meta['update']['err'] = self.UPDATE_ERROR
            meta['update']['err_msg'] = human_message(self.UPDATE_ERROR)
        else:
            # don't include targets if we can't update correctly?
            # TODO handle delegation case
            for target, _, alteration in self.TARGETS:
                target_meta = {
                    'bad_hash': alteration == 'bad-hash',
                    'length_too_short': alteration == 'oversized',
                }
                meta['meta']['targets']['signed']['targets'][target] = target_meta

                # TODO need to handle delegation cases, like broken chains, etc.
                target_meta = {
                    'is_success': alteration is None,
                }

                if alteration is not None:
                    if alteration == 'bad-hash':
                        err = 'TargetHashMismatch'
                    elif alteration == 'oversized':
                        err = 'OversizedTarget'
                    else:
                        raise Exception('Unknown alteration: {}'.format(alteration))
                    target_meta['err'] = err
                    target_meta['err_msg'] = human_message(err)

                meta['targets'][target] = target_meta

        return meta

    def write_static(self) -> None:
        self.write_metadata('root.json', self.root)
        self.write_metadata('targets.json', self.targets)

        if self.uptane_role != 'director':
            self.write_metadata('snapshot.json', self.snapshot)
            self.write_metadata('timestamp.json', self.timestamp)
            self.write_targets_content()

    def generate_root(self) -> None:
        signed = {
            '_type': 'Root',
            'version': self.ROOT_VERSION,
            'consistent_snapshot': False,
            'expires': '2017-01-01T00:00:00Z' if self.ROOT_EXPIRED else '2038-01-19T03:14:06Z',
            'keys': {},
            'roles': {
                'root': {
                    'keyids': [self.key_id(self.get_key(i)[1], bad_id=False)
                               for i in self.ROOT_KEYS],
                    'threshold': len(self.ROOT_KEYS) + self.ROOT_THRESHOLD_MOD
                },
                'targets': {
                    'keyids': [self.key_id(self.get_key(i)[1], bad_id=False)
                               for i in self.TARGETS_KEYS],
                    'threshold': len(self.TARGETS_KEYS) + self.TARGETS_THRESHOLD_MOD
                },
                'timestamp': {
                    'keyids': [self.key_id(self.get_key(i)[1], bad_id=False)
                               for i in self.TIMESTAMP_KEYS],
                    'threshold': len(self.TIMESTAMP_KEYS) + self.TIMESTAMP_THRESHOLD_MOD
                },
                'snapshot': {
                    'keyids': [self.key_id(self.get_key(i)[1], bad_id=False)
                               for i in self.SNAPSHOT_KEYS],
                    'threshold': len(self.SNAPSHOT_KEYS) + self.SNAPSHOT_THRESHOLD_MOD
                },
            }
        }

        for key_idx, bad in [(i, i in self.ROOT_KEYS_BAD_IDS) for i in self.ROOT_KEYS] + \
                            [(i, i in self.TARGETS_KEYS_BAD_IDS) for i in self.TARGETS_KEYS] + \
                            [(i, i in self.TIMESTAMP_KEYS_BAD_IDS) for i in self.TIMESTAMP_KEYS] + \
                            [(i, i in self.SNAPSHOT_KEYS_BAD_IDS) for i in self.SNAPSHOT_KEYS]:
            _, pub = self.get_key(key_idx)
            signed['keys'][self.key_id(pub, bad_id=bad)] = {
                'keytype': short_key_type(self.key_type),
                'keyval': {
                    'public': pub
                },
            }

        sig_directives = [(self.get_key(key_idx), key_idx in self.ROOT_KEYS_BAD_SIGN)
                          for key_idx in self.ROOT_KEYS_SIGN]
        self.root = {'signed': signed, 'signatures': self.sign(sig_directives, signed)}

    def generate_targets(self) -> None:
        signed = {
            '_type': 'Targets',
            'version': self.TARGETS_VERSION,
            'expires': '2017-01-01T00:00:00Z' if self.TARGETS_EXPIRED else '2038-01-19T03:14:06Z',
            'targets': {},
        }

        for target, content, alteration in self.TARGETS:
            len_diff = 0
            bad_hash = False

            if alteration is None:
                pass
            elif alteration == 'bad-hash':
                bad_hash = True
            elif alteration == 'oversized':
                len_diff = 1
            else:
                raise Exception('Unknown alteration: {}'.format(alteration))

            # TODO uptane custom
            meta = {
                'length': len(content) - len_diff,
                'hashes': {
                    'sha256': sha256(content, bad_hash=bad_hash),
                    'sha512': sha512(content, bad_hash=bad_hash),
                }
            }

            signed['targets'][target] = meta

        sig_directives = [(self.get_key(i), i in self.TARGETS_KEYS_BAD_SIGN)
                          for i in self.TARGETS_KEYS_SIGN]
        self.targets = {'signed': signed, 'signatures': self.sign(sig_directives, signed)}

    def generate_snapshot(self) -> None:
        root_json = self.jsonify(self.root)

        signed = {
            '_type': 'Snapshot',
            'version': self.SNAPSHOT_VERSION,
            'expires': '2017-01-01T00:00:00Z' if self.SNAPSHOT_EXPIRED else '2038-01-19T03:14:06Z',
            'meta': {
                'root.json': {
                    'version': self.ROOT_VERSION,
                    'length': len(root_json),
                    'hashes': {
                        'sha256': sha256(root_json, bad_hash=False),
                        'sha512': sha512(root_json, bad_hash=False),
                    },
                },
                'targets.json': {
                    'version': self.TARGETS_VERSION,
                },
            },
        }

        sig_directives = [(self.get_key(i), i in self.SNAPSHOT_KEYS_BAD_SIGN)
                          for i in self.SNAPSHOT_KEYS_SIGN]
        self.snapshot = {'signed': signed, 'signatures': self.sign(sig_directives, signed)}

    def generate_timestamp(self) -> None:
        snapshot_json = self.jsonify(self.snapshot)

        signed = {
            '_type': 'Timestamp',
            'version': self.TIMESTAMP_VERSION,
            'expires': '2017-01-01T00:00:00Z' if self.TIMESTAMP_EXPIRED else '2038-01-19T03:14:06Z',
            'meta': {
                'snapshot.json': {
                    'version': self.SNAPSHOT_VERSION,
                    'length': len(snapshot_json),
                    'hashes': {
                        'sha256': sha256(snapshot_json, bad_hash=False),
                        'sha512': sha512(snapshot_json, bad_hash=False),
                    },
                },
            },
        }

        sig_directives = [(self.get_key(i), i in self.TIMESTAMP_KEYS_BAD_SIGN)
                          for i in self.TIMESTAMP_KEYS_SIGN]
        self.timestamp = {'signed': signed, 'signatures': self.sign(sig_directives, signed)}

    def write_targets_content(self) -> None:
        for target, content, _ in self.TARGETS:
            split = target.split('/')
            if len(split) > 1:
                os.makedirs(path.join(self.output_dir, *split[:-1]), exist_ok=True)

            with open(path.join(self.output_dir, *split), 'wb') as f:
                f.write(content)

    def write_metadata(self, role: str, content) -> None:
        with open(path.join(self.output_dir, *role.split('/')), 'w') as f:
            f.write(self.jsonify(content))


class SimpleStep(Step):

    def self_test(self) -> None:
        meta = self.generate_meta()

        assert self.UPDATE_ERROR is None
        assert len(self.TARGETS) == 1

        for role in [r.lower() for r in ALL_ROLES]:
            assert getattr(self, '{}_VERSION'.format(role.upper())) == 1

            assert len(getattr(self, '{}_KEYS'.format(role.upper()))) == 1
            assert len(getattr(self, '{}_KEYS_BAD_IDS'.format(role.upper()))) == 0
            assert len(getattr(self, '{}_KEYS_SIGN'.format(role.upper()))) == 1
            assert len(getattr(self, '{}_KEYS_BAD_SIGN'.format(role.upper()))) == 0

            assert getattr(self, '{}_THRESHOLD_MOD'.format(role.upper())) == 0
            assert meta['meta']['root']['signed']['roles'][role]['threshold'] == 1

            assert len(getattr(self, role)['signatures']) == 1
            assert len(meta['meta'][role]['signatures']) == 1

            assert getattr(self, role)['signed']['expires'].startswith('2038')
            assert meta['meta'][role]['signed']['expired'] == False

            assert len(meta['targets']) == 1
            assert list(meta['targets'].items())[0][1]['is_success'] is True


for _role in ALL_ROLES:
    def gen_test():
        role = _role

        def self_test(self) -> None:
            meta = self.generate_meta()

            assert getattr(self, '{}_EXPIRED'.format(role.upper()))
            assert getattr(self, role.lower())['signed']['expires'].startswith('2017')
            assert meta['meta'][role.lower()]['signed']['expired']

            err = 'ExpiredMetadata::{}'.format(role)
            assert self.UPDATE_ERROR == err
            assert meta['update']['is_success'] == False
            assert meta['update']['err'] == err
        return self_test

    fields = {
        'self_test': gen_test(),
        'UPDATE_ERROR': 'ExpiredMetadata::{}'.format(_role),
        '{}_EXPIRED'.format(_role.upper()): True
    }

    name = _role + 'ExpiredStep'
    setattr(sys.modules[__name__], name, type(name, (Step,), fields))


for _role in ALL_ROLES:
    def gen_test():
        role = _role

        def self_test(self) -> None:
            meta = self.generate_meta()

            assert len(getattr(self, '{}_KEYS'.format(role.upper()))) == 2
            assert len(meta['meta'][role.lower()]['signatures']) == 1
            assert len(self.root['signed']['roles'][role.lower()]['keyids']) == 2
            assert self.root['signed']['roles'][role.lower()]['threshold'] == 2

            err = 'UnmetThreshold::{}'.format(role)
            assert self.UPDATE_ERROR == err
            assert not meta['update']['is_success'] is True
            assert meta['update']['err'] == err
        return self_test

    fields = {
        'self_test': gen_test(),
        'UPDATE_ERROR': 'UnmetThreshold::{}'.format(_role),
        '{}_KEYS'.format(_role.upper()): getattr(Step, '{}_KEYS'.format(_role.upper())) + [5],
    }

    name = _role + 'UnmetThresholdStep'
    setattr(sys.modules[__name__], name, type(name, (Step,), fields))


for _role in ALL_ROLES:
    def gen_test():
        role = _role

        def self_test(self) -> None:
            meta = self.generate_meta()

            assert len(getattr(self, '{}_KEYS'.format(role.upper()))) == 1
            assert len(getattr(self, '{}_KEYS_SIGN'.format(role.upper()))) == 2
            assert len(set(getattr(self, '{}_KEYS_SIGN'.format(role.upper())))) == 1
            assert len(meta['meta'][role.lower()]['signatures']) == 2
            assert len(set(x['key_index'] for x in meta['meta'][role.lower()]['signatures'])) == 1

            err = 'NonUniqueSignatures::{}'.format(role)
            assert self.UPDATE_ERROR == err
            assert meta['update']['is_success'] == False
            assert meta['update']['err'] == err
        return self_test

    fields = {
        'self_test': gen_test(),
        'UPDATE_ERROR': 'NonUniqueSignatures::{}'.format(_role),
        '{}_KEYS_SIGN'.format(_role.upper()): getattr(Step, '{}_KEYS'.format(_role.upper())) * 2,
    }

    name = _role + 'NonUniqueSignaturesStep'
    setattr(sys.modules[__name__], name, type(name, (Step,), fields))


for _role in ALL_ROLES:
    def gen_test():
        role = _role

        def self_test(self) -> None:
            meta = self.generate_meta()

            assert getattr(self, '{}_THRESHOLD_MOD'.format(role.upper())) == -1
            assert self.root['signed']['roles'][role.lower()]['threshold'] == 0

            for r in ALL_ROLES:
                assert meta['meta']['root']['signed']['roles'][r.lower()]['threshold'] == \
                    0 if r.lower() == role.lower() else 1

            err = 'IllegalThreshold::{}'.format(role)
            assert self.UPDATE_ERROR == err
            assert meta['update']['is_success'] == False
            assert meta['update']['err'] == err
        return self_test

    fields = {
        'self_test': gen_test(),
        'UPDATE_ERROR': 'IllegalThreshold::{}'.format(_role),
        '{}_THRESHOLD_MOD'.format(_role.upper()): -1 * len(getattr(Step, '{}_KEYS'.format(_role.upper()))),
    }

    name = _role + 'ZeroThresholdStep'
    setattr(sys.modules[__name__], name, type(name, (Step,), fields))


for _role in ALL_ROLES:
    def gen_test():
        role = _role

        def self_test(self) -> None:
            meta = self.generate_meta()

            assert getattr(self, '{}_THRESHOLD_MOD'.format(role.upper())) == -2
            assert self.root['signed']['roles'][role.lower()]['threshold'] == -1

            for r in ALL_ROLES:
                assert meta['meta']['root']['signed']['roles'][r.lower()]['threshold'] == \
                    -1 if r.lower() == role.lower() else 1

            err = 'IllegalThreshold::{}'.format(role)
            assert self.UPDATE_ERROR == err
            assert meta['update']['is_success'] == False
            assert meta['update']['err'] == err
        return self_test

    fields = {
        'self_test': gen_test(),
        'UPDATE_ERROR': 'IllegalThreshold::{}'.format(_role),
        '{}_THRESHOLD_MOD'.format(_role.upper()): -1 - len(getattr(Step, '{}_KEYS'.format(_role.upper()))),
    }

    name = _role + 'NegativeThresholdStep'
    setattr(sys.modules[__name__], name, type(name, (Step,), fields))


class TargetHashMismatchStep(Step):

    TARGETS = [('targets/file.txt', b'wat wat wat', 'bad-hash')]

    def self_test(self) -> None:
        meta = self.generate_meta()
        assert meta['targets']['targets/file.txt']['is_success'] == False
        assert meta['targets']['targets/file.txt']['err'] == 'TargetHashMismatch'
        assert meta['meta']['targets']['signed']['targets']['targets/file.txt']['bad_hash'] is True


class OversizedTargetStep(Step):

    TARGETS = [('targets/file.txt', b'wat wat wat', 'oversized')]

    def self_test(self) -> None:
        meta = self.generate_meta()
        assert meta['targets']['targets/file.txt']['is_success'] == False
        assert meta['targets']['targets/file.txt']['err'] == 'OversizedTarget'
        assert meta['meta']['targets']['signed']['targets'][
            'targets/file.txt']['length_too_short'] is True
