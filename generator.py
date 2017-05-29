#!/usr/bin/env python3

from os import path

# activate the virtual environment
activate_this = path.join(path.abspath(path.dirname(__file__)),
                          path.join('venv', 'bin', 'activate_this.py'))
with open(activate_this) as f:
    code = compile(f.read(), activate_this, 'exec')
    exec(code, dict(__file__=activate_this))


import base64
import binascii
import ed25519
import hashlib
import json
import logging
import migrate
import os

from argparse import ArgumentParser
from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from securesystemslib.formats import encode_canonical as cjson

SIGNATURE_ENCODING = None
OUTPUT_DIR = None
COMPACT_JSON = False


def log():
    log = logging.getLogger(__name__)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)
    return log

log = log()


def main(repo_type, signature_encoding, output_dir, target_repo=None, compact=False):
    migrate.migrate(repo_type, output_dir, log)

    global SIGNATURE_ENCODING, OUTPUT_DIR, COMPACT_JSON
    SIGNATURE_ENCODING = signature_encoding
    OUTPUT_DIR = output_dir
    COMPACT_JSON = bool(compact)

    vector_meta = {'version': migrate.CURRENT_VERSION,
                   'vectors': []
                   }

    for repo in subclasses(Repo if repo_type == 'tuf' else Uptane):
        vector_meta['vectors'].append(repo.vector_meta())

        if target_repo is not None and repo.NAME != target_repo:
            continue

        log.info('Generating {} repo {}'.format(repo_type, repo.NAME))
        repo = repo()
        log.info('Repo {} done'.format(repo.NAME))

    with open(path.join(OUTPUT_DIR, 'vector-meta.json'), 'w') as f:
        f.write(jsonify(vector_meta))


def subclasses(cls) -> list:
    '''Returns a sorted list of all Repo/Uptane subclasses. Elements are unique.
    '''
    def inner(c):
        return c.__subclasses__() + [g for s in c.__subclasses__()
                                     for g in inner(s)]

    # filter is to ignore unnamed inner classes
    return sorted(list(set(filter(lambda x: hasattr(x, 'NAME'),
                                  inner(cls)))),
                  key=lambda x: x.NAME)


def sha256(byts, alter=False) -> str:
    h = hashlib.sha256()
    h.update(byts)
    d = h.digest()

    if alter:
        d = bytearray(d)
        d[0] ^= 0x01
        d = bytes(d)

    return binascii.hexlify(d).decode('utf-8')


def sha512(byts, alter=False) -> str:
    h = hashlib.sha512()
    h.update(byts)
    d = h.digest()

    if alter:
        d = bytearray(d)
        d[0] ^= 0x01
        d = bytes(d)

    return binascii.hexlify(d).decode('utf-8')


def key_id(pub, alter=False) -> str:
    if alter:
        byts = bytearray(cjson(pub).encode('utf-8'))
        byts[0] ^= 0x01
        return sha256(bytes(byts))
    else:
        return sha256(cjson(pub).encode('utf-8'))


def key_type(sig_method) -> str:
    if sig_method == 'ed25519':
        return 'ed25519'
    elif sig_method == 'rsassa-pss-sha256':
        return 'rsa'
    elif sig_method == 'rsassa-pss-sha512':
        return 'rsa'
    else:
        raise Exception('unknown signature method: {}'.format(sig_method))


def jsonify(jsn) -> str:
    global COMPACT_JSON
    kwargs = {'sort_keys': True, }

    if not COMPACT_JSON:
        kwargs['indent'] = 2

    out = json.dumps(jsn, **kwargs)

    if not COMPACT_JSON:
        out += '\n'

    return out


def human_message(err) -> str:
    if err == 'TargetHashMismatch':
        return "The target's calculated hash did not match the hash in the metadata."
    elif err == 'OversizedTarget':
        return "The target's size was greater than the size in the metadata."
    elif '::' in err:
        err_base, err_sub = err.split('::')

        if err_base == 'MissingRepo':
            assert err_sub in ['Director', 'Repo'], err_sub
            return 'The {} repo is missing.'.format(err_sub.lower())

        assert err_sub in ['Root', 'Targets', 'Timestamp', 'Snapshot'], err_sub

        if err_base == 'ExpiredMetadata':
            return "The {} metadata was expired.".format(err_sub.lower())
        elif err_base == 'UnmetThreshold':
            return "The {} metadata had an unmet threshold.".format(err_sub.lower())
        elif err_base == 'MetadataHashMismatch':
            return  "The {} metadata's hash did not match the hash in the metadata." \
                    .format(err_sub.lower())
        elif err_base == 'OversizedMetadata':
            return  "The {} metadata's size was greater than the size in the metadata." \
                    .format(err_sub.lower())
        elif err_base == 'IllegalThreshold':
            return 'The role {} had an illegal signature threshold.'.format(err_sub.lower())
        else:
            raise Exception('Unknown err: {}'.format(err_base))
    else:
        raise Exception('Unknown err: {}'.format(err))


def encode_signature(sig) -> str:
    global SIGNATURE_ENCODING

    if SIGNATURE_ENCODING == 'hex':
        return binascii.hexlify(sig).decode('utf-8')
    elif SIGNATURE_ENCODING == 'base64':
        return base64.b64encode(sig).decode('utf-8')
    else:
        raise Exception('Invalid signature encoding: {}'.format(SIGNATURE_ENCODING))


def sign(keys, signed) -> list:
    data = cjson(signed).encode('utf-8')

    sigs = []
    for sig_method, priv, pub in keys:
        if sig_method == 'ed25519':
            priv = ed25519.SigningKey(binascii.unhexlify(priv))
            sig = priv.sign(data)
        elif sig_method.startswith('rsassa-pss'):
            if sig_method == 'rsassa-pss-sha256':
                h = SHA256.new(data)
            elif sig_method == 'rsassa-pss-sha512':
                h = SHA512.new(data)
            else:
                raise Exception('Bad sig method: {}'.format(sig_method))

            rsa = RSA.importKey(priv)
            signer = PKCS1_PSS.new(rsa)
            sig = signer.sign(h)
        else:
            raise Exception('unknown signature method: {}'.format(sig_method))

        sig_data = {
            'keyid': key_id(pub),
            'method': sig_method,
            'sig': encode_signature(sig),
        }
        sigs.append(sig_data)

    return sigs


class Repo:

    '''The error that TUF should encounter, if any. None implies success.
    '''
    ERROR = None

    '''The name of the metadata that is expired.
    '''
    EXPIRED = None

    '''The signature methods for the root keys.
    '''
    ROOT_KEYS = {'versions': [[1]],
                 'keys': ['ed25519'],
                 }

    '''The signature methods for the targets keys.
    '''
    TARGETS_KEYS = [['ed25519']]

    '''The signature methods for the timestamp keys.
    '''
    TIMESTAMP_KEYS = [['ed25519']]

    '''The signature methods for the snapshot keys.
    '''
    SNAPSHOT_KEYS = [['ed25519']]

    '''The repo's targets.
    '''
    TARGETS = [('file.txt', b'wat wat wat\n')]

    '''The modifiers to the root thesholds.
    '''
    ROOT_THRESHOLD_MOD = [0]

    '''The modifier to the targets theshold.
    '''
    TARGETS_THRESHOLD_MOD = [0]

    '''The modifier to the timestamp theshold.
    '''
    TIMESTAMP_THRESHOLD_MOD = [0]

    '''The modifier to the targets theshold.
    '''
    SNAPSHOT_THRESHOLD_MOD = [0]

    '''The number of signatures to skip when signing targets metadata.
    '''
    TARGETS_SIGN_SKIP = [0]

    '''The number of signatures to skip when signing timestamp metadata.
    '''
    TIMESTAMP_SIGN_SKIP = [0]

    '''The number of signatures to skip when signing snapshot metadata.
    '''
    SNAPSHOT_SIGN_SKIP = [0]

    '''The keys to use for each signing. An entry with at index X means
       "use the keys with indices in VALUE to do the cross signing for 
       (X + 1).root.json.
    '''
    ROOT_SIGN = [[1]]

    '''The key IDs to intentionally miscalculate.
    '''
    BAD_KEY_IDS = None

    '''The versions of the snapshot metadata that have an incorrect root.json size.
       The modified size is 1 less than the original size to trigger an oversized error.
    '''
    SNAPSHOT_BAD_ROOT_SIZE_VERSIONS = []

    '''The versions of the snapshot metadata that have an incorrect root.json hashes.
    '''
    SNAPSHOT_BAD_ROOT_HASH_VERSIONS = []

    def __init__(self, output_prefix=None, uptane_role=None):
        assert (output_prefix is None and uptane_role is None) or \
                (output_prefix is not None and uptane_role is not None)

        self.uptane_role = uptane_role
        self.output_prefix = output_prefix

        for d in ['keys', path.join('repo', 'targets')]:
            os.makedirs(path.join(self.output_dir, d), exist_ok=True)

        self.root_keys = []
        self.targets_keys = []
        self.timestamp_keys = []
        self.snapshot_keys = []

        self.root_meta = []

        for key_idx, sig_method in enumerate(self.ROOT_KEYS['keys']):
            log.info('Making root key {} with method {}'.format(key_idx + 1, sig_method))
            priv, pub = self.gen_key('root-{}'.format(key_idx + 1), sig_method)
            self.root_keys.append((sig_method, priv, pub))

        for version_idx in range(len(self.ROOT_KEYS['versions'])):
            log.info('Making keys for targets version {}'.format(version_idx + 1))
            key_group = []

            for key_idx, sig_method in enumerate(self.TARGETS_KEYS[version_idx]):
                log.info('Making targets key {} with method {}'.format(key_idx + 1, sig_method))

                priv, pub = self.gen_key('{}.targets-{}'.format(version_idx + 1, key_idx + 1),
                                         sig_method)
                key_group.append((sig_method, priv, pub))

            self.targets_keys.append(key_group)

            log.info('Making keys for timestamp version {}'.format(version_idx + 1))
            key_group = []

            for key_idx, sig_method in enumerate(self.TIMESTAMP_KEYS[version_idx]):
                log.info('Making timestamp key {} with method {}'.format(key_idx + 1, sig_method))

                priv, pub = self.gen_key('{}.timestamp-{}'.format(version_idx + 1, key_idx + 1),
                                         sig_method)
                key_group.append((sig_method, priv, pub))

            self.timestamp_keys.append(key_group)

            log.info('Making keys for snapshot version {}'.format(version_idx + 1))
            key_group = []

            for key_idx, sig_method in enumerate(self.SNAPSHOT_KEYS[version_idx]):
                log.info('Making snapshot key {} with method {}'.format(key_idx + 1, sig_method))

                priv, pub = self.gen_key('{}.snapshot-{}'.format(version_idx + 1, key_idx + 1),
                                         sig_method)
                key_group.append((sig_method, priv, pub))

            self.snapshot_keys.append(key_group)

            for target, content in self.TARGETS:
                log.info('Writing target: {}'.format(target))

                with open(path.join(self.output_dir, 'repo', 'targets', target), 'wb') as f:
                    f.write(self.alter_target(content))

            log.info('Making root metadata')
            self.root_meta.append(self.make_root(version_idx))

            for version_idx, root in enumerate(self.root_meta):
                log.info('Making root metadata version {}'.format(version_idx + 1))
                self.write_meta('{}.root'.format(version_idx + 1), root)

            self.write_meta('root', self.root_meta[-1])

            log.info('Making targets metadata')
            self.make_targets(version_idx)
            self.write_meta('targets', self.targets_meta)

            log.info('Making snapshot metadata')
            self.make_snapshot(version_idx)
            self.write_meta('snapshot', self.snapshot_meta)

            log.info('Making timestamp metadata')
            self.make_timestamp(version_idx)
            self.write_meta('timestamp', self.timestamp_meta)

    def alter_target(self, target) -> bytes:
        return target

    @property
    def output_dir(self) -> str:
        if self.output_prefix is not None:
            return path.join(OUTPUT_DIR, self.output_prefix, self.uptane_role)
        else:
            return path.join(OUTPUT_DIR, self.NAME)

    def gen_key(self, role, sig_method):
        typ = key_type(sig_method)

        try:
            with open(path.join(self.output_dir, 'keys', '{}.priv'.format(role)), 'r') as f:
                priv = f.read().strip()

            with open(path.join(self.output_dir, 'keys', '{}.pub'.format(role)), 'r') as f:
                pub = f.read().strip()
        except FileNotFoundError:
            if typ == 'ed25519':
                priv, pub = ed25519.create_keypair()
                priv = binascii.hexlify(priv.to_bytes()).decode('utf-8')
                pub = binascii.hexlify(pub.to_bytes()).decode('utf-8')
            elif typ == 'rsa':
                rsa = RSA.generate(2048)
                priv = rsa.exportKey(format='PEM').decode('utf-8')
                pub = rsa.publickey().exportKey(format='PEM').decode('utf-8')
            else:
                raise Exception('unknown key type: {}'.format(typ))
        finally:
            with open(path.join(self.output_dir, 'keys', '{}.priv'.format(role)), 'w') as f:
                f.write(priv)
                f.write('\n')

            with open(path.join(self.output_dir, 'keys', '{}.pub'.format(role)), 'w') as f:
                f.write(pub)
                f.write('\n')

        return (priv, pub)

    def write_meta(self, name, data) -> None:
        with open(path.join(self.output_dir, 'repo', name + '.json'), 'w') as f:
            f.write(jsonify(data))

    def make_root(self, version_idx) -> None:
        signed = {
            '_type': 'Root',
            'consistent_snapshot': False,
            'expires': '2017-01-01T00:00:00Z' if self.EXPIRED == 'root' else '2038-01-19T03:14:06Z',
            'version': version_idx + 1,
            'keys': {},
            'roles': {
                'root': {
                    'keyids': [],
                    'threshold': len(self.ROOT_KEYS['versions'][version_idx]) + self.ROOT_THRESHOLD_MOD[version_idx],
                },
                'targets': {
                    'keyids': [],
                    'threshold': len(self.targets_keys[version_idx]) + self.TARGETS_THRESHOLD_MOD[version_idx],
                },
                'timestamp': {
                    'keyids': [],
                    'threshold': len(self.timestamp_keys[version_idx]) + self.TIMESTAMP_THRESHOLD_MOD[version_idx],
                },
                'snapshot': {
                    'keyids': [],
                    'threshold': len(self.snapshot_keys[version_idx]) + self.SNAPSHOT_THRESHOLD_MOD[version_idx],
                },
            }
        }

        root_keys = list(map(lambda x: self.root_keys[x - 1], self.ROOT_KEYS['versions'][version_idx]))
        keys = []

        for sig_method, _, pub in root_keys:
            k_id = key_id(pub, self.BAD_KEY_IDS == 'root')
            keys.append((sig_method, pub, k_id))
            signed['roles']['root']['keyids'].append(k_id)

        for sig_method, _, pub in self.targets_keys[version_idx]:
            k_id = key_id(pub, self.BAD_KEY_IDS == 'targets')
            keys.append((sig_method, pub, k_id))
            signed['roles']['targets']['keyids'].append(k_id)

        for sig_method, _, pub in self.timestamp_keys[version_idx]:
            k_id = key_id(pub, self.BAD_KEY_IDS == 'timestamp')
            keys.append((sig_method, pub, k_id))
            signed['roles']['timestamp']['keyids'].append(k_id)

        for sig_method, _, pub in self.snapshot_keys[version_idx]:
            k_id = key_id(pub, self.BAD_KEY_IDS == 'snapshot')
            keys.append((sig_method, pub, k_id))
            signed['roles']['snapshot']['keyids'].append(k_id)

        for sig_method, pub, k_id in keys:
            signed['keys'][k_id] = {
                'keytype': key_type(sig_method),
                'keyval': {'public': pub},
            }

        keys = []
        for root_key_version in self.ROOT_SIGN[version_idx]:
            keys.append(self.root_keys[root_key_version - 1])

        return {'signatures': sign(keys, signed), 'signed': signed}

    def make_targets(self, version_idx) -> None:
        file_data = {} 

        for target, content in self.TARGETS:
            meta = {
                'length': len(content),
                'hashes': {
                    'sha512': sha512(content),
                    'sha256': sha256(content),
                }
            }

            if self.uptane_role == 'director':
                meta['custom'] = {
                    'release_counter': 1,
                    'hardware_identifier': 'abc-def',
                    'ecu_identifier': '01:02:03:04:05:06',
                }

            file_data['targets/' + target] = meta

        signed = {
            '_type': 'Targets',
            'expires': '2017-01-01T00:00:00Z' if self.EXPIRED == 'targets' \
                    else '2038-01-19T03:14:06Z',
            'version': 1,
            'targets': file_data,
        }

        self.targets_meta = {
            'signatures': sign(
                self.targets_keys[version_idx][0:len(self.targets_keys[version_idx]) - self.TARGETS_SIGN_SKIP[version_idx]],
                signed),
            'signed': signed}

    def make_snapshot(self, version_idx) -> None:
        signed = {
            '_type': 'Snapshot',
            'expires': '2017-01-01T00:00:00Z' if self.EXPIRED == 'snapshot' else '2038-01-19T03:14:06Z',
            'version': 1,
            'meta': {
                'targets.json': {
                    'version': version_idx + 1,  # TODO this might need updating
                },
            }
        }

        # TODO not sure if all versions of root need to be included
        for root_version_idx, root in enumerate(self.root_meta):
            name = '{}.root.json'.format(root_version_idx + 1)
            jsn = jsonify(root)

            signed['meta'][name] = {
                'length': len(jsn) if version_idx + 1 not in self.SNAPSHOT_BAD_ROOT_SIZE_VERSIONS else len(jsn) - 1,
                'version': root['signed']['version'],
                'hashes': {
                    'sha512': sha512(
                        jsn.encode('utf-8'),
                        version_idx + 1 in self.SNAPSHOT_BAD_ROOT_HASH_VERSIONS),
                    'sha256': sha256(
                        jsn.encode('utf-8'),
                        version_idx + 1 in self.SNAPSHOT_BAD_ROOT_HASH_VERSIONS),
                },
            }

            signed['meta']['root.json'] = signed['meta'][name]

        self.snapshot_meta = {
            'signatures': sign(
                self.snapshot_keys[version_idx][0:len(self.snapshot_keys[version_idx]) - self.SNAPSHOT_SIGN_SKIP[version_idx]],
                signed),
            'signed': signed}

    def make_timestamp(self, version_idx) -> None:
        jsn = jsonify(self.snapshot_meta)

        signed = {
            '_type': 'Timestamp',
            'expires': '2017-01-01T00:00:00Z' if self.EXPIRED == 'timestamp' else '2038-01-19T03:14:06Z',
            'version': 1,
            'meta': {
                'snapshot.json': {
                    'length': len(jsn),
                    'version': 1,
                    'hashes': {
                        'sha512': sha512(
                            jsn.encode('utf-8')),
                        'sha256': sha256(
                            jsn.encode('utf-8')),
                    },
                },
            }}

        self.timestamp_meta = {
            'signatures': sign(
                self.timestamp_keys[version_idx][0:len(self.timestamp_keys[version_idx]) - self.TIMESTAMP_SIGN_SKIP[version_idx]],
                signed),
            'signed': signed}

    @classmethod
    def vector_meta(cls) -> dict:
        root_keys = []

        for version in cls.ROOT_KEYS['versions'][0]:
            sig_method = cls.ROOT_KEYS['keys'][version - 1]
            key_meta = {
                'type': key_type(sig_method),
                'path': 'root-{}.pub'.format(version),
            }
            root_keys.append(key_meta)

        meta = {
            'repo': cls.NAME,
            'is_success': cls.ERROR is None,
            'root_keys': root_keys,
        }

        if cls.ERROR is not None:
            meta['error'] = cls.ERROR
            meta['error_msg'] = human_message(cls.ERROR)

        return meta


class Uptane:

    DIRECTOR_CLS = None
    REPO_CLS = None

    def __init__(self):
        if self.DIRECTOR_CLS is not None:
            self.director = self.DIRECTOR_CLS(self.NAME, uptane_role='director')

        if self.REPO_CLS is not None:
            self.repo = self.REPO_CLS(self.NAME, uptane_role='repo')

    @classmethod
    def vector_meta(cls) -> dict:
        is_success = cls.DIRECTOR_CLS is not None and cls.REPO_CLS is not None

        meta = {
            'repo': cls.NAME,
            'root_keys': {
                'director': [],
                'repo': [],
            },
        }

        if cls.DIRECTOR_CLS is not None:
            is_success = is_success and cls.DIRECTOR_CLS.ERROR is None

            for version in cls.DIRECTOR_CLS.ROOT_KEYS['versions'][0]:
                sig_method = cls.DIRECTOR_CLS.ROOT_KEYS['keys'][version - 1]
                key_meta = {
                    'type': key_type(sig_method),
                    'path': 'root-{}.pub'.format(version),
                }

                meta['root_keys']['director'].append(key_meta)

        if cls.REPO_CLS is not None:
            is_success = is_success and cls.REPO_CLS.ERROR is None

            for version in cls.REPO_CLS.ROOT_KEYS['versions'][0]:
                sig_method = cls.REPO_CLS.ROOT_KEYS['keys'][version - 1]
                key_meta = {
                    'type': key_type(sig_method),
                    'path': 'root-{}.pub'.format(version),
                }

                meta['root_keys']['repo'].append(key_meta)

        meta['is_success'] = is_success

        if not is_success:
            meta['errors'] = {}

            if cls.DIRECTOR_CLS is None:
                err_str = 'MissingRepo::Director'
                err = {
                    'error': err_str,
                    'error_msg': human_message(err_str),
                }
                meta['errors']['director'] = err
            elif cls.DIRECTOR_CLS.ERROR is not None:
                err = {
                    'error': cls.DIRECTOR_CLS.ERROR,
                    'error_msg': human_message(cls.DIRECTOR_CLS.ERROR),
                }
                meta['errors']['director'] = err

            if cls.REPO_CLS is None:
                err_str = 'MissingRepo::Repo'
                err = {
                    'error': err_str,
                    'error_msg': human_message(err_str),
                }
                meta['errors']['repo'] = err
            elif cls.REPO_CLS.ERROR is not None:
                err = {
                    'error': cls.REPO_CLS.ERROR,
                    'error_msg': human_message(cls.REPO_CLS.ERROR),
                }
                meta['errors']['repo'] = err

        return meta


class ValidEd25519Repo(Repo):

    NAME = '001'


class TargetHashMismatchRepo(Repo):

    NAME = '002'
    ERROR = 'TargetHashMismatch'

    def alter_target(self, target) -> bytes:
        new = bytearray(target)
        new[0] ^= 0x01
        return bytes(new)


class Valid2048RsaSsaPssSha256Repo(Repo):

    NAME = '003'

    ROOT_KEYS = {'versions': [[1]],
                 'keys': ['rsassa-pss-sha256'],
                 }
    TARGETS_KEYS = [['rsassa-pss-sha256']]
    TIMESTAMP_KEYS = [['rsassa-pss-sha256']]
    SNAPSHOT_KEYS = [['rsassa-pss-sha256']]


class RsaTargetHashMismatchRepo(TargetHashMismatchRepo, Valid2048RsaSsaPssSha256Repo):

    NAME = '004'


class OversizedTargetRepo(Repo):

    NAME = '005'
    ERROR = 'OversizedTarget'

    def alter_target(self, target) -> bytes:
        return target + b'\n'


class RsaOversizedTargetRepo(OversizedTargetRepo, Valid2048RsaSsaPssSha256Repo):

    NAME = '006'


class ExpiredRootRepo(Repo):

    NAME = '007'
    ERROR = 'ExpiredMetadata::Root'
    EXPIRED = 'root'


class ExpiredTargetsRepo(Repo):

    NAME = '008'
    ERROR = 'ExpiredMetadata::Targets'
    EXPIRED = 'targets'


class ExpiredTimestampRepo(Repo):

    NAME = '009'
    ERROR = 'ExpiredMetadata::Timestamp'
    EXPIRED = 'timestamp'


class ExpiredSnapshotRepo(Repo):

    NAME = '010'
    ERROR = 'ExpiredMetadata::Snapshot'
    EXPIRED = 'snapshot'


class UnmetRootThresholdRepo(Repo):

    NAME = '011'
    ERROR = 'UnmetThreshold::Root'
    ROOT_KEYS = {'versions': [[1, 2]],
                 'keys': ['ed25519', 'ed25519'],
                 }
    ROOT_SIGN = [[1]]


class UnmetTargetsThresholdRepo(Repo):

    NAME = '012'
    ERROR = 'UnmetThreshold::Targets'
    TARGETS_KEYS = [['ed25519', 'ed25519']]
    TARGETS_SIGN_SKIP = [1]


class UnmetTimestampThresholdRepo(Repo):

    NAME = '013'
    ERROR = 'UnmetThreshold::Timestamp'
    TIMESTAMP_KEYS = [['ed25519', 'ed25519']]
    TIMESTAMP_SIGN_SKIP = [1]


class UnmetSnapshotThresholdRepo(Repo):

    NAME = '014'
    ERROR = 'UnmetThreshold::Snapshot'
    SNAPSHOT_KEYS = [['ed25519', 'ed25519']]
    SNAPSHOT_SIGN_SKIP = [1]


class ValidRootKeyRotationRepo(Repo):
    '''Good rotation from 1.root.json to 2.root.json.
    '''

    NAME = '015'
    ROOT_KEYS = {'versions': [[1], [2]],
                 'keys': ['ed25519', 'ed25519'],
                 }
    ROOT_SIGN = [[1], [1, 2]]
    TARGETS_KEYS = [['ed25519'], ['ed25519']]
    TIMESTAMP_KEYS = [['ed25519'], ['ed25519']]
    SNAPSHOT_KEYS = [['ed25519'], ['ed25519']]
    ROOT_THRESHOLD_MOD = [0, 0]
    TARGETS_THRESHOLD_MOD = [0, 0]
    TIMESTAMP_THRESHOLD_MOD = [0, 0]
    SNAPSHOT_THRESHOLD_MOD = [0, 0]
    TARGETS_SIGN_SKIP = [0, 0]
    TIMESTAMP_SIGN_SKIP = [0, 0]
    SNAPSHOT_SIGN_SKIP = [0, 0]


class InvalidRootKeyRotationRepo(ValidRootKeyRotationRepo):
    '''Bad rotation. Keys from 1.root.json don't sign 2.root.json.
    '''

    NAME = '016'
    ERROR = 'UnmetThreshold::Root'
    ROOT_SIGN = [[1], [2]]


class BadRootKeyIdsRepo(ValidEd25519Repo):

    NAME = '017'
    ERROR = 'UnmetThreshold::Root'
    BAD_KEY_IDS = 'root'


class BadTargetsKeyIdsRepo(ValidEd25519Repo):

    NAME = '018'
    ERROR = 'UnmetThreshold::Targets'
    BAD_KEY_IDS = 'targets'


class BadTimestampKeyIdsRepo(ValidEd25519Repo):

    NAME = '019'
    ERROR = 'UnmetThreshold::Timestamp'
    BAD_KEY_IDS = 'timestamp'


class BadSnapshotKeyIdsRepo(ValidEd25519Repo):

    NAME = '020'
    ERROR = 'UnmetThreshold::Snapshot'
    BAD_KEY_IDS = 'snapshot'


class InvalidRootSizeInSnapshotMetaRepo(ValidRootKeyRotationRepo):
    '''Because the first step in a download is downloading the root,
       so it shuldn't matter if the meta data is wrong.
    '''

    NAME = '021'
    SNAPSHOT_BAD_ROOT_SIZE_VERSIONS = [2]


class InvalidRootHasInSnapshotMetaRepo(ValidRootKeyRotationRepo):
    '''Because the first step in a download is downloading the root,
       so it shuldn't matter if the meta data is wrong.
    '''

    NAME = '022'
    SNAPSHOT_BAD_ROOT_HASH_VERSIONS = [2]


class RootThresholdZeroRepo(Repo):

    NAME = '023'
    ERROR = 'IllegalThreshold::Root'
    ROOT_THRESHOLD_MOD = [-1]


class TargetsThresholdZeroRepo(Repo):

    NAME = '024'
    ERROR = 'IllegalThreshold::Targets'
    TARGETS_THRESHOLD_MOD = [-1]


class TimestampThresholdZeroRepo(Repo):

    NAME = '025'
    ERROR = 'IllegalThreshold::Timestamp'
    TIMESTAMP_THRESHOLD_MOD = [-1]


class SnapshotThresholdZeroRepo(Repo):

    NAME = '026'
    ERROR = 'IllegalThreshold::Snapshot'
    SNAPSHOT_THRESHOLD_MOD = [-1]


class Valid2048RsaSsaPssSha512Repo(Repo):

    NAME = '027'

    ROOT_KEYS = {'versions': [[1]],
                 'keys': ['rsassa-pss-sha512'],
                 }
    TARGETS_KEYS = [['rsassa-pss-sha512']]
    TIMESTAMP_KEYS = [['rsassa-pss-sha512']]
    SNAPSHOT_KEYS = [['rsassa-pss-sha512']]


class ValidMixedKeysRepo(Repo):

    NAME = '028'

    ROOT_KEYS = {'versions': [[1, 2, 3]],
                 'keys': ['ed25519', 'rsassa-pss-sha256', 'rsassa-pss-sha512'],
                 }
    ROOT_SIGN = [[1, 2, 3]]
    TARGETS_KEYS = [['ed25519', 'rsassa-pss-sha256', 'rsassa-pss-sha512']]
    TIMESTAMP_KEYS = [['ed25519', 'rsassa-pss-sha256', 'rsassa-pss-sha512']]
    SNAPSHOT_KEYS = [['ed25519', 'rsassa-pss-sha256', 'rsassa-pss-sha512']]


class InvalidRootKeyRotationUnmetSecondThresholdRepo(ValidRootKeyRotationRepo):
    '''2.root.json has unmet threshold from own keys.
    '''

    NAME = '029'
    ERROR = 'UnmetThreshold::Root'
    ROOT_KEYS = {'versions': [[1], [2, 3]],
                 'keys': ['ed25519', 'ed25519', 'ed25519', 'ed25519'],
                 }
    ROOT_SIGN = [[1], [2]]


class InvalidRootKeyRotationUnmetFirstThresholdRepo(ValidRootKeyRotationRepo):
    '''2.root.json has unmet threshold from 1.root.json's keys.
    '''

    NAME = '030'
    ERROR = 'UnmetThreshold::Root'
    ROOT_KEYS = {'versions': [[1, 2], [3]],
                 'keys': ['ed25519', 'ed25519', 'ed25519', 'ed25519'],
                 }
    ROOT_SIGN = [[1], [3]]


class ValidUptane(Uptane):
    '''Everything is good. Simple repo with ed25519 keys.
    '''

    NAME = '001'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = ValidEd25519Repo


class BadDirectorTargetHashesUptane(Uptane):
    '''Director provides metadata with bad target hashes.
    '''

    NAME = '002'
    DIRECTOR_CLS = TargetHashMismatchRepo
    REPO_CLS = ValidEd25519Repo


class BadRepoHashesUptane(Uptane):
    '''Repo provides metadata with bad target hashes.
    '''

    NAME = '003'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = TargetHashMismatchRepo


class MissingDirectorUptane(Uptane):
    '''Missing director repo.
    '''

    NAME = '004'
    DIRECTOR_CLS = None
    REPO_CLS = ValidEd25519Repo


class MissingRepoUptane(Uptane):
    '''Missing repo.
    '''

    NAME = '005'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = None


class OversizedTargetsUptane(Uptane):
    '''Both director and repo report target with size N, but received target is N+1
    '''

    NAME = '006'
    DIRECTOR_CLS = OversizedTargetRepo
    REPO_CLS = OversizedTargetRepo


class OversizedDirectorTargetsUptane(Uptane):
    '''Director reports target with size N, but received target is N+1
    '''

    class LongerTarget(Repo):

        def __init__(self, *nargs, **kwargs):
            cls = type(self)
            cls.TARGETS = list(map(lambda x: (x[0], x[1] + b'\n'), cls.TARGETS))
            super(cls, self).__init__(*nargs, **kwargs)

    NAME = '007'
    DIRECTOR_CLS = OversizedTargetRepo
    REPO_CLS = LongerTarget


class ExpiredDirectorRootRoleUptane(Uptane):

    NAME = '008'
    DIRECTOR_CLS = ExpiredRootRepo
    REPO_CLS = ValidEd25519Repo


class ExpiredDirectorTargetRoleUptane(Uptane):

    NAME = '009'
    DIRECTOR_CLS = ExpiredTargetsRepo
    REPO_CLS = ValidEd25519Repo


class ExpiredDirectorTimestampRoleUptane(Uptane):

    NAME = '010'
    DIRECTOR_CLS = ExpiredTimestampRepo
    REPO_CLS = ValidEd25519Repo


class ExpiredDirectorSnapshotRoleUptane(Uptane):

    NAME = '011'
    DIRECTOR_CLS = ExpiredSnapshotRepo
    REPO_CLS = ValidEd25519Repo


class ExpiredRepoRootRoleUptane(Uptane):

    NAME = '012'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = ExpiredRootRepo


class ExpiredRepoTargetsRoleUptane(Uptane):

    NAME = '013'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = ExpiredTargetsRepo


class ExpiredRepoTimestampRoleUptane(Uptane):

    NAME = '014'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = ExpiredTimestampRepo


class ExpiredRepoSnapshotRoleUptane(Uptane):

    NAME = '015'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = ExpiredSnapshotRepo


class DirectorRootThresholdZeroUptane(Uptane):

    NAME = '016'
    DIRECTOR_CLS = RootThresholdZeroRepo
    REPO_CLS = ValidEd25519Repo


class DirectorTargetsThresholdZeroUptane(Uptane):

    NAME = '017'
    DIRECTOR_CLS = TargetsThresholdZeroRepo
    REPO_CLS = ValidEd25519Repo


class DirectorTimestampThresholdZeroUptane(Uptane):

    NAME = '018'
    DIRECTOR_CLS = TimestampThresholdZeroRepo
    REPO_CLS = ValidEd25519Repo


class DirectorSnapshotThresholdZeroUptane(Uptane):

    NAME = '019'
    DIRECTOR_CLS = SnapshotThresholdZeroRepo
    REPO_CLS = ValidEd25519Repo


class RepoRootThresholdZeroUptane(Uptane):

    NAME = '020'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = RootThresholdZeroRepo


class RepoTargetsThresholdZeroUptane(Uptane):

    NAME = '021'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = TargetsThresholdZeroRepo


class RepoTimestampThresholdZeroUptane(Uptane):

    NAME = '022'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = TimestampThresholdZeroRepo


class RepoSnapshotThresholdZeroUptane(Uptane):

    NAME = '023'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = SnapshotThresholdZeroRepo


class ValidRsaUptane(Uptane):

    NAME = '024'
    DIRECTOR_CLS = Valid2048RsaSsaPssSha256Repo
    REPO_CLS = Valid2048RsaSsaPssSha256Repo


class BadDirectorRsaTargetHashesUptane(Uptane):

    NAME = '025'
    DIRECTOR_CLS = RsaTargetHashMismatchRepo
    REPO_CLS = RsaTargetHashMismatchRepo


class DirectorUnmetRootThresholdUptane(Uptane):

    NAME = '026'
    DIRECTOR_CLS = UnmetRootThresholdRepo
    REPO_CLS = ValidEd25519Repo


class DirectorUnmetTargetsThresholdUptane(Uptane):

    NAME = '027'
    DIRECTOR_CLS = UnmetTargetsThresholdRepo
    REPO_CLS = ValidEd25519Repo


class DirectorUnmetTimestampThresholdUptane(Uptane):

    NAME = '028'
    DIRECTOR_CLS = UnmetTimestampThresholdRepo
    REPO_CLS = ValidEd25519Repo


class DirectorUnmetSnapshotThresholdUptane(Uptane):

    NAME = '029'
    DIRECTOR_CLS = UnmetSnapshotThresholdRepo
    REPO_CLS = ValidEd25519Repo


class RepoUnmetRootThresholdUptane(Uptane):

    NAME = '030'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = UnmetRootThresholdRepo


class RepoUnmetTargetsThresholdUptane(Uptane):

    NAME = '031'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = UnmetTargetsThresholdRepo


class RepoUnmetTimestampThresholdUptane(Uptane):

    NAME = '032'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = UnmetTimestampThresholdRepo


class RepoUnmetSnapshotThresholdUptane(Uptane):

    NAME = '033'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = UnmetSnapshotThresholdRepo


class DirectorBadRootKeyIdsUptane(Uptane):

    NAME = '034'
    DIRECTOR_CLS = BadRootKeyIdsRepo
    REPO_CLS = ValidEd25519Repo


class DirectorBadTargetsKeyIdsUptane(Uptane):

    NAME = '035'
    DIRECTOR_CLS = BadTargetsKeyIdsRepo
    REPO_CLS = ValidEd25519Repo


class DirectorBadTimestampKeyIdsUptane(Uptane):

    NAME = '036'
    DIRECTOR_CLS = BadTimestampKeyIdsRepo
    REPO_CLS = ValidEd25519Repo


class DirectorBadSnapshotKeyIdsUptane(Uptane):

    NAME = '037'
    DIRECTOR_CLS = BadSnapshotKeyIdsRepo
    REPO_CLS = ValidEd25519Repo


class RepoBadRootKeyIdsUptane(Uptane):

    NAME = '038'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = BadRootKeyIdsRepo


class RepoBadTargetsKeyIdsUptane(Uptane):

    NAME = '039'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = BadTargetsKeyIdsRepo


class RepoBadTimestampKeyIdsUptane(Uptane):

    NAME = '040'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = BadTimestampKeyIdsRepo


class RepoBadSnapshotKeyIdsUptane(Uptane):

    NAME = '041'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = BadSnapshotKeyIdsRepo


class DirectorValidRootKeyRotationUptane(Uptane):

    NAME = '042'
    DIRECTOR_CLS = ValidRootKeyRotationRepo
    REPO_CLS = ValidEd25519Repo


class DirectorInvalidRootKeyRotationUptane(Uptane):

    NAME = '043'
    DIRECTOR_CLS = InvalidRootKeyRotationRepo
    REPO_CLS = ValidEd25519Repo


class RepoValidRootKeyRotationUptane(Uptane):

    NAME = '044'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = ValidRootKeyRotationRepo


class DirectorInvalidRootKeyRotationUptane(Uptane):

    NAME = '045'
    DIRECTOR_CLS = ValidEd25519Repo
    REPO_CLS = InvalidRootKeyRotationRepo


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
    args = parser.parse_args()

    main(args.type, args.signature_encoding, args.output_dir, args.repo, args.compact)
