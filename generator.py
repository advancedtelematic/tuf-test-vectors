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
import os

from argparse import ArgumentParser
from canonicaljson import encode_canonical_json as cjson
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

SIGNATURE_ENCODING = None
OUTPUT_DIR = None

log = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)-8s %(message)s')
handler.setFormatter(formatter)
log.addHandler(handler)
log.setLevel(logging.DEBUG)


def main(signature_encoding, output_dir, target_repo=None):
    global SIGNATURE_ENCODING, OUTPUT_DIR
    SIGNATURE_ENCODING = signature_encoding
    OUTPUT_DIR = output_dir

    vector_meta = []
    for repo in Repo.subclasses():
        vector_meta.append(repo.vector_meta())

        if target_repo is not None and repo.NAME != target_repo:
            continue

        log.info('Generating repo {}'.format(repo.NAME))
        repo = repo()
        log.info('Repo {} done'.format(repo.NAME))

    # verify vector_meta
    for meta in vector_meta:
        assert 'repo' in meta
        assert isinstance(meta['is_success'], bool)

    with open(path.join(OUTPUT_DIR, 'vector-meta.json'), 'w') as f:
        f.write(jsonify(vector_meta))


def sha256(byts, alter=False):
    h = hashlib.sha256()
    h.update(byts)
    d = h.digest()

    if alter:
        d = bytearray(d)
        d[0] ^= 0x01
        d = bytes(d)

    return binascii.hexlify(d).decode('utf-8')


def sha512(byts, alter=False):
    h = hashlib.sha512()
    h.update(byts)
    d = h.digest()

    if alter:
        d = bytearray(d)
        d[0] ^= 0x01
        d = bytes(d)

    return binascii.hexlify(d).decode('utf-8')


def key_id(pub, alter=False):
    if alter:
        byts = bytearray(cjson(pub))
        byts[0] ^= 0x01
        return sha256(bytes(byts))
    else:
        return sha256(cjson(pub))


def key_type(sig_method):
    if sig_method == 'ed25519':
        return 'ed25519'
    elif sig_method == 'rsassa-pss-sha256':
        return 'rsa'
    else:
        raise Exception('unknown signature method: {}'.format(sig_method))


def jsonify(jsn):
    return json.dumps(jsn, sort_keys=True, indent=2) + '\n'


def human_message(err):
    if err == 'TargetHashMismatch':
        return "The target's calculated hash did not match the hash in the metadata."
    elif err == 'OversizedTarget':
        return "The target's size was greater than the size in the metadata."
    elif '::' in err:
        err_base, err_sub = err.split('::')
        assert err_sub in ['Root', 'Targets', 'Timestamp', 'Snapshot']

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
        else:
            raise Exception('Unknown err: {}'.format(err_base))
    else:
        raise Exception('Unknown err: {}'.format(err))


def encode_signature(sig):
    global SIGNATURE_ENCODING

    if SIGNATURE_ENCODING == 'hex':
        return binascii.hexlify(sig).decode('utf-8')
    elif SIGNATURE_ENCODING == 'base64':
        return base64.b64encode(sig).decode('utf-8')
    else:
        raise Exception('Invalid signature encoding: {}'.format(SIGNATURE_ENCODING))


def sign(keys, signed):
    data = cjson(signed)

    sigs = []
    for sig_method, priv, pub in keys:
        if sig_method == 'ed25519':
            priv = ed25519.SigningKey(binascii.unhexlify(priv))
            sig = priv.sign(data)
        elif sig_method == 'rsassa-pss-sha256':
            h = SHA256.new(data)
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
    ROOT_KEYS = [['ed25519']]

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

    '''The versions to skip root cross signing.
       E.g, if this is set to [2], then 1.root.json will not sign 2.root.json
    '''
    ROOT_CROSS_SIGN_SKIP = []

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

    def __init__(self):
        for d in ['keys', path.join('repo', 'targets')]:
            os.makedirs(path.join(self.output_dir, d), exist_ok=True)

        self.root_keys = []
        self.targets_keys = []
        self.timestamp_keys = []
        self.snapshot_keys = []

        self.root_meta = []

        for version_idx in range(len(self.ROOT_KEYS)):
            log.info('Making keys for root version {}'.format(version_idx + 1))
            key_group = []

            for key_idx, sig_method in enumerate(self.ROOT_KEYS[version_idx]):
                log.info('Making root key {} with method {}'.format(key_idx + 1, sig_method))

                priv, pub = self.gen_key('{}.root-{}'.format(version_idx + 1, key_idx + 1),
                                         sig_method)
                key_group.append((sig_method, priv, pub))

            self.root_keys.append(key_group)

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
    def output_dir(self):
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
                    'threshold': len(self.root_keys[version_idx]) + self.ROOT_THRESHOLD_MOD[version_idx],
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

        keys = []

        for sig_method, _, pub in self.root_keys[version_idx]:
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

        keys = self.root_keys[version_idx]

        if version_idx > 0 and (version_idx + 1) not in self.ROOT_CROSS_SIGN_SKIP:
            keys.extend(self.root_keys[version_idx - 1])

        return {'signatures': sign(keys, signed), 'signed': signed}

    def make_targets(self, version_idx):
        file_data = dict()

        for target, content in self.TARGETS:
            file_data['targets/' + target] = {
                'length': len(content),
                'hashes': {
                    'sha512': sha512(content),
                    'sha256': sha256(content),
                }
            }

        signed = {
            '_type': 'Targets',
            'expires': '2017-01-01T00:00:00Z' if self.EXPIRED == 'targets' else '2038-01-19T03:14:06Z',
            'version': 1,
            'targets': file_data,
        }

        self.targets_meta = {'signatures': sign(self.targets_keys[version_idx], signed), 'signed': signed}

    def make_snapshot(self, version_idx):
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
                    'sha512': sha512(jsn.encode('utf-8'), version_idx + 1 in self.SNAPSHOT_BAD_ROOT_HASH_VERSIONS),
                    'sha256': sha256(jsn.encode('utf-8'), version_idx + 1 in self.SNAPSHOT_BAD_ROOT_HASH_VERSIONS),
                },
            }

            signed['meta']['root.json'] = signed['meta'][name]

        self.snapshot_meta = {'signatures': sign(self.snapshot_keys[version_idx], signed), 'signed': signed}

    def make_timestamp(self, version_idx):
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
                        'sha512': sha512(jsn.encode('utf-8')),
                        'sha256': sha256(jsn.encode('utf-8')),
                    },
                },
            }
        }

        self.timestamp_meta = {'signatures': sign(self.timestamp_keys[version_idx], signed), 'signed': signed}

    @classmethod
    def vector_meta(cls) -> dict:
        root_keys = []
        for version_idx, sig_method in enumerate(cls.ROOT_KEYS[0]):
            key_meta = {
                'type': key_type(sig_method),
                'path': '1.root-{}.pub'.format(version_idx + 1),
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

    @classmethod
    def subclasses(cls) -> list:
        '''Returns a sorted list of all Repo subclasses. Elements are unique.
        '''
        return sorted(list(set(cls.__subclasses__() + [g for s in cls.__subclasses__()
                                                       for g in s.subclasses()])),
                      key=lambda x: x.NAME)


class Repo001(Repo):

    NAME = '001'


class Repo002(Repo):

    NAME = '002'
    ERROR = 'TargetHashMismatch'

    def alter_target(self, target) -> bytes:
        new = bytearray(target)
        new[0] ^= 0x01
        return bytes(new)


class Repo003(Repo):

    NAME = '003'

    ROOT_KEYS = [['rsassa-pss-sha256']]
    TARGETS_KEYS = [['rsassa-pss-sha256']]
    TIMESTAMP_KEYS = [['rsassa-pss-sha256']]
    SNAPSHOT_KEYS = [['rsassa-pss-sha256']]


class Repo004(Repo002, Repo003):

    NAME = '004'


class Repo005(Repo):

    NAME = '005'
    ERROR = 'OversizedTarget'

    def alter_target(self, target) -> bytes:
        return target + b'\n'


class Repo006(Repo005, Repo003):

    NAME = '006'


class Repo007(Repo):

    NAME = '007'
    ERROR = 'ExpiredMetadata::Root'
    EXPIRED = 'root'


class Repo008(Repo):

    NAME = '008'
    ERROR = 'ExpiredMetadata::Targets'
    EXPIRED = 'targets'


class Repo009(Repo):

    NAME = '009'
    ERROR = 'ExpiredMetadata::Timestamp'
    EXPIRED = 'timestamp'


class Repo010(Repo):

    NAME = '010'
    ERROR = 'ExpiredMetadata::Snapshot'
    EXPIRED = 'snapshot'


class Repo011(Repo):

    NAME = '011'
    ERROR = 'UnmetThreshold::Root'
    ROOT_KEYS = [['ed25519', 'ed25519']]
    ROOT_THRESHOLD_MOD = [1]


class Repo012(Repo):

    NAME = '012'
    ERROR = 'UnmetThreshold::Targets'
    TARGETS_KEYS = [['ed25519', 'ed25519']]
    TARGETS_THRESHOLD_MOD = [1]


class Repo013(Repo):

    NAME = '013'
    ERROR = 'UnmetThreshold::Timestamp'
    TIMESTAMP_KEYS = [['ed25519', 'ed25519']]
    TIMESTAMP_THRESHOLD_MOD = [1]


class Repo014(Repo):

    NAME = '014'
    ERROR = 'UnmetThreshold::Snapshot'
    SNAPSHOT_KEYS = [['ed25519', 'ed25519']]
    SNAPSHOT_THRESHOLD_MOD = [1]


class Repo015(Repo):
    '''Good rotation from 1.root.json to 2.root.json.
    '''

    NAME = '015'
    ROOT_KEYS = [['ed25519'], ['ed25519']]
    TARGETS_KEYS = [['ed25519'], ['ed25519']]
    TIMESTAMP_KEYS = [['ed25519'], ['ed25519']]
    SNAPSHOT_KEYS = [['ed25519'], ['ed25519']]
    ROOT_THRESHOLD_MOD = [0, 0]
    TARGETS_THRESHOLD_MOD = [0, 0]
    TIMESTAMP_THRESHOLD_MOD = [0, 0]
    SNAPSHOT_THRESHOLD_MOD = [0, 0]


class Repo016(Repo015):
    '''Bad rotation from 1.root.json to 2.root.json.
    '''

    NAME = '016'
    ERROR = 'UnmetThreshold::Root'
    ROOT_CROSS_SIGN_SKIP = [2]


class Repo017(Repo001):

    NAME = '017'
    ERROR = 'UnmetThreshold::Root'
    BAD_KEY_IDS = 'root'


class Repo018(Repo001):

    NAME = '018'
    ERROR = 'UnmetThreshold::Targets'
    BAD_KEY_IDS = 'targets'


class Repo019(Repo001):

    NAME = '019'
    ERROR = 'UnmetThreshold::Timestamp'
    BAD_KEY_IDS = 'timestamp'


class Repo020(Repo001):

    NAME = '020'
    ERROR = 'UnmetThreshold::Snapshot'
    BAD_KEY_IDS = 'snapshot'


class Repo021(Repo015):
    '''Because the first step in a download is downloading the root,
       so it shuldn't matter if the meta data is wrong.
    '''

    NAME = '021'
    SNAPSHOT_BAD_ROOT_SIZE_VERSIONS = [2]


class Repo022(Repo015):
    '''Because the first step in a download is downloading the root,
       so it shuldn't matter if the meta data is wrong.
    '''

    NAME = '022'
    SNAPSHOT_BAD_ROOT_HASH_VERSIONS = [2]


if __name__ == '__main__':
    parser = ArgumentParser(path.basename(__file__))
    parser.add_argument('-o', '--output-dir', help='The path to write the repos',
                        default=path.join(path.dirname(path.abspath(__file__)), 'vectors'))
    parser.add_argument('-r', '--repo', help='The repo to generate', default=None)
    parser.add_argument('--signature-encoding', help='The encoding for cryptographic signatures',
                        default='hex', choices=['hex', 'base64'])
    args = parser.parse_args()

    main(args.signature_encoding, args.output_dir, args.repo)
