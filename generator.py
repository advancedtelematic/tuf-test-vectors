#!/usr/bin/env python3

from os import path

# activate the virtual environment
if __name__ == '__main__':
    try:
        activate_this = path.join(path.abspath(path.dirname(__file__)),
                                  path.join('venv', 'bin', 'activate_this.py'))
        with open(activate_this) as f:
            code = compile(f.read(), activate_this, 'exec')
            exec(code, dict(__file__=activate_this))
    except FileNotFoundError:
        pass

import base64
import binascii
import ed25519
import hashlib
import json
import logging
import os

from argparse import ArgumentParser
from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from securesystemslib.formats import encode_canonical as olpc_cjson

SIGNATURE_ENCODING = None
OUTPUT_DIR = None
COMPACT_JSON = False
CANONICAL_JSON = None
CURRENT_VERSION = 2


def log():
    log = logging.getLogger(__name__)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)
    return log

log = log()


def main(repo_type, signature_encoding, output_dir, target_repo, compact, cjson_format):
    global SIGNATURE_ENCODING, OUTPUT_DIR, COMPACT_JSON, CANONICAL_JSON
    SIGNATURE_ENCODING = signature_encoding
    OUTPUT_DIR = output_dir
    COMPACT_JSON = bool(compact)
    CANONICAL_JSON = cjson_format

    if cjson_format == 'json-subset':
        log.warn('Using a subset of JSON for canonicalizing JSON. '
                 'This might change in the future')

    vector_meta = {'version': CURRENT_VERSION,
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


def cjson(jsn):
    if CANONICAL_JSON == 'olpc':
        return olpc_cjson(jsn)
    elif CANONICAL_JSON == 'json-subset':
        cjson_subset_check(jsn)
        return json.dumps(jsn, sort_keys=True, separators=(',', ':'))
    else:
        raise Exception('Unsupported CJSON format: {}'.format(CANONICAL_JSON))


def cjson_subset_check(jsn):
    if isinstance(jsn, list):
        for j in jsn:
            cjson_subset_check(j)
    elif isinstance(jsn, dict):
        for _, v in jsn.items():
            cjson_subset_check(v)
    elif isinstance(jsn, str):
        pass
    elif isinstance(jsn, bool):
        pass
    elif jsn is None:
        pass
    elif isinstance(jsn, int):
        pass
    elif isinstance(jsn, float):
        raise Exception('CJSON does not allow floats')
    else:
        raise Exception('What sort of type is this? {}'.format(jsn))

def jsonify(jsn) -> str:
    kwargs = {'sort_keys': True, }

    if not COMPACT_JSON:
        kwargs['indent'] = 2
    else:
        kwargs['separators'] = (':', ',')

    out = json.dumps(jsn, **kwargs)

    if not COMPACT_JSON:
        out += '\n'

    return out


def human_message(err) -> str:
    if err == 'TargetHashMismatch':
        return "The target's calculated hash did not match the hash in the metadata."
    elif err == 'OversizedTarget':
        return "The target's size was greater than the size in the metadata."
    elif err == 'IllegalRsaKeySize':
        return 'The RSA key had an illegal size.'
    elif err == 'UnavailableTarget':
        return 'The target either does not exist or was not in the chain of trusted metadata.'
    elif '::' in err:
        err_base, err_sub = err.split('::')

        if err_base == 'MissingRepo':
            assert err_sub in ['Director', 'Repo'], err_sub
            return 'The {} repo is missing.'.format(err_sub.lower())

        assert err_sub in ['Root', 'Targets', 'Timestamp', 'Snapshot', 'Delegation'], err_sub

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
        elif err_base == 'NonUniqueSignatures':
            return 'The role {} had non-unique signatures.'.format(err_sub.lower())
        else:
            raise Exception('Unavailable err: {}'.format(err_base))
    else:
        raise Exception('Unavailable err: {}'.format(err))


def encode_signature(sig) -> str:
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


def gen_key(role, sig_method, rsa_key_size, output_dir):
    typ = key_type(sig_method)

    try:
        with open(path.join(output_dir, 'keys', '{}.priv'.format(role)), 'r') as f:
            priv = f.read().strip()

        with open(path.join(output_dir, 'keys', '{}.pub'.format(role)), 'r') as f:
            pub = f.read().strip()
    except FileNotFoundError:
        if typ == 'ed25519':
            priv, pub = ed25519.create_keypair()
            priv = binascii.hexlify(priv.to_bytes()).decode('utf-8')
            pub = binascii.hexlify(pub.to_bytes()).decode('utf-8')
        elif typ == 'rsa':
            rsa = RSA.generate(rsa_key_size)
            priv = rsa.exportKey(format='PEM').decode('utf-8')
            pub = rsa.publickey().exportKey(format='PEM').decode('utf-8')
        else:
            raise Exception('unknown key type: {}'.format(typ))
    finally:
        with open(path.join(output_dir, 'keys', '{}.priv'.format(role)), 'w') as f:
            f.write(priv)
            f.write('\n')

        with open(path.join(output_dir, 'keys', '{}.pub'.format(role)), 'w') as f:
            f.write(pub)
            f.write('\n')

    return (priv, pub)


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
    TARGETS_KEYS = {'versions': [[1]],
                    'keys': ['ed25519'],
                    }

    '''The signature methods for the timestamp keys.
    '''
    TIMESTAMP_KEYS = {'versions': [[1]],
                      'keys': ['ed25519'],
                      }

    '''The signature methods for the snapshot keys.
    '''
    SNAPSHOT_KEYS = {'versions': [[1]],
                     'keys': ['ed25519'],
                     }

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

    '''The keys to use for each signing. An entry with at index X means
       "use the keys with indices in VALUE to do the signing for
       (X + 1).root.json.
    '''
    ROOT_SIGN = [[1]]

    '''The keys to use for each signing. An entry with at index X means
       "use the keys with indices in VALUE to do the signing for
       (X + 1).root.json.
    '''
    TARGETS_SIGN = [[1]]

    '''The keys to use for each signing. An entry with at index X means
       "use the keys with indices in VALUE to do the signing for
       (X + 1).timestamp.json.
    '''
    TIMESTAMP_SIGN = [[1]]

    '''The keys to use for each signing. An entry with at index X means
       "use the keys with indices in VALUE to do the signing for
       (X + 1).snapshot.json.
    '''
    SNAPSHOT_SIGN = [[1]]

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

    '''The number of bits in the public part of the RSA key
    '''
    RSA_KEY_SIZE = 2048

    '''The group to use for delegated roles.
    '''
    DELEGATIONS_GROUP_CLS = None

    '''Which pieces of metadata to not include in the snapshot.json
    '''
    SNAPSHOT_META_SKIP = []

    def __init__(self, output_prefix=None, uptane_role=None):
        assert (output_prefix is None and uptane_role is None) or \
            (output_prefix is not None and uptane_role is not None)

        self.uptane_role = uptane_role
        self.output_prefix = output_prefix

        for d in ['keys', path.join('repo', 'targets')]:
            os.makedirs(path.join(self.output_dir, d), exist_ok=True)

        if self.DELEGATIONS_GROUP_CLS is not None:
            self.delegations_group = self.DELEGATIONS_GROUP_CLS(
                output_prefix, uptane_role, self.output_dir)
        else:
            self.delegations_group = None

        self.root_keys = []
        self.targets_keys = []
        self.timestamp_keys = []
        self.snapshot_keys = []

        self.root_meta = []

        for key_idx, sig_method in enumerate(self.ROOT_KEYS['keys']):
            log.info('Making root key {} with method {}'.format(key_idx + 1, sig_method))
            priv, pub = gen_key('root-{}'.format(key_idx + 1), sig_method,
                                self.RSA_KEY_SIZE, self.output_dir)
            self.root_keys.append((sig_method, priv, pub))

        for key_idx, sig_method in enumerate(self.TARGETS_KEYS['keys']):
            log.info('Making target key {} with method {}'.format(key_idx + 1, sig_method))
            priv, pub = gen_key('targets-{}'.format(key_idx + 1), sig_method,
                                self.RSA_KEY_SIZE, self.output_dir)
            self.targets_keys.append((sig_method, priv, pub))

        for key_idx, sig_method in enumerate(self.TIMESTAMP_KEYS['keys']):
            log.info('Making timestamp key {} with method {}'.format(key_idx + 1, sig_method))
            priv, pub = gen_key('timestamp-{}'.format(key_idx + 1),
                                sig_method, self.RSA_KEY_SIZE, self.output_dir)
            self.timestamp_keys.append((sig_method, priv, pub))

        for key_idx, sig_method in enumerate(self.SNAPSHOT_KEYS['keys']):
            log.info('Making timestamp key {} with method {}'.format(key_idx + 1, sig_method))
            priv, pub = gen_key('snapshot-{}'.format(key_idx + 1), sig_method,
                                self.RSA_KEY_SIZE, self.output_dir)
            self.snapshot_keys.append((sig_method, priv, pub))

        self.write_targets_content()

        for version_idx in range(len(self.ROOT_KEYS['versions'])):
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

    def write_targets_content(self):
        for target, content in self.TARGETS:
            log.info('Writing target: {}'.format(target))
            with open(path.join(self.output_dir, 'repo', 'targets', target), 'wb') as f:
                f.write(self.alter_target(content))

    @property
    def output_dir(self) -> str:
        if self.output_prefix is not None:
            return path.join(OUTPUT_DIR, self.output_prefix, self.uptane_role)
        else:
            return path.join(OUTPUT_DIR, self.NAME)

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
                    'threshold': len(
                        self.ROOT_KEYS['versions'][version_idx]) + self.ROOT_THRESHOLD_MOD[version_idx],
                },
                'targets': {
                    'keyids': [],
                    'threshold': len(
                        self.TARGETS_KEYS['versions'][version_idx]) + self.TARGETS_THRESHOLD_MOD[version_idx],
                },
                'timestamp': {
                    'keyids': [],
                    'threshold': len(
                        self.TIMESTAMP_KEYS['versions'][version_idx]) + self.TIMESTAMP_THRESHOLD_MOD[version_idx],
                },
                'snapshot': {
                    'keyids': [],
                    'threshold': len(
                        self.SNAPSHOT_KEYS['versions'][version_idx]) + self.SNAPSHOT_THRESHOLD_MOD[version_idx],
                },
            }}

        root_keys = list(map(lambda x: self.root_keys[
                         x - 1], self.ROOT_KEYS['versions'][version_idx]))
        targets_keys = list(map(lambda x: self.targets_keys[
            x - 1], self.TARGETS_KEYS['versions'][version_idx]))
        timestamp_keys = list(map(lambda x: self.timestamp_keys[
            x - 1], self.TIMESTAMP_KEYS['versions'][version_idx]))
        snapshot_keys = list(map(lambda x: self.snapshot_keys[
            x - 1], self.SNAPSHOT_KEYS['versions'][version_idx]))
        keys = []

        for sig_method, _, pub in root_keys:
            k_id = key_id(pub, self.BAD_KEY_IDS == 'root')
            keys.append((sig_method, pub, k_id))
            signed['roles']['root']['keyids'].append(k_id)

        for sig_method, _, pub in targets_keys:
            k_id = key_id(pub, self.BAD_KEY_IDS == 'targets')
            keys.append((sig_method, pub, k_id))
            signed['roles']['targets']['keyids'].append(k_id)

        for sig_method, _, pub in timestamp_keys:
            k_id = key_id(pub, self.BAD_KEY_IDS == 'timestamp')
            keys.append((sig_method, pub, k_id))
            signed['roles']['timestamp']['keyids'].append(k_id)

        for sig_method, _, pub in snapshot_keys:
            k_id = key_id(pub, self.BAD_KEY_IDS == 'snapshot')
            keys.append((sig_method, pub, k_id))
            signed['roles']['snapshot']['keyids'].append(k_id)

        for sig_method, pub, k_id in keys:
            signed['keys'][k_id] = {
                'keytype': key_type(sig_method),
                'keyval': {'public': pub},
            }

        keys = []
        for key_version in self.ROOT_SIGN[version_idx]:
            keys.append(self.root_keys[key_version - 1])

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
            'expires': '2017-01-01T00:00:00Z' if self.EXPIRED == 'targets'
            else '2038-01-19T03:14:06Z',
            'version': 1,
            'targets': file_data,
        }

        if self.delegations_group is not None:
            signed['delegations'] = self.delegations_group.make_targets_section()

        keys = []
        for key_version in self.TARGETS_SIGN[version_idx]:
            keys.append(self.targets_keys[key_version - 1])

        self.targets_meta = {'signatures': sign(keys, signed), 'signed': signed}

    def make_snapshot(self, version_idx) -> None:
        signed = {
            '_type': 'Snapshot',
            'expires': '2017-01-01T00:00:00Z' if self.EXPIRED == 'snapshot' else '2038-01-19T03:14:06Z',
            'version': 1,
            'meta': {
                'targets.json': {
                    'version': version_idx + 1,
                },
            }}

        if self.delegations_group is not None:
            for role, version in self.delegations_group.list_all():
                signed['meta']['{}.json'.format(role)] = {'version': version}

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

        for skip in self.SNAPSHOT_META_SKIP:
            signed['meta'].pop(skip, None)

        keys = []
        for key_version in self.SNAPSHOT_SIGN[version_idx]:
            keys.append(self.snapshot_keys[key_version - 1])

        self.snapshot_meta = {'signatures': sign(keys, signed), 'signed': signed}

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

        keys = []
        for key_version in self.TIMESTAMP_SIGN[version_idx]:
            keys.append(self.timestamp_keys[key_version - 1])

        self.timestamp_meta = {'signatures': sign(keys, signed), 'signed': signed}

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

        # TODO include ordered list of files to download from cls.TARGETS & delegations.TARGETS

        if cls.ERROR is not None:
            meta['error'] = cls.ERROR
            meta['error_msg'] = human_message(cls.ERROR)

        return meta


class DelegationsGroup:

    '''List of sig_methods
    '''
    KEYS = []

    '''List of delegated roles
    '''
    ROLES = []

    def __init__(self, output_prefix, uptane_role, repo_dir):
        self.output_prefix = output_prefix
        self.uptane_role = uptane_role
        self.repo_dir = repo_dir
        self.roles = []
        self.keys = []

        for key_idx, key in enumerate(self.KEYS):
            # TODO this key name is shared by all nested delegation groups and therefore 
            # means that they all share keys which makes some of the tests BS
            priv, pub = gen_key('delegation-{}'.format(key_idx + 1), key, 2048, self.repo_dir)
            self.keys.append((key, priv, pub))

        for role in self.ROLES:
            r = role['role'](role['name'], output_prefix, uptane_role, repo_dir,
                             list(map(lambda x: self.keys[x - 1], role['keys'])))
            role_copy = role.copy()
            role_copy['role'] = r
            self.roles.append(role_copy)

    def make_targets_section(self) -> dict:
        roles = []
        for role in self.roles:
            role_meta = {
                'name': role['name'],
                'threshold': role['threshold'],
                'keyids': list(map(lambda x: key_id(self.keys[x - 1][2]), role['keys'])),
                'paths': role['paths'],
                'terminating': False,  # TODO allow terminating, test
            }
            roles.append(role_meta)

        keys = {}
        for sig_method, _, pub in self.keys:
            keys[key_id(pub)] = {
                'keytype': key_type(sig_method),
                'keyval': {'public': pub},
            }

        return {'keys': keys,
                'roles': roles,
                }

    def list_all(self) -> list:
        '''Returns a list of (role_name, role_version)
        '''
        roles = list(map(lambda x: (x['name'], 1), self.roles))

        for role in self.roles:
            if role['role'].delegations_group is not None:
                roles += role['role'].delegations_group.list_all()

        return roles


class Delegation(Repo):

    def __init__(self, name, output_prefix, uptane_role, output_dir, keys):
        '''Keys is list[('method', 'priv', 'pub')]
        '''
        self.NAME = path.basename(output_dir)
        self.output_prefix = output_prefix
        self.uptane_role = uptane_role

        if self.DELEGATIONS_GROUP_CLS is not None:
            self.delegations_group = \
                self.DELEGATIONS_GROUP_CLS(output_prefix, uptane_role, self.output_dir)
        else:
            self.delegations_group = None

        self.targets_keys = keys
        self.make_targets(0)
        self.write_meta(name, self.targets_meta)
        self.write_targets_content()


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
    ROOT_SIGN = [[1]]

    TARGETS_KEYS = {'versions': [[1]],
                    'keys': ['rsassa-pss-sha256'],
                    }
    TARGETS_SIGN = [[1]]

    TIMESTAMP_KEYS = {'versions': [[1]],
                      'keys': ['rsassa-pss-sha256'],
                      }
    TIMESTAMP_SIGN = [[1]]

    SNAPSHOT_KEYS = {'versions': [[1]],
                     'keys': ['rsassa-pss-sha256'],
                     }
    SNAPSHOT_SIGN = [[1]]


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
    TARGETS_KEYS = {'versions': [[1, 2]],
                    'keys': ['ed25519', 'ed25519'],
                    }
    TARGETS_SIGN = [[1]]


class UnmetTimestampThresholdRepo(Repo):

    NAME = '013'
    ERROR = 'UnmetThreshold::Timestamp'
    TIMESTAMP_KEYS = {'versions': [[1, 2]],
                      'keys': ['ed25519', 'ed25519'],
                      }
    TIMESTAMP_SIGN = [[1]]


class UnmetSnapshotThresholdRepo(Repo):

    NAME = '014'
    ERROR = 'UnmetThreshold::Snapshot'
    SNAPSHOT_KEYS = {'versions': [[1, 2]],
                     'keys': ['ed25519', 'ed25519'],
                     }
    SNAPSHOT_SIGN = [[1]]


class ValidRootKeyRotationRepo(Repo):
    '''Good rotation from 1.root.json to 2.root.json.
    '''

    NAME = '015'
    ROOT_KEYS = {'versions': [[1], [2]],
                 'keys': ['ed25519', 'ed25519'],
                 }
    ROOT_SIGN = [[1], [1, 2]]
    ROOT_THRESHOLD_MOD = [0, 0]

    TARGETS_KEYS = {'versions': [[1], [2]],
                    'keys': ['ed25519', 'ed25519'],
                    }
    TARGETS_SIGN = [[1], [2]]
    TARGETS_THRESHOLD_MOD = [0, 0]

    TIMESTAMP_KEYS = {'versions': [[1], [2]],
                      'keys': ['ed25519', 'ed25519'],
                      }
    TIMESTAMP_SIGN = [[1], [2]]
    TIMESTAMP_THRESHOLD_MOD = [0, 0]

    SNAPSHOT_KEYS = {'versions': [[1], [2]],
                     'keys': ['ed25519', 'ed25519'],
                     }
    SNAPSHOT_SIGN = [[1], [2]]
    SNAPSHOT_THRESHOLD_MOD = [0, 0]


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


class InvalidRootHashInSnapshotMetaRepo(ValidRootKeyRotationRepo):
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
    ROOT_SIGN = [[1]]

    TARGETS_KEYS = {'versions': [[1]],
                    'keys': ['rsassa-pss-sha512'],
                    }
    TARGETS_SIGN = [[1]]

    TIMESTAMP_KEYS = {'versions': [[1]],
                      'keys': ['rsassa-pss-sha512'],
                      }
    TIMESTAMP_SIGN = [[1]]

    SNAPSHOT_KEYS = {'versions': [[1]],
                     'keys': ['rsassa-pss-sha512'],
                     }
    SNAPSHOT_SIGN = [[1]]


class ValidMixedKeysRepo(Repo):

    NAME = '028'

    ROOT_KEYS = {'versions': [[1, 2, 3]],
                 'keys': ['ed25519', 'rsassa-pss-sha256', 'rsassa-pss-sha512'],
                 }
    ROOT_SIGN = [[1, 2, 3]]

    TARGETS_KEYS = {'versions': [[1, 2, 3]],
                    'keys': ['ed25519', 'rsassa-pss-sha256', 'rsassa-pss-sha512'],
                    }
    TARGETS_SIGN = [[1, 2, 3]]

    TIMESTAMP_KEYS = {'versions': [[1, 2, 3]],
                      'keys': ['ed25519', 'rsassa-pss-sha256', 'rsassa-pss-sha512'],
                      }
    TIMESTAMP_SIGN = [[1, 2, 3]]

    SNAPSHOT_KEYS = {'versions': [[1, 2, 3]],
                     'keys': ['ed25519', 'rsassa-pss-sha256', 'rsassa-pss-sha512'],
                     }
    SNAPSHOT_SIGN = [[1, 2, 3]]


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


class ValidRootKeyRotationFixedKeyRepo(ValidRootKeyRotationRepo):
    '''Valid root.json rotation with fixed key between 1.root.json and 2.root.json.
    '''

    NAME = '031'
    ROOT_KEYS = {'versions': [[1], [1]],
                 'keys': ['ed25519'],
                 }
    ROOT_SIGN = [[1], [1]]


class InvalidRootKeyRotationSharedKeysUnmetFirstThresholdRepo(ValidRootKeyRotationRepo):
    '''2.root.json has unmet threshold from 1.root.json's keys, and v 1 & 2 share some keys.
    '''

    NAME = '032'
    ERROR = 'UnmetThreshold::Root'
    ROOT_KEYS = {'versions': [[1, 2], [2, 3]],
                 'keys': ['ed25519', 'ed25519', 'ed25519'],
                 }
    ROOT_SIGN = [[1, 2], [2, 3]]


class InvalidRootKeyRotationSharedKeysUnmetSecondThresholdRepo(ValidRootKeyRotationRepo):
    '''2.root.json has unmet threshold from own keys, and v 1 & 2 share some keys.
    '''

    NAME = '033'
    ERROR = 'UnmetThreshold::Root'
    ROOT_KEYS = {'versions': [[1, 2], [2, 3]],
                 'keys': ['ed25519', 'ed25519', 'ed25519'],
                 }
    ROOT_SIGN = [[1, 2], [1, 2]]


class ValidRootKeyRotationSharedKeysUnmetVariableThresholdRepo(ValidRootKeyRotationRepo):
    '''Valid root rotation with shared keys and variable threshold
    '''

    NAME = '034'
    ROOT_KEYS = {'versions': [[1, 2], [2, 3]],
                 'keys': ['ed25519', 'ed25519', 'ed25519'],
                 }
    ROOT_SIGN = [[1, 2], [1, 2]]
    ROOT_THRESHOLD_MOD = [0, -1]


class InvalidRsaKeySize1792Repo(Valid2048RsaSsaPssSha256Repo):
    '''Uses RSA keys with incorrect size (1792 bits)
    '''

    NAME = '035'
    ERROR = 'IllegalRsaKeySize'
    RSA_KEY_SIZE = 1792


class InvalidRsaKeySize1024Repo(Valid2048RsaSsaPssSha256Repo):
    '''Uses RSA keys with incorrect size (1024 bits)
    '''

    NAME = '036'
    ERROR = 'IllegalRsaKeySize'
    RSA_KEY_SIZE = 1024


class NonUniqueRootSignatureRepo(Repo):

    NAME = '037'
    ERROR = 'NonUniqueSignatures::Root'
    ROOT_SIGN = [[1, 1]]


class NonUniqueTargetsSignatureRepo(Repo):

    NAME = '038'
    ERROR = 'NonUniqueSignatures::Targets'
    TARGETS_SIGN = [[1, 1]]


class NonUniqueTimestampSignatureRepo(Repo):

    NAME = '039'
    ERROR = 'NonUniqueSignatures::Timestamp'
    TIMESTAMP_SIGN = [[1, 1]]


class NonUniqueSnapshotSignatureRepo(Repo):

    NAME = '040'
    ERROR = 'NonUniqueSignatures::Snapshot'
    SNAPSHOT_SIGN = [[1, 1]]


class NonUniqueRsaRootSignatureRepo(Valid2048RsaSsaPssSha256Repo):

    NAME = '041'
    ERROR = 'NonUniqueSignatures::Root'
    ROOT_SIGN = [[1, 1]]


class NonUniqueRsaTargetsSignatureRepo(Valid2048RsaSsaPssSha256Repo):

    NAME = '042'
    ERROR = 'NonUniqueSignatures::Targets'
    TARGETS_SIGN = [[1, 1]]


class NonUniqueRsaTimestampSignatureRepo(Valid2048RsaSsaPssSha256Repo):

    NAME = '043'
    ERROR = 'NonUniqueSignatures::Timestamp'
    TIMESTAMP_SIGN = [[1, 1]]


class NonUniqueRsaSnapshotSignatureRepo(Valid2048RsaSsaPssSha256Repo):

    NAME = '044'
    ERROR = 'NonUniqueSignatures::Snapshot'
    SNAPSHOT_SIGN = [[1, 1]]


class SimpleDelegation(Delegation):

    pass


class SimpleDelegationsGroup(DelegationsGroup):

    KEYS = ['ed25519']

    ROLES = [{'keys': [1],
              'role': SimpleDelegation,
              'name': 'delegation-1',
              'threshold': 1,
              'paths': ['targets/file.txt'],
              }
             ]


class SimpleDelegationRepo(Repo):

    NAME = '045'
    DELEGATIONS_GROUP_CLS = SimpleDelegationsGroup
    TARGETS = []


class NestedDelegation(Delegation):

    TARGETS = []
    DELEGATIONS_GROUP_CLS = SimpleDelegationsGroup


class NestedDelegationsGroup(DelegationsGroup):

    KEYS = ['ed25519']

    ROLES = [{'keys': [1],
              'role': NestedDelegation,
              'name': 'delegation-2',
              'threshold': 1,
              'paths': ['targets/file.txt'],
              }
             ]


class NestedDelegationRepo(Repo):

    NAME = '046'
    DELEGATIONS_GROUP_CLS = NestedDelegationsGroup
    TARGETS = []


class NestedDelegationFirstLinkMissingRepo(NestedDelegationRepo):

    NAME = '047'
    ERROR = 'UnavailableTarget'
    SNAPSHOT_META_SKIP = ['delegation-2.json']


class NestedDelegationSecondLinkMissingRepo(NestedDelegationRepo):

    NAME = '048'
    ERROR = 'UnavailableTarget'
    SNAPSHOT_META_SKIP = ['delegation-1.json']


class ThresholdUnmetDelegation(Delegation):

    TARGETS_SIGN = [[]]


class ThresholdUnmetDelegationGroup(DelegationsGroup):

    KEYS = ['ed25519']

    ROLES = [{'keys': [1],
              'role': ThresholdUnmetDelegation,
              'name': 'delegation-1',
              'threshold': 1,
              'paths': ['targets/file.txt'],
              }
             ]


class DelegationThresholdUnmetRepo(Repo):

    NAME = '049'
    ERROR = 'UnmetThreshold::Delegation'
    DELEGATIONS_GROUP_CLS = ThresholdUnmetDelegationGroup
    TARGETS = []


class NoPathTargetDelegationsGroup(DelegationsGroup):

    KEYS = ['ed25519']

    ROLES = [{'keys': [1],
              'role': SimpleDelegation,
              'name': 'delegation-1',
              'threshold': 1,
              'paths': [],
              }
             ]

class NoPathTargetDelegationRepo(Repo):

    NAME = '050'
    ERROR = 'UnavailableTarget'
    DELEGATIONS_GROUP_CLS = NoPathTargetDelegationsGroup
    TARGETS = []


class BadPathTargetDelegationsGroup(DelegationsGroup):

    KEYS = ['ed25519']

    ROLES = [{'keys': [1],
              'role': SimpleDelegation,
              'name': 'delegation-1',
              'threshold': 1,
              'paths': ['targets-file.txt'],
              }
             ]


class BadPathTargetDelegationRepo(Repo):

    NAME = '051'
    ERROR = 'UnavailableTarget'
    DELEGATIONS_GROUP_CLS = BadPathTargetDelegationsGroup
    TARGETS = []


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
    parser.add_argument('--cjson', help='The formatter to use for canonical JSON',
                        default='olpc', choices=['olpc', 'json-subset'])
    args = parser.parse_args()

    main(args.type, args.signature_encoding, args.output_dir, args.repo, args.compact, args.cjson)
