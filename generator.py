#!/usr/bin/env python3

from os import path

# activate the virtual environment
activate_this = path.join(path.abspath(path.dirname(__file__)),
                          'venv/bin/activate_this.py')
with open(activate_this) as f:
    code = compile(f.read(), activate_this, 'exec')
    exec(code, dict(__file__=activate_this))


import binascii
import ed25519
import hashlib
import json
import logging
import os

from canonicaljson import encode_canonical_json as cjson
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS


OUTPUT_DIR = path.join(path.dirname(path.abspath(__file__)), 'vectors')

log = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(levelname)-8s %(message)s')
handler.setFormatter(formatter)
log.addHandler(handler)
log.setLevel(logging.DEBUG)


def main():
    vector_meta = []
    for repo in Repo.subclasses():
        log.info('Generating repo {}'.format(repo.NAME))
        repo = repo()
        vector_meta.append(repo.vector_meta())
        log.info('Repo {} done'.format(repo.NAME))

    # verify vector_meta
    for meta in vector_meta:
        assert 'repo' in meta
        assert isinstance(meta['is_success'], bool)

    with open(path.join(OUTPUT_DIR, 'vector-meta.json'), 'w') as f:
        f.write(jsonify(vector_meta))
        f.write('\n')


def sha256(byts):
    h = hashlib.sha256()
    h.update(byts)
    return h.hexdigest()


def sha512(byts):
    h = hashlib.sha512()
    h.update(byts)
    return h.hexdigest()


def key_id(pub):
    return sha256(cjson(pub))


def key_type(sig_method):
    if sig_method == 'ed25519':
        return 'ed25519'
    elif sig_method == 'rsassa-pss-sha256':
        return 'rsa'
    else:
        raise Exception('unknown signature method: {}'.format(sig_method))


def jsonify(jsn):
    return json.dumps(jsn, sort_keys=True, indent=2)


def human_message(err):

    if err == 'TargetHashMismatch':
        return "The target's calculated hash did not match the hash in the metadata."
    elif err == 'OversizedTarget':
        return "The target's size was greater than the size in the metadata."
    elif '::' in err:
        err_base, err_sub = err.split('::')

        if err_base == 'ExpiredMetadata':
            return "The {} metadata was expired.".format(err_sub)
        else:
            raise Exception('Unknown err: {}'.format(err_base))
    else:
        raise Exception('Unknown err: {}'.format(err))


def sign(keys, signed):
    data = cjson(signed)

    sigs = []
    for sig_method, priv, pub in keys:
        if sig_method == 'ed25519':
            priv = ed25519.SigningKey(binascii.unhexlify(priv))
            sig = priv.sign(data, encoding='hex').decode('utf-8')
        elif sig_method == 'rsassa-pss-sha256':
            h = SHA256.new(data)
            rsa = RSA.importKey(priv)
            signer = PKCS1_PSS.new(rsa)
            sig = binascii.hexlify(signer.sign(h)).decode('utf-8')
        else:
            raise Exception('unknown signature method: {}'.format(sig_method))

        sig_data = {
            'keyid': key_id(pub),
            'method': sig_method,
            'sig': sig,
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
    TARGETS_KEYS = ['ed25519']

    '''The signature methods for the timestamp keys.
    '''
    TIMESTAMP_KEYS = ['ed25519']

    '''The signature methods for the snapshot keys.
    '''
    SNAPSHOT_KEYS = ['ed25519']

    '''The repo's targets.
    '''
    TARGETS = [('file.txt', b'wat wat wat\n')]

    def __init__(self):
        for d in ['keys', 'targets']:
            os.makedirs(path.join(self.output_dir, d), exist_ok=True)

        self.root_keys = []

        for version, keys in enumerate(self.ROOT_KEYS):
            log.info('Making keys for root version {}'.format(version + 1))

            root_key_group = []

            for key_num, sig_method in enumerate(keys):
                log.info('Making root key {} with method {}'.format(key_num + 1, sig_method))

                priv, pub = self.gen_key('{}.root-{}'.format(version + 1, key_num + 1),
                                         sig_method)
                root_key_group.append((sig_method, priv, pub))

            self.root_keys.append(root_key_group)

        self.targets_keys = []
        for key_num, sig_method in enumerate(self.TARGETS_KEYS):
            log.info('Making targets key {} with method {}'.format(key_num + 1, sig_method))

            priv, pub = self.gen_key('targets-{}'.format(key_num + 1), sig_method)
            self.targets_keys.append((sig_method, priv, pub))

        self.timestamp_keys = []
        for key_num, sig_method in enumerate(self.TIMESTAMP_KEYS):
            log.info('Making timestamp key {} with method {}'.format(key_num + 1, sig_method))

            priv, pub = self.gen_key('timestamp-{}'.format(key_num + 1), sig_method)
            self.timestamp_keys.append((sig_method, priv, pub))

        self.snapshot_keys = []
        for key_num, sig_method in enumerate(self.SNAPSHOT_KEYS):
            log.info('Making snapshot key {} with method {}'.format(key_num + 1, sig_method))

            priv, pub = self.gen_key('snapshot-{}'.format(key_num + 1), sig_method)
            self.snapshot_keys.append((sig_method, priv, pub))

        for target, content in self.TARGETS:
            log.info('Writing target: {}'.format(target))

            with open(path.join(self.output_dir, 'targets', target), 'wb') as f:
                f.write(self.alter_target(content))

        self.make_root(1)
        for version, root in enumerate(self.root_meta):
            log.info('Making root metadata version {}'.format(version))

            # TODO cross sign verion N+1 with keys from version N
            self.write_meta('{}.root'.format(version + 1), root)
        self.write_meta('root', self.root_meta[-1])

        log.info('Making targets metadata')
        self.make_targets()
        self.write_meta('targets', self.targets_meta)

        log.info('Making snapshot metadata')
        self.make_snapshot()
        self.write_meta('snapshot', self.snapshot_meta)

        log.info('Making timestamp metadata')
        self.make_timestamp()
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
        with open(path.join(self.output_dir, name + '.json'), 'w') as f:
            f.write(jsonify(data))
            f.write('\n')

    def make_root(self, version) -> None:
        signed = {
            '_type': 'Root',
            'consistent_snapshot': False,
            'expires': '2017-01-01T00:00:00Z' if self.EXPIRED == 'root' else '2038-01-19T03:14:06Z',
            'version': version,
            'keys': {},
            'roles': {
                'root': {
                    'keyids': [],
                    'threshold': 1,
                },
                'targets': {
                    'keyids': [],
                    'threshold': 1,
                },
                'timestamp': {
                    'keyids': [],
                    'threshold': 1,
                },
                'snapshot': {
                    'keyids': [],
                    'threshold': 1,
                },
            }
        }

        keys = []

        for sig_method, _, pub in self.root_keys[version - 1]:
            k_id = key_id(pub)
            keys.append((sig_method, pub))
            signed['roles']['root']['keyids'].append(k_id)

        for sig_method, _, pub in self.targets_keys:
            k_id = key_id(pub)
            keys.append((sig_method, pub))
            signed['roles']['targets']['keyids'].append(k_id)

        for sig_method, _, pub in self.timestamp_keys:
            k_id = key_id(pub)
            keys.append((sig_method, pub))
            signed['roles']['timestamp']['keyids'].append(k_id)

        for sig_method, _, pub in self.snapshot_keys:
            k_id = key_id(pub)
            keys.append((sig_method, pub))
            signed['roles']['snapshot']['keyids'].append(k_id)

        for sig_method, pub in keys:
            signed['keys'][key_id(pub)] = {
                'keytype': key_type(sig_method),
                'keyvalue': {'public': pub},
            }

        meta = {'signatures': sign(self.root_keys[version - 1], signed), 'signed': signed}

        if not hasattr(self, 'root_meta'):
            self.root_meta = []

        self.root_meta.append(meta)

    def make_targets(self):
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

        self.targets_meta = {'signatures': sign(self.targets_keys, signed), 'signed': signed}

    def make_snapshot(self):
        signed = {
            '_type': 'Snapshot',
            'expires': '2017-01-01T00:00:00Z' if self.EXPIRED == 'snapshot' else '2038-01-19T03:14:06Z',
            'version': 1,
            'meta': {
                'targets.json': {
                    'version': 1,
                },
            }
        }

        # TODO not sure if all versions of root need to be included
        for version, root in enumerate(self.root_meta):
            name = '{}.root.json'.format(version + 1)
            jsn = jsonify(root)

            signed['meta'][name] = {
                'length': len(jsn),
                'version': root['signed']['version'],
                'hashes': {
                    'sha512': sha512(jsn.encode('utf-8')),
                    'sha256': sha256(jsn.encode('utf-8')),
                },
            }

            signed['meta']['root.json'] = signed['meta'][name]

        self.snapshot_meta = {'signatures': sign(self.snapshot_keys, signed), 'signed': signed}

    def make_timestamp(self):
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

        self.timestamp_meta = {'signatures': sign(self.timestamp_keys, signed), 'signed': signed}

    @classmethod
    def vector_meta(cls) -> dict:
        meta = {
            'repo': cls.NAME,
            'is_success': cls.ERROR is None,
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
    TARGETS_KEYS = ['rsassa-pss-sha256']
    TIMESTAMP_KEYS = ['rsassa-pss-sha256']
    SNAPSHOT_KEYS = ['rsassa-pss-sha256']


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


if __name__ == '__main__':
    main()
