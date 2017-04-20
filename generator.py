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
import os

from canonicaljson import encode_canonical_json as cjson


OUTPUT_DIR = path.join(path.dirname(path.abspath(__file__)), 'vectors')


def main():
    vector_meta = []
    for repo in Repo.subclasses():
        repo = repo()
        vector_meta.append(repo.vector_meta())

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
    else:
        raise Exception('unknown signature method: {}'.format(sig_method))


def jsonify(jsn):
    return json.dumps(jsn, sort_keys=True, indent=2)


def sign(keys, signed):
    data = cjson(signed)

    sigs = []
    for sig_method, priv, pub in keys:
        if sig_method == 'ed25519':
            priv = ed25519.SigningKey(binascii.unhexlify(priv))
            sig = priv.sign(data, encoding='hex').decode('utf-8')

            sig_data = {
                'keyid': key_id(pub),
                'method': sig_method,
                'sig': sig,
            }

            sigs.append(sig_data)
        else:
            raise Exception('unknown signature method: {}'.format(sig_method))

    return sigs


class Repo:

    ROOT_KEYS = [['ed25519']]
    TARGETS_KEYS = ['ed25519']
    TIMESTAMP_KEYS = ['ed25519']
    SNAPSHOT_KEYS = ['ed25519']
    TARGETS = [('file.txt', 'wat wat wat')]

    def __init__(self):
        for d in ['keys', 'targets']:
            os.makedirs(path.join(self.output_dir, d), exist_ok=True)

        self.root_keys = []

        for version, keys in enumerate(self.ROOT_KEYS):
            root_key_group = []

            for key_num, sig_method in enumerate(keys):
                key_data = self.gen_key('{}.root-{}'.format(version + 1, key_num + 1),
                                    sig_method)
                root_key_group.append((sig_method, key_data[0], key_data[1]))

            self.root_keys.append(root_key_group)

        self.targets_keys = []
        for sig_method in self.TARGETS_KEYS:
            key_data = self.gen_key('targets', sig_method)
            self.targets_keys.append((sig_method, key_data[0], key_data[1]))

        self.timestamp_keys = []
        for sig_method in self.TIMESTAMP_KEYS:
            key_data = self.gen_key('timestamp', sig_method)
            self.timestamp_keys.append((sig_method, key_data[0], key_data[1]))

        self.snapshot_keys = []
        for sig_method in self.SNAPSHOT_KEYS:
            key_data = self.gen_key('snapshot', sig_method)
            self.snapshot_keys.append((sig_method, key_data[0], key_data[1]))

        for target, content in self.TARGETS:
            with open(path.join(self.output_dir, 'targets', target), 'w') as f:
                f.write(content)

        self.make_root(1)
        for version, root in enumerate(self.root_meta):
            self.write_meta('{}.root'.format(version + 1), root)
        self.write_meta('root', self.root_meta[-1])

        self.make_targets()
        self.write_meta('targets', self.targets_meta)

        self.make_snapshot()
        self.write_meta('snapshot', self.snapshot_meta)

        self.make_timestamp()
        self.write_meta('timestamp', self.timestamp_meta)

    @property
    def output_dir(self):
        return path.join(OUTPUT_DIR, self.NAME)

    def gen_key(self, role, sig_method):
        if sig_method == 'ed25519':
            try:
                with open(path.join(self.output_dir, 'keys', '{}.priv'.format(role)), 'r') as f:
                    priv = f.read().strip()

                with open(path.join(self.output_dir, 'keys', '{}.pub'.format(role)), 'r') as f:
                    pub = f.read().strip()
            except FileNotFoundError:
                priv, pub = ed25519.create_keypair()
                priv = binascii.hexlify(priv.to_bytes()).decode('utf-8')
                pub = binascii.hexlify(pub.to_bytes()).decode('utf-8')
            finally:
                with open(path.join(self.output_dir, 'keys', '{}.priv'.format(role)), 'w') as f:
                    f.write(priv)
                    f.write('\n')

                with open(path.join(self.output_dir, 'keys', '{}.pub'.format(role)), 'w') as f:
                    f.write(pub)
                    f.write('\n')
        else:
            raise Exception('unknown signature method: {}'.format(sig_method))

        return (priv, pub)

    def write_meta(self, name, data) -> None:
        with open(path.join(self.output_dir, name + '.json'), 'w') as f:
            f.write(jsonify(data))
            f.write('\n')

    def make_root(self, version) -> None:
        signed = {
            '_type': 'Root',
            'consistent_snapshot': False,
            'expires': '2038-01-19T03:14:06Z',
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
            signed['roles']['root'] = k_id

        for sig_method, pub in keys:
            signed['keys'][key_id(pub)] = {
                'keytype': key_type(sig_method),
                'keyvalue': { 'public': pub },
            }

        meta = {'signatures': sign(self.root_keys[version - 1], signed), 'signed': signed }

        if not hasattr(self, 'root_meta'):
            self.root_meta = []

        self.root_meta.append(meta)

    def make_targets(self):
        file_data = dict()

        for root, _, filenames in os.walk(path.join(self.output_dir, 'targets')):
            for filename in filenames:
                full_path = os.path.join(root, filename)
                with open(full_path, 'rb') as f:
                    byts = f.read()
                    file_data[full_path.replace(path.join(self.output_dir, ''), '')] = {
                        'length': len(byts),
                        'hashes': {
                            'sha512': sha512(byts),
                            'sha256': sha256(byts),
                        }
                    }

        signed = {
            '_type': 'Targets',
            'expires': '2038-01-19T03:14:06Z',
            'version': 1,
            'targets': file_data,
        }

        self.targets_meta = {'signatures': sign(self.targets_keys, signed), 'signed': signed }

    def make_snapshot(self):
        signed = {
            '_type': 'Snapshot',
            'expires': '2038-01-19T03:14:06Z',
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

            signed['meta'][name] = {
                'length': len(root),
                'version': root['signed']['version'],
                'hashes': {
                    'sha512': sha512(jsonify(root).encode('utf-8')),
                    'sha256': sha256(jsonify(root).encode('utf-8')),
                },
            }

            signed['meta']['root.json'] = signed['meta'][name]

        self.snapshot_meta = {'signatures': sign(self.snapshot_keys, signed), 'signed': signed }

    def make_timestamp(self):
        signed = {
            '_type': 'Timestamp',
            'expires': '2038-01-19T03:14:06Z',
            'version': 1,
            'meta': {
                'snapshot.json': {
                    'length': len(self.snapshot_meta),
                    'version': 1,
                    'hashes': {
                        'sha512': sha512(jsonify(self.snapshot_meta).encode('utf-8')),
                        'sha256': sha256(jsonify(self.snapshot_meta).encode('utf-8')),
                    },
                },
            }
        }

        self.timestamp_meta = {'signatures': sign(self.timestamp_keys, signed), 'signed': signed }

    @classmethod
    def vector_meta(cls):
        meta = {
            'repo': cls.NAME,
            'is_success': cls.IS_SUCCESS,
        }

        try:
            meta['error'] = cls.ERROR
            meta['error_msg'] = cls.ERROR_MESSAGE
        except AttributeError:
            pass

        return meta

    @classmethod
    def subclasses(cls) -> list:
        return cls.__subclasses__() + [g for s in cls.__subclasses__()
                                       for g in s.subclasses()]


class Repo001(Repo):

    NAME = '001'
    IS_SUCCESS = True


if __name__ == '__main__':
    main()
