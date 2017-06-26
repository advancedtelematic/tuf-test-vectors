# -*- coding: utf-8 -*-

import base64
import binascii
import ed25519
import hashlib
import json
import re

from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from os import path
from securesystemslib.formats import encode_canonical as olpc_cjson

TEST_META_VERSION = 1
ALL_ROLES = ['Root', 'Targets', 'Timestamp', 'Snapshot']
ALL_UPTANE_ROLES = ['Director', 'ImageRepo']


def subclasses(cls) -> list:
    '''Returns a sorted list of all Repo/Uptane subclasses. Elements are unique.
    '''
    def inner(c):
        return c.__subclasses__() + [g for s in c.__subclasses__()
                                     for g in inner(s)]

    # filter is to ignore unnamed inner classes
    return sorted(list(set(x for x in inner(cls) if not x.IS_INNER)),
                  key=lambda x: x.name())


def short_key_type(typ) -> str:
    if typ == 'ed25519':
        return 'ed25519'
    elif typ.startswith('rsa'):
        return 'rsa'
    else:  # pragma: no cover
        raise Exception('Unknown key typ: {}'.format(typ))


def sha256(data, bad_hash: bool) -> str:
    if isinstance(data, str):
        data = data.encode('utf-8')
    h = hashlib.sha256()
    h.update(data)
    d = h.digest()

    if bad_hash:
        d = bytearray(d)
        d[0] ^= 0x01
        d = bytes(d)

    return binascii.hexlify(d).decode('utf-8')


def sha512(data, bad_hash: bool) -> str:
    if isinstance(data, str):
        data = data.encode('utf-8')
    h = hashlib.sha512()
    h.update(data)
    d = h.digest()

    if bad_hash:
        d = bytearray(d)
        d[0] ^= 0x01
        d = bytes(d)

    return binascii.hexlify(d).decode('utf-8')


def human_message(err: str) -> str:
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
        else:  # pragma: no cover
            raise Exception('Unavailable err: {}'.format(err_base))
    else:  # pragma: no cover
        raise Exception('Unavailable err: {}'.format(err))


def _cjson_subset_check(jsn):
    if isinstance(jsn, list):
        for j in jsn:
            _cjson_subset_check(j)
    elif isinstance(jsn, dict):
        for _, v in jsn.items():
            _cjson_subset_check(v)
    elif isinstance(jsn, str):
        pass
    elif isinstance(jsn, bool):
        pass
    elif jsn is None:
        pass
    elif isinstance(jsn, int):
        pass
    elif isinstance(jsn, float):  # pragma: no cover
        raise ValueError('CJSON does not allow floats')
    else:  # pragma: no cover
        raise ValueError('What sort of type is this? {} {}'.format(type(jsn), jsn))


class Generator:

    IS_INNER = False

    @classmethod
    def name(cls) -> str:
        n = cls.__name__
        if n.endswith(cls.CLASS_SUFFIX):
            n = n[:-len(cls.CLASS_SUFFIX)]
            n = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', n)
            return re.sub('([a-z0-9])([A-Z])', r'\1_\2', n).lower()
        else:  # pragma: no cover
            raise ValueError('Class name needs to end in "{}": {}'.format(cls.CLASS_SUFFIX, n))

    def generate_meta(cls) -> None:  # pragma: no cover
        '''Generate the static JSON metadata used to describe a test case.
        '''
        raise NotImplementedError

    def write_meta(cls) -> dict:  # pragma: no cover
        '''Write the generic metadata about the test case.
        '''
        raise NotImplementedError

    def write_static(self) -> None:  # pragma: no cover
        '''Write the static set of files used to serve the test case.
        '''
        raise NotImplementedError

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
            kwargs['separators'] = (':', ',')

        out = json.dumps(jsn, **kwargs)

        if not self.compact:
            out += '\n'

        return out

    def encode_signature(self, sig) -> str:
        if self.signature_encoding == 'hex':
            return binascii.hexlify(sig).decode('utf-8')
        elif self.signature_encoding == 'base64':
            return base64.b64encode(sig).decode('utf-8')
        else:  # pragma: no cover
            raise ValueError('Invalid signature encoding: {}'.format(self.signature_encoding))

    def get_key(self, key_idx) -> (str, str, str):
        try:
            (priv, pub) = self.key_store[key_idx]
        except KeyError:
            path_base = path.join(path.dirname(__file__), '..', 'keys',
                                  '{}-{}.'.format(self.key_type, key_idx))
            with open('{}priv'.format(path_base)) as f:
                priv = f.read()

            with open('{}pub'.format(path_base)) as f:
                pub = f.read()

            self.key_store[key_idx] = (priv, pub)

        return (priv, pub)

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

    def self_test(self) -> None:  # pragma: no cover
        '''Do a self test against generted files to ensure all desired properties hold.
        '''
        raise NotImplementedError
