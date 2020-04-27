# -*- coding: utf-8 -*-

import binascii
import hashlib

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
    return sorted(list(set(x for x in inner(cls))),
                  key=lambda x: x.name())


def short_key_type(typ) -> str:
    if typ == 'ed25519':
        return 'ed25519'
    elif typ.startswith('rsa'):
        return 'rsa'
    else:
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
    elif '::' in err:
        err_base, err_sub, *err_extra = err.split('::')

        if err_base == 'MetadataFetchFailure':
            return "Failed to fetch role {} in {} repository.".format(err_sub.lower(), err_extra[0].lower())
        if err_base == 'DelegationHashMismatch':
            return "The calculated hash of delegated role {} did not match the hash in the metadata.". \
                    format(err_sub.lower())
        if err_base == 'DelegationMissing':
            return "The delegated role {} is missing.".format(err_sub.lower())
        if err_base == 'VersionMismatch':
            return 'The version of role {} does not match the entry in Snapshot metadata.'.format(err_sub.lower())
        if err_base == 'UnmetThreshold':
            return "The {} metadata had an unmet threshold.".format(err_sub.lower())
        elif err_base == 'IllegalThreshold':
            return 'The role {} had an illegal signature threshold.'.format(err_sub.lower())
        elif err_base == 'NonUniqueSignatures':
            return 'The role {} had non-unique signatures.'.format(err_sub.lower())
        elif err_base == 'SecurityException':
            return 'Metadata type invalidrole does not match expected role {}'.format(err_sub.lower())

        assert err_sub in ['Root', 'Targets', 'Timestamp', 'Snapshot', 'Delegation'], err_sub

        if err_base == 'ExpiredMetadata':
            return "The {} metadata was expired.".format(err_sub.lower())
        # Unused, but probably should be:
        elif err_base == 'MetadataHashMismatch':
            return "The {} metadata's hash did not match the hash in the metadata." \
                   .format(err_sub.lower())
        # Unused, but probably should be:
        elif err_base == 'OversizedMetadata':
            return "The {} metadata's size was greater than the size in the metadata." \
                   .format(err_sub.lower())
        else:
            raise Exception('Unavailable err: {}'.format(err_base))
    elif err == 'BadKeyId':
        return 'A key has an incorrect associated key ID'
    elif err == 'BadHardwareId':
        return "The target had a hardware ID that did not match the client's configured " \
               "hardware ID."
    elif err == 'BadEcuId':
        return "The target had an ECU ID that did not match the client's configured ECU ID."
    elif err == 'TargetMismatch':
        return "The target metadata in the Image and Director repos do not match."
    elif err == 'DirectorDelegation':
        return "The targets metadata failed to parse: Found unexpected delegation."
    elif err == 'DirectorRepeatedEcuId':
        return "The targets metadata failed to parse: Found repeated ECU ID."
    elif err == 'RootRotationError':
        return "Version in Root metadata does not match its expected value."
    else:
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
    elif isinstance(jsn, float):
        raise ValueError('CJSON does not allow floats')
    else:
        raise ValueError('What sort of type is this? {} {}'.format(type(jsn), jsn))
