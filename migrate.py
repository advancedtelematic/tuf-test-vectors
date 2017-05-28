import json
import os

from os import path


CURRENT_VERSION = 1
log = None


def migrate(repo_type, repo_path, _log):
    global log
    log = _log

    log.info('Running migrations')
    repo_version = get_repo_version(repo_path)
    log.info('Repos are at version {}'.format(repo_version))

    if repo_version is None:
        return

    if repo_version > CURRENT_VERSION:
        raise Exception('Repo version greater than current known version: {} > {}' \
                        .format(repo_version, CURRENT_VERSION))

    if repo_version <= 0:
        do_0_to_1(repo_type, repo_path)


def get_repo_version(repo_path):
    try:
        with open(path.join(repo_path, 'vector-meta.json')) as f:
            jsn = json.loads(f.read())
    except FileNotFoundError:
        return None
    else:
        if isinstance(jsn, list):
            return 0
        else:
            return jsn['version']


def do_0_to_1(repo_type, repo_path):
    log.info('Migrating from {} version 0 to 1'.format(repo_type))

    if repo_type == 'tuf':
        dirs = ['.']
    else:
        dirs = ['repo', 'director']

    for d in os.listdir(repo_path):
        full_path = path.join(repo_path, d)

        if not path.isdir(full_path):
            continue

        keys = {}
        for repo_dir in dirs:
            # case of uptane w/ missing repo
            if repo_type == 'uptane' and not path.exists(path.join(full_path, repo_dir)):
                    continue

            for k in os.listdir(path.join(full_path, repo_dir, 'keys')):
                _, key, suffix = k.split('.')
                key = key.split('-')[0]
                if key in keys:
                    keys[key][suffix].append(k)
                else:
                    keys[key] = {
                        'pub': [k] if suffix == 'pub' else [],
                        'priv': [k] if suffix == 'priv' else [],
                    }

            for role, key_data in keys.items():
                if role != 'root':
                    continue

                for typ in ['pub', 'priv']: 
                    for key_idx, key_name in enumerate(key_data[typ]):
                        try:
                            os.rename(path.join(full_path, repo_dir, 'keys', key_name),
                                      path.join(full_path, repo_dir, 'keys', '{}-{}.{}'.format(role, key_idx + 1, typ)))
                        except Exception:
                            pass
