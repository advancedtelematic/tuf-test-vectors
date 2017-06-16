# -*- coding: utf-8 -*-

import json
import sys

from os import path
from tuf_vectors import tuf, Generator, TEST_META_VERSION, ALL_ROLES, ALL_UPTANE_ROLES


class Uptane(Generator):

    CLASS_SUFFIX = 'Uptane'

    DIRECTOR_CLS = None
    IMAGE_REPO_CLS = None

    def __init__(
            self,
            output_dir,
            key_type,
            signature_scheme,
            signature_encoding,
            compact,
            cjson_strategy):
        self.output_dir = path.join(output_dir, self.name())
        self.key_type = key_type
        self.signature_scheme = signature_scheme
        self.signature_encoding = signature_encoding
        self.compact = compact
        self.cjson_strategy = cjson_strategy

        self.director = self.DIRECTOR_CLS(output_dir=self.output_dir, key_type=key_type,
                                          signature_scheme=signature_scheme,
                                          uptane_role='director', compact=compact,
                                          signature_encoding=signature_encoding,
                                          cjson_strategy=cjson_strategy)

        self.image_repo = self.IMAGE_REPO_CLS(output_dir=self.output_dir, key_type=key_type,
                                              signature_scheme=signature_scheme,
                                              uptane_role='image-repo', compact=compact,
                                              signature_encoding=signature_encoding,
                                              cjson_strategy=cjson_strategy)

    @classmethod
    def generate_meta(cls) -> dict:
        director_meta = cls.DIRECTOR_CLS.generate_meta()
        image_repo_meta = cls.IMAGE_REPO_CLS.generate_meta()

        if len(director_meta['steps']) != len(image_repo_meta['steps']):  # pragma: no cover
            raise Exception('Director steps did not equal image repo steps')

        steps = []
        for dir_step, img_step in zip(director_meta['steps'], image_repo_meta['steps']):
            meta = {
                'director': dir_step,
                'image_repo': img_step,
            }

            del meta['director']['meta']['timestamp']
            del meta['director']['meta']['snapshot']

            # TODO ? merge dir/img targets into one
            steps.append(meta)

        update_meta = {
            'version': TEST_META_VERSION,
            'steps': steps,
        }

        return update_meta

    @classmethod
    def write_meta(cls) -> None:
        with open(path.join(path.dirname(__file__), '..', 'metadata', 'uptane',
                            '{}.json'.format(cls.name())), 'w') as f:
            f.write(json.dumps(cls.generate_meta(), indent=2, sort_keys=True))

    def write_static(self) -> None:
        self.director.write_static()
        self.image_repo.write_static()

    def self_test(self) -> None:
        meta = self.generate_meta()

        for step in meta['steps']:
            for r in ['timestamp', 'snapshot']:
                assert not r in step['director']['meta']

        self.director.self_test()
        self.image_repo.self_test()


class SimpleUptane(Uptane):

    DIRECTOR_CLS = tuf.SimpleTuf
    IMAGE_REPO_CLS = tuf.SimpleTuf


for _name in ['Expired', 'UnmetThreshold', 'NonUniqueSignatures', 'ZeroThreshold', 'NegativeThreshold']:
    for uptane_role in ALL_UPTANE_ROLES:
        for role in ALL_ROLES:
            if uptane_role == 'Director' and role in ['Snapshot', 'Timestamp']:
                continue

            cls = getattr(tuf, role + _name + 'Tuf')

            fields = {
                'DIRECTOR_CLS': cls if uptane_role == 'Director' else tuf.SimpleTuf,
                'IMAGE_REPO_CLS': cls if uptane_role == 'ImageRepo' else tuf.SimpleTuf,
            }

            name = uptane_role + role + _name + 'Uptane'
            setattr(sys.modules[__name__], name, type(name, (Uptane,), fields))
