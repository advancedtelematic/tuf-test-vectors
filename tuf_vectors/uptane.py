# -*- coding: utf-8 -*-

import json
import sys

from os import path
from tuf_vectors import tuf, step, Generator, TEST_META_VERSION, ALL_ROLES, ALL_UPTANE_ROLES


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

    def generate_meta(self) -> dict:
        director_meta = self.director.generate_meta()
        image_repo_meta = self.image_repo.generate_meta()

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
            del meta['director']['targets']
            # TODO ? merge dir/img targets into one
            steps.append(meta)

        update_meta = {
            'version': TEST_META_VERSION,
            'steps': steps,
        }

        return update_meta

    def write_meta(self) -> None:
        with open(path.join(path.dirname(__file__), '..', 'metadata', 'uptane',
                            '{}.json'.format(self.name())), 'w') as f:
            f.write(json.dumps(self.generate_meta(), indent=2, sort_keys=True))

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


for _name in [
    'Expired',
    'UnmetThreshold',
    'NonUniqueSignatures',
    'ZeroThreshold',
        'NegativeThreshold',
        'BadKeyIds']:
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


for _name in ['ValidRootRotation', 'RootRotationNoCrossSign']:
    for uptane_role in ALL_UPTANE_ROLES:
        cls = getattr(tuf, _name + 'Tuf')

        class SimpleRepeatedTuf(tuf.Tuf):
            IS_INNER = True
            STEPS = [step.SimpleStep, step.SimpleStep]

        fields = {
            'DIRECTOR_CLS': cls if uptane_role == 'Director' else SimpleRepeatedTuf,
            'IMAGE_REPO_CLS': cls if uptane_role == 'ImageRepo' else SimpleRepeatedTuf,
        }

        name = uptane_role + _name + 'Uptane'
        setattr(sys.modules[__name__], name, type(name, (Uptane,), fields))


for _name in ['OversizedTarget', 'TargetHashMismatch']:
    cls = getattr(tuf, _name + 'Tuf')

    fields = {
        'DIRECTOR_CLS': cls if uptane_role == 'Director' else tuf.SimpleTuf,
        'IMAGE_REPO_CLS': cls if uptane_role == 'ImageRepo' else tuf.SimpleTuf,
    }

    name = uptane_role + _name + 'Uptane'
    setattr(sys.modules[__name__], name, type(name, (Uptane,), fields))
