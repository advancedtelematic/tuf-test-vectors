# -*- coding: utf-8 -*-

import json
import os
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
            cjson_strategy,
            include_custom,
            ecu_identifier,
            hardware_id):
        if include_custom and (not ecu_identifier or not hardware_id):
            raise ValueError('include_custom requries an ecu_identifier and hardware_id')

        self.output_dir = path.join(output_dir, self.name())
        self.key_type = key_type
        self.signature_scheme = signature_scheme
        self.signature_encoding = signature_encoding
        self.compact = compact
        self.cjson_strategy = cjson_strategy
        self.include_custom = include_custom
        self.ecu_identifier = ecu_identifier
        self.hardware_id = hardware_id

        self.director = self.DIRECTOR_CLS(output_dir=self.output_dir, key_type=key_type,
                                          signature_scheme=signature_scheme,
                                          uptane_role='director', compact=compact,
                                          signature_encoding=signature_encoding,
                                          cjson_strategy=cjson_strategy,
                                          include_custom=include_custom,
                                          ecu_identifier=ecu_identifier,
                                          hardware_id=hardware_id)

        self.image_repo = self.IMAGE_REPO_CLS(output_dir=self.output_dir, key_type=key_type,
                                              signature_scheme=signature_scheme,
                                              uptane_role='image-repo', compact=compact,
                                              signature_encoding=signature_encoding,
                                              cjson_strategy=cjson_strategy,
                                              include_custom=include_custom,
                                              ecu_identifier=ecu_identifier,
                                              hardware_id=hardware_id)

    def generate_description(self) -> dict:
        director_meta = self.director.generate_description()
        image_repo_meta = self.image_repo.generate_description()

        if len(director_meta['steps']) != len(image_repo_meta['steps']):  # pragma: no cover
            raise Exception('Director steps did not equal image repo steps')

        steps = []
        for dir_step, img_step in zip(director_meta['steps'], image_repo_meta['steps']):
            meta = {
                'director': dir_step,
                'image_repo': img_step,
            }

            meta['director']['meta'].pop('timestamp', None)
            meta['director']['meta'].pop('snapshot', None)

            director_targets = meta['director'].pop('targets', {})
            for k, v in director_targets.items():
                if k in meta['image_repo']['targets']:
                    img_meta = meta['image_repo']['targets'][k]
                    if img_meta['is_success'] is True and v['is_success'] is False:
                        meta['image_repo']['targets'][k] = v
                else:
                    meta['image_repo']['targets'][k] = v

            steps.append(meta)

        update_meta = {
            'version': TEST_META_VERSION,
            'steps': steps,
        }

        return update_meta

    def write_meta(self) -> None:
        base_path = path.join(path.dirname(path.abspath(__file__)), '..', 'metadata', 'uptane')
        os.makedirs(base_path, exist_ok=True)
        with open(path.join(base_path, '{}.json'.format(self.name())), 'w') as f:
            f.write(json.dumps(self.generate_description(), indent=2, sort_keys=True))

    def write_static(self) -> None:
        self.director.write_static()
        self.image_repo.write_static()

    def self_test(self) -> None:
        meta = self.generate_description()

        for _step in meta['steps']:
            for r in ['timestamp', 'snapshot']:
                assert r not in _step['director']['meta']

        self.director.self_test()
        self.image_repo.self_test()

        if hasattr(self, 'extra_tests'):
            self.extra_tests()


class SimpleUptane(Uptane):

    DIRECTOR_CLS = tuf.SimpleTuf
    IMAGE_REPO_CLS = tuf.SimpleTuf


for _name in [
    'Expired',
    'UnmetThreshold',
    'NonUniqueSignatures',
    'ZeroThreshold',
    'NegativeThreshold',
    'BadKeyIds',
    'Unsigned',
        ]:
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
        'DIRECTOR_CLS': cls,
        'IMAGE_REPO_CLS': cls,
    }

    name = uptane_role + _name + 'Uptane'
    setattr(sys.modules[__name__], name, type(name, (Uptane,), fields))


for uptane_role in ALL_UPTANE_ROLES:
    def gen_test():
        def extra_tests(self):
            meta = self.generate_description()
            assert meta['steps'][0]['image_repo']['targets']['file.txt']['is_success'] is False
        return extra_tests

    fields = {
        'DIRECTOR_CLS': tuf.BadHardwareIdTuf if uptane_role == 'Director' else tuf.SimpleTuf,
        'IMAGE_REPO_CLS': tuf.BadHardwareIdTuf if uptane_role == 'ImageRepo' else tuf.SimpleTuf,
        'extra_tests': gen_test(),
    }
    name = uptane_role + 'BadHardwareIdUptane'
    setattr(sys.modules[__name__], name, type(name, (Uptane,), fields))


class BadHardwareIdUptane(Uptane):

    DIRECTOR_CLS = tuf.BadHardwareIdTuf
    IMAGE_REPO_CLS = tuf.BadHardwareIdTuf

    def extra_tests(self):
        meta = self.generate_description()
        assert meta['steps'][0]['image_repo']['targets']['file.txt']['is_success'] is False


class BadEcuIdUptane(Uptane):

    DIRECTOR_CLS = tuf.BadEcuIdTuf
    IMAGE_REPO_CLS = tuf.SimpleTuf

    def extra_tests(self):
        meta = self.generate_description()
        assert meta['steps'][0]['image_repo']['targets']['file.txt']['is_success'] is False
