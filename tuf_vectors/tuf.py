# -*- coding: utf-8 -*-

import json
import os
import sys

from os import path
from tuf_vectors import step, Generator, TEST_META_VERSION, ALL_ROLES


class Tuf(Generator):

    CLASS_SUFFIX = 'Tuf'

    def __init__(
            self,
            output_dir,
            key_type,
            signature_scheme,
            signature_encoding,
            compact,
            cjson_strategy,
            uptane_role=None):
        if uptane_role is None:
            self.output_dir = path.join(output_dir, self.name())
        else:
            self.output_dir = path.join(output_dir, uptane_role)

        self.uptane_role = uptane_role
        self.key_type = key_type
        self.signature_scheme = signature_scheme
        self.signature_encoding = signature_encoding
        self.compact = compact
        self.cjson_strategy = cjson_strategy
        self.steps = []

        for idx, step in enumerate(self.STEPS):
            step = step(self.output_dir, step_index=idx,
                        key_type=key_type, signature_scheme=signature_scheme,
                        signature_encoding=signature_encoding, compact=compact,
                        cjson_strategy=cjson_strategy)
            self.steps.append(step)

    def generate_meta(self) -> dict:
        meta = {
            'version': TEST_META_VERSION,
            'steps': [],
        }

        for step in self.steps:
            meta['steps'].append(step.generate_meta())

        return meta

    def write_meta(self) -> None:
        with open(path.join(path.dirname(__file__), '..', 'metadata', 'tuf',
                            '{}.json'.format(self.name())), 'w') as f:
            f.write(json.dumps(self.generate_meta(), indent=2, sort_keys=True))

    def write_static(self) -> None:
        for step in self.steps:
            step.write_static()

    def self_test(self) -> None:
        for step in self.steps:
            step.self_test()


class SimpleTuf(Tuf):

    STEPS = [step.SimpleStep]


for _name in [
    'Expired',
    'UnmetThreshold',
    'NonUniqueSignatures',
    'ZeroThreshold',
        'NegativeThreshold']:
    for role in ALL_ROLES:
        fields = {
            'STEPS': [getattr(step, role + _name + 'Step')],
        }

        name = role + _name + 'Tuf'
        setattr(sys.modules[__name__], name, type(name, (Tuf,), fields))


class ValidRootRotationTuf(Tuf):

    class RootSignedBy0and4Step(step.Step):

        IS_INNER = True
        ROOT_VERSION = 2
        ROOT_KEYS = [4]
        ROOT_KEYS_SIGN = [0, 4]

        def self_test(self) -> None:
            meta = self.generate_meta()
            assert meta['update']['is_success'] is True
            assert meta['update'].get('err') is None
            assert self.UPDATE_ERROR is None

            assert len(self.root['signatures']) == 2
            assert len(self.root['signed']['roles']['root']['keyids']) == 1

    STEPS = [
        step.SimpleStep,
        RootSignedBy0and4Step,
    ]


class RootRotationNoCrossSignTuf(Tuf):

    class RootSignedByOnly4Step(step.Step):

        IS_INNER = True
        ROOT_VERSION = 2
        ROOT_KEYS = [4]
        ROOT_KEYS_SIGN = [4]
        UPDATE_ERROR = 'UnmetThreshold::Root'

        def self_test(self) -> None:
            meta = self.generate_meta()
            assert meta['update']['is_success'] == False
            assert meta['update']['err'] == 'UnmetThreshold::Root'

            assert len(self.root['signatures']) == 1
            assert len(self.root['signed']['roles']['root']['keyids']) == 1

    STEPS = [
        step.SimpleStep,
        RootSignedByOnly4Step,
    ]


class TargetHashMismatchTuf(Tuf):

    STEPS = [step.TargetHashMismatchStep]


class OversizedTargetTuf(Tuf):

    STEPS = [step.OversizedTargetStep]
