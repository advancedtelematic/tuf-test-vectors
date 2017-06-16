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

    @classmethod
    def generate_meta(cls) -> dict:
        meta = {
            'version': TEST_META_VERSION,
            'steps': [],
        }

        for step in cls.STEPS:
            meta['steps'].append(step.generate_meta())

        return meta

    @classmethod
    def write_meta(cls) -> None:
        with open(path.join(path.dirname(__file__), '..', 'metadata', 'tuf',
                            '{}.json'.format(cls.name())), 'w') as f:
            f.write(json.dumps(cls.generate_meta(), indent=2, sort_keys=True))

    def write_static(self) -> None:
        for step in self.steps:
            step.write_static()

    def self_test(self) -> None:
        for step in self.steps:
            step.self_test()


class SimpleTuf(Tuf):

    STEPS = [step.SimpleStep]


for _name in ['Expired', 'UnmetThreshold', 'NonUniqueSignatures', 'ZeroThreshold', 'NegativeThreshold']:
    for role in ALL_ROLES:
        fields = {
            'STEPS': [getattr(step, role + _name + 'Step')],
        }

        name = role + _name + 'Tuf'
        setattr(sys.modules[__name__], name, type(name, (Tuf,), fields))
