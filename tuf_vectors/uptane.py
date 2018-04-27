# -*- coding: utf-8 -*-

import re

from os import path

from tuf_vectors.step import Step


class Uptane:

    CLASS_SUFFIX = 'Uptane'

    '''2-tuple of (Director, Image Repo)'''
    STEPS = []

    def __init__(self, **kwargs) -> None:
        output_dir = kwargs.get('output_dir', None)
        if output_dir is None:
            raise ValueError("Missing kwarg 'output_dir'")
        output_dir = path.join(output_dir, self.name())
        kwargs['output_dir'] = output_dir

        self.steps = []
        for idx, (director_step, image_step) in enumerate(self.STEPS):
            args = kwargs.copy()
            args.update(step_index=idx)
            image_step = image_step(uptane_role='image_repo', **args)
            director_step = director_step(uptane_role='director', **args)
            self.steps.append((director_step, image_step))

    @classmethod
    def name(cls) -> str:
        n = cls.__name__
        if n.endswith(cls.CLASS_SUFFIX):
            n = n[:-len(cls.CLASS_SUFFIX)]
            n = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', n)
            return re.sub('([a-z0-9])([A-Z])', r'\1_\2', n).lower()
        else:
            raise ValueError('Class name needs to end in "{}": {}'.format(cls.CLASS_SUFFIX, n))

    def persist(self) -> None:
        for (director_step, image_step) in self.steps:
            director_step.persist()
            image_step.persist()

    def meta(self) -> dict:
        '''Used to indicate if this update should pass/fail'''
        meta = {'steps': []}

        for director_step, image_step in self.steps:
            meta['steps'].append({
                'director': director_step.meta(),
                'image_repo': image_step.meta(),
            })

        return meta


class SimpleUptane(Uptane):

    class ImageStep(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        SNAPSHOT_KWARGS = {
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
        }

        TIMESTAMP_KWARGS = {
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

    class DirectorStep(Step):

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]
