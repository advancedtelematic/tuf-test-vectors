# -*- coding: utf-8 -*-

import re

from os import path

from tuf_vectors.metadata import Target, Delegation, Role, SKIPPED_DELEGATION_NAME
from tuf_vectors.step import Step, DEFAULT_TARGET_NAME, DEFAULT_TARGET_CONTENT, DEFAULT_DELEGATION_NAME, MISSING_DELEGATION_NAME


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

    '''The most basic happy case for Uptane.'''

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


class DirectorRootZeroThresholdUptane(Uptane):

    '''The Director has a threshold of zero for the Root role.'''

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
        UPDATE_ERROR = 'IllegalThreshold::Root'

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'root_threshold': 0,
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class DirectorTargetsZeroThresholdUptane(Uptane):

    '''The Director has a threshold of zero for the Targets role.'''

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
        UPDATE_ERROR = 'IllegalThreshold::Targets'

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_threshold': 0,
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class ImageRepoRootZeroThresholdUptane(Uptane):

    '''The Image repo has a threshold of zero for the Root role.'''

    class ImageStep(Step):

        UPDATE_ERROR = 'IllegalThreshold::Root'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
            'root_threshold': 0,
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


class ImageRepoTargetsZeroThresholdUptane(Uptane):

    '''The Image repo has a threshold of zero for the Targets role.'''

    class ImageStep(Step):

        UPDATE_ERROR = 'IllegalThreshold::Targets'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
            'targets_threshold': 0,
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


class ImageRepoSnapshotZeroThresholdUptane(Uptane):

    '''The Image repo has a threshold of zero for the Snapshot role.'''

    class ImageStep(Step):

        UPDATE_ERROR = 'IllegalThreshold::Snapshot'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
            'snapshot_threshold': 0,
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


class ImageRepoTimestampZeroThresholdUptane(Uptane):

    '''The Image repo has a threshold of zero for the Timestamp role.'''

    class ImageStep(Step):

        UPDATE_ERROR = 'IllegalThreshold::Timestamp'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
            'timestamp_threshold': 0,
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


class DirectorRootExpiredUptane(Uptane):

    '''The Director has expired Root metadata'''

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

        UPDATE_ERROR = 'ExpiredMetadata::Root'

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'is_expired': True,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class DirectorTargetsExpiredUptane(Uptane):

    '''The Director has expired Targets metadata'''

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

        UPDATE_ERROR = 'ExpiredMetadata::Targets'

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'is_expired': True,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class ImageRepoRootExpiredUptane(Uptane):

    '''The Image repo has expired Root metadata'''

    class ImageStep(Step):

        UPDATE_ERROR = 'ExpiredMetadata::Root'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
            'is_expired': True,
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


class ImageRepoTargetsExpiredUptane(Uptane):

    '''The Image repo has expired Targets metadata'''

    class ImageStep(Step):

        UPDATE_ERROR = 'ExpiredMetadata::Targets'

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
            'is_expired': True,
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


class ImageRepoSnapshotExpiredUptane(Uptane):

    '''The Image repo has expired Snapshot metadata'''

    class ImageStep(Step):

        UPDATE_ERROR = 'ExpiredMetadata::Snapshot'

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
            'is_expired': True,
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


class ImageRepoTimestampExpiredUptane(Uptane):

    '''The Image repo has expired Timestamp metadata'''

    class ImageStep(Step):

        UPDATE_ERROR = 'ExpiredMetadata::Timestamp'

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
            'is_expired': True,
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


class DirectorTargetHashMismatchUptane(Uptane):

    '''The Director has a target with bad hashes'''

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

        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'TargetMismatch',
        }

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        def __targets(hardware_id: str, ecu_identifier: str = None) -> list:
            return [Target(name=DEFAULT_TARGET_NAME,
                           content=DEFAULT_TARGET_CONTENT,
                           hardware_id=hardware_id,
                           ecu_identifier=ecu_identifier,
                           alteration='bad-hash')]

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': __targets,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class ImageRepoTargetHashMismatchUptane(Uptane):

    '''The Image repo has a target with bad hashes'''

    class ImageStep(Step):

        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'TargetMismatch',
        }

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        def __targets(hardware_id: str, ecu_identifier: str = None) -> list:
            return [Target(name=DEFAULT_TARGET_NAME,
                           content=DEFAULT_TARGET_CONTENT,
                           hardware_id=hardware_id,
                           ecu_identifier=ecu_identifier,
                           alteration='bad-hash')]

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': __targets,
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


class DirectorRootUnmetThresholdUptane(Uptane):

    '''The Director Root metadata has an unmet threshold'''

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

        UPDATE_ERROR = 'UnmetThreshold::Root'

        TARGETS_KEYS_IDX = [6]

        ROOT_KWARGS = {
            'root_keys_idx': [4, 5],
            'root_sign_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class DirectorTargetsUnmetThresholdUptane(Uptane):

    '''The Director Targets metadata has an unmet threshold'''

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

        UPDATE_ERROR = 'UnmetThreshold::Targets'

        TARGETS_KEYS_IDX = [5, 6]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX[0:-1],
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class ImageRepoRootUnmetThresholdUptane(Uptane):

    '''The Image repo Targets metadata has an unmet threshold'''

    class ImageStep(Step):

        UPDATE_ERROR = 'UnmetThreshold::Root'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0, 6],
            'root_sign_keys_idx': [0],
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


class ImageRepoTargetsUnmetThresholdUptane(Uptane):

    '''The Image repo Targets metadata has an unmet threshold'''

    class ImageStep(Step):

        UPDATE_ERROR = 'UnmetThreshold::Targets'

        TARGETS_KEYS_IDX = [1, 6]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX[0:-1],
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


class ImageRepoSnapshotUnmetThresholdUptane(Uptane):

    '''The Image repo Snapshot metadata has an unmet threshold'''

    class ImageStep(Step):

        UPDATE_ERROR = 'UnmetThreshold::Snapshot'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2, 6]
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
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX[0:-1],
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


class ImageRepoTimestampUnmetThresholdUptane(Uptane):

    '''The Image repo Timestamp metadata has an unmet threshold'''

    class ImageStep(Step):

        UPDATE_ERROR = 'UnmetThreshold::Timestamp'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3, 6]

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
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX[0:-1],
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


class DirectorRootNonUniqueSignaturesUptane(Uptane):

    '''The Director Root metadata has duplicate signatures'''

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

        UPDATE_ERROR = 'NonUniqueSignatures::Root'

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'root_sign_keys_idx': [4, 4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class DirectorTargetsNonUniqueSignaturesUptane(Uptane):

    '''The Director Targets metadata has duplicate signatures'''

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

        UPDATE_ERROR = 'NonUniqueSignatures::Targets'

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets_sign_keys_idx': TARGETS_KEYS_IDX + TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class ImageRepoRootNonUniqueSignaturesUptane(Uptane):

    '''The Image repo Root metadata has duplicate signatures'''

    class ImageStep(Step):

        UPDATE_ERROR = 'NonUniqueSignatures::Root'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'root_sign_keys_idx': [0, 0],
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


class ImageRepoTargetsNonUniqueSignaturesUptane(Uptane):

    '''The Image repo Targets metadata has duplicate signatures'''

    class ImageStep(Step):

        UPDATE_ERROR = 'NonUniqueSignatures::Targets'

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
            'targets_sign_keys_idx': TARGETS_KEYS_IDX + TARGETS_KEYS_IDX,
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


class ImageRepoSnapshotNonUniqueSignaturesUptane(Uptane):

    '''The Image repo Snapshot metadata has duplicate signatures'''

    class ImageStep(Step):

        UPDATE_ERROR = 'NonUniqueSignatures::Snapshot'

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
            'snapshot_sign_keys_idx': SNAPSHOT_KEYS_IDX + SNAPSHOT_KEYS_IDX,
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


class ImageRepoTimestampNonUniqueSignaturesUptane(Uptane):

    '''The Image repo Timestamp metadata has duplicate signatures'''

    class ImageStep(Step):

        UPDATE_ERROR = 'NonUniqueSignatures::Timestamp'

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
            'timestamp_sign_keys_idx': TIMESTAMP_KEYS_IDX + TIMESTAMP_KEYS_IDX,
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
################################


class DirectorRootUnsignedUptane(Uptane):

    '''The Director Root metadata has no signatures'''

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

        UPDATE_ERROR = 'UnmetThreshold::Root'

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'root_sign_keys_idx': [],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class DirectorTargetsUnsignedUptane(Uptane):

    '''The Director Targets metadata has no signatures'''

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

        UPDATE_ERROR = 'UnmetThreshold::Targets'

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets_sign_keys_idx': [],
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class ImageRepoRootUnsignedUptane(Uptane):

    '''The Image repo Root metadata has no signatures'''

    class ImageStep(Step):

        UPDATE_ERROR = 'UnmetThreshold::Root'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'root_sign_keys_idx': [],
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


class ImageRepoTargetsUnsignedUptane(Uptane):

    '''The Image repo Targets metadata has no signatures'''

    class ImageStep(Step):

        UPDATE_ERROR = 'UnmetThreshold::Targets'

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
            'targets_sign_keys_idx': [],
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


class ImageRepoSnapshotUnsignedUptane(Uptane):

    '''The Image repo Snapshot metadata has no signatures'''

    class ImageStep(Step):

        UPDATE_ERROR = 'UnmetThreshold::Snapshot'

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
            'snapshot_sign_keys_idx': [],
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


class ImageRepoTimestampUnsignedUptane(Uptane):

    '''The Image repo Timestamp metadata has no signatures'''

    class ImageStep(Step):

        UPDATE_ERROR = 'UnmetThreshold::Timestamp'

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
            'timestamp_sign_keys_idx': [],
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


class DirectorRootBadKeyIdsUptane(Uptane):

    '''The Director Root metadata has bad key IDs for the Root role'''

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

        UPDATE_ERROR = 'BadKeyId'
        ROOT_KEYS_IDX = [4]
        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': ROOT_KEYS_IDX,
            'root_bad_key_ids': ROOT_KEYS_IDX,
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class DirectorTargetsBadKeyIdsUptane(Uptane):

    '''The Director Root metadata has bad key IDs for the Targets role'''

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

        UPDATE_ERROR = 'BadKeyId'
        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets_bad_key_ids': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class ImageRepoRootBadKeyIdsUptane(Uptane):

    '''The Image repo Root metadata has bad key IDs for the Root role'''

    class ImageStep(Step):

        UPDATE_ERROR = 'BadKeyId'
        ROOT_KEYS_IDX = [0]
        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': ROOT_KEYS_IDX,
            'root_bad_key_ids': ROOT_KEYS_IDX,
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


class ImageRepoTargetsBadKeyIdsUptane(Uptane):

    '''The Image repo Root metadata has bad key IDs for the Targets role'''

    class ImageStep(Step):

        UPDATE_ERROR = 'BadKeyId'
        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets_bad_key_ids': TARGETS_KEYS_IDX,
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


class ImageRepoSnapshotBadKeyIdsUptane(Uptane):

    '''The Image repo Root metadata has bad key IDs for the Snapshot role'''

    class ImageStep(Step):

        UPDATE_ERROR = 'BadKeyId'
        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'snapshot_bad_key_ids': SNAPSHOT_KEYS_IDX,
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


class ImageRepoTimestampBadKeyIdsUptane(Uptane):

    '''The Image repo Root metadata has bad key IDs for the Timestamp role'''

    class ImageStep(Step):

        UPDATE_ERROR = 'BadKeyId'
        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
            'timestamp_bad_key_ids': TIMESTAMP_KEYS_IDX,
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


class DirectorTargetOversizedUptane(Uptane):

    '''The Director's metadata states that a target is smaller than it actually is.
       The target metadata in the Image and Director repos do not match.
    '''

    class ImageStep(Step):

        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'TargetMismatch',
        }

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

        def __targets(hardware_id: str, ecu_identifier: str = None) -> list:
            return [Target(name=DEFAULT_TARGET_NAME,
                           content=DEFAULT_TARGET_CONTENT,
                           hardware_id=hardware_id,
                           ecu_identifier=ecu_identifier,
                           alteration='oversized')]

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': __targets,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class ImageRepoTargetOversizedUptane(Uptane):

    '''The Image repo's metadata states that a target is smaller than it actually is.
       The target metadata in the Image and Director repos do not match.
    '''

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

        def __targets(hardware_id: str, ecu_identifier: str = None) -> list:
            return [Target(name=DEFAULT_TARGET_NAME,
                           content=DEFAULT_TARGET_CONTENT,
                           hardware_id=hardware_id,
                           ecu_identifier=ecu_identifier,
                           alteration='oversized')]

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': __targets,
        }

        SNAPSHOT_KWARGS = {
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
        }

        TIMESTAMP_KWARGS = {
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

    class DirectorStep(Step):

        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'TargetMismatch',
        }

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


class TargetOversizedUptane(Uptane):

    '''Both the Director's and Image repo's metadata states that a target is smaller than it
       actually is.
    '''

    class ImageStep(Step):

        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'TargetHashMismatch',
        }

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        def __targets(hardware_id: str, ecu_identifier: str = None) -> list:
            return [Target(name=DEFAULT_TARGET_NAME,
                           content=DEFAULT_TARGET_CONTENT,
                           hardware_id=hardware_id,
                           ecu_identifier=ecu_identifier,
                           alteration='oversized')]

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': __targets,
        }

        SNAPSHOT_KWARGS = {
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
        }

        TIMESTAMP_KWARGS = {
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

    class DirectorStep(Step):

        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'OversizedTarget',
        }

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        def __targets(hardware_id: str, ecu_identifier: str = None) -> list:
            return [Target(name=DEFAULT_TARGET_NAME,
                           content=DEFAULT_TARGET_CONTENT,
                           hardware_id=hardware_id,
                           ecu_identifier=ecu_identifier,
                           alteration='oversized')]

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': __targets,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class DirectorRootRotationUptane(Uptane):

    '''Director step 0 has root v1, step 1 has root v2, it is correctly cross signed'''

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

    class DirectorStep1(Step):

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    class DirectorStep2(Step):

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'version': 2,
            'root_keys_idx': [6],
            'root_sign_keys_idx': [4, 6],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep1, ImageStep),
        (DirectorStep2, ImageStep),
    ]


class DirectorRootRotationMultipleUptane(Uptane):

    '''Director step 0 has root v1, step 1 has root v3, it is correctly cross signed'''

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

    class DirectorStep1(Step):

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    class DirectorStep2(Step):

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = [
            {
                'version': 2,
                'root_keys_idx': [6],
                'root_sign_keys_idx': [4, 6],
                'targets_keys_idx': TARGETS_KEYS_IDX,
            },
            {
                'version': 3,
                'root_keys_idx': [7],
                'root_sign_keys_idx': [6, 7],
                'targets_keys_idx': TARGETS_KEYS_IDX,
            },
        ]

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep1, ImageStep),
        (DirectorStep2, ImageStep),
    ]


class ImageRepoRootRotationUptane(Uptane):

    '''Image repo step 0 has root v1, step 1 has root v2, it is correctly cross signed'''

    class ImageStep1(Step):

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

    class ImageStep2(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'version': 2,
            'root_keys_idx': [6],
            'root_sign_keys_idx': [0, 6],
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
        (DirectorStep, ImageStep1),
        (DirectorStep, ImageStep2),
    ]


class ImageRepoRootRotationMultipleUptane(Uptane):

    '''Image repo step 0 has root v1, step 1 has root v3, it is correctly cross signed'''

    class ImageStep1(Step):

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

    class ImageStep2(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = [
            {
                'version': 2,
                'root_keys_idx': [6],
                'root_sign_keys_idx': [0, 6],
                'targets_keys_idx': TARGETS_KEYS_IDX,
                'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
                'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
            },
            {
                'version': 3,
                'root_keys_idx': [7],
                'root_sign_keys_idx': [6, 7],
                'targets_keys_idx': TARGETS_KEYS_IDX,
                'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
                'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
            },
        ]

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
        (DirectorStep, ImageStep1),
        (DirectorStep, ImageStep2),
    ]


class DirectorRootRotationNoOriginalSignatureUptane(Uptane):

    '''Director step 0 has root v1, step 1 has root v2, it is only signed by the second root
       keys
    '''

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

    class DirectorStep1(Step):

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    class DirectorStep2(Step):

        UPDATE_ERROR = 'BadKeyId'

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'version': 2,
            'root_keys_idx': [6],
            'root_sign_keys_idx': [6],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep1, ImageStep),
        (DirectorStep2, ImageStep),
    ]


class ImageRepoRootRotationNoOriginalSignatureUptane(Uptane):

    '''Image repo step 0 has root v1, step 1 has root v2, it is only signed by the second root
       keys
    '''

    class ImageStep1(Step):

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

    class ImageStep2(Step):

        UPDATE_ERROR = 'BadKeyId'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'version': 2,
            'root_keys_idx': [6],
            'root_sign_keys_idx': [6],
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
        (DirectorStep, ImageStep1),
        (DirectorStep, ImageStep2),
    ]


class DirectorRootRotationNoNewSignatureUptane(Uptane):

    '''Director step 0 has root v1, step 1 has root v2, it is only signed by the first root
       keys
    '''

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

    class DirectorStep1(Step):

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    class DirectorStep2(Step):

        UPDATE_ERROR = 'BadKeyId'

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'version': 2,
            'root_keys_idx': [6],
            'root_sign_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep1, ImageStep),
        (DirectorStep2, ImageStep),
    ]


class ImageRepoRootRotationNoNewSignatureUptane(Uptane):

    '''Image repo step 0 has root v1, step 1 has root v2, it is only signed by the first root
       keys
    '''

    class ImageStep1(Step):

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

    class ImageStep2(Step):

        UPDATE_ERROR = 'BadKeyId'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'version': 2,
            'root_keys_idx': [6],
            'root_sign_keys_idx': [0],
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
        (DirectorStep, ImageStep1),
        (DirectorStep, ImageStep2),
    ]


class DirectorRootRotationVersionUnchangedUptane(Uptane):

    '''Director step 0 has root v1, step 1 has root v2, and it is correctly cross signed,
       but the version is unchanged. The standard accepts this but we do not.'''

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

    class DirectorStep1(Step):

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    class DirectorStep2(Step):

        # Note that aktualizr doesn't actually throw an exception; it just fails.
        UPDATE_ERROR = 'RootRotationError'

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'version': 2,
            'root_keys_idx': [6],
            'root_sign_keys_idx': [4, 6],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'stated_version': 1,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep1, ImageStep),
        (DirectorStep2, ImageStep),
    ]


class ImageRepoRootRotationVersionUnchangedUptane(Uptane):

    '''Image repo step 0 has root v1, step 1 has root v2, and it is correctly cross signed,
       but the version is unchanged. The standard accepts this but we do not.'''

    class ImageStep1(Step):

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

    class ImageStep2(Step):

        # Note that aktualizr doesn't actually throw an exception; it just fails.
        UPDATE_ERROR = 'RootRotationError'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'version': 2,
            'root_keys_idx': [6],
            'root_sign_keys_idx': [0, 6],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
            'stated_version': 1,
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
        (DirectorStep, ImageStep1),
        (DirectorStep, ImageStep2),
    ]


class DirectorRootRotationVersionSkipUptane(Uptane):

    '''Director step 0 has root v1, step 1 has root v2, and it is correctly cross signed,
       but the version skips the expected value.'''

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

    class DirectorStep1(Step):

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    class DirectorStep2(Step):

        # Note that aktualizr doesn't actually throw an exception; it just fails.
        UPDATE_ERROR = 'RootRotationError'

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'version': 2,
            'root_keys_idx': [6],
            'root_sign_keys_idx': [4, 6],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'stated_version': 3,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep1, ImageStep),
        (DirectorStep2, ImageStep),
    ]


class ImageRepoRootRotationVersionSkipUptane(Uptane):

    '''Image repo step 0 has root v1, step 1 has root v2, and it is correctly cross signed,
       but the version skips the expected value.'''

    class ImageStep1(Step):

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

    class ImageStep2(Step):

        # Note that aktualizr doesn't actually throw an exception; it just fails.
        UPDATE_ERROR = 'RootRotationError'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'version': 2,
            'root_keys_idx': [6],
            'root_sign_keys_idx': [0, 6],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
            'stated_version': 3,
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
        (DirectorStep, ImageStep1),
        (DirectorStep, ImageStep2),
    ]


class ImageRepoMetadataChangedWhileVersionSameUptane(Uptane):

    '''Image repo step 0 has timestamp, snapshot, and targets v1, step 1 has different metadata than step 0,
       but, the version is the same. Update should succeed in this case, since the specification does NOT forbid it '''

    class ImageStep1(Step):
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
            'targets': lambda hardware_id, ecu_identifier: [
                Target(name=DEFAULT_TARGET_NAME,
                       content=DEFAULT_TARGET_CONTENT,
                       hardware_id=hardware_id,
                       ecu_identifier=ecu_identifier)
            ]
        }

        SNAPSHOT_KWARGS = {
            'add_targets_hash_and_length': True,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
        }

        TIMESTAMP_KWARGS = {
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

    class ImageStep2(Step):
        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'version': 1,
            'root_keys_idx': [6],
            'root_sign_keys_idx': [0, 6],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda hardware_id, ecu_identifier: [
                Target(name=DEFAULT_TARGET_NAME,
                       content=DEFAULT_TARGET_CONTENT,
                       hardware_id=hardware_id,
                       ecu_identifier=ecu_identifier),
                Target(name='file01.txt',
                       content=b'some foobar content',
                       hardware_id=hardware_id,
                       ecu_identifier=ecu_identifier)

            ]
        }

        SNAPSHOT_KWARGS = {
            'add_targets_hash_and_length': True,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
        }

        TIMESTAMP_KWARGS = {
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

    class DirectorStep1(Step):
        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda hardware_id, ecu_identifier: [
                Target(name=DEFAULT_TARGET_NAME,
                       content=DEFAULT_TARGET_CONTENT,
                       hardware_id=hardware_id,
                       ecu_identifier=ecu_identifier)
            ]
        }

    class DirectorStep2(Step):
        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'version': 2,
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda hardware_id, ecu_identifier: [
                Target(name='file01.txt',
                       content=b'some foobar content',
                       hardware_id=hardware_id,
                       ecu_identifier=ecu_identifier)

                ]
        }

    STEPS = [
        (DirectorStep1, ImageStep1),
        (DirectorStep2, ImageStep2),
    ]


class DirectorBadHwIdUptane(Uptane):

    '''The Director Targets metadata has a bad hardware ID'''

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

        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'BadHardwareId',
        }

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        def __targets(hardware_id: str, ecu_identifier: str = None) -> list:
            return [Target(name=DEFAULT_TARGET_NAME,
                           content=DEFAULT_TARGET_CONTENT,
                           hardware_id=hardware_id,
                           ecu_identifier=ecu_identifier,
                           alteration='bad-hw-id')]

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': __targets,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class ImageRepoBadHwIdUptane(Uptane):

    '''The Image repo Targets metadata has a bad hardware ID'''

    class ImageStep(Step):

        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'TargetMismatch',
        }

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        def __targets(hardware_id: str, ecu_identifier: str = None) -> list:
            return [Target(name=DEFAULT_TARGET_NAME,
                           content=DEFAULT_TARGET_CONTENT,
                           hardware_id=hardware_id,
                           ecu_identifier=ecu_identifier,
                           alteration='bad-hw-id')]

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': __targets,
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


class BadHwIdUptane(Uptane):

    '''Both Targets metadata have a bad hardware ID'''

    class ImageStep(Step):

        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'BadHardwareId',
        }

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        def __targets(hardware_id: str, ecu_identifier: str = None) -> list:
            return [Target(name=DEFAULT_TARGET_NAME,
                           content=DEFAULT_TARGET_CONTENT,
                           hardware_id=hardware_id,
                           ecu_identifier=ecu_identifier,
                           alteration='bad-hw-id')]

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': __targets,
        }

        SNAPSHOT_KWARGS = {
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
        }

        TIMESTAMP_KWARGS = {
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

    class DirectorStep(Step):

        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'BadHardwareId',
        }

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        def __targets(hardware_id: str, ecu_identifier: str = None) -> list:
            return [Target(name=DEFAULT_TARGET_NAME,
                           content=DEFAULT_TARGET_CONTENT,
                           hardware_id=hardware_id,
                           ecu_identifier=ecu_identifier,
                           alteration='bad-hw-id')]

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': __targets,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class DirectorBadEcuIdUptane(Uptane):

    '''The Director Targets metadata has a bad ECU ID'''

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

        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'BadEcuId',
        }

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        def __targets(hardware_id: str, ecu_identifier: str = None) -> list:
            return [Target(name=DEFAULT_TARGET_NAME,
                           content=DEFAULT_TARGET_CONTENT,
                           hardware_id=hardware_id,
                           ecu_identifier=ecu_identifier,
                           alteration='bad-ecu-id')]

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': __targets,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class ImageRepoSnapshotTargetsVersionMismatchUptane(Uptane):

    '''The Image repo Snapshot metadata expects a newer version of the Targets metadata'''

    class ImageStep(Step):

        UPDATE_ERROR = 'VersionMismatch::targets'

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
            'targets_version': 2,
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


class DelegationSimpleUptane(Uptane):

    '''The most basic delegation happy case where Targets points at one delegation'''

    class ImageStep(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            DEFAULT_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda ecu_id, hw_id: [],
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations': Step.default_delegations,
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


class DelegationRedundantUptane(Uptane):

    '''A target is listed in both the top-level Targets and a delegation'''

    class ImageStep(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            DEFAULT_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
                # Leave the delegation unsigned to create an obvious error so
                # that if the delegation were verified, it would fail. However,
                # it shouldn't even be downloaded, since the target should be
                # found in the top-level Targets.
                'targets_sign_keys_idx': [],
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            # Leave the default Target in the Targets metadata.
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations': Step.default_delegations,
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


class DelegationPathMismatchUptane(Uptane):

    '''The target name does not match the delegated role's path'''

    class ImageStep(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            DEFAULT_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        def __delegations(delegations_keys_idx: list = None, **kwargs) -> list:
            return [
                Delegation(
                    keys_idx=delegations_keys_idx,
                    role=Role(
                        keys_idx=delegations_keys_idx,
                        name=DEFAULT_DELEGATION_NAME,
                        paths=['does-not-match'],
                        terminating=False,
                        threshold=1,
                        **kwargs
                    ),
                    **kwargs
                ),
            ]

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda ecu_id, hw_id: [],
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations': __delegations,
        }

        SNAPSHOT_KWARGS = {
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
        }

        TIMESTAMP_KWARGS = {
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

    class DirectorStep(Step):

        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'TargetMismatch',
        }

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


class DelegationKeyMissingUptane(Uptane):

    '''The top-level Targets metadata is missing a key ID for a delegated role'''

    class ImageStep(Step):

        UPDATE_ERROR = 'BadKeyId'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            DEFAULT_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        def __delegations(delegations_keys_idx: list = None, **kwargs) -> list:
            return [
                Delegation(
                    # Note that keys_idx is empty!
                    role=Role(
                        keys_idx=delegations_keys_idx,
                        name=DEFAULT_DELEGATION_NAME,
                        paths=[DEFAULT_TARGET_NAME],
                        terminating=False,
                        threshold=1,
                        **kwargs
                    ),
                    **kwargs
                ),
            ]

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda ecu_id, hw_id: [],
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations': __delegations,
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


class DelegationUnsignedUptane(Uptane):

    '''The delegated metadata has no signatures'''

    class ImageStep(Step):

        UPDATE_ERROR = 'UnmetThreshold::' + DEFAULT_DELEGATION_NAME

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            DEFAULT_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
                'targets_sign_keys_idx': [],
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda ecu_id, hw_id: [],
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations': Step.default_delegations,
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


class DelegationBadKeyIdsUptane(Uptane):

    '''The top-level Targets metadata has bad key IDs for a delegated role'''

    class ImageStep(Step):

        UPDATE_ERROR = 'BadKeyId'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            DEFAULT_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda ecu_id, hw_id: [],
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations_bad_key_ids': DELEGATION_KEYS_IDX,
            'delegations': Step.default_delegations,
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


class DelegationMissingUptane(Uptane):

    '''A delegation's metadata is unavailable'''

    class ImageStep(Step):

        UPDATE_ERROR = 'DelegationMissing::' + MISSING_DELEGATION_NAME

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            MISSING_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda ecu_id, hw_id: [],
            'delegation_name': MISSING_DELEGATION_NAME,
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations': Step.default_delegations,
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


class DelegationEmptyUptane(Uptane):

    '''The target is not present in the delegated role'''

    class ImageStep(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            DEFAULT_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
                'targets': lambda ecu_id, hw_id: [],
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda ecu_id, hw_id: [],
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations': Step.default_delegations,
        }

        SNAPSHOT_KWARGS = {
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
        }

        TIMESTAMP_KWARGS = {
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

    class DirectorStep(Step):

        # Should perhaps be a failure in the Image repo, since that is where
        # the target is missing, but that doesn't work. The error could also be
        # more accurate.
        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'TargetMismatch',
        }

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


class DelegationHashMismatchUptane(Uptane):

    '''The delegation has a target with bad hashes'''

    class ImageStep(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        def __targets(hardware_id: str, ecu_identifier: str = None) -> list:
            return [Target(name=DEFAULT_TARGET_NAME,
                           content=DEFAULT_TARGET_CONTENT,
                           hardware_id=hardware_id,
                           ecu_identifier=ecu_identifier,
                           alteration='bad-hash')]

        DELEGATIONS = {
            DEFAULT_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
                'targets': __targets,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda ecu_id, hw_id: [],
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations': Step.default_delegations,
        }

        SNAPSHOT_KWARGS = {
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
        }

        TIMESTAMP_KWARGS = {
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

    class DirectorStep(Step):

        # Should be a failure in the Image repo, since that is where the
        # target is missing, but that doesn't work.
        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'TargetMismatch',
        }

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


class DelegationExpiredUptane(Uptane):

    '''The delegated metadata has expired'''

    class ImageStep(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            DEFAULT_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
                'is_expired': True,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda ecu_id, hw_id: [],
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations': Step.default_delegations,
        }

        SNAPSHOT_KWARGS = {
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
        }

        TIMESTAMP_KWARGS = {
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

    class DirectorStep(Step):

        # Should be a failure in the Image repo, since that is where the
        # target is missing, but that doesn't work. The error could also be
        # more accurate.
        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'TargetMismatch',
        }

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


class DelegationSnapshotMissingUptane(Uptane):

    '''The Snapshot metadata does not list a delegation'''

    class ImageStep(Step):

        UPDATE_ERROR = 'VersionMismatch::' + SKIPPED_DELEGATION_NAME

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            SKIPPED_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda ecu_id, hw_id: [],
            'delegation_name': SKIPPED_DELEGATION_NAME,
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations': Step.default_delegations,
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


class DelegationSnapshotVersionMismatchUptane(Uptane):

    '''The Snapshot metadata expects a newer version of a delegation'''

    class ImageStep(Step):

        UPDATE_ERROR = 'VersionMismatch::' + DEFAULT_DELEGATION_NAME

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            DEFAULT_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
                'snapshot_version': 2,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda ecu_id, hw_id: [],
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations': Step.default_delegations,
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


class DelegationZeroThresholdUptane(Uptane):

    '''A delegation has a threshold of zero.'''

    class ImageStep(Step):

        UPDATE_ERROR = 'IllegalThreshold::' + DEFAULT_DELEGATION_NAME

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            DEFAULT_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda ecu_id, hw_id: [],
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegation_threshold': 0,
            'delegations': Step.default_delegations,
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


class DelegationUnmetThresholdUptane(Uptane):

    '''A delegation has an unmet threshold'''

    class ImageStep(Step):

        UPDATE_ERROR = 'UnmetThreshold::' + DEFAULT_DELEGATION_NAME

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6, 7]

        DELEGATIONS = {
            DEFAULT_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
                'targets_sign_keys_idx': DELEGATION_KEYS_IDX[0:-1],
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda ecu_id, hw_id: [],
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations': Step.default_delegations,
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


class DelegationTwoSignaturesUptane(Uptane):

    '''Simple delegation case with two signatures required'''

    class ImageStep(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6, 7]

        DELEGATIONS = {
            DEFAULT_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
                'targets_sign_keys_idx': DELEGATION_KEYS_IDX,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda ecu_id, hw_id: [],
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations': Step.default_delegations,
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


class DelegationNonUniqueSignaturesUptane(Uptane):

    '''A delegation has duplicate signatures'''
    # Note that at present, the threshold is only set to 1, so one could argue
    # this should not be an error, just a warning. (This also affects the other
    # non-unique signature tests.)

    class ImageStep(Step):

        UPDATE_ERROR = 'NonUniqueSignatures::' + DEFAULT_DELEGATION_NAME

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            DEFAULT_DELEGATION_NAME: {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
                'targets_sign_keys_idx': DELEGATION_KEYS_IDX + DELEGATION_KEYS_IDX,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': lambda ecu_id, hw_id: [],
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations': Step.default_delegations,
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


class DirectorRootRoleTypeMismatchUptane(Uptane):
    """
    The type of role must have an appropriate name in the metadata file.
    Director role Root: _type = "Root"
    """
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

        UPDATE_ERROR = 'SecurityException::Root'

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            '_type': 'invalidrole',
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class DirectorTargetsRoleTypeMismatchUptane(Uptane):
    """
    The type of role must have an appropriate name in the metadata file.
    Director role Targets: _type = "Targets"
    """
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

        UPDATE_ERROR = 'SecurityException::Targets'

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            '_type': 'invalidrole',
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class ImageRepoRootRoleTypeMismatchUptane(Uptane):
    """
    The type of role must have an appropriate name in the metadata file.
    ImageRepo role Root: _type = "Root"
    """
    class ImageStep(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        UPDATE_ERROR = 'SecurityException::Root'

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
            '_type': 'invalidrole',
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


class ImageRepoTargetsRoleTypeMismatchUptane(Uptane):
    """
    The type of role must have an appropriate name in the metadata file.
    ImageRepo role Targets: _type = "Targets"
    """
    class ImageStep(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        UPDATE_ERROR = 'SecurityException::Targets'

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            '_type': 'invalidrole',
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


class ImageRepoSnapshotRoleTypeMismatchUptane(Uptane):
    """
    The type of role must have an appropriate name in the metadata file.
    ImageRepo role Snapshot: _type = "Root"
    """
    class ImageStep(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        UPDATE_ERROR = 'SecurityException::Snapshot'

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
            '_type': 'invalidrole',
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


class ImageRepoTimestampRoleTypeMismatchUptane(Uptane):
    """
    The type of role must have an appropriate name in the metadata file.
    ImageRepo role Snapshot: _type = "Root"
    """
    class ImageStep(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]

        UPDATE_ERROR = 'SecurityException::Timestamp'

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
            '_type': 'invalidrole',
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


class DirectorDelegationsUptane(Uptane):

    '''Director Targets metadata should not have delegations.'''

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
        # There's no need to create the actual delegation, because the mere
        # presence of the delegation in the top-level Targets metadata should
        # be enough to cause a problem.

        UPDATE_ERROR = 'DirectorDelegation'

        TARGETS_KEYS_IDX = [5]
        DELEGATION_KEYS_IDX = [6]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'delegations_keys_idx': DELEGATION_KEYS_IDX,
            'delegations': Step.default_delegations,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class DirectorTargetsSameEcuUptane(Uptane):

    '''The Director Targets metadata lists two targets with the same ECU ID'''

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

        UPDATE_ERROR = 'DirectorRepeatedEcuId'

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        def __targets(hardware_id: str, ecu_identifier: str = None) -> list:
            return [Target(name=DEFAULT_TARGET_NAME,
                           content=DEFAULT_TARGET_CONTENT,
                           hardware_id=hardware_id,
                           ecu_identifier=ecu_identifier),
                    Target(name='alt.txt',
                           content=b'something else',
                           hardware_id=hardware_id,
                           ecu_identifier=ecu_identifier)]

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'targets': __targets,
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]


class ImageRepoTargetsTooLargeUptane(Uptane):

    '''The size of targets.json of image repo is over the limitation.'''

    class ImageStep(Step):

        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'MetadataFetchFailure::Targets::Image',
        }

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
            'too_large': "TRUE",
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


class DirectorTargetsTooLargeUptane(Uptane):

    '''The size of targets.json of Director is over the limitation.'''

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

        TARGET_ERRORS = {
            DEFAULT_TARGET_NAME: 'MetadataFetchFailure::Targets::Director',
        }

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        TARGETS_KWARGS = {
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'too_large': "TRUE",
        }

    STEPS = [
        (DirectorStep, ImageStep),
    ]
