# -*- coding: utf-8 -*-

import re

from os import path

from tuf_vectors.metadata import Target, Delegation, Role
from tuf_vectors.step import Step, DEFAULT_TARGET_NAME, DEFAULT_TARGET_CONTENT


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

    '''The director has a threshold of zero for the root role.'''

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

    '''The director has a threshold of zero for the targets role.'''

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

    '''The image repo has a threshold of zero for the root role.'''

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

    '''The image repo has a threshold of zero for the targets role.'''

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

    '''The image repo has a threshold of zero for the snapshot role.'''

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

    '''The image repo has a threshold of zero for the timestamp role.'''

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

    '''The director has expired root metadata'''

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

    '''The director has expired targets metadata'''

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

    '''The image repo has expired root metadata'''

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

    '''The image repo has expired targets metadata'''

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

    '''The image repo has expired snapshot metadata'''

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

    '''The image repo has expired timestamp metadata'''

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

    '''The director has lists a target with bad hashes'''

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
            DEFAULT_TARGET_NAME: 'TargetHashMismatch',
        }

        TARGETS_KEYS_IDX = [5]

        ROOT_KWARGS = {
            'root_keys_idx': [4],
            'targets_keys_idx': TARGETS_KEYS_IDX,
        }

        def __targets(hardware_id: str, ecu_identifier: str=None) -> list:
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

    '''The image repo has lists a target with bad hashes'''

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

        def __targets(hardware_id: str, ecu_identifier: str=None) -> list:
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

    '''The director root metadata has an unmet threshold'''

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

    '''The director targets metadata has an unmet threshold'''

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

    '''The image repo targets metadata has an unmet threshold'''

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

    '''The image repo targets metadata has an unmet threshold'''

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

    '''The image repo snapshot metadata has an unmet threshold'''

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

    '''The image repo timestamp metadata has an unmet threshold'''

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

    '''The director root metadata has duplicate signatures'''

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

    '''The director targets metadata has duplicate signatures'''

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

    '''The image repo root metadata has duplicate signatures'''

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

    '''The image repo targets metadata has duplicate signatures'''

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

    '''The image repo snapshot metadata has duplicate signatures'''

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

    '''The image repo timestamp metadata has duplicate signatures'''

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

    '''The director root metadata has no signatures'''

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

    '''The director targets metadata has no signatures'''

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

    '''The image repo root metadata has no signatures'''

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

    '''The image repo targets metadata has no signatures'''

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

    '''The image repo snapshot metadata has no signatures'''

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

    '''The image repo timestamp metadata has no signatures'''

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

    '''The director root metadata has bad key IDs for the root role'''

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

    '''The director root metadata has bad key IDs for the targets role'''

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

    '''The image repo root metadata has bad key IDs for the root role'''

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

    '''The image repo root metadata has bad key IDs for the targets role'''

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

    '''The image repo root metadata has bad key IDs for the snapshot role'''

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

    '''The image repo root metadata has bad key IDs for the timestamp role'''

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

class TargetOversizedUptane(Uptane):

    '''The both the director's and image repo's metadata states that a target is smaller than it
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

        def __targets(hardware_id: str, ecu_identifier: str=None) -> list:
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

        def __targets(hardware_id: str, ecu_identifier: str=None) -> list:
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

        UPDATE_ERROR = 'UnmetThreshold::Root'

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

        UPDATE_ERROR = 'UnmetThreshold::Root'

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

        UPDATE_ERROR = 'UnmetThreshold::Root'

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

        UPDATE_ERROR = 'UnmetThreshold::Root'

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


class DirectorBadHwIdUptane(Uptane):

    '''The director targets metadata has a bad hardware ID'''

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

        def __targets(hardware_id: str, ecu_identifier: str=None) -> list:
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

class BadHwIdUptane(Uptane):

    '''The both targets metadata have a bad hardware ID'''

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

        def __targets(hardware_id: str, ecu_identifier: str=None) -> list:
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

        def __targets(hardware_id: str, ecu_identifier: str=None) -> list:
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

    '''The director targets metadata has a bad ECU ID'''

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

        def __targets(hardware_id: str, ecu_identifier: str=None) -> list:
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


class DelegationSimpleUptane(Uptane):

    '''The most basic delegation happy case where targets points at one delegation'''

    class ImageStep(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            'foo': {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        def __delegations(**kwargs) -> list:
            return [
                Delegation(
                    keys_idx=[6],
                    role=Role(
                        keys_idx=[6],
                        name='foo',
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


class DelegationPathMismatchUptane(Uptane):

    '''Simple delegation but target name does not match path'''

    class ImageStep(Step):

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            'foo': {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        def __delegations(**kwargs) -> list:
            return [
                Delegation(
                    keys_idx=[6],
                    role=Role(
                        keys_idx=[6],
                        name='foo',
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
            DEFAULT_TARGET_NAME: 'TargetHashMismatch',
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

    '''Simple delegation but delegation's key is missing'''

    class ImageStep(Step):

        UPDATE_ERROR = 'BadKeyId'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            'foo': {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        def __delegations(**kwargs) -> list:
            return [
                Delegation(
                    # Note that keys_idx is empty!
                    role=Role(
                        keys_idx=[6],
                        name='foo',
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


class DelegationBadKeyIdsUptane(Uptane):

    '''The most basic delegation happy case where targets points at one delegation'''

    class ImageStep(Step):

        UPDATE_ERROR = 'BadKeyId'

        TARGETS_KEYS_IDX = [1]
        SNAPSHOT_KEYS_IDX = [2]
        TIMESTAMP_KEYS_IDX = [3]
        DELEGATION_KEYS_IDX = [6]

        DELEGATIONS = {
            'foo': {
                'targets_keys_idx': DELEGATION_KEYS_IDX,
            },
        }

        ROOT_KWARGS = {
            'root_keys_idx': [0],
            'targets_keys_idx': TARGETS_KEYS_IDX,
            'snapshot_keys_idx': SNAPSHOT_KEYS_IDX,
            'timestamp_keys_idx': TIMESTAMP_KEYS_IDX,
        }

        def __delegations(**kwargs) -> list:
            return [
                Delegation(
                    keys_idx=[6],
                    bad_key_ids=[6],
                    role=Role(
                        keys_idx=[6],
                        name='foo',
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


