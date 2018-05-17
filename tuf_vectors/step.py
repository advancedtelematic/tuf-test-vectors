# -*- coding: utf-8 -*-

from tuf_vectors import human_message
from tuf_vectors.metadata import Root, Targets, Snapshot, Timestamp, Target

DEFAULT_TARGET_NAME = 'file.txt'
DEFAULT_TARGET_CONTENT = b'wat wat wat'


class Step:

    CLASS_SUFFIX = 'Step'
    UPTANE_ONLY = False
    UPDATE_ERROR = None

    __ROOT_DEFAULT = {
        'version': 1,
        'is_expired': False,
    }
    ROOT_KWARGS = {}

    __TIMESTAMP_DEFAULT = {
        'timestamp_version': 1,
        'is_expired': False,
        'timestamp_keys_bad_sign_idx': [],
        'snapshot_version': None,
    }
    TIMESTAMP_KWARGS = {}

    __SNAPSHOT_DEFAULT = {
        'version': 1,
        'is_expired': False,
    }
    SNAPSHOT_KWARGS = {}

    def __default_targets(hardware_id: str, ecu_identifier: str=None) -> list:
        return [Target(name=DEFAULT_TARGET_NAME,
                       content=DEFAULT_TARGET_CONTENT,
                       hardware_id=hardware_id,
                       ecu_identifier=ecu_identifier)]

    __TARGETS_DEFAULT = {
        'version': 1,
        'is_expired': False,
        'targets': __default_targets
    }
    TARGETS_KWARGS = {}

    TARGET_ERRORS = {}

    # delegation name -> kwargs
    DELEGATIONS = {}

    def __init__(self, **kwargs) -> None:
        uptane_role = kwargs.get('uptane_role', None)
        if uptane_role is None:
            raise ValueError("Missing kwarg 'uptane_role'")
        if uptane_role not in ('director', 'image_repo'):
            raise ValueError('Bad uptane_role: {}'.format(uptane_role))
        self.uptane_role = uptane_role

        root_args = self.__ROOT_DEFAULT.copy()
        root_args.update(**self.ROOT_KWARGS)
        root_args.update(**kwargs)
        self.root = Root(**root_args)

        targets_args = self.__TARGETS_DEFAULT.copy()
        targets_args.update(**self.TARGETS_KWARGS)
        targets_args.update(**kwargs)
        if uptane_role == 'image_repo':
            targets_args.pop('ecu_identifier', None)
        self.targets = Targets(**targets_args)

        if self.uptane_role == 'image_repo':
            self.delegations = {}
            for name, delegation_args in self.DELEGATIONS.items():
                args = self.__TARGETS_DEFAULT.copy()
                args.update(**delegation_args)
                args.update(**kwargs)
                args['role_name'] = name
                self.delegations[name] = Targets(**args)

            snapshot_args = self.__SNAPSHOT_DEFAULT.copy()
            snapshot_args.update(**self.SNAPSHOT_KWARGS)
            snapshot_args.update(**kwargs)
            self.snapshot = Snapshot(targets=self.targets.value,
                                     delegations=self.delegations,
                                     **snapshot_args)

            timestamp_args = self.__TIMESTAMP_DEFAULT.copy()
            timestamp_args.update(**self.TIMESTAMP_KWARGS)
            timestamp_args.update(**kwargs)
            self.timestamp = Timestamp(snapshot=self.snapshot.value,
                                       **timestamp_args)

    def persist(self) -> None:
        self.root.persist()
        self.targets.persist()

        if self.uptane_role == 'image_repo':
            self.snapshot.persist()
            self.timestamp.persist()

            for _, value in self.delegations.items():
                value.persist()

    def meta(self) -> dict:
        '''Used to indicate if this update should pass/fail'''
        meta = {
            "update": {
                "is_success": self.UPDATE_ERROR is None,
            },
        }

        if self.UPDATE_ERROR is not None:
            meta['update']['err'] = self.UPDATE_ERROR
            meta['update']['err_msg'] = human_message(self.UPDATE_ERROR)

        targets = {}
        for target in self.targets.targets:
            target_error = self.TARGET_ERRORS.get(target.name, None)
            if target_error is None:
                info = {'is_success': True}
            else:
                info = {
                    'is_success': False,
                    'err': target_error,
                    'err_msg': human_message(target_error),
                }
            targets[target.name] = info
        meta['targets'] = targets

        return meta
