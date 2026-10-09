# SPDX-License-Identifier: GPL-3.0-or-later
"""Native guarded-delivery admission; no executable delivery capability.

A successful preflight proves only this call's configured, live worker identity.
No helper is imported/executed. No shell, subprocess, transport or DB write exists.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import NoReturn

TOOL = 'guarded_delivery_admission'
PHASES = ('preflight', 'feature-canonical', 'guarded-integration',
          'main-canonical', 'reconciliation')
SCHEMA = {
    'name': TOOL,
    'description': 'Read-only live worker admission. Does not execute delivery phases.',
    'parameters': {
        'type': 'object', 'properties': {'phase': {'type': 'string', 'enum': list(PHASES)}},
        'required': ['phase'], 'additionalProperties': False,
    },
}
NATIVE_MODULES = ('agent.delegation_context', 'hermes_cli.kanban_db_dispatch')
POLICY_KEYS = {'version', 'mode', 'board', 'owner_task', 'profile', 'board_db',
               'runtime', 'artifacts', 'permissions', 'delivery_contract'}
RUNTIME_KEYS = {'exposure', 'source_root', 'interpreter', 'files'}
CONTRACT_KEYS = {'repository', 'target_ref', 'review_task', 'candidate_sha',
                 'expected_old_sha', 'transport', 'executables'}


class Refused(ValueError):
    """Stable machine-readable refusal, without secrets or filesystem contents."""


def deny(reason) -> NoReturn:
    raise Refused(reason)


def require(value, reason):
    if not value:
        deny(reason)


def regular_bytes(path):
    """Refuse linked parents/leaves and read a regular file without following it."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'path_not_absolute_literal')
    require(not any(parent.is_symlink() for parent in (path, *path.parents)), 'symlink_refused')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as handle:
        require(stat.S_ISREG(os.fstat(handle.fileno()).st_mode), 'nonregular_file')
        return handle.read()


def pinned_bytes(path, digest):
    require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'invalid_pin')
    raw = regular_bytes(path)
    require(hashlib.sha256(raw).hexdigest() == digest, 'digest_mismatch')
    return raw


def exact_keys(value, keys, reason):
    require(isinstance(value, dict) and set(value) == keys, reason)


def nonempty(value):
    return isinstance(value, str) and bool(value) and value == value.strip()


def validate_runtime(runtime):
    exact_keys(runtime, RUNTIME_KEYS, 'runtime_fields_invalid')
    require(runtime['exposure'] == 'native-worker-process', 'runtime_exposure_unknown')
    require(Path(runtime['source_root']).is_absolute(), 'runtime_root_invalid')
    exact_keys(runtime['interpreter'], {'path', 'sha256'}, 'interpreter_fields_invalid')
    files = runtime['files']
    require(isinstance(files, dict) and all(nonempty(key) for key in files), 'runtime_pins_invalid')
    for module in NATIVE_MODULES:
        require(module.replace('.', '/') + '.py' in files, 'native_pin_missing')
    for name in files:
        require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'runtime_pin_path_invalid')


def validate_contract(contract):
    exact_keys(contract, CONTRACT_KEYS, 'delivery_contract_fields_invalid')
    require(all(nonempty(contract[key]) for key in CONTRACT_KEYS - {'executables'}), 'delivery_contract_invalid')
    require(Path(contract['repository']).is_absolute() and contract['target_ref'].startswith('refs/heads/'), 'repository_ref_invalid')
    require(re.fullmatch('t_[0-9a-f]{8}', contract['review_task']), 'review_task_invalid')
    require(all(re.fullmatch('[0-9a-f]{40}', contract[key]) for key in ('candidate_sha', 'expected_old_sha')), 'product_sha_invalid')
    require(contract['transport'] in ('local', 'ssh'), 'transport_unknown')
    require(contract['executables'] == [], 'executable_capability_unavailable')


def validate_policy(value):
    exact_keys(value, POLICY_KEYS, 'policy_fields_invalid')
    require(type(value['version']) is int and value['version'] == 1, 'policy_version_invalid')
    require(value['mode'] == 'admission-only', 'effects_not_implemented')
    require(all(nonempty(value[key]) for key in ('board', 'owner_task', 'profile')), 'identity_invalid')
    require(re.fullmatch('[A-Za-z0-9_-]+', value['board']), 'board_invalid')
    require(re.fullmatch('t_[0-9a-f]{8}', value['owner_task']), 'task_invalid')
    require(nonempty(value['board_db']) and Path(value['board_db']).is_absolute()
            and '..' not in Path(value['board_db']).parts, 'board_db_invalid')
    validate_runtime(value['runtime'])
    require(isinstance(value['artifacts'], list) and bool(value['artifacts']), 'artifact_pins_missing')
    for artifact in value['artifacts']:
        exact_keys(artifact, {'path', 'sha256'}, 'artifact_fields_invalid')
    require(value['permissions'] == ['preflight'], 'operation_permissions_invalid')
    validate_contract(value['delivery_contract'])
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_policy_key')
        result[key] = value
    return result


def load_policy(path, digest):
    return validate_policy(json.loads(pinned_bytes(path, digest), object_pairs_hook=unique_object))


class NativeRuntime:
    """Read native authority; never reconstruct or pass worker markers to a child."""

    def __init__(self, policy):
        runtime = policy['runtime']
        root = Path(runtime['source_root'])
        for name, pin in runtime['files'].items():
            pinned_bytes(root / name, pin)
        interpreter = runtime['interpreter']
        require(Path('/proc/self/exe').resolve() == Path(interpreter['path']), 'interpreter_mismatch')
        pinned_bytes(interpreter['path'], interpreter['sha256'])
        modules = {}
        for name in NATIVE_MODULES:
            module = importlib.import_module(name)
            expected = root / (name.replace('.', '/') + '.py')
            origin = module.__file__
            if not isinstance(origin, str):
                deny('native_module_origin_missing')
            require(Path(origin).resolve() == expected, 'native_module_origin_mismatch')
            modules[name] = module
        self.context = modules['agent.delegation_context']
        self.dispatch = modules['hermes_cli.kanban_db_dispatch']

    def snapshot(self):
        # Only read our process environment, never ancestor environ or claim arguments.
        require(self.context.is_dispatcher_owned_worker_context(), 'not_dispatcher_owned')
        task = self.context.owned_kanban_task()
        require(bool(task), 'worker_identity_missing')
        return {
            'task': task, 'board': os.environ.get('HERMES_KANBAN_BOARD'),
            'run': os.environ.get('HERMES_KANBAN_RUN_ID'),
            'claim': os.environ.get('HERMES_KANBAN_CLAIM_LOCK'),
            'db': os.environ.get('HERMES_KANBAN_DB'),
            'profile': os.environ.get('HERMES_PROFILE'), 'pid': os.getpid(),
            'fingerprint': self.dispatch._process_fingerprint(os.getpid()),
            'now': time.time(),
        }


def current_records(path, task, run):
    path = Path(path)
    # Validate path without loading schema, migration, CLI dispatch or writable connection.
    require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), 'board_db_missing_or_linked')
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA query_only=ON')
        conn.execute('BEGIN')
        task_row = conn.execute('SELECT id,status,assignee,current_run_id,claim_lock,claim_expires,worker_pid,worker_started_at FROM tasks WHERE id=?', (task,)).fetchone()
        run_row = conn.execute('SELECT id,task_id,profile,status,claim_lock,claim_expires,worker_pid,worker_started_at,ended_at FROM task_runs WHERE id=?', (run,)).fetchone()
        return dict(task_row) if task_row else None, dict(run_row) if run_row else None


def validate_records(policy, snapshot, task, run):
    if task is None or run is None:
        deny('native_record_missing')
    require(task['status'] == 'running' and run['status'] == 'running' and run['ended_at'] is None, 'run_not_live')
    require(task['id'] == policy['owner_task'] and run['task_id'] == task['id'], 'native_task_mismatch')
    require(type(task['current_run_id']) is int and task['current_run_id'] == run['id'] == snapshot['run'], 'stale_run')
    require(task['assignee'] == run['profile'] == policy['profile'], 'native_profile_mismatch')
    require(nonempty(snapshot['claim']) and task['claim_lock'] == run['claim_lock'] == snapshot['claim'], 'claim_mismatch')
    require(all(type(row['claim_expires']) is int and row['claim_expires'] > snapshot['now'] for row in (task, run)), 'claim_expired')
    require(type(snapshot['pid']) is int and task['worker_pid'] == run['worker_pid'] == snapshot['pid'], 'worker_pid_mismatch')
    fingerprint = snapshot['fingerprint']
    require(nonempty(fingerprint) and '|' in fingerprint and fingerprint != 'unverified', 'fingerprint_unverified')
    require(task['worker_started_at'] == run['worker_started_at'] == fingerprint, 'worker_start_mismatch')


def admission(policy, runtime):
    snapshot = runtime.snapshot()
    require(snapshot['task'] == policy['owner_task'], 'foreign_worker')
    require(snapshot['board'] == policy['board'], 'foreign_board')
    require(snapshot['profile'] == policy['profile'], 'foreign_profile')
    require(snapshot['db'] == policy['board_db'], 'foreign_db')
    require(isinstance(snapshot['run'], str) and re.fullmatch('[1-9][0-9]*', snapshot['run']), 'run_marker_invalid')
    snapshot['run'] = int(snapshot['run'])
    task, run = current_records(policy['board_db'], snapshot['task'], snapshot['run'])
    validate_records(policy, snapshot, task, run)
    for artifact in policy['artifacts']:
        pinned_bytes(artifact['path'], artifact['sha256'])
    # Reobserve ownership after I/O. A retained preflight cannot grant later operations.
    final = runtime.snapshot()
    require(all(final[key] == snapshot[key] for key in ('task', 'board', 'profile', 'pid', 'fingerprint', 'claim', 'db')), 'ownership_changed_during_probe')
    require(final['run'] == str(snapshot['run']), 'run_changed_during_probe')
    final['run'] = int(final['run'])
    task, run = current_records(policy['board_db'], final['task'], final['run'])
    validate_records(policy, final, task, run)
    # Claim lock is compared but must not escape in responses, errors, logs or receipts.
    return {key: snapshot[key] for key in ('task', 'board', 'profile', 'run', 'pid', 'fingerprint')}


def handle(args, policy_path, policy_pin):
    result = {'ok': False, 'admitted': False, 'workflow_ready': False, 'effects': False}
    try:
        require(isinstance(args, dict) and set(args) == {'phase'}, 'unknown_or_missing_parameters')
        require(type(args['phase']) is str and args['phase'] in PHASES, 'phase_unregistered')
        policy = load_policy(policy_path, policy_pin)
        identity = admission(policy, NativeRuntime(policy))
        require(args['phase'] == 'preflight', 'phase_requires_reviewed_execution_seam')
        result.update({'ok': True, 'admitted': True, 'identity': identity,
                       'phase': 'preflight', 'policy_sha256': policy_pin})
    except Refused as exc:
        result['reason'] = str(exc)
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error, ImportError, AttributeError):
        result['reason'] = 'unavailable_or_malformed_native_authority'
    return json.dumps(result, sort_keys=True)


def register(ctx):
    """Supported registration seam only; registration never confers ownership."""
    # Capture exact operator settings; callers cannot select a policy or its digest.
    path, pin = ctx.get_config('policy_path'), ctx.get_config('policy_sha256')

    def handler(args, **_kwargs):
        if ctx.get_config('policy_path') != path or ctx.get_config('policy_sha256') != pin:
            return json.dumps({'ok': False, 'admitted': False, 'workflow_ready': False,
                               'effects': False, 'reason': 'configuration_changed'})
        return handle(args, path, pin)

    ctx.register_tool(name=TOOL, toolset='guarded-delivery-admission', schema=SCHEMA,
                      handler=handler, description=SCHEMA['description'], override=False)
