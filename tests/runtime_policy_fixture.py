"""Generate a disposable refusal fixture; never copy an operator policy."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


def digest(path: Path) -> str:
    """Hash the real pinned fixture input without executing it."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_terminal_policy(scope: Path, plugin_root: Path) -> Path:
    """Pin real native files but synthetic identity, ensuring ordinary callers refuse.

    This is not a dispatcher-owned positive fixture or a deployment template.
    The deliberately absent board database must not be opened by this caller.
    """
    source = Path(os.environ['HERMES_AGENT_ROOT']).resolve(strict=True)
    interpreter = Path('/proc/self/exe').resolve(strict=True)
    native_files = ('agent/delegation_context.py', 'hermes_cli/kanban_db_dispatch.py')
    policy = {
        'version': 1, 'mode': 'admission-only', 'board': 'synthetic-board',
        'owner_task': 't_12345678', 'profile': 'synthetic-owner',
        'board_db': str(scope / 'never-created-board.db'),
        'runtime': {
            'exposure': 'native-worker-process', 'source_root': str(source),
            'interpreter': {'path': str(interpreter), 'sha256': digest(interpreter)},
            'files': {name: digest(source / name) for name in native_files},
        },
        'artifacts': [{'path': str(plugin_root / '__init__.py'),
                       'sha256': digest(plugin_root / '__init__.py')}],
        'permissions': ['preflight'],
        'delivery_contract': {
            'repository': str(scope / 'synthetic-repository'),
            'target_ref': 'refs/heads/main', 'review_task': 't_87654321',
            'candidate_sha': '1' * 40, 'expected_old_sha': '2' * 40,
            'transport': 'local', 'executables': [],
        },
    }
    destination = scope / 'terminal-refusal-policy.json'
    destination.write_text(json.dumps(policy, indent=2) + '\n')
    return destination
