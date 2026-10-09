# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic identity tests plus actual installed loader/transport negatives.

Never alter production environment/boards. Positive admission uses a FakeRuntime
and tiny scratch SQLite fixture; it is explicitly NOT dispatcher ownership proof.
"""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('staged_admission_test_subject', ROOT/'__init__.py')
if spec is None or spec.loader is None:
    raise RuntimeError('test subject unavailable')
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


def pin(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class FakeRuntime:
    """A constructed in-memory snapshot, never installed into os.environ."""
    def __init__(self, snapshot, second=None):
        self.value = snapshot
        self.second = second
        self.calls = 0

    def snapshot(self):
        self.calls += 1
        return copy.deepcopy(self.second if self.calls > 1 and self.second else self.value)


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifact = self.root/'artifact.txt'
        self.artifact.write_text('immutable synthetic helper input\n')
        self.db = self.root/'board.db'
        self.policy = {
            'version':1, 'mode':'admission-only', 'board':'synthetic-board',
            'owner_task':'t_12345678', 'profile':'synthetic-owner', 'board_db':str(self.db),
            'runtime': {'exposure':'native-worker-process', 'source_root':str(self.root),
                        'interpreter':{'path':str(self.artifact), 'sha256':pin(self.artifact)},
                        'files':{name.replace('.', '/')+'.py':'0'*64 for name in subject.NATIVE_MODULES}},
            'artifacts':[{'path':str(self.artifact), 'sha256':pin(self.artifact)}],
            'permissions':['preflight'],
            'delivery_contract': {'repository':str(self.root/'repository'), 'target_ref':'refs/heads/main',
                                  'review_task':'t_87654321', 'candidate_sha':'1'*40, 'expected_old_sha':'2'*40,
                                  'transport':'local', 'executables':[]},
        }
        self.snapshot = {'task':'t_12345678', 'board':'synthetic-board', 'run':'7',
                         'claim':'synthetic-claim-not-an-environment-value', 'db':str(self.db),
                         'profile':'synthetic-owner', 'pid':112233, 'fingerprint':'synthetic-boot|777', 'now':1000.0}
        self.task = {'id':'t_12345678', 'status':'running','assignee':'synthetic-owner', 'current_run_id':7,
                     'claim_lock':self.snapshot['claim'], 'claim_expires':1100, 'worker_pid':112233,
                     'worker_started_at':'synthetic-boot|777'}
        self.run_record = {'id':7, 'task_id':'t_12345678','profile':'synthetic-owner','status':'running',
                    'claim_lock':self.snapshot['claim'], 'claim_expires':1100,'worker_pid':112233,
                    'worker_started_at':'synthetic-boot|777','ended_at':None}
        with sqlite3.connect(self.db) as conn:
            for table, value in (('tasks', self.task), ('task_runs', self.run_record)):
                conn.execute('CREATE TABLE '+table+' ('+', '.join(value)+')')
                conn.execute('INSERT INTO '+table+' VALUES ('+','.join('?' for _ in value)+')', tuple(value.values()))
        self.policy_file = self.root/'policy.json'
        self.policy_file.write_text(json.dumps(self.policy))

    def denied(self, reason, action):
        with self.assertRaisesRegex(subject.Refused, reason):
            action()

    def test_synthetic_admission_is_read_only_and_excludes_claim(self):
        before = pin(self.db)
        identity = subject.admission(self.policy, FakeRuntime(self.snapshot))
        self.assertEqual(identity['run'], 7)
        self.assertEqual(identity['pid'], 112233)
        self.assertNotIn('claim', identity)
        self.assertEqual(before, pin(self.db))
        with sqlite3.connect(self.db.as_uri()+'?mode=ro',uri=True) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM tasks').fetchone()[0],1)

    def test_foreign_snapshot_fields(self):
        for key, value, reason in (('task','t_abcdefab','foreign_worker'), ('board','other','foreign_board'),
                                  ('profile','other','foreign_profile'), ('db',str(self.root/'other.db'),'foreign_db')):
            with self.subTest(field=key):
                changed = dict(self.snapshot, **{key:value})
                self.denied(reason, lambda:subject.admission(self.policy,FakeRuntime(changed)))

    def test_run_markers_are_literal_positive_integer_strings(self):
        for value in (None, '', '0', '-1','7.0',' 7','07',7,True):
            with self.subTest(value=value):
                self.denied('run_marker_invalid',lambda:subject.admission(self.policy,FakeRuntime(dict(self.snapshot,run=value))))

    def test_native_task_and_run_refusals(self):
        snapshot = dict(self.snapshot, run=7)
        cases = [('task','status','done','run_not_live'), ('run','status','done','run_not_live'),
                 ('run','ended_at',1001,'run_not_live'), ('task','id','t_aaaaaaaa','native_task_mismatch'),
                 ('run','task_id','t_aaaaaaaa','native_task_mismatch'), ('task','current_run_id',8,'stale_run'),
                 ('run','id',8,'stale_run'), ('task','assignee','foreign','native_profile_mismatch'),
                 ('run','profile','foreign','native_profile_mismatch'), ('task','claim_lock','other','claim_mismatch'),
                 ('run','claim_lock','other','claim_mismatch'), ('task','claim_expires',999,'claim_expired'),
                 ('run','claim_expires',1000,'claim_expired'), ('task','claim_expires',True,'claim_expired'),
                 ('task','claim_expires',float('inf'),'claim_expired'),
                 ('task','worker_pid',112234,'worker_pid_mismatch'), ('run','worker_pid',112234,'worker_pid_mismatch'),
                 ('task','worker_started_at','other-boot|777','worker_start_mismatch'),
                 ('run','worker_started_at','synthetic-boot|778','worker_start_mismatch')]
        for which,key,value,reason in cases:
            with self.subTest(which=which,key=key,value=value):
                task, run = copy.deepcopy(self.task), copy.deepcopy(self.run_record)
                (task if which == 'task' else run)[key] = value
                self.denied(reason,lambda:subject.validate_records(self.policy,snapshot,task,run))
        self.denied('native_record_missing',lambda:subject.validate_records(self.policy,snapshot,None,self.run_record))
        self.denied('native_record_missing',lambda:subject.validate_records(self.policy,snapshot,self.task,None))

    def test_unverified_fingerprints_and_empty_claim(self):
        for value in (None,'','unverified','777',777):
            with self.subTest(value=value):
                self.denied('fingerprint_unverified',lambda:subject.validate_records(self.policy,dict(self.snapshot,run=7,fingerprint=value),self.task,self.run_record))
        self.denied('claim_mismatch',lambda:subject.validate_records(self.policy,dict(self.snapshot,run=7,claim=''),self.task,self.run_record))

    def test_ownership_rechecked_after_pin_io(self):
        for key,value in (('task','t_aaaaaaaa'),('pid',112234),('fingerprint','new|777'),('claim','stale'),('run','8')):
            with self.subTest(key=key):
                self.denied('changed_during_probe',lambda:subject.admission(self.policy,FakeRuntime(self.snapshot,dict(self.snapshot,**{key:value}))))

    def test_db_claim_rechecked_after_pin_io(self):
        original = subject.pinned_bytes
        def revoke(path,digest):
            raw=original(path,digest)
            with sqlite3.connect(self.db) as conn:
                conn.execute("UPDATE task_runs SET status='done', ended_at=1001")
            return raw
        with patch.object(subject,'pinned_bytes',side_effect=revoke):
            self.denied('run_not_live',lambda:subject.admission(self.policy,FakeRuntime(self.snapshot)))

    def test_missing_changed_or_linked_artifact_refuses(self):
        self.artifact.write_text('changed\n')
        self.denied('digest_mismatch',lambda:subject.admission(self.policy,FakeRuntime(self.snapshot)))
        self.artifact.unlink()
        target=self.root/'target'
        target.write_text('immutable synthetic helper input\n')
        self.artifact.symlink_to(target)
        self.denied('symlink_refused',lambda:subject.admission(self.policy,FakeRuntime(self.snapshot)))
        self.artifact.unlink()
        with self.assertRaises(FileNotFoundError):
            subject.admission(self.policy,FakeRuntime(self.snapshot))

    def test_linked_parent_and_nonregular_file(self):
        link=self.root/'link'
        link.symlink_to(self.root,target_is_directory=True)
        self.denied('symlink_refused',lambda:subject.regular_bytes(link/'artifact.txt'))
        with self.assertRaises((IsADirectoryError,subject.Refused)):
            subject.regular_bytes(self.root)
        fifo=self.root/'fifo'
        os.mkfifo(fifo)
        self.denied('nonregular_file',lambda:subject.regular_bytes(fifo))

    def test_changed_native_pin_refuses_before_import(self):
        for name in subject.NATIVE_MODULES:
            path=self.root/(name.replace('.', '/')+'.py')
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('raise RuntimeError("must never execute")\n')
        self.denied('digest_mismatch',lambda:subject.NativeRuntime(self.policy))

    def test_db_link_refuses(self):
        link=self.root/'linked.db'
        link.symlink_to(self.db)
        self.denied('board_db_missing_or_linked',lambda:subject.current_records(link,'t_12345678',7))

    def test_readonly_connection_rejects_writes(self):
        real_connect=sqlite3.connect
        def checked(database, **kwargs):
            self.assertIn('mode=ro',database)
            conn=real_connect(database,**kwargs)
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("UPDATE tasks SET status='done'")
            conn.rollback()  # The deliberately refused write began a transaction.
            return conn
        with patch.object(subject.sqlite3,'connect',side_effect=checked):
            subject.current_records(self.db,'t_12345678',7)

    def test_policy_shapes_permissions_runtime_and_exec_default_deny(self):
        changes = [('version',True), ('mode','enabled'), ('owner_task','t_12345678 '),('board','../foreign'),
                   ('permissions',subject.PHASES),('permissions',['preflight','guarded-integration'])]
        for key,value in changes:
            with self.subTest(key=key,value=value):
                self.denied('.',lambda:subject.validate_policy(dict(self.policy,**{key:value})))
        changed=copy.deepcopy(self.policy);changed['runtime']['exposure']='managed-mcp'
        self.denied('runtime_exposure_unknown',lambda:subject.validate_policy(changed))
        changed=copy.deepcopy(self.policy);changed['delivery_contract']['executables']=['/bin/sh']
        self.denied('executable_capability_unavailable',lambda:subject.validate_policy(changed))
        changed=copy.deepcopy(self.policy);changed['runtime']['files']={'../escape.py':'0'*64}
        self.denied('native_pin_missing',lambda:subject.validate_policy(changed))
        changed=copy.deepcopy(self.policy);changed['runtime']['files']['../escape.py']='0'*64
        self.denied('runtime_pin_path_invalid',lambda:subject.validate_policy(changed))
        for section in (None,'runtime','delivery_contract'):
            with self.subTest(section=section):
                changed=copy.deepcopy(self.policy)
                (changed if section is None else changed[section])['arbitrary_shell']='true'
                self.denied('fields_invalid',lambda:subject.validate_policy(changed))

    def test_changed_policy_digest_and_duplicate_json(self):
        digest=pin(self.policy_file)
        subject.load_policy(self.policy_file,digest)
        self.policy_file.write_text(json.dumps(dict(self.policy,profile='foreign')))
        self.denied('digest_mismatch',lambda:subject.load_policy(self.policy_file,digest))
        self.policy_file.write_text('{"version":1,"version":1}')
        self.denied('duplicate_policy_key',lambda:subject.load_policy(self.policy_file,pin(self.policy_file)))
        for digest in ('x'*64,'0'*63,'A'*64,None):
            with self.subTest(digest=digest):
                self.denied('invalid_pin',lambda:subject.load_policy(self.policy_file,digest))

    def test_handler_rejects_all_arbitrary_selectors(self):
        for args in ({}, {'phase':'shell'}, {'phase':'preflight','task':'t_12345678'},
                     {'phase':'preflight','scope':'foreign'}, {'phase':'preflight','command':'true'},
                     {'phase':'preflight','policy_path':str(self.policy_file)},None,[],{'phase':True}):
            with self.subTest(args=args):
                result=json.loads(subject.handle(args,self.policy_file,pin(self.policy_file)))
                self.assertFalse(result['ok']);self.assertFalse(result['effects'])
                self.assertFalse(result['workflow_ready']);self.assertFalse(result['admitted'])

    def test_all_effectful_phases_unavailable_even_with_synthetic_admission(self):
        with patch.object(subject,'NativeRuntime',return_value=FakeRuntime(self.snapshot)):
            for phase in subject.PHASES:
                with self.subTest(phase=phase):
                    result=json.loads(subject.handle({'phase':phase},self.policy_file,pin(self.policy_file)))
                    self.assertFalse(result['effects']);self.assertFalse(result['workflow_ready'])
                    self.assertEqual(result['ok'],phase=='preflight')
                    if phase != 'preflight':
                        self.assertEqual(result['reason'],'phase_requires_reviewed_execution_seam')

    def test_plugin_config_change_invalidates_registration(self):
        class Context:
            values={'policy_path':str(self.policy_file),'policy_sha256':pin(self.policy_file)}
            def get_config(self,key):return self.values.get(key)
            def register_tool(self,**values):self.registration=values
        ctx=Context();subject.register(ctx)
        self.assertFalse(ctx.registration['override'])
        ctx.values=dict(ctx.values,policy_sha256='0'*64)
        result=json.loads(ctx.registration['handler']({'phase':'preflight'}))
        self.assertEqual(result['reason'],'configuration_changed')
        self.assertFalse(result['effects'])


class InstalledRuntimeTests(unittest.TestCase):
    def test_public_example_is_inert_before_native_authority(self):
        example = ROOT / 'examples/policy.example.json'
        with patch.object(subject, 'NativeRuntime') as runtime, patch.object(subject, 'current_records') as records:
            result = json.loads(subject.handle({'phase': 'preflight'}, str(example), pin(example)))
        self.assertEqual(result['reason'], 'product_sha_invalid')
        self.assertFalse(result['ok'])
        self.assertFalse(result['admitted'])
        self.assertFalse(result['effects'])
        self.assertFalse(result['workflow_ready'])
        runtime.assert_not_called()
        records.assert_not_called()

    def test_actual_installed_loader_and_terminal_refusal(self):
        from hermes_constants import set_hermes_home_override, reset_hermes_home_override
        from hermes_cli.plugins import PluginManager
        from hermes_cli.plugins_manifest import parse_manifest_file, manifest_key
        from tools.registry import registry
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as scratch:
            scope=Path(scratch)
            from runtime_policy_fixture import write_terminal_policy
            example=write_terminal_policy(scope, ROOT)
            # Isolated synthetic config; never edit live profile/config.
            (scope/'config.yaml').write_text('plugins:\n  entries:\n    guarded-delivery-admission:\n      settings:\n        policy_path: '+str(example)+'\n        policy_sha256: '+pin(example)+'\n')
            manager=PluginManager(scope_key=str(scope))
            manifest=parse_manifest_file(ROOT/'plugin.yaml',ROOT,'project','')
            if manifest is None:
                self.fail('installed manifest parser refused candidate')
            key=manifest_key(manifest)
            try:
                manager._load_plugin(manifest)
                loaded=manager._plugins[key]
                self.assertTrue(loaded.enabled,loaded.error)
                self.assertEqual(loaded.tools_registered,[subject.TOOL])
                entry=registry.get_entry(subject.TOOL,scope=str(scope))
                if entry is None:
                    self.fail('installed registry did not expose isolated candidate')
                token=set_hermes_home_override(str(scope))
                try:
                    result=json.loads(entry.handler({'phase':'preflight'}))
                    from tools.arg_coercion import coerce_tool_args
                    for args in ({'phase':'shell'}, {'phase':True},
                                 {'phase':'preflight','task':'t_abcdefab'},
                                 {'phase':'preflight','command':'true'}):
                        wire=coerce_tool_args(subject.TOOL,dict(args))
                        refused=json.loads(entry.handler(wire))
                        self.assertFalse(refused['ok'])
                        self.assertFalse(refused['effects'])
                        self.assertIn(refused['reason'],('phase_unregistered','unknown_or_missing_parameters'))
                finally:
                    reset_hermes_home_override(token)
                from agent.delegation_context import is_dispatcher_owned_worker_context, non_dispatcher_owned_context
                expected = 'worker_identity_missing' if is_dispatcher_owned_worker_context() else 'not_dispatcher_owned'
                self.assertEqual(result['reason'], expected)
                token=set_hermes_home_override(str(scope))
                try:
                    with non_dispatcher_owned_context():
                        fenced = json.loads(entry.handler({'phase':'preflight'}))
                finally:
                    reset_hermes_home_override(token)
                self.assertEqual(fenced['reason'], 'not_dispatcher_owned')
                self.assertFalse(fenced['admitted'])
                self.assertFalse(fenced['effects'])
                self.assertFalse(fenced['workflow_ready'])
                self.assertFalse(result['effects']);self.assertFalse(result['admitted'])
                self.assertFalse(result['workflow_ready'])
                self.assertNotIn('claim',json.dumps(result))
            finally:
                manager.unload(key)
            self.assertIsNone(registry.get_entry(subject.TOOL,scope=str(scope)))

    def test_actual_installed_native_contexts_deny_terminal_delegate_and_cron(self):
        from agent.delegation_context import (is_dispatcher_owned_worker_context,
            owned_kanban_task, delegated_child_context, non_dispatcher_owned_context)
        # Native context eligibility alone does not prove an ordinary caller owns a task.
        self.assertEqual(owned_kanban_task(),'')
        with delegated_child_context():
            self.assertFalse(is_dispatcher_owned_worker_context());self.assertEqual(owned_kanban_task(),'')
        with non_dispatcher_owned_context():
            self.assertFalse(is_dispatcher_owned_worker_context());self.assertEqual(owned_kanban_task(),'')

    def test_actual_managed_transport_does_not_expose_candidate(self):
        from agent.transports.hermes_tools_mcp_server import EXPOSED_TOOLS, _signature_from_schema
        self.assertNotIn(subject.TOOL,EXPOSED_TOOLS)
        signature,annotations=_signature_from_schema(subject.SCHEMA['parameters'])
        self.assertEqual(list(signature.parameters),['phase'])
        self.assertIs(annotations['phase'],str)
        self.assertEqual(signature.parameters['phase'].kind,signature.parameters['phase'].KEYWORD_ONLY)

    def test_no_effectful_operations_or_product_constants_in_generic_source(self):
        import ast
        raw=(ROOT/'__init__.py').read_text()
        tree=ast.parse(raw)
        imports={node.names[0].name for node in ast.walk(tree) if isinstance(node,ast.Import)}
        self.assertNotIn('subprocess',imports)
        self.assertNotIn('socket',imports)
        self.assertNotIn('synthetic-board',raw)
        self.assertNotIn('t_12345678',raw)
        self.assertNotIn('synthetic-owner',raw)
        self.assertNotIn('os.environ[',raw)
        self.assertNotIn('sys.modules',raw)
        sql=[node.value for node in ast.walk(tree) if isinstance(node,ast.Constant) and isinstance(node.value,str) and (node.value.startswith('SELECT ') or node.value.startswith('PRAGMA ') or node.value=='BEGIN')]
        self.assertEqual(len(sql),4)
        self.assertTrue(all(value.startswith(('SELECT ','PRAGMA query_only=','BEGIN')) for value in sql))


if __name__=='__main__':
    unittest.main(verbosity=2)
