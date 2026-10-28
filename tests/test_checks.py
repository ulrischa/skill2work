import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'probe-skill/scripts'))
import checks
import probe

class ChecksTests(unittest.TestCase):
    def test_exact_success(self):
        result = checks.run_check([sys.executable, '-c', 'print("ok")'], expected='ok')
        self.assertEqual(result['status'], 'passed')
        self.assertTrue(result['started'])

    def test_bad_output_and_exit(self):
        self.assertEqual(checks.run_check([sys.executable, '-c', 'print("wrong")'], expected='ok')['status'], 'failed')
        self.assertEqual(checks.run_check([sys.executable, '-c', 'exit(3)'])['exit_code'], 3)

    def test_timeout(self):
        self.assertEqual(checks.run_check([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=.05)['status'], 'timeout')

    def test_missing_program(self):
        self.assertEqual(checks.run_check(['/nonexistent/s2w'])['status'], 'start_failed')

    def test_real_runtime_and_import(self):
        result = checks.functional_tests(python_modules=['json', 's2w_module_that_does_not_exist'])
        records = {r['target']: r for r in result['results'] if r['command'] == 'python3'}
        self.assertEqual(records['runtime']['status'], 'passed')
        self.assertEqual(records['python:json']['status'], 'passed')
        self.assertEqual(records['python:s2w_module_that_does_not_exist']['status'], 'failed')

    def test_import_argument_validation(self):
        with self.assertRaises(ValueError):
            checks.functional_tests(python_modules=['json;evil()'])
        with self.assertRaises(ValueError):
            checks.functional_tests(node_modules=['../../evil'])

    def test_atomic_large_profile_retained(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'profile.json'
            checks.atomic_json(path, {'large': 'x' * (9 * 1024 * 1024)})
            self.assertGreater(path.stat().st_size, 8 * 1024 * 1024)
            self.assertEqual(len(json.loads(path.read_text())['large']), 9 * 1024 * 1024)

    def test_resume_no_duplicate_records(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as private:
            root = Path(root)
            (root/'a'/'b').mkdir(parents=True)
            tool = root/'a'/'tool'
            tool.write_text('never execute this')
            tool.chmod(0o755)
            checkpoint = str(Path(private)/'checkpoint.json')
            first = probe.scan_additional_executables({}, roots=[root], mounts=[], max_dirs=1, checkpoint=checkpoint)
            self.assertTrue(first[3]['truncated'])
            resumed = probe.scan_additional_executables({}, roots=[root], mounts=[], max_dirs=100, checkpoint=checkpoint, resume=True)
            self.assertTrue(resumed[3]['complete'])
            self.assertEqual([x['name'] for x in resumed[0]], ['tool'])
            self.assertEqual(resumed[3]['directories_scanned'], 3)

    def test_resume_rejects_other_scope(self):
        with tempfile.TemporaryDirectory() as root:
            checkpoint = str(Path(root)/'state.json')
            probe.scan_additional_executables({}, roots=[root], mounts=[], checkpoint=checkpoint)
            with self.assertRaises(ValueError):
                probe.scan_additional_executables({}, roots=['/unrelated'], mounts=[], checkpoint=checkpoint, resume=True)

    def test_finite_positive_options(self):
        for value in ['nan', 'inf', '0', '-1']:
            with self.assertRaises(Exception):
                checks.positive_float(value)

class FailureIsolationTests(unittest.TestCase):
    def test_failed_inventory_stage_does_not_prevent_function_tests(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            options = {'destination': Path(folder)/'profile.json', 'max_directories': 1, 'scan_seconds': .01}
            with patch.object(probe, 'extension_inventory', side_effect=PermissionError), patch.object(probe, 'functional_tests', return_value={'results': []}):
                result = probe.gather(options=options)
            self.assertIn('functional_tests', result)
            self.assertTrue(any('Extensions: PermissionError' in line for line in result['limitations']))

class CandidateEvidenceTests(unittest.TestCase):
    def test_exact_path_evidence_and_skip_reason(self):
        commands = {'node': {'candidates': [{'resolved_path': '/usr/bin/node'}]}}
        outside = [{'name': 'node', 'resolved_path': '/opt/other/node'}]
        checks.annotate_candidates(commands, outside, {'results': [
            {'command': 'node', 'target': 'runtime', 'executable': '/usr/bin/node', 'status': 'passed'}]})
        self.assertEqual(commands['node']['state'], 'tested')
        self.assertEqual(outside[0]['state'], 'found_untested')
        self.assertEqual(outside[0]['test_reason'], 'no_reviewed_test_for_this_path')

    def test_module_success_does_not_mark_runtime_tested(self):
        outside = [{'name': 'python3', 'resolved_path': '/opt/python'}]
        checks.annotate_candidates({}, outside, {'results': [
            {'command': 'python3', 'target': 'python:json', 'executable': '/opt/python', 'status': 'passed'}]})
        self.assertEqual(outside[0]['state'], 'found_untested')

    def test_test_failure_is_not_absence(self):
        outside = [{'name': 'node', 'resolved_path': '/opt/node'}]
        checks.annotate_candidates({}, outside, {'results': [
            {'command': 'node', 'target': 'runtime', 'executable': '/opt/node', 'status': 'failed', 'reason': 'nonzero_exit'}]})
        self.assertEqual(outside[0]['state'], 'test_failed')
        self.assertEqual(outside[0]['test_reason'], 'nonzero_exit')

    def test_untrusted_runtime_is_recorded_but_not_executed(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            executable = Path(folder)/'node'
            marker = Path(folder)/'executed'
            executable.write_text('#!/bin/sh\ntouch ' + str(marker))
            executable.chmod(0o755)
            with patch.dict(os.environ, {'PATH': folder}):
                tests = checks.functional_tests()
            record = next(r for r in tests['results'] if r['command'] == 'node')
            self.assertEqual(record['reason'], 'outside_trusted_roots')
            self.assertEqual(record['state'], 'found_untested')
            self.assertEqual(record['executable'], str(executable))
            self.assertFalse(marker.exists())

    def test_failure_has_structured_diagnostics(self):
        failed = checks.run_check([sys.executable, '-c', 'exit(7)'], expected='ok')
        self.assertEqual((failed['reason'], failed['exit_code']), ('nonzero_exit', 7))
        missing = checks.run_check(['/nonexistent/s2w'])
        self.assertEqual(missing['reason'], 'process_start_error')
        self.assertEqual(missing['errno'], 2)

    def test_off_path_duplicate_name_is_not_discarded(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'path').mkdir(); (root/'other').mkdir()
            for part in ('path', 'other'):
                p = root/part/'custom'
                p.write_text('never execute'); p.chmod(0o755)
            from unittest.mock import patch
            with patch.dict(os.environ, {'PATH': str(root/'path')}):
                commands, _, _ = probe.scan_commands()
            outside, _, _, _ = probe.scan_additional_executables(commands, roots=[root], mounts=[])
            self.assertEqual([e['invocation_path'] for e in outside], [str(root/'other'/'custom')])
            self.assertEqual(commands['custom']['candidates'][0]['invocation_path'], str(root/'path'/'custom'))

    def test_missing_adapter_runtime_has_explicit_absence_state(self):
        from unittest.mock import patch
        with patch.object(checks.shutil, 'which', return_value=None):
            records = checks.functional_tests()['results']
        node = next(r for r in records if r['command'] == 'node')
        self.assertEqual(node['state'], 'not_found')
        self.assertEqual(node['reason'], 'not_found_in_runtime_search')
