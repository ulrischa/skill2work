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
