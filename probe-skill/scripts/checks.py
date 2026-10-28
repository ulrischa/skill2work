"""Shared process-test engine with small runtime adapters; no uploaded code execution."""
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid


def atomic_json(destination, value):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=destination.name + '.', dir=destination.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=True, separators=(',', ':'))
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def positive_float(value):
    import argparse
    import math
    try:
        result = float(value)
        if not math.isfinite(result) or result <= 0:
            raise ValueError()
        return result
    except ValueError:
        raise argparse.ArgumentTypeError('Expected a finite positive number')


def positive_int(value):
    import argparse
    try:
        result = int(value)
        if result <= 0:
            raise ValueError()
        return result
    except ValueError:
        raise argparse.ArgumentTypeError('Expected a positive integer')


def run_check(argv, timeout=5, expected=None):
    """Run reviewed arguments in a temporary cwd; store no arbitrary stdout/stderr."""
    started = time.monotonic()
    result = {'status': 'unknown', 'exit_code': None, 'started': False}
    with tempfile.TemporaryDirectory(prefix='skill2work-test-') as folder:
        # Child output goes to bounded files, not unbounded parent memory.
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            env = {k: v for k, v in os.environ.items() if k in
                   ('PATH', 'PYTHONPATH', 'NODE_PATH', 'LD_LIBRARY_PATH', 'LANG', 'LC_ALL', 'SYSTEMROOT')}
            env.update(HOME=folder, TMPDIR=folder, PYTHONDONTWRITEBYTECODE='1',
                       PYTHONNOUSERSITE='1', NO_PROXY='*')
            def limits():
                import resource
                resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            process = None
            try:
                process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                    cwd=folder, env=env, start_new_session=True,
                    preexec_fn=limits if os.name == 'posix' else None)
                result['started'] = True
                result['exit_code'] = process.wait(timeout=timeout)
                output.seek(0)
                text = output.read(65536).decode('utf-8', errors='replace').strip()
                result['status'] = ('passed' if result['exit_code'] == 0 and
                                    (expected is None or text == expected) else 'failed')
                result['output_matches'] = expected is not None and text == expected
            except subprocess.TimeoutExpired:
                result['status'] = 'timeout'
            except OSError as error:
                result['status'] = 'start_failed'
                result['error_type'] = type(error).__name__
            finally:
                if process:
                    try:
                        if os.name == 'posix':
                            os.killpg(process.pid, signal.SIGKILL)
                        elif process.poll() is None:
                            process.kill()
                    except ProcessLookupError:
                        pass
                    process.wait()
    result['duration_seconds'] = round(time.monotonic() - started, 3)
    return result


def resolve_runtime(name):
    candidate = sys.executable if name == 'python3' else shutil.which(name)
    if not candidate:
        return None
    candidate = Path(candidate).resolve()
    roots = [Path(p).resolve() for p in ('/usr/bin', '/usr/local/bin', '/bin', '/usr/sbin')]
    owned_runtime = os.environ.get('CODEX_PRIMARY_RUNTIME_ROOT')
    if candidate == Path(sys.executable).resolve() or candidate.parent in roots:
        return str(candidate)
    if owned_runtime and candidate.is_relative_to(Path(owned_runtime).resolve()):
        return str(candidate)
    return None


def functional_tests(timeout=5, budget=120, python_modules=(), node_modules=()):
    marker = 'skill2work-' + uuid.uuid4().hex
    # Adapters only supply invocation syntax. The runner and evidence model are shared.
    definitions = [
        ('python3', 'runtime', ['-S', '-c', 'import json; assert json.loads(\'{"v":3}\')["v"] == 3; print(' + repr(marker) + ')']),
        ('node', 'runtime', ['-e', 'if(JSON.parse(\'{"v":3}\').v!==3)process.exit(2);console.log(' + json.dumps(marker) + ')']),
        ('php', 'runtime', ['-n', '-r', 'if(json_decode(\'{"v":3}\',true)["v"]!==3)exit(2);echo ' + json.dumps(marker) + ';']),
        ('ruby', 'runtime', ['--disable-gems', '-e', 'raise unless 1+2==3;puts ' + json.dumps(marker)]),
        ('perl', 'runtime', ['-e', 'die unless 1+2==3;print ' + json.dumps(marker) + ';']),
    ]
    for name in python_modules:
        if not re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*', name):
            raise ValueError('Invalid Python module name')
        definitions.append(('python3', 'python:' + name, ['-c',
            'import importlib; importlib.import_module(' + repr(name) + '); print(' + repr(marker) + ')']))
    for name in node_modules:
        if not re.fullmatch(r'(?:@[a-zA-Z0-9_-]+/)?[a-zA-Z0-9_-][a-zA-Z0-9_.-]*', name):
            raise ValueError('Invalid Node package name')
        definitions.append(('node', 'node:' + name, ['-e',
            'import(' + json.dumps(name) + ').then(()=>console.log(' + json.dumps(marker) + ')).catch(()=>process.exit(1))']))
    results = []
    start = time.monotonic()
    for name, target, arguments in definitions:
        remaining = budget - (time.monotonic() - start)
        path = resolve_runtime(name)
        record = {'command': name, 'target': target, 'scope': 'isolated_temp_cwd_sanitized_environment',
                  'test': 'stdlib_smoke' if target == 'runtime' else 'explicit_module_import'}
        if remaining <= 0:
            record.update(status='not_tested', reason='test_budget_exhausted')
        elif path is None:
            record.update(status='not_tested', reason='runtime_missing_or_outside_trusted_roots')
        else:
            record['executable'] = path.replace(str(Path.home()) + '/', '~/')
            record['arguments'] = arguments
            record.update(run_check([path, *arguments], min(timeout, remaining), marker))
        results.append(record)
    return {'results': results, 'complete': all(x['status'] != 'not_tested' for x in results),
            'scope': 'Only listed tests; installed packages are not automatically imported.',
            'limitations': ['A passing import does not test every library function.',
                'Temporary cwd and timeouts are not a security sandbox; explicit imports execute installed code.',
                'No intentional network requests; third-party module side effects are not prevented.']}
