---
name: skill2work-runtime-probe
description: Inventory the current Work runtime on request, run reviewed functional tests for supported runtimes and create skill2work-runtime.json. Also use for resuming a scan or applying optional prompt parameters.
---

Use an actual execution tool and this skill's scripts/probe.py. On installation, never run the probe automatically. A request to run or refresh the probe authorizes the inventory and bundled standard-library smoke tests. Do not invent a profile when execution is unavailable.

Run `python3 <skill-directory>/scripts/probe.py --deep-scan <writable-output>/skill2work-runtime.json`. Resolve the actual skill directory; never guess a fixed installation path. The helper module checks.py must remain beside probe.py.

## Optional prompt parameters

Use defaults without asking questions. Translate only parameters supplied by the user into arguments. Accept natural language such as “Scan for 20 minutes with 10 seconds per test”. Do not pass prompt text as shell code; use correctly quoted arguments or an argv list.

| Prompt setting | Argument | Default |
| --- | --- | --- |
| Scan time | --scan-seconds | 600 seconds per run |
| Maximum directories | --max-directories | 1000000 per run |
| Additional executables | --max-executables | 100000 total |
| Time per functional test | --test-timeout | 5 seconds |
| Total functional test budget | --test-seconds | 120 seconds |
| Resume | --resume | off |
| Test Python module | --python-module NAME (repeatable) | none |
| Test Node package | --node-module NAME (repeatable) | none |

Require finite positive values. If the user requests unsupported parameters or unlimited execution, explain the supported options; never silently claim to apply them. A faster installation-roots scan is available by omitting --deep-scan when explicitly requested.

## Evidence and tests

Inventory all discoverable PATH entries and accessible ordinary filesystem trees, including hidden installation paths and regular mounts. Inspect virtual kernel trees only through the script's allowlisted metadata. Do not open arbitrary document contents or device nodes. Do not execute newly discovered binaries merely to test their names.

The shared engine runs reviewed standard-library smoke tests for Python, Node, PHP, Ruby and Perl when the selected executable is in an accepted runtime location. Unrecognized runtimes remain found but untested. This is deliberately extensible, not proof of every language. Report the exact test scope, status, exit code and whether the expected result matched.

Only pass --python-module or --node-module when the user explicitly requests that library check. An import executes installed package code; temporary directories, scrubbed credentials and timeouts are not a security sandbox. Do not automatically import every discovered module or execute tests from uploaded skills. A successful import proves loading, not all library operations. Modules are resolved in a temporary test directory with selected runtime search paths; project-local resolution can differ.

If the user asks whether a particular skill works, inspect its actual requirements. Report untested functions and unsupported adapters; do not infer functionality from file presence. Do not claim PATH detection equals successful execution.

## Interrupted and large scans

The output JSON is written atomically after PATH discovery, after inventory, and after functional tests. The filesystem checkpoint is written approximately every five seconds and on normal scan completion. The supervisor imposes an additional wall-clock deadline (scan budget + test budget + 120 seconds) and preserves existing output on timeout. Inaccessible kernel I/O can still outlive process cancellation.

To continue, use the same output path with --resume in the same runtime. Preserve the adjacent .checkpoint.json privately; it contains raw local paths and pending directories and is not the converter input. The checkpoint validates roots, mount table, interpreter, boot ID and PATH. It is a best-effort continuation of a changing filesystem, not an immutable snapshot. Increase the executable limit if that limit stopped progress. Other inventory and test stages run again on resume.

The compact JSON is not discarded for exceeding 8 MiB. The converter accepts up to 64 MiB, subject to PHP upload configuration. Above that, retain the full file and report the import limit; do not truncate data or claim importability. If execution is interrupted, label the available JSON as partial and explain which stages completed.

## Deliver

Inspect the produced JSON before delivery; check coverage and functional_tests, including not_tested and failed records. Report this run's limitations. Never describe the profile as complete Work capability coverage: ordinary filesystem discovery cannot enumerate all agent tools or cloud plugins. If requested, document only tools actually exposed in the current agent registry separately, without invoking services or claiming account-wide completeness.

Deliver the created profile, not the private checkpoint. Explain that runtime paths and package names can be sensitive and that this is a snapshot of the current execution environment, not a promise about future sessions. Save the profile using the available file delivery workflow.
