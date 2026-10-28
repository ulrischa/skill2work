# skill2work 1.5

Inspect Codex/Agent Skills ZIP archives, compare their requirements with an observed ChatGPT Work runtime, and export individual skill ZIPs with compatibility reports.

The converter is a PHP 8.2+ web application. It needs no database, Composer, Node.js or external API. The optional runtime probe uses Python 3 and its standard library.

**Conversion is not a guarantee of execution or skill import eligibility.** The converter never runs uploaded scripts. A runtime profile describes the session where the probe actually ran; it is not a permanent list of Work capabilities.

## Quick start

```sh
git clone https://github.com/ulrischa/skill2work.git
cd skill2work
php -S 127.0.0.1:8080 -t public
```

Open <http://127.0.0.1:8080>. PHP needs sessions, uploads, and either `ZipArchive` or `PharData`. The system temporary directory must be writable. The built-in PHP server is intended for local use.

1. Download the runtime probe from the application, or use [`dist/skill2work-runtime-probe.zip`](dist/skill2work-runtime-probe.zip).
2. Import the probe into your target Work environment if skill import is available to your account. Installation alone does not run it.
3. Ask: **“Run the skill2work runtime probe.”** The agent must actually execute the script and provide `skill2work-runtime.json`. If execution is unavailable, there is no valid profile.
4. In the PHP application, upload a source skill ZIP and that JSON profile. A repository ZIP containing multiple skills is also accepted.
5. Select **Analyze & create ZIP**, inspect the findings, and download the individual `<name>-work.zip` files.
6. Review `references/skill2work-compatibility.md` inside each output before importing and trying it in Work. Unresolved dependencies can remain even when a ZIP is generated.

You can convert without a profile, but runtime requirements remain unverified. Do not upload the probe ZIP as the source skill you want to convert. A profile generated on a PC, server or Raspberry Pi describes that machine, not Work.

The bundled `agents/openai.yaml` supplies an optional suggested prompt. It cannot force an installation-time Run button or guarantee that a particular UI displays that prompt. If skill installation is unavailable, execution from an ordinary attachment is only an alternative when that environment actually supports it.

## Runtime probe

The skill defaults to a recursive metadata scan from `/`, including accessible regular mounts, hidden directories and unusual installation locations. It inventories PATH executables, off-PATH candidates, Python modules and distributions, system packages, selected runtime/package-manager metadata, discoverable extensions and skill/plugin manifests.

It does not recursively read `/proc`, `/sys`, `/dev` or `/run`. Instead, reviewed routines collect selected kernel, resource, mount and device metadata. Directory symlinks are not followed. Arbitrary document contents and newly discovered executables are not opened or run to guess their behavior.

The inventory can reveal software names and paths. Environment variable names and selected sanitized path values are recorded; secret values are not intentionally exported. Review the JSON before sharing. ChatGPT processes data created there, so this is not equivalent to exclusive local visibility.

### Optional prompt settings

No parameters are required. For example:

> Run the probe with 20 minutes of scan time and 10 seconds per test. Also test the Python modules numpy and pandas.

| Setting | CLI option | Default |
| --- | --- | --- |
| Scan budget | `--scan-seconds` | 600 seconds per run |
| Directory limit | `--max-directories` | 1,000,000 per run |
| Off-PATH executable records | `--max-executables` | 100,000 total |
| Time per functional test | `--test-timeout` | 5 seconds |
| Total functional test budget | `--test-seconds` | 120 seconds |
| Resume filesystem scan | `--resume` | Disabled |
| Python import checks | `--python-module NAME` | None; repeatable |
| Node package load checks | `--node-module NAME` | None; repeatable |

Values must be positive and finite. These are phase budgets, not an exact total runtime guarantee. A supervisor adds a wall-clock deadline of scan budget + test budget + 120 seconds; blocked kernel I/O can outlive cancellation. Other metadata inventories have separate collection/output limits, reported where supported.

To execute manually **inside the target runtime**:

```sh
python3 probe-skill/scripts/probe.py --deep-scan /writable/path/skill2work-runtime.json
python3 probe-skill/scripts/probe.py --deep-scan --scan-seconds 1200 --test-timeout 10 \
  --python-module numpy --python-module pandas /writable/path/skill2work-runtime.json
```

Replace `/writable/path` with a real writable directory. Inside an installed skill, resolve its actual directory rather than assuming this repository layout. The skill supplies `--deep-scan`; invoking the script directly without that flag selects a smaller installation-roots scan.

### Functional evidence

A shared engine manages process startup, a temporary working directory, a reduced environment, deadlines, bounded output and expected-result comparison. Reviewed adapters supply small standard-library or arithmetic tests for Python, Node, PHP, Ruby and Perl. Other programs remain untested; their discovery does not authorize executing them.

| Evidence | Meaning |
| --- | --- |
| `available` in inventory | Found according to that inventory method |
| `passed` | The recorded test started and produced the expected result |
| `failed` | The process failed or its output did not match |
| `start_failed` | The test process could not start |
| `timeout` | The test exceeded its budget |
| `not_tested` | No execution evidence, for example no trusted runtime or exhausted budget |

Additional Python/Node imports are performed only when explicitly requested. Importing a package executes its code; this process isolation is **not a security sandbox**. A successful import proves loading, not every library operation. Project-local search paths may differ from the temporary test environment. Review unfamiliar packages before requesting import checks.

### Partial results and resuming

The output JSON is saved atomically after PATH discovery, after inventory, and after functional tests. Errors in individual metadata phases are reported without necessarily stopping other phases. A filesystem checkpoint is saved approximately every five seconds and at normal scan completion.

To resume, keep the same output path and environment:

```sh
python3 probe-skill/scripts/probe.py --deep-scan --resume /writable/path/skill2work-runtime.json
```

Keep the adjacent `.checkpoint.json` private: it contains raw paths and pending directories. **Upload only the runtime JSON to the converter.** Resume validates environment identifiers and continues the filesystem walk; other inventory/test phases run again. Increase `--max-executables` if that limit stopped progress. A changing filesystem is not an immutable snapshot.

Large output is retained rather than discarded at the old 8 MiB threshold. The converter accepts at most 64 MiB and has additional schema field limits. It does not support multipart profiles. Check `partial`, `coverage`, `limitations`, `inventory.filesystem_scan` and `functional_tests`; an output file alone does not imply completed coverage.

### Who runs it, and when?

A normal user can run the probe when their environment permits script execution. Administrator privileges are not inherently required. Separate users/environments may have different permissions and plugins; an administrator's reference profile does not establish everyone's capabilities.

Reuse a profile for subsequent conversions in the same environment. Refresh after runtime/permission changes, unexpected failures or before important use. Monthly refresh is a practical maintenance choice, not a platform requirement. The converter warns about profiles older than 30 days. Even a recent profile remains a snapshot.

## Conversion rules

| Source pattern | Result |
| --- | --- |
| Missing/invalid basic skill metadata | Add or normalize supported scalar frontmatter; flag unsupported YAML |
| `python` / `nodejs` command examples in `SKILL.md` | Rewrite to `python3` / `node` only when profile evidence supports the alias |
| Human-facing `$hyphenated-skill` and `/skills` Markdown references | Rewrite to ChatGPT `@` selection wording; report external skill dependencies |
| Entire prose line: `Run` followed by `codex exec "literal task"` in inline code | Generate a direct Work task with file/permission checks; report before/after and location |
| Flags, pipes, redirects, dynamic prompts, session IDs, scripts or fenced Codex calls | Preserve the invocation; report limitations and task alternatives |
| Hooks, MCP, Codex paths and external `AGENTS.md` | Report requirements; ZIP import does not deploy or authorize them |

`@skill` is a composer selection convention, not a shell command or a guaranteed programmatic skill-to-skill API. `codex exec` has subprocess, output and authentication semantics that a Work instruction cannot reproduce. Other Codex subcommands get task-level guidance, not executable replacements.

See [`docs/architecture.md`](docs/architecture.md) for implementation details and analysis limits. Unsupported cases appear in the UI and reports, including `references/skill2work-work-actions.md` when applicable. Original executable scripts are preserved. The converter does not translate arbitrary user-authored skill content into English; its own interface, guidance and reports are English.

### Assessment labels

| Status | Interpretation |
| --- | --- |
| `instructions-only` | No relevant program execution detected; indirect calls may be missed |
| `observed` | Detected requirements were found in the supplied profile; functionality is not guaranteed |
| `unverified` | Evidence is missing, stale or incomplete, or requirements need review |
| `incompatible` | At least one detected dependency is missing from the profile |
| `review` | Static security findings need manual review |

With complete PATH coverage, `missing` means unavailable by bare command name via that PATH. Off-PATH files are reported separately and never treated as an automatic replacement. Package versions, all dependency graphs, network permissions and every possible operation are not verified. Filesystem discovery cannot enumerate all Work agent tools or cloud plugins; `coverage.agent_tools_complete` remains false.

## Deployment and limits

Serve **only `public/`**. For remote use, configure both `SKILL2WORK_HTTP_USER` and `SKILL2WORK_HTTP_PASSWORD` in the server environment and use HTTPS. Without both settings, only requests whose remote address is localhost are accepted. Configure authentication at a reverse proxy too: a localhost proxy can otherwise make external traffic appear local. Configure PHP's HTTPS/session handling correctly behind your proxy.

For large profiles, an example PHP configuration is:

```ini
upload_max_filesize = 64M
post_max_size = 96M
memory_limit = 512M
```

Adjust server/proxy body limits as well. Actual memory needs depend on archive/profile complexity. Basic authentication requires HTTPS. Session cookies, CSRF protection, HTML escaping and a restrictive CSP are included. Downloads are session-scoped and expire after one hour; cleanup occurs on later requests for that session. Abandoned temporary files may require OS-level cleanup.

| Input/output | Application limit |
| --- | --- |
| Source ZIP | 30,000,000 bytes compressed; 1,500 entries |
| Expanded source | 35,000,000 bytes total; 15,000,000 bytes per file |
| Skills per archive | 24 |
| Individual output | 500 files; 25,000,000 bytes uncompressed |
| Runtime JSON | 64 MiB, plus schema collection limits |

ZIP validation rejects traversal, symbolic links, duplicate paths, unsupported encryption/compression, ZIP64 and excessive compression ratios. These safeguards are not a malware detector. Generated reports occupy output entries, so a source near the file limit may still exceed it. Platform upload rules and account permissions are separate from these application limits.

The converter itself makes no external API calls and runs no uploaded code. It does not remotely fetch GitHub repositories, install packages, provide a Work CLI, or upload skills to ChatGPT for you.

## Development

```sh
php tests/run.php
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m py_compile probe-skill/scripts/probe.py probe-skill/scripts/checks.py
python3 scripts/build_probe.py
```

The repository includes the generated probe ZIP for convenient import. Rebuild it whenever probe sources change. Tests cover ZIP handling, profiles, migration boundaries, filesystem limits/resume and functional-test outcomes. A passing suite is not a guarantee for every imported skill or Work session.

| Directory | Purpose |
| --- | --- |
| `public/` | Web UI, upload/download handling and CSS |
| `src/` | Archive validation, analysis, profiles and conversion |
| `probe-skill/` | Probe instructions, metadata and Python sources |
| `dist/` | Importable probe ZIP |
| `tests/` | PHP and Python regression tests |
| `scripts/` | Reproducible probe packaging |
| `docs/` | Architecture and maintenance documentation |
