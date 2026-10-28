# Architecture and maintenance

## Converter flow

`public/index.php` validates the request and CSRF token, parses the optional runtime profile, reads the archive, discovers manifests and converts each skill independently. Results and temporary downloads belong to the current PHP session.

- `Archive`: validates the original ZIP central directory before using `ZipArchive` or `PharData`; checks paths, sizes, compression and reader output. Generates ZIPs without extracting uploads into the web root.
- `Profile`: accepts schema 1 and 2 snapshots, validates essential types/limits and attaches coverage/age warnings. Functional evidence is optional for backward compatibility.
- `Analyzer`: scans recognized text/code formats, shell command positions, imports and common package manifests. Produces dependency and security findings without execution.
- `SkillReferences`: migrates recognizable human-facing skill selectors while preserving fenced code and identifying external dependencies.
- `CodexCompatibility`: migrates narrow literal prose instructions and documents retained CLI/slash calls with locations and task-level alternatives. English and German source imperative keywords are accepted; generated guidance is English.
- `Converter`: normalizes supported frontmatter, combines analysis and migration evidence, adds runtime guidance/reports and packages each skill.

All PHP class methods use camelCase. Global PHP functions and variables use snake_case. Comments and project-owned output text are English.

## Probe flow

`probe.py` inventories the actual host where it is executed. PATH discovery is dynamic. A mount-aware filesystem scan gathers metadata and executable candidates; selected virtual-filesystem routines collect bounded system information. Package/extension collectors are independent best-effort phases. The script uses Python standard-library facilities and reviewed local metadata commands rather than installing packages.

The supervisor starts a worker with a deadline. The worker writes partial JSON atomically and maintains a separate private filesystem checkpoint. Resume is validated against roots, mounts and runtime identity. It cannot turn a mutable filesystem into a consistent snapshot.

`checks.py` supplies the common functional-test engine and reviewed runtime adapters. An adapter declares the command, target and expected result; the engine handles launch, deadlines, output and status. To add a runtime, review its executable resolution and test side effects, add a small deterministic adapter, and cover success/failure/timeouts. Never execute arbitrary discovered programs or import every package as an inventory shortcut.

The interface distinguishes inventory availability from functional test evidence. Successful smoke tests establish only their recorded scope. The converter downgrades relevant failed/unverified evidence; it does not solve full package version constraints or every language's project module resolution.

## Known boundaries

Analysis is based on patterns, not a complete parser or execution model. Dynamic commands, indirect imports, unusual quoting, deeply nested shell syntax and implicit dependencies can be missed or misclassified. Review the original source and generated reports. The converter does not understand arbitrary task semantics and cannot safely replace general process APIs with agent instructions.

Profiles are user-supplied, unsigned observations. Full capability coverage, account permissions, plugin authorization, network behavior and future runtime stability cannot be inferred from them. Non-PATH inventory collectors have their own bounds in addition to configurable filesystem/test limits. Review coverage and limitations instead of interpreting absence as proof.

## Packaging and validation

Run the commands in the root README before publishing changes. `scripts/build_probe.py` builds a deterministic ZIP from exactly four source files, with a single `skill2work-runtime-probe/` root. It excludes checkpoints, profiles, caches and development files. The web probe download uses the same four sources, though its ZIP bytes may differ because its archive writer differs.

For manual end-to-end verification, start the local PHP server, download the probe, upload a small source ZIP with a profile, inspect English findings, and download/open the result ZIP. Include both a simple prose migration and a flagged call with options, and confirm that executable source remains unchanged.
