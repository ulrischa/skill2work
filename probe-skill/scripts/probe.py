#!/usr/bin/env python3
"""Create a bounded, read-only inventory of the process runtime used by skill2work."""

import argparse
import signal
import importlib.metadata
import importlib.util
import pkgutil
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from checks import annotate_candidates, atomic_json, functional_tests, positive_float, positive_int

SCHEMA = 2
MAX_COMMANDS = 12000
MAX_PACKAGES = 10000
MAX_EXTENSIONS = 2500
MAX_MODULES = 16000
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_SCAN_DIRECTORIES = 1000000
MAX_OFF_PATH_EXECUTABLES = 100000
MAX_SCAN_SECONDS = 600
# Kernel-backed pseudo filesystems require targeted API reads, not recursive scanning.
VIRTUAL_FS_TYPES = {
    "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "securityfs",
    "debugfs", "tracefs", "configfs", "pstore", "mqueue", "hugetlbfs",
    "fusectl", "binfmt_misc", "bpf", "efivarfs", "nsfs", "autofs", "rpc_pipefs",
}
# /run is usually a tmpfs containing sockets, credentials and ephemeral state.
# We report its mount but never inventory file names inside it.
RUNTIME_PSEUDO_ROOTS = ("/proc", "/sys", "/dev", "/run")
BIN_NAMES = {"bin", "sbin", "Scripts", ".bin", "executables", "commands"}
SAFE_ENV_VALUES = ("LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TZ", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE", "PIP_DISABLE_PIP_VERSION_CHECK", "VIRTUAL_ENV_PROMPT")
PATH_ENV_NAMES = ("PATH", "PYTHONPATH", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "NODE_PATH",
                  "VIRTUAL_ENV", "CONDA_PREFIX", "JAVA_HOME", "CARGO_HOME", "RUSTUP_HOME",
                  "GEM_HOME", "GEM_PATH", "PHPRC", "COMPOSER_HOME", "NPM_CONFIG_PREFIX",
                  "XDG_DATA_DIRS", "XDG_CONFIG_HOME", "PERL5LIB", "R_LIBS", "R_LIBS_USER")
SECRET_NAMES = re.compile(r"(PASSWORD|TOKEN|SECRET|PRIVATE|CREDENTIAL|AUTH|COOKIE|SESSION|API_?KEY|SSH_|DATABASE_URL|PROXY|BEARER)", re.I)
SAFE_PACKAGE_TOOLS = {
    "dpkg-query": ["-W", "-f=${binary:Package}\t${Version}\\n"],
    "rpm": ["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\\n"],
    "apk": ["info", "-v"],
    "php": ["-m"],
    "npm": ["ls", "--global", "--depth=0", "--json", "--offline"],
}
SYSTEM_BINARY_DIRS = ("/usr/bin", "/usr/local/bin", "/usr/sbin", "/usr/local/sbin", "/bin", "/sbin")
EXTRA_ROOTS = ("/opt", "/srv", "/usr/local", "/home/oai/share", "/home/oai/skills")
EXTENSION_ROOTS = {
    "vscode": (".vscode/extensions", ".vscode-server/extensions", ".vscode-server-insiders/extensions", ".local/share/code-server/extensions"),
    "codex_skills": (".codex/skills", ".agents/skills"),
    "claude_skills": (".claude/skills",),
    "openclaw_skills": (".openclaw/skills",),
}


def clean_path(value):
    """Redact usernames and ephemeral directory identifiers in displayed paths."""
    value = str(value)
    home = str(Path.home())
    if home and home != "/":
        value = value.replace(home, "~")
    value = re.sub(r"(?i)^(/home|/users)/[^/]+", r"\1/<user>", value)
    value = re.sub(r"^(/tmp|/var/tmp)/[^/]+", r"\1/<temporary>", value)
    return value[:300]


def inspect_executable(directory, name):
    if not name or name.startswith(".") or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+@-]{0,127}", name):
        return False
    try:
        candidate = directory / name
        metadata = candidate.stat()
        return stat.S_ISREG(metadata.st_mode) and os.access(candidate, os.X_OK)
    except (OSError, ValueError):
        return False


def directory_executables(directory, limit):
    result = []
    failed = False
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if len(result) >= limit:
                    return sorted(set(result)), False, "limit"
                if inspect_executable(directory, entry.name):
                    result.append(entry.name)
    except (PermissionError, OSError):
        failed = True
    return sorted(set(result)), not failed, "unreadable" if failed else None


def scan_commands():
    names = {}
    paths = []
    complete = True
    for entry in os.environ.get("PATH", os.defpath).split(os.pathsep):
        # Empty PATH elements refer to CWD. Do not inventory arbitrary user project directories.
        if not entry or not os.path.isabs(entry):
            paths.append({"directory": "<relative-or-empty-PATH-entry>", "checked": False})
            complete = False
            continue
        folder = Path(entry)
        commands, ok, reason = directory_executables(folder, MAX_COMMANDS - len(names))
        paths.append({"directory": clean_path(folder), "checked": ok, "count": len(commands), "limitation": reason})
        complete = complete and ok and reason is None
        for name in commands:
            key = name.lower()
            candidate = {"name": name, "path": clean_path(folder / name),
                         "invocation_path": str(folder / name), "resolved_path": os.path.realpath(folder / name),
                         "invocable_by_name": key not in names, "state": "found_untested",
                         "test_reason": "tests_not_run"}
            if key not in names:
                names[key] = {"available": True, "evidence": "executable_in_PATH",
                              "path": clean_path(folder / name), "candidates": [],
                              "state": "found_untested", "test_reason": "tests_not_run"}
            if not any(c["invocation_path"] == candidate["invocation_path"] for c in names[key]["candidates"]):
                names[key]["candidates"].append(candidate)
        if len(names) >= MAX_COMMANDS:
            complete = False
            break
    return dict(sorted(names.items())), paths, complete


def default_scan_roots():
    """Enumerate likely install locations, not arbitrary user documents."""
    home = Path.home()
    roots = set(EXTRA_ROOTS)
    roots.update((str(home / ".local"), str(home / ".cargo"), str(home / ".rustup"),
                  str(home / ".nvm"), str(home / ".pyenv"), str(home / ".bun"),
                  str(home / ".deno"), str(home / ".codex"), str(home / ".agents"),
                  str(home / ".vscode-server"), str(home / ".config/composer")))
    for name in ("VIRTUAL_ENV", "CONDA_PREFIX", "CARGO_HOME", "RUSTUP_HOME", "NPM_CONFIG_PREFIX",
                 "JAVA_HOME", "COMPOSER_HOME", "GEM_HOME"):
        value = os.environ.get(name, "")
        if value and os.path.isabs(value):
            roots.add(value)
    return sorted(roots)


def read_mount_table(path="/proc/self/mountinfo"):
    """Read mount metadata only. Never export device sources, options or paths to secrets."""
    mounts = []
    issues = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if len(mounts) >= 4096:
                    issues.append("Mount table entry limit reached")
                    break
                left, delimiter, right = line.partition(" - ")
                if not delimiter:
                    continue
                fields, fs_fields = left.split(), right.split()
                if len(fields) < 5 or not fs_fields:
                    continue
                # Linux mountinfo escapes whitespace as octal sequences.
                mount = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4])
                if not mount.startswith("/"):
                    continue
                mounts.append({"mountpoint": mount, "filesystem_type": fs_fields[0]})
    except OSError as error:
        issues.append("Cannot inspect mount table: " + type(error).__name__)
    return mounts, issues


def virtual_filesystem_inventory(mounts):
    """Read bounded, allowlisted kernel metadata; never device nodes or process env."""
    safe_files = {
        "kernel_release": ("/proc/sys/kernel/osrelease", 256),
        "kernel_version": ("/proc/version", 512),
        "memory_summary": ("/proc/meminfo", 4096),
        "process_limits": ("/proc/self/limits", 4096),
        "process_security": ("/proc/self/status", 32768),
        "supported_filesystems": ("/proc/filesystems", 8192),
        "cgroup_memory_limit": ("/sys/fs/cgroup/memory.max", 128),
        "cgroup_cpu_limit": ("/sys/fs/cgroup/cpu.max", 128),
        "cgroup_process_limit": ("/sys/fs/cgroup/pids.max", 128),
        "distribution": ("/etc/os-release", 2048),
    }
    result = {"mounts": [], "kernel": {}, "device_types": {}, "sys_classes": [],
              "notes": ["No arbitrary /proc process data, /dev device content, or /run credentials are read."]}
    for item in mounts[:256]:
        mount = item["mountpoint"]
        kind = item["filesystem_type"]
        result["mounts"].append({"path": clean_path(mount), "type": kind,
                                  "scan_method": "kernel_metadata" if kind in VIRTUAL_FS_TYPES or mount in ("/proc", "/sys", "/dev") else
                                                 "runtime_metadata" if mount == "/run" else "filesystem"})
    for key, (name, limit) in safe_files.items():
        try:
            with open(name, "r", encoding="utf-8", errors="replace") as handle:
                content = handle.read(limit + 1)
            if len(content) > limit:
                continue
            if key == "memory_summary":
                allow = ("MemTotal:", "MemAvailable:", "SwapTotal:")
                result["kernel"][key] = [x for x in content.splitlines() if x.startswith(allow)]
            elif key == "distribution":
                result["kernel"][key] = [x for x in content.splitlines()
                                         if x.startswith(("ID=", "VERSION_ID=", "PRETTY_NAME="))]
            elif key == "process_security":
                allow = ("NoNewPrivs:", "Seccomp:", "Seccomp_filters:", "CapEff:", "Threads:")
                result["kernel"][key] = [x for x in content.splitlines() if x.startswith(allow)]
            else:
                result["kernel"][key] = content.strip()[:4096]
        except OSError:
            continue
    for folder, label in (("/dev", "device_types"), ("/sys/class", "sys_classes")):
        try:
            with os.scandir(folder) as entries:
                if label == "device_types":
                    counts = {"character": 0, "block": 0, "socket": 0, "other": 0}
                    for i, entry in enumerate(entries):
                        if i >= 5000:
                            result["notes"].append("Device type count truncated at 5000 entries")
                            break
                        try:
                            mode = entry.stat(follow_symlinks=False).st_mode
                        except OSError:
                            continue
                        kind = "character" if stat.S_ISCHR(mode) else "block" if stat.S_ISBLK(mode) else "socket" if stat.S_ISSOCK(mode) else "other"
                        counts[kind] += 1
                    result["device_types"] = counts
                else:
                    result["sys_classes"] = sorted(entry.name for entry in entries if entry.name and not entry.name.startswith("."))[:100]
        except OSError:
            continue
    return result


def scan_additional_executables(known, deep=False, roots=None, max_dirs=MAX_SCAN_DIRECTORIES,
                                max_seconds=MAX_SCAN_SECONDS, mounts=None, checkpoint=None, resume=False):
    """Read-only metadata inventory of accessible directories, including regular mounts.

    Full mode recursively walks /, without following directory symlinks. The mount
    table decides which *kernel-backed virtual trees* must be skipped; ordinary
    installations, personal/hidden folders, /srv and regular extra mounts are not
    hardcoded exclusions. Never open discovered executable contents.
    """
    mounts, mount_issues = (read_mount_table() if mounts is None else (mounts, []))
    virtual_mounts = {m["mountpoint"] for m in mounts if m["filesystem_type"] in VIRTUAL_FS_TYPES}
    # /dev can also be mounted as tmpfs. Skip it and other kernel/runtime trees.
    # /run is commonly a tmpfs containing ephemeral credentials and sockets.
    virtual_mounts.update(RUNTIME_PSEUDO_ROOTS)
    # Only use the most specific scan roots in targeted mode; full mode covers all.
    candidates = roots if roots is not None else (["/"] if deep else default_scan_roots())
    start = time.monotonic()
    scanned = 0
    off_path = {}
    scanned_roots = []
    issues = list(mount_issues)
    skipped = []
    manifests = {"skill": [], "plugin": [], "hooks": []}
    manifest_limits_reached = False
    inaccessible = 0
    scanned_mounts = set()
    truncated = False
    limit_reason = None
    # Metadata only; reject files with names that cannot be used as CLI commands.
    def inspect_directory(folder):
        nonlocal truncated, limit_reason, inaccessible
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    if len(off_path) >= MAX_OFF_PATH_EXECUTABLES:
                        truncated, limit_reason = True, "executable_record_limit"
                        break
                    name = entry.name
                    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+@-]{0,127}", name):
                        continue
                    try:
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        mode = entry.stat(follow_symlinks=False).st_mode
                        if not (mode & 0o111) or not os.access(entry.path, os.X_OK):
                            continue
                    except OSError:
                        continue
                    known_paths = {c.get("invocation_path") for c in known.get(name.lower(), {}).get("candidates", [])}
                    if entry.path not in known_paths:
                        path = clean_path(entry.path)
                        off_path.setdefault((name, entry.path), {"name": name, "path": path,
                            "invocation_path": entry.path, "resolved_path": os.path.realpath(entry.path),
                            "invocable_by_name": False, "state": "found_untested",
                            "test_reason": "no_reviewed_test_for_this_path"})
        except OSError:
            inaccessible += 1

    mountpoints = {m["mountpoint"] for m in mounts}
    pending = [str(p) for p in sorted({Path(item) for item in candidates}, key=str)]
    identity = {"roots": pending[:], "mounts": mounts, "python": sys.executable,
                "path": os.environ.get("PATH", ""), "boot": ""}
    try:
        identity["boot"] = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        pass
    if resume and checkpoint and Path(checkpoint).exists():
        state = json.loads(Path(checkpoint).read_text())
        if state.get("identity") != identity:
            raise ValueError("Checkpoint belongs to a different runtime or scan scope")
        pending = state["pending"]
        off_path = {(x["name"], x.get("invocation_path", x["path"])): x for x in state["executables"]}
        manifests = state["manifests"]
        scanned = state["scanned"]
        inaccessible = state["inaccessible"]
        skipped = state["skipped"]
        manifest_limits_reached = state["manifest_limits_reached"]
    initial_scanned = scanned
    last_save = time.monotonic()
    def save_state():
        if checkpoint:
            atomic_json(Path(checkpoint), {"identity": identity, "pending": pending,
                "executables": list(off_path.values()), "manifests": manifests,
                "scanned": scanned, "inaccessible": inaccessible, "skipped": skipped,
                "manifest_limits_reached": manifest_limits_reached})
    while pending:
        if scanned - initial_scanned >= max_dirs or time.monotonic() - start >= max_seconds:
            truncated = True
            limit_reason = "directory_limit" if scanned - initial_scanned >= max_dirs else "duration_limit"
            break
        current = pending[-1]
        if any(current == v or current.startswith(v + "/") for v in virtual_mounts):
            pending.pop()
            if len(skipped) < 100:
                skipped.append({"path": clean_path(current), "reason": "virtual_or_runtime_mount"})
            continue
        folder = Path(current)
        if folder.is_symlink():
            pending.pop()
            continue
        try:
            with os.scandir(folder) as entries:
                children, filenames = [], set()
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False):
                        children.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        filenames.add(entry.name)
            inspect_directory(folder)
            if truncated:
                break
            for filename, group in (("SKILL.md", "skill"), ("plugin.json", "plugin"), ("hooks.json", "hooks")):
                if filename in filenames:
                    value = clean_path(folder / filename)
                    if value not in manifests[group]:
                        manifests[group].append(value)
            pending.pop()
            pending.extend(sorted(children, reverse=True))
            scanned += 1
            if current in mountpoints:
                scanned_mounts.add(current)
        except OSError:
            inaccessible += 1
            pending.pop()
        if time.monotonic() - last_save >= 5:
            save_state()
            last_save = time.monotonic()
    scanned_roots = [clean_path(x) for x in candidates]
    save_state()
    if truncated:
        issues.append("Filesystem scan truncated: " + (limit_reason or "unknown limit"))
    if inaccessible:
        issues.append("Filesystem paths inaccessible: " + str(inaccessible))
    if manifest_limits_reached:
        issues.append("Candidate skill/plugin manifests capped at 3000 per type")
    # 'complete' only means the allowed ordinary directory tree was exhausted.
    complete = not truncated and inaccessible == 0 and not mount_issues and not manifest_limits_reached
    report = {"mode": "mount-aware-recursive-root" if deep else "mount-aware-installation-roots",
              "directories_scanned": scanned, "directory_limit": max_dirs,
              "duration_seconds": round(time.monotonic() - start, 3),
              "duration_limit_seconds": max_seconds,
              "truncated": truncated, "truncation_reason": limit_reason,
              "inaccessible_directory_count": inaccessible,
              "excluded_paths_sample": skipped,
              "mount_count": len(mounts), "regular_mounts_seen": len(scanned_mounts),
              "virtual_mounts_skipped": len(virtual_mounts),
              "candidate_manifests": manifests,
              "candidate_manifest_limit_reached": manifest_limits_reached,
              "symlinks_followed": False, "cross_device_mounts": True,
              "contents_read": False, "complete": complete}
    return list(off_path.values()), scanned_roots, issues, report

def python_inventory():
    distributions = []
    modules = {}
    issues = []
    module_candidates = set()
    stdlib_candidates = set(getattr(sys, "stdlib_module_names", ()))
    try:
        for package in importlib.metadata.distributions():
            if len(distributions) >= MAX_PACKAGES:
                issues.append("Python package list truncated.")
                break
            name = package.metadata.get("Name", "")
            version = package.version or ""
            if name and len(name) < 150:
                distributions.append({"name": name, "version": str(version)[:100]})
            top_level = package.read_text("top_level.txt") or ""
            candidates = [line.strip() for line in top_level.splitlines()]
            if not candidates:
                # RECORD-based fallback for wheels without top_level.txt.
                files = package.files or ()
                candidates = [str(file).split("/", 1)[0].removesuffix(".py") for file in files[:2000]]
            for module in candidates:
                if len(modules) >= MAX_MODULES:
                    issues.append("Python module list truncated.")
                    break
                if re.fullmatch(r"[A-Za-z_]\w*", module):
                    module_candidates.add(module)
    except (OSError, ValueError, TypeError) as exc:
        issues.append("Python package inventory incomplete: " + type(exc).__name__)
    # Include modules visible to the current interpreter even without package metadata.
    for folder in sys.path[:100]:
        if not folder or not os.path.isabs(folder) or not Path(folder).is_dir():
            continue
        try:
            for entry in pkgutil.iter_modules([folder]):
                if len(module_candidates) >= MAX_MODULES:
                    issues.append("Module candidate inventory truncated.")
                    break
                module_candidates.add(entry.name)
        except (OSError, ValueError):
            issues.append("Could not enumerate module directory " + clean_path(folder))
    # Find specs without importing the modules or running their code.
    for module in sorted(module_candidates | stdlib_candidates):
        if len(modules) >= MAX_MODULES:
            issues.append("Python import specification inventory truncated.")
            break
        if not re.fullmatch(r"[A-Za-z_]\w*", module):
            continue
        try:
            spec = importlib.util.find_spec(module)
            if spec is not None:
                modules[module] = {"available": True, "evidence": "import_spec_without_import"}
        except (ImportError, AttributeError, ValueError, OSError, ModuleNotFoundError):
            pass
    return dict(sorted(modules.items())), sorted(distributions, key=lambda x: x["name"].lower()), issues


def trusted_tool(name):
    candidate = shutil.which(name)
    if not candidate:
        return None
    try:
        resolved = Path(candidate).resolve(strict=True)
        roots = [Path(path).resolve() for path in SYSTEM_BINARY_DIRS if Path(path).is_dir()]
        if any(resolved == root / resolved.name for root in roots):
            return str(resolved)
    except (OSError, RuntimeError):
        pass
    return None


def run_inventory_tool(name, arguments, max_chars=350_000):
    executable = trusted_tool(name)
    if not executable:
        return None, "unavailable_or_not_trusted_system_binary"
    try:
        result = subprocess.run([executable, *arguments], capture_output=True, text=True,
                                errors="replace", timeout=8, check=False,
                                env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C", "HOME": str(Path.home())})
        output = result.stdout
        if len(output) > max_chars:
            return output[:max_chars], "output_truncated"
        if result.returncode not in (0, 1):
            return output, "exit_" + str(result.returncode)
        return output, None
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, type(exc).__name__


def system_packages():
    for name in ("dpkg-query", "rpm", "apk"):
        output, issue = run_inventory_tool(name, SAFE_PACKAGE_TOOLS[name], max_chars=650_000)
        if output is None:
            continue
        entries = []
        for line in output.splitlines()[:MAX_PACKAGES]:
            if name == "apk":
                parts = line.rsplit("-", 1)
            else:
                parts = line.split("\t", 1)
            if len(parts) == 2 and parts[0]:
                entries.append({"name": parts[0][:120], "version": parts[1][:120]})
        if len(output.splitlines()) > MAX_PACKAGES:
            issue = "entry_limit"
        return name, entries, issue
    return None, [], "no_supported_system_package_database"


def additional_runtime_metadata():
    extensions = []
    php_output, php_issue = run_inventory_tool("php", ["-m"], 50_000)
    if php_output is not None:
        extensions = sorted(set(line.strip() for line in php_output.splitlines()
                                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", line.strip())))
    npm_packages = []
    npm_output, npm_issue = run_inventory_tool("npm", SAFE_PACKAGE_TOOLS["npm"], 150_000)
    if npm_output:
        try:
            items = json.loads(npm_output).get("dependencies", {})
            if isinstance(items, dict):
                npm_packages = [{"name": name[:160], "version": str(value.get("version", ""))[:100]}
                                for name, value in list(items.items())[:MAX_PACKAGES]
                                if isinstance(value, dict)]
        except (json.JSONDecodeError, AttributeError):
            npm_issue = "invalid_json"
    return extensions, php_issue, npm_packages, npm_issue


def extension_inventory():
    home = Path.home()
    roots = {key: [home / part for part in paths] for key, paths in EXTENSION_ROOTS.items()}
    roots["shared_skills"] = [Path("/home/oai/skills"), Path("/opt/skills"), Path("/srv/skills")]
    groups = {}
    issues = []
    for group, folders in roots.items():
        plugins = []
        for folder in folders:
            try:
                if not folder.is_dir() or folder.is_symlink():
                    continue
                children = sorted(folder.iterdir(), key=lambda x: x.name.lower())
            except OSError:
                issues.append("Could not list extensions in " + clean_path(folder))
                continue
            for child in children[:MAX_EXTENSIONS]:
                if len(plugins) >= MAX_EXTENSIONS:
                    issues.append("Extension inventory truncated for " + group)
                    break
                if not child.is_dir() or child.is_symlink():
                    continue
                meta = {"name": child.name[:200], "source": clean_path(folder)}
                # Only read standard metadata, never SKILL.md body or executable code.
                if group == "vscode":
                    manifest = child / "package.json"
                    try:
                        if manifest.is_file() and manifest.stat().st_size <= 100_000:
                            item = json.loads(manifest.read_text(encoding="utf-8"))
                            meta["name"] = str(item.get("publisher", "") + "." + item.get("name", "")).strip(".")[:200] or meta["name"]
                            meta["version"] = str(item.get("version", ""))[:100]
                    except (OSError, ValueError, TypeError):
                        pass
                else:
                    meta["has_skill_manifest"] = (child / "SKILL.md").is_file()
                    if not meta["has_skill_manifest"] and group == "shared_skills":
                        continue
                plugins.append(meta)
            if len(children) > MAX_EXTENSIONS:
                issues.append("Extension directory truncated: " + clean_path(folder))
        groups[group] = plugins
    return groups, issues



def node_package_manifests():
    roots = [Path("/usr/local/lib/node_modules"), Path("/usr/lib/node_modules"),
             Path.home() / ".local/lib/node_modules"]
    nvm = Path.home() / ".nvm/versions/node"
    if nvm.is_dir():
        roots.extend(root / "lib/node_modules" for root in sorted(nvm.iterdir())[:40] if root.is_dir())
    packages = []
    issues = []
    for root in roots:
        if not root.is_dir() or root.is_symlink():
            continue
        try:
            dirs = sorted(root.iterdir())[:300]
            for folder in dirs:
                if folder.name.startswith("@") and folder.is_dir() and not folder.is_symlink():
                    candidates = sorted(folder.iterdir())[:150]
                else:
                    candidates = [folder]
                for candidate in candidates:
                    manifest = candidate / "package.json"
                    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 100_000:
                        continue
                    try:
                        data = json.loads(manifest.read_text(encoding="utf-8"))
                        packages.append({"name": str(data.get("name", candidate.name))[:160],
                                         "version": str(data.get("version", ""))[:80],
                                         "install_root": clean_path(root)})
                    except (OSError, ValueError, TypeError):
                        issues.append("Node package metadata unreadable: " + clean_path(manifest))
        except OSError:
            issues.append("Node package directory inaccessible: " + clean_path(root))
    return packages[:MAX_PACKAGES], issues


def composer_package_manifests():
    paths = [Path.home() / ".config/composer/vendor/composer/installed.json",
             Path.home() / ".composer/vendor/composer/installed.json"]
    packages = []
    for path in paths:
        try:
            if not path.is_file() or path.stat().st_size > 2_000_000:
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            records = data.get("packages", []) if isinstance(data, dict) else data
            if isinstance(records, list):
                for record in records[:MAX_PACKAGES]:
                    if isinstance(record, dict) and isinstance(record.get("name"), str):
                        packages.append({"name": record["name"][:160], "version": str(record.get("version", ""))[:80]})
        except (OSError, ValueError, TypeError):
            pass
    return packages[:MAX_PACKAGES]


def runtime_versions():
    commands = {"python3": ["--version"], "php": ["--version"],
                "node": ["--version"], "git": ["--version"],
                "ffmpeg": ["-version"], "pandoc": ["--version"],
                "java": ["-version"], "gcc": ["--version"],
                "docker": ["--version"], "ruby": ["--version"],
                "go": ["version"], "npm": ["--version"]}
    versions = {"current_python": platform.python_version()}
    for command, arguments in commands.items():
        output, issue = run_inventory_tool(command, arguments, 2000)
        if output:
            versions[command] = output.splitlines()[0][:180]
        elif issue is None:
            versions[command] = "<no-version-output>"
    return versions

def environment_inventory():
    vars_by_name = sorted(key for key in os.environ if len(key) < 200)
    safe = {}
    for key in SAFE_ENV_VALUES:
        if key in os.environ and not SECRET_NAMES.search(key):
            value = os.environ[key]
            if len(value) < 120 and not any(ch in value for ch in "\r\n\x00"):
                safe[key] = value
    paths = {}
    for key in PATH_ENV_NAMES:
        if key in os.environ and not SECRET_NAMES.search(key):
            parts = [part for part in os.environ[key].split(os.pathsep) if part]
            paths[key] = [clean_path(part) if os.path.isabs(part) else "<relative-path>" for part in parts[:120]]
    return {"names_only": vars_by_name, "safe_values": safe, "path_values_redacted": paths,
            "redaction": "Secret and arbitrary environment variable values intentionally omitted."}


def writable_temp_feature():
    try:
        with tempfile.TemporaryDirectory(prefix="skill2work-probe-") as directory:
            path = Path(directory) / "test.txt"
            path.write_text("test", encoding="utf-8")
            return path.read_text(encoding="utf-8") == "test"
    except OSError:
        return False


def gather(deep_scan=False, options=None):
    options = options or {}
    stage_issues = []
    def collect(label, callback, fallback):
        try:
            return callback()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            stage_issues.append(label + ": " + type(error).__name__ + "; inventory incomplete")
            return fallback
    commands, path_dirs, path_complete = scan_commands()
    destination = options.get("destination")
    if destination:
        atomic_json(destination, {"schema_version": SCHEMA, "source": "skill2work-probe",
            "timestamp": datetime.now(timezone.utc).isoformat(), "commands": commands,
            "python_modules": {}, "features": {}, "inventory": {},
            "coverage": {"path_inventory_complete": path_complete,
                "python_module_metadata_complete": False, "agent_tools_complete": False},
            "limitations": ["Interrupted or still running; only PATH stage completed."],
            "partial": True})
    mounts, mount_issues = read_mount_table()
    extra, scanned_roots, root_issues, filesystem_scan = scan_additional_executables(commands, deep=deep_scan, mounts=mounts,
        max_dirs=options.get("max_directories", MAX_SCAN_DIRECTORIES),
        max_seconds=options.get("scan_seconds", MAX_SCAN_SECONDS),
        checkpoint=options.get("checkpoint"), resume=options.get("resume", False))
    modules, python_packages, python_issues = collect("Python metadata", python_inventory, ({}, [], ["Python inventory unavailable"]))
    package_manager, os_packages, os_issue = collect("System packages", system_packages, (None, [], "unavailable"))
    php_extensions, php_issue, npm_packages, npm_issue = collect("Runtime metadata", additional_runtime_metadata, ([], "unavailable", [], "unavailable"))
    user_extensions, extension_issues = collect("Extensions", extension_inventory, ({}, ["Extension inventory unavailable"]))
    node_manifests, node_issues = collect("Node manifests", node_package_manifests, ([], ["Node manifests unavailable"]))
    composer_manifests = collect("Composer manifests", composer_package_manifests, [])
    issues = stage_issues + mount_issues + node_issues + root_issues + python_issues + extension_issues
    for label, issue in (("system packages", os_issue), ("PHP extensions", php_issue), ("global npm packages", npm_issue)):
        if issue:
            issues.append(label + ": " + issue)
    result = {
        "schema_version": SCHEMA,
        "source": "skill2work-probe",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "python_version": platform.python_version(),
        "commands": commands,
        "python_modules": modules,
        "features": {"python_script_execution": True, "temporary_file_write": writable_temp_feature()},
        "inventory": {
            "path_directories": path_dirs,
            "additional_scan_roots": scanned_roots,
            "filesystem_scan": filesystem_scan,
            "virtual_filesystems": collect("Virtual metadata", lambda: virtual_filesystem_inventory(mounts), {}),
            "executables_outside_path": extra,
            "environment_variables": environment_inventory(),
            "python_distributions": python_packages,
            "system_package_manager": package_manager,
            "system_packages": os_packages,
            "php_extensions": php_extensions,
            "global_npm_packages": npm_packages,
            "global_npm_package_manifests": node_manifests,
            "global_composer_packages": composer_manifests,
            "runtime_versions": collect("Runtime versions", runtime_versions, {}),
            "installed_extensions": user_extensions,
            "python_paths": [clean_path(x) for x in sys.path if x and os.path.isabs(x)][:100],
        },
        "coverage": {
            "path_inventory_complete": path_complete,
            "python_module_metadata_complete": not python_issues,
            "system_package_inventory_complete": os_issue is None,
            "agent_tools_complete": False,
            "off_path_inventory_complete": filesystem_scan["complete"],
        },
        "limitations": [
            "This is an inventory of the Python process and its reachable filesystem, NOT a complete list of ChatGPT Work tools or plugins.",
            "Installed binaries and package metadata do not establish successful execution, permissions or API access.",
            "Filesystem discovery is mount-aware and bounded. --deep-scan traverses accessible ordinary directories and mounts from /, without opening arbitrary file contents. Virtual kernel mounts and /run are inventoried via targeted metadata.",
            "Neither scan mode establishes complete program coverage: permissions, symlinks, executable-name filtering, virtual filesystems, mount access and limits may hide programs. A blocked I/O operation cannot always be interrupted by the scan timer.",
            "Paths can be sensitive. Display paths are redacted, but invocation_path, resolved_path and test executable fields retain exact paths for review and invocation.",
            "Variable values (except selected harmless locale settings) and file contents are not exported.",
            "The JSON is passed to ChatGPT when generated there; sharing is governed by ChatGPT's data handling and account settings.",
            "Tool/plugin visibility must be documented separately by the assistant; a Python process cannot discover all agent tools.",
            "Inventory initiates no network requests or installations. Reviewed smoke tests run; explicitly requested imports execute installed package code and are not network-isolated.",
        ] + issues,
    }
    result["limitations"].extend(x for x in stage_issues if x not in result["limitations"])
    result["probe_version"] = "1.6"
    result["configuration"] = {key: value for key, value in options.items() if key not in ("destination", "checkpoint")}
    if destination:
        atomic_json(destination, result)
    result["functional_tests"] = functional_tests(options.get("test_timeout", 5), options.get("test_seconds", 120), options.get("python_modules", []), options.get("node_modules", []))
    annotate_candidates(commands, extra, result["functional_tests"])
    return result


def main():
    parser = argparse.ArgumentParser(description="Inventory the current runtime without reading file contents or secrets")
    parser.add_argument("output", nargs="?", help="Output filename (default: /mnt/data or current folder)")
    parser.add_argument("--deep-scan", action="store_true",
                        help="Mount-aware traversal from /; skips kernel virtual trees, symlinks and /run")
    parser.add_argument("--scan-seconds", type=positive_float, default=600)
    parser.add_argument("--max-directories", type=positive_int, default=1000000)
    parser.add_argument("--max-executables", type=positive_int, default=100000)
    parser.add_argument("--test-timeout", type=positive_float, default=5)
    parser.add_argument("--test-seconds", type=positive_float, default=120)
    parser.add_argument("--python-module", action="append", default=[])
    parser.add_argument("--node-module", action="append", default=[])
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    global MAX_OFF_PATH_EXECUTABLES
    MAX_OFF_PATH_EXECUTABLES = arguments.max_executables
    if arguments.output:
        destination = Path(arguments.output)
    elif Path("/mnt/data").is_dir() and os.access("/mnt/data", os.W_OK):
        destination = Path("/mnt/data/skill2work-runtime.json")
    else:
        destination = Path.cwd() / "skill2work-runtime.json"
    options = {"destination": destination, "checkpoint": str(destination) + ".checkpoint.json",
        "resume": arguments.resume, "scan_seconds": arguments.scan_seconds,
        "max_directories": arguments.max_directories, "max_executables": arguments.max_executables,
        "test_timeout": arguments.test_timeout, "test_seconds": arguments.test_seconds,
        "python_modules": arguments.python_module, "node_modules": arguments.node_module}
    if not arguments.worker:
        worker = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], "--worker"],
                                  start_new_session=True)
        try:
            code = worker.wait(timeout=arguments.scan_seconds + arguments.test_seconds + 120)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            if os.name == "posix":
                os.killpg(worker.pid, signal.SIGKILL)
            else:
                worker.kill()
            worker.wait()
            if destination.exists():
                partial = json.loads(destination.read_text())
                partial["partial"] = True
                partial.setdefault("limitations", []).append("Supervisor interrupted worker; resume from checkpoint if present.")
                atomic_json(destination, partial)
            print("Interrupted; existing profile/checkpoint retained.")
            return
        if code:
            raise SystemExit(code)
        return
    inventory = gather(deep_scan=arguments.deep_scan, options=options)
    atomic_json(destination, inventory)
    print("Profile:", destination)
    print("Programs:", len(inventory["commands"]), "Python modules:", len(inventory["python_modules"]))
    print("Python packages:", len(inventory["inventory"]["python_distributions"]), "extensions:",
          sum(len(group) for group in inventory["inventory"]["installed_extensions"].values()))
    print("Filesystem directories inspected:", inventory["inventory"]["filesystem_scan"]["directories_scanned"])
    print("Limitations:", len(inventory["limitations"]), "inventory metadata and scoped functional tests")


if __name__ == "__main__":
    main()
