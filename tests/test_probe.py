"""Tests for read-only inventory and redaction logic."""

import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROBE = Path(__file__).resolve().parent.parent / "probe-skill/scripts/probe.py"
spec = importlib.util.spec_from_file_location("skill2work_runtime_probe", PROBE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeTests(unittest.TestCase):
    def test_scans_all_executable_names_without_executing(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / "executed.txt"
            executable = Path(folder) / "unlisted-custom-utility"
            executable.write_text("#!/bin/sh\ntouch " + str(marker) + "\n", encoding="utf-8")
            executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            with patch.dict(os.environ, {"PATH": folder}):
                commands, paths, complete = probe.scan_commands()
            self.assertTrue(complete)
            self.assertIn("unlisted-custom-utility", commands)
            self.assertEqual(commands["unlisted-custom-utility"]["evidence"], "executable_in_PATH")
            self.assertFalse(marker.exists(), "Inventory must not run discovered programs")
            self.assertEqual(paths[0]["count"], 1)

    def test_missing_path_marks_inventory_incomplete(self):
        with patch.dict(os.environ, {"PATH": "/does/not/exist/skill2work"}):
            _, _, complete = probe.scan_commands()
        self.assertFalse(complete)

    def test_scrubs_environment_values(self):
        with patch.dict(os.environ, {"S2W_API_TOKEN": "secret_value_should_not_leak",
                                          "UNSAFE_PASSWORD": "another_private_value",
                                          "LANG": "de_DE.UTF-8"}):
            data = probe.environment_inventory()
        text = str(data)
        self.assertIn("S2W_API_TOKEN", text)
        self.assertNotIn("secret_value_should_not_leak", text)
        self.assertNotIn("another_private_value", text)
        self.assertEqual(data["safe_values"]["LANG"], "de_DE.UTF-8")

    def test_home_path_redacted(self):
        result = probe.clean_path(str(Path.home() / "private/test"))
        self.assertTrue(result.startswith("~/"))
        self.assertNotIn(str(Path.home()), result)

    def test_recursive_scan_finds_nested_binary_and_skips_symlinks(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            binary = root / "app" / "deep" / "nested" / "bin"
            binary.mkdir(parents=True)
            script = binary / "deep-tool"
            script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            script.chmod(script.stat().st_mode | stat.S_IXUSR)
            (root / "symlink").symlink_to(binary, target_is_directory=True)
            result, roots, issues, coverage = probe.scan_additional_executables(
                {}, roots=[root], max_dirs=100, max_seconds=3)
            names = {item["name"] for item in result}
            self.assertIn("deep-tool", names)
            self.assertEqual(coverage["mode"], "mount-aware-installation-roots")
            self.assertFalse(coverage["symlinks_followed"])
            self.assertFalse(coverage["contents_read"])
            self.assertTrue(coverage["complete"])
            self.assertGreaterEqual(coverage["directories_scanned"], 4)

    def test_recursive_scan_limit_is_recorded(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "first" / "second").mkdir(parents=True)
            _files, _roots, issues, coverage = probe.scan_additional_executables(
                {}, roots=[root], max_dirs=1, max_seconds=3)
            self.assertTrue(coverage["truncated"])
            self.assertTrue(any("limit" in x for x in issues))

    def test_module_detection_does_not_require_import(self):
        modules, packages, errors = probe.python_inventory()
        self.assertIn("json", modules)
        self.assertTrue(packages)
        self.assertIn("import_spec_without_import", modules["json"]["evidence"])
        self.assertIsInstance(errors, list)


if __name__ == "__main__":
    unittest.main()

# Extra mount-aware regression cases are added below via a second TestCase to
# keep the original test expectations stable for earlier probe versions.
class MountAwareTests(unittest.TestCase):
    def test_mount_table_decodes_escaped_paths_and_not_sources(self):
        with tempfile.TemporaryDirectory() as folder:
            info = Path(folder) / "mountinfo"
            info.write_text("12 1 0:1 / /proc rw - proc proc rw\n"
                            "13 1 0:2 / /mnt/my\\040tools rw - ext4 /dev/very-private-volume rw\n")
            mounts, issues = probe.read_mount_table(str(info))
            self.assertEqual(issues, [])
            self.assertEqual(mounts[1]["mountpoint"], "/mnt/my tools")
            self.assertNotIn("very-private", str(mounts))

    def test_virtual_mount_is_skipped_not_regular_mount(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            pseudo = root / "proc"
            real = root / "srv" / "app" / "custom"
            pseudo.mkdir()
            real.mkdir(parents=True)
            for path in (pseudo / "fake-kernel", real / "my-tool"):
                path.write_text("#!/bin/sh\nexit 0\n")
                path.chmod(0o755)
            mounts = [{"mountpoint": str(pseudo), "filesystem_type": "proc"},
                      {"mountpoint": str(real), "filesystem_type": "ext4"}]
            results, _, _, coverage = probe.scan_additional_executables(
                {}, deep=True, roots=[root], mounts=mounts, max_dirs=100, max_seconds=10)
            self.assertIn("my-tool", {item["name"] for item in results})
            self.assertNotIn("fake-kernel", {item["name"] for item in results})
            self.assertTrue(coverage["cross_device_mounts"])
            self.assertTrue(coverage["complete"])

    def test_manifest_candidates_are_discovered_without_reading_contents(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            subdir = root / "custom-app" / ".agents" / "skills" / "hello"
            subdir.mkdir(parents=True)
            (subdir / "SKILL.md").write_text("private wording which must not be read")
            _, _, _, coverage = probe.scan_additional_executables(
                {}, roots=[root], mounts=[], max_dirs=100, max_seconds=5)
            self.assertEqual(len(coverage["candidate_manifests"]["skill"]), 1)
            self.assertNotIn("private wording", str(coverage))
            self.assertTrue(coverage["complete"])

    def test_deep_scan_preserves_truncation_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "level1" / "level2").mkdir(parents=True)
            _, _, issues, coverage = probe.scan_additional_executables(
                {}, deep=True, roots=[root], mounts=[], max_dirs=1, max_seconds=5)
            self.assertFalse(coverage["complete"])
            self.assertEqual(coverage["truncation_reason"], "directory_limit")
            self.assertTrue(issues)
