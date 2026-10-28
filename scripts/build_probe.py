#!/usr/bin/env python3
"""Build the importable probe ZIP from tracked sources deterministically."""
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ("SKILL.md", "agents/openai.yaml", "scripts/probe.py", "scripts/checks.py")


def main():
    output = ROOT / "dist" / "skill2work-runtime-probe.zip"
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in FILES:
            info = zipfile.ZipInfo("skill2work-runtime-probe/" + name, (2026, 10, 28, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o100755 if name.endswith(".py") else 0o100644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, (ROOT / "probe-skill" / name).read_bytes())
    print(output)


if __name__ == "__main__":
    main()
