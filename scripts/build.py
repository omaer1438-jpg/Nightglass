"""Build the private Windows package into dist\\Nightglass (local only; never publish it).

    .venv\\Scripts\\python scripts\\build.py

Steps: run PyInstaller (icon: app\\assets\\nightglass.ico from docs\\brand) with nightglass.spec, then copy the
editable catalog (tools\\) and pinned binaries (bin\\) next to Nightglass.exe.
Tool venvs (envs\\) and case data (cases\\) are never copied.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist" / "Nightglass"


def _clear_readonly(func, path, _exc) -> None:
    """ExifTool ships read-only files; make them writable so an old build can be removed."""
    os.chmod(path, stat.S_IWRITE)
    func(path)


def main() -> int:
    # A test run of the exe keeps its data in dist\Nightglass\cases. PyInstaller replaces the
    # whole output folder, so that data is moved aside for the build and put back afterwards.
    kept = DIST.parent / "_cases_kept"
    if kept.exists() and (DIST / "cases").exists():
        print(f"Stopped: {kept} is left from an interrupted build and {DIST / 'cases'} also exists. "
              "Merge or remove one of them by hand; nothing was deleted.")
        return 1
    if (DIST / "cases").exists():
        shutil.move(DIST / "cases", kept)
    try:
        if DIST.exists():
            shutil.rmtree(DIST, onerror=_clear_readonly)
        subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "nightglass.spec"],
                       cwd=ROOT, check=True)
    finally:
        if kept.exists():
            DIST.mkdir(parents=True, exist_ok=True)
            shutil.move(kept, DIST / "cases")
    shutil.copytree(ROOT / "tools", DIST / "tools", dirs_exist_ok=True)
    bin_target = DIST / "bin"
    bin_target.mkdir(exist_ok=True)
    for item in (ROOT / "bin").iterdir():
        if item.is_dir():
            shutil.copytree(item, bin_target / item.name, dirs_exist_ok=True)
        else:
            shutil.copy2(item, bin_target / item.name)
    shutil.copy2(ROOT / "README.md", DIST / "README.md")
    (DIST / "envs").mkdir(exist_ok=True)
    report = ROOT / "build" / "selfcheck.json"
    check = subprocess.run([str(DIST / "Nightglass.exe"), "--self-check", str(report)], cwd=DIST, timeout=120)
    if check.returncode != 0:
        print(f"Self-check FAILED (exit {check.returncode}); see {report}")
        return check.returncode
    print(f"Built {DIST / 'Nightglass.exe'} (self-check passed: {report})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
