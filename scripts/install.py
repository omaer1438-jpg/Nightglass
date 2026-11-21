"""Install the packaged build for this Windows user (local only; never publish it).

    .venv\\Scripts\\python scripts\\build.py
    .venv\\Scripts\\python scripts\\install.py

Copies dist\\Nightglass to %LOCALAPPDATA%\\Programs\\Nightglass, copies the tool environments
(envs\\) from this checkout, and adds Desktop and Start menu shortcuts. The installed cases\\
folder is never touched. The app folder stays out of the Desktop on purpose: the Desktop is often
synced to OneDrive, and case data must stay on this computer. Only the shortcut goes there.
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
TARGET = Path(os.environ["LOCALAPPDATA"]) / "Programs" / "Nightglass"
KEEP = {"cases", "envs"}

# Paths reach PowerShell through environment variables, never through the command text.
SHORTCUTS = r"""
$shell = New-Object -ComObject WScript.Shell
foreach ($folder in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs'))) {
    $link = $shell.CreateShortcut((Join-Path $folder 'Nightglass.lnk'))
    $link.TargetPath = $env:NG_EXE
    $link.WorkingDirectory = $env:NG_DIR
    $link.IconLocation = "$env:NG_EXE,0"
    $link.Description = 'Nightglass private OSINT workbench'
    $link.Save()
    Write-Output (Join-Path $folder 'Nightglass.lnk')
}
"""


def _clear_readonly(func, path, _exc) -> None:
    """ExifTool ships read-only files; make them writable so the old copy can be replaced."""
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _replace(source: Path, target: Path) -> None:
    if target.is_dir():
        shutil.rmtree(target, onerror=_clear_readonly)
    elif target.exists():
        target.unlink()
    if source.is_dir():
        shutil.copytree(source, target)
    else:
        shutil.copy2(source, target)


def main() -> int:
    if not (DIST / "Nightglass.exe").is_file():
        print("No build found. Run scripts\\build.py first.")
        return 1
    TARGET.mkdir(parents=True, exist_ok=True)
    try:
        for item in DIST.iterdir():
            if item.name not in KEEP:
                _replace(item, TARGET / item.name)
    except PermissionError as error:
        print(f"Close Nightglass first, then run this again ({error.filename}).")
        return 1
    (TARGET / "envs").mkdir(exist_ok=True)
    for env in sorted((ROOT / "envs").iterdir()) if (ROOT / "envs").is_dir() else []:
        if (env / "Scripts" / "python.exe").is_file():
            _replace(env, TARGET / "envs" / env.name)
            print(f"Tool environment: {env.name}")
    exe = TARGET / "Nightglass.exe"
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", SHORTCUTS],
        env={**os.environ, "NG_EXE": str(exe), "NG_DIR": str(TARGET)},
        capture_output=True, text=True, check=False,
    )
    print(result.stdout.strip() or result.stderr.strip())
    print(f"Installed {exe}")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
