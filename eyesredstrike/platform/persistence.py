"""Inspection des points de persistance : registry (Windows), cron/systemd (Linux), launchd (macOS)."""
from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class PersistenceEntry:
    os_name: str
    mechanism: str
    location: str
    value: str


def _check_windows() -> list[PersistenceEntry]:
    entries: list[PersistenceEntry] = []
    try:
        import winreg
    except ImportError:
        return entries

    run_keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive, subkey in run_keys:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        # REG_BINARY/REG_DWORD renvoient bytes/int : repr() plutôt qu'un
                        # f-string brut pour rester lisible (bytes s'afficheraient sinon
                        # comme b'\x01\x02...' sans échappement propre).
                        value_str = value if isinstance(value, str) else repr(value)
                        entries.append(
                            PersistenceEntry(
                                os_name="windows",
                                mechanism="registry_run_key",
                                location=f"{'HKCU' if hive == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{subkey}",
                                value=f"{name} = {value_str}",
                            )
                        )
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            continue
    return entries


def _check_linux() -> list[PersistenceEntry]:
    entries: list[PersistenceEntry] = []

    cron_paths = [Path("/etc/crontab"), Path("/etc/cron.d"), Path.home() / ".crontab"]
    for p in cron_paths:
        if p.is_file():
            try:
                content = p.read_text(errors="ignore")
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entries.append(
                            PersistenceEntry(os_name="linux", mechanism="cron", location=str(p), value=line)
                        )
            except OSError:
                pass
        elif p.is_dir():
            for f in p.iterdir():
                try:
                    entries.append(
                        PersistenceEntry(
                            os_name="linux", mechanism="cron", location=str(f), value=f.read_text(errors="ignore")[:200]
                        )
                    )
                except OSError:
                    pass

    try:
        out = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=5
        )
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                if line.strip() and not line.strip().startswith("#"):
                    entries.append(
                        PersistenceEntry(os_name="linux", mechanism="user_crontab", location="crontab -l", value=line)
                    )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    systemd_dirs = [Path("/etc/systemd/system"), Path.home() / ".config/systemd/user"]
    for d in systemd_dirs:
        if d.is_dir():
            for f in d.glob("*.service"):
                entries.append(
                    PersistenceEntry(os_name="linux", mechanism="systemd_service", location=str(f), value=f.name)
                )

    ld_preload = Path("/etc/ld.so.preload")
    if ld_preload.is_file():
        try:
            content = ld_preload.read_text(errors="ignore").strip()
            if content:
                entries.append(
                    PersistenceEntry(
                        os_name="linux", mechanism="ld_preload", location=str(ld_preload), value=content
                    )
                )
        except OSError:
            pass

    return entries


def _check_macos() -> list[PersistenceEntry]:
    entries: list[PersistenceEntry] = []
    launch_dirs = [
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
        Path.home() / "Library/LaunchAgents",
    ]
    for d in launch_dirs:
        if d.is_dir():
            for f in d.glob("*.plist"):
                entries.append(
                    PersistenceEntry(os_name="macos", mechanism="launchd", location=str(d), value=f.name)
                )

    login_items_script = (
        'tell application "System Events" to get the name of every login item'
    )
    try:
        out = subprocess.run(
            ["osascript", "-e", login_items_script], capture_output=True, text=True, timeout=5
        )
        if out.returncode == 0 and out.stdout.strip():
            for item in out.stdout.strip().split(", "):
                entries.append(
                    PersistenceEntry(os_name="macos", mechanism="login_item", location="System Events", value=item)
                )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return entries


def check_persistence() -> list[PersistenceEntry]:
    system = platform.system()
    if system == "Windows":
        return _check_windows()
    if system == "Linux":
        return _check_linux()
    if system == "Darwin":
        return _check_macos()
    return []
