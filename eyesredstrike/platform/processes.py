"""Inspection des processus en cours et de leurs connexions réseau."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

SUSPICIOUS_PROCESS_NAMES = {
    "nc", "ncat", "netcat", "mshta.exe", "certutil.exe", "regsvr32.exe",
}

SUSPICIOUS_ARGS_SNIPPETS = [
    "-encodedcommand", "-enc ", "invoke-expression", "downloadstring",
    "frombase64string", "/dev/tcp/",
]


@dataclass
class ProcessFinding:
    pid: int
    name: str
    exe: Optional[str]
    cmdline: str
    connections: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def list_suspicious_processes() -> list[ProcessFinding]:
    if psutil is None:
        raise RuntimeError("psutil n'est pas installé. Lancez : pip install psutil")

    findings: list[ProcessFinding] = []

    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            cmdline_list = info.get("cmdline") or []
            cmdline = " ".join(cmdline_list)
            cmdline_lower = cmdline.lower()

            reasons = []
            if name in SUSPICIOUS_PROCESS_NAMES:
                reasons.append(f"nom de processus sensible : {name}")
            for snippet in SUSPICIOUS_ARGS_SNIPPETS:
                if snippet in cmdline_lower:
                    reasons.append(f"argument suspect : '{snippet}'")

            connections = []
            try:
                for c in proc.net_connections(kind="inet"):
                    if c.status == psutil.CONN_ESTABLISHED and c.raddr:
                        connections.append(f"{c.raddr.ip}:{c.raddr.port}")
            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                pass

            if reasons or (connections and name not in {"chrome", "firefox", "safari"}):
                findings.append(
                    ProcessFinding(
                        pid=info.get("pid"),
                        name=info.get("name") or "",
                        exe=info.get("exe"),
                        cmdline=cmdline,
                        connections=connections,
                        reasons=reasons or ["connexion réseau active à corréler manuellement"],
                    )
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return findings
