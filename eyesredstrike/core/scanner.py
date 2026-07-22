"""Orchestrateur de scan : parcourt le filesystem et agrège hashdb + YARA + heuristiques."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .hashdb import HashDB, sha256_of_file
from .heuristics import analyze_file, HeuristicFinding
from .quarantine import Quarantine
from .yara_engine import YaraEngine, YaraMatch

DEFAULT_EXCLUDES = {
    ".git", "node_modules", "__pycache__", ".eyesredstrike", "venv", ".venv",
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


@dataclass
class FileFinding:
    path: str
    sha256: str
    ioc_match: Optional[str] = None          # famille si hash connu
    yara_matches: list[YaraMatch] = field(default_factory=list)
    heuristics: list[HeuristicFinding] = field(default_factory=list)
    quarantined: bool = False

    @property
    def severity(self) -> str:
        if self.ioc_match:
            return "high"
        levels = [m.confidence for m in self.yara_matches] + [h.severity for h in self.heuristics]
        levels = [l for l in levels if l in SEVERITY_ORDER]
        if not levels:
            return "info"
        return max(levels, key=lambda l: SEVERITY_ORDER[l])

    @property
    def is_clean(self) -> bool:
        return not self.ioc_match and not self.yara_matches and not self.heuristics


@dataclass
class ScanReport:
    scanned_files: int = 0
    skipped_files: int = 0
    findings: list[FileFinding] = field(default_factory=list)

    @property
    def threats(self) -> list[FileFinding]:
        return [f for f in self.findings if not f.is_clean]


class Scanner:
    def __init__(
        self,
        hashdb: Optional[HashDB] = None,
        yara_engine: Optional[YaraEngine] = None,
        quarantine: Optional[Quarantine] = None,
        excludes: Optional[set[str]] = None,
        max_file_size: int = 200_000_000,
    ):
        self.hashdb = hashdb or HashDB()
        try:
            self.yara_engine = yara_engine or YaraEngine()
        except (RuntimeError, FileNotFoundError):
            self.yara_engine = None  # dégrade gracieusement si yara-python absent
        self.quarantine = quarantine or Quarantine()
        self.excludes = excludes or DEFAULT_EXCLUDES
        self.max_file_size = max_file_size

    def _iter_files(self, root: Path):
        if root.is_file():
            yield root
            return
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in self.excludes]
            for name in filenames:
                yield Path(dirpath) / name

    def scan_file(self, path: Path) -> Optional[FileFinding]:
        try:
            size = path.stat().st_size
        except OSError:
            return None
        if size == 0 or size > self.max_file_size:
            return None

        try:
            digest = sha256_of_file(path)
        except (OSError, PermissionError):
            return None

        finding = FileFinding(path=str(path), sha256=digest)

        ioc = self.hashdb.lookup(digest)
        if ioc:
            finding.ioc_match = ioc.family

        if self.yara_engine:
            finding.yara_matches = self.yara_engine.scan_file(path)

        finding.heuristics = analyze_file(path)

        return finding

    def scan_path(
        self,
        root: Path,
        quarantine_min_severity: Optional[str] = None,
        progress_cb: Optional[Callable[[Path], None]] = None,
    ) -> ScanReport:
        report = ScanReport()
        root = Path(root)

        for path in self._iter_files(root):
            if progress_cb:
                progress_cb(path)
            finding = self.scan_file(path)
            if finding is None:
                report.skipped_files += 1
                continue
            report.scanned_files += 1
            if not finding.is_clean:
                report.findings.append(finding)
                if (
                    quarantine_min_severity
                    and SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[quarantine_min_severity]
                ):
                    reason = finding.ioc_match or (
                        finding.yara_matches[0].rule if finding.yara_matches else "heuristic"
                    )
                    try:
                        self.quarantine.quarantine_file(Path(finding.path), finding.sha256, reason)
                        finding.quarantined = True
                    except OSError:
                        pass

        return report
