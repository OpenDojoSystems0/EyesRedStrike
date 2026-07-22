"""Heuristiques complémentaires : entropie, indices de packing, obfuscation de script."""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

HIGH_ENTROPY_THRESHOLD = 7.2  # sur 8 bits max ; > 7.2 = quasi-aléatoire (packé/chiffré/compressé)
SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".hta", ".bat", ".sh", ".py"}

SUSPICIOUS_SCRIPT_PATTERNS = [
    re.compile(rb"powershell.{0,40}-e(nc(odedcommand)?)?\b", re.IGNORECASE),
    re.compile(rb"frombase64string", re.IGNORECASE),
    re.compile(rb"invoke-expression|iex\(", re.IGNORECASE),
    re.compile(rb"downloadstring|downloadfile", re.IGNORECASE),
    re.compile(rb"certutil.{0,20}-decode", re.IGNORECASE),
    re.compile(rb"add-mppreference.{0,40}-exclusionpath", re.IGNORECASE),  # désactivation Defender
]


@dataclass
class HeuristicFinding:
    kind: str
    detail: str
    severity: str  # "info" | "low" | "medium" | "high"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_pe(data: bytes) -> bool:
    return len(data) > 2 and data[0:2] == b"MZ"


def is_elf(data: bytes) -> bool:
    return len(data) > 4 and data[0:4] == b"\x7fELF"


def is_macho(data: bytes) -> bool:
    magics = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}
    return len(data) > 4 and data[0:4] in magics


def analyze_file(path: Path, max_bytes: int = 20_000_000) -> list[HeuristicFinding]:
    findings: list[HeuristicFinding] = []
    try:
        size = path.stat().st_size
    except OSError:
        return findings

    if size == 0 or size > max_bytes:
        return findings

    with open(path, "rb") as f:
        data = f.read(max_bytes)

    ext = path.suffix.lower()
    entropy = shannon_entropy(data)

    if entropy >= HIGH_ENTROPY_THRESHOLD:
        binary = is_pe(data) or is_elf(data) or is_macho(data)
        severity = "medium" if binary else "low"
        findings.append(
            HeuristicFinding(
                kind="high_entropy",
                detail=f"Entropie Shannon élevée ({entropy:.2f}/8.0) — packé, chiffré ou compressé",
                severity=severity,
            )
        )

    if ext in {".js", ".vbs", ".ps1", ".hta", ".bat", ".sh"} or not (is_pe(data) or is_elf(data) or is_macho(data)):
        hits = [p.pattern.decode(errors="ignore") for p in SUSPICIOUS_SCRIPT_PATTERNS if p.search(data)]
        if len(hits) >= 2:
            findings.append(
                HeuristicFinding(
                    kind="obfuscated_script",
                    detail=f"{len(hits)} patterns d'évasion/obfuscation détectés dans un script",
                    severity="high",
                )
            )
        elif len(hits) == 1:
            findings.append(
                HeuristicFinding(
                    kind="suspicious_script_pattern",
                    detail="1 pattern suspect détecté (à corréler)",
                    severity="low",
                )
            )

    if is_pe(data) and b"UPX!" in data:
        findings.append(
            HeuristicFinding(kind="packer", detail="Packer UPX détecté", severity="info")
        )

    return findings
