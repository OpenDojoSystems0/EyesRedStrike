"""Moteur YARA : compilation des règles et scan de fichiers."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yara
except ImportError:  # pragma: no cover
    yara = None

DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


@dataclass
class YaraMatch:
    rule: str
    family: str
    confidence: str
    description: str
    strings_matched: list = field(default_factory=list)


class YaraEngine:
    def __init__(self, rules_dir: Path = DEFAULT_RULES_DIR):
        if yara is None:
            raise RuntimeError(
                "yara-python n'est pas installé. Lancez : pip install yara-python"
            )
        self.rules_dir = Path(rules_dir)
        self._compiled = self._compile()

    def _compile(self):
        rule_files = sorted(self.rules_dir.glob("*.yar"))
        if not rule_files:
            raise FileNotFoundError(f"Aucune règle YARA trouvée dans {self.rules_dir}")
        sources = {f.stem: str(f) for f in rule_files}
        return yara.compile(filepaths=sources)

    def scan_file(self, path: Path, timeout: int = 30) -> list[YaraMatch]:
        try:
            matches = self._compiled.match(str(path), timeout=timeout)
        except yara.Error:
            return []
        results = []
        for m in matches:
            meta = m.meta or {}
            results.append(
                YaraMatch(
                    rule=m.rule,
                    family=meta.get("family", "unknown"),
                    confidence=meta.get("confidence", "unknown"),
                    description=meta.get("description", ""),
                    strings_matched=[s.identifier for s in m.strings] if hasattr(m, "strings") else [],
                )
            )
        return results

    def scan_bytes(self, data: bytes) -> list[YaraMatch]:
        try:
            matches = self._compiled.match(data=data)
        except yara.Error:
            return []
        results = []
        for m in matches:
            meta = m.meta or {}
            results.append(
                YaraMatch(
                    rule=m.rule,
                    family=meta.get("family", "unknown"),
                    confidence=meta.get("confidence", "unknown"),
                    description=meta.get("description", ""),
                )
            )
        return results
