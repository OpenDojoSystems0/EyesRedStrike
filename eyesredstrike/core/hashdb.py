"""Base d'IOCs par hash SHA-256 : chargement, lookup, mise à jour depuis MalwareBazaar."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "iocs.json"
CHUNK_SIZE = 1024 * 1024  # 1 MiB


@dataclass
class IOCMatch:
    sha256: str
    family: str
    source: str
    added: Optional[str] = None


class HashDB:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self._data = self._load()

    def _load(self) -> dict:
        if not self.db_path.exists():
            return {"_meta": {}, "hashes": {}}
        with open(self.db_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def save(self) -> None:
        self._data.setdefault("_meta", {})["last_updated"] = datetime.now(timezone.utc).isoformat()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)

    def __len__(self) -> int:
        return len(self._data.get("hashes", {}))

    def lookup(self, sha256: str) -> Optional[IOCMatch]:
        entry = self._data.get("hashes", {}).get(sha256.lower())
        if entry is None:
            return None
        return IOCMatch(
            sha256=sha256.lower(),
            family=entry.get("family", "unknown"),
            source=entry.get("source", "unknown"),
            added=entry.get("added"),
        )

    def add(self, sha256: str, family: str, source: str) -> None:
        self._data.setdefault("hashes", {})[sha256.lower()] = {
            "family": family,
            "source": source,
            "added": datetime.now(timezone.utc).isoformat(),
        }

    def add_bulk(self, entries: dict) -> int:
        added = 0
        hashes = self._data.setdefault("hashes", {})
        for sha256, meta in entries.items():
            hashes[sha256.lower()] = meta
            added += 1
        return added


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()
