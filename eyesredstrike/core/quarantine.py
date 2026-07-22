"""Quarantaine réversible : déplace les fichiers détectés, ne les supprime jamais directement.

Le fichier est XOR-obfusqué (empêche toute exécution accidentelle / double scan AV) et
stocké avec ses métadonnées d'origine dans un registre JSON. `restore()` inverse
l'opération à l'identique. `purge()` est la seule opération destructrice et n'est
jamais appelée automatiquement par le scanner.
"""
from __future__ import annotations

import json
import os
import shutil
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

XOR_KEY = 0xA5  # obfuscation triviale, pas de la vraie crypto — juste "rend le binaire inerte"
DEFAULT_QUARANTINE_DIR = Path.home() / ".eyesredstrike" / "quarantine"


@dataclass
class QuarantineRecord:
    id: str
    original_path: str
    quarantined_at: str
    reason: str
    sha256: str
    stored_name: str


def _xor_transform(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY for b in data)


class Quarantine:
    def __init__(self, quarantine_dir: Path = DEFAULT_QUARANTINE_DIR):
        self.dir = Path(quarantine_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.registry_path = self.dir / "registry.json"
        self._registry = self._load_registry()

    def _load_registry(self) -> dict:
        if not self.registry_path.exists():
            return {}
        with open(self.registry_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_registry(self) -> None:
        with open(self.registry_path, "w", encoding="utf-8") as f:
            json.dump(self._registry, f, indent=2, ensure_ascii=False)

    def quarantine_file(self, path: Path, sha256: str, reason: str) -> QuarantineRecord:
        qid = uuid.uuid4().hex[:12]
        stored_name = f"{qid}.quar"
        stored_path = self.dir / stored_name

        with open(path, "rb") as f:
            data = f.read()
        with open(stored_path, "wb") as f:
            f.write(_xor_transform(data))

        os.remove(path)

        record = QuarantineRecord(
            id=qid,
            original_path=str(path.resolve()),
            quarantined_at=datetime.now(timezone.utc).isoformat(),
            reason=reason,
            sha256=sha256,
            stored_name=stored_name,
        )
        self._registry[qid] = asdict(record)
        self._save_registry()
        return record

    def list_records(self) -> list[QuarantineRecord]:
        return [QuarantineRecord(**r) for r in self._registry.values()]

    def get(self, qid: str) -> Optional[QuarantineRecord]:
        r = self._registry.get(qid)
        return QuarantineRecord(**r) if r else None

    def restore(self, qid: str, target_path: Optional[Path] = None) -> Path:
        record = self.get(qid)
        if record is None:
            raise KeyError(f"Aucun élément en quarantaine avec l'id {qid}")

        stored_path = self.dir / record.stored_name
        try:
            with open(stored_path, "rb") as f:
                data = _xor_transform(f.read())

            dest = Path(target_path) if target_path else Path(record.original_path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "wb") as f:
                f.write(data)

            os.remove(stored_path)
        except OSError as e:
            raise OSError(
                f"Impossible de restaurer '{qid}' — fichier verrouillé ou inaccessible : {e}"
            ) from e

        del self._registry[qid]
        self._save_registry()
        return dest

    def purge(self, qid: str) -> None:
        """Suppression DÉFINITIVE. La confirmation utilisateur doit être faite en amont (CLI)."""
        record = self.get(qid)
        if record is None:
            raise KeyError(f"Aucun élément en quarantaine avec l'id {qid}")
        stored_path = self.dir / record.stored_name
        try:
            if stored_path.exists():
                os.remove(stored_path)
        except OSError as e:
            raise OSError(
                f"Impossible de purger '{qid}' — fichier verrouillé ou inaccessible : {e}"
            ) from e
        del self._registry[qid]
        self._save_registry()
