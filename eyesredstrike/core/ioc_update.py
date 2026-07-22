"""Mise à jour de la base d'IOCs depuis MalwareBazaar (abuse.ch), source publique de threat intel.

Nécessite une clé API gratuite : https://bazaar.abuse.ch/api/#get_apikey
Exportez-la dans la variable d'environnement ABUSE_CH_API_KEY avant d'appeler update_from_malwarebazaar().
"""
from __future__ import annotations

import os
from typing import Optional

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

from .hashdb import HashDB

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"

# Tags MalwareBazaar pertinents pour ce projet (trojans/backdoors Windows + scripts).
DEFAULT_TAGS = ["Wacatac", "trojan", "backdoor", "RAT"]


def update_from_malwarebazaar(hashdb: Optional[HashDB] = None, tags: Optional[list[str]] = None, limit: int = 100) -> int:
    if requests is None:
        raise RuntimeError("requests n'est pas installé. Lancez : pip install requests")

    api_key = os.environ.get("ABUSE_CH_API_KEY")
    if not api_key:
        raise RuntimeError(
            "Variable d'environnement ABUSE_CH_API_KEY absente. "
            "Obtenez une clé gratuite sur https://bazaar.abuse.ch/api/#get_apikey puis "
            "export ABUSE_CH_API_KEY=votre_cle"
        )

    db = hashdb or HashDB()
    tags = tags or DEFAULT_TAGS
    headers = {"Auth-Key": api_key}
    total_added = 0

    for tag in tags:
        try:
            resp = requests.post(
                MALWAREBAZAAR_URL,
                data={"query": "get_taginfo", "tag": tag, "limit": str(limit)},
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            payload = resp.json()
        except (requests.RequestException, ValueError) as e:
            print(f"[!] Échec de récupération pour le tag '{tag}' : {e}")
            continue

        if payload.get("query_status") != "ok":
            continue

        entries = {}
        for sample in payload.get("data", []):
            sha256 = sample.get("sha256_hash")
            if not sha256:
                continue
            entries[sha256] = {
                "family": sample.get("signature") or tag,
                "source": "malwarebazaar",
                "added": sample.get("first_seen"),
            }
        added = db.add_bulk(entries)
        total_added += added
        print(f"[+] Tag '{tag}' : {added} hashs ajoutés/mis à jour")

    db.save()
    return total_added
