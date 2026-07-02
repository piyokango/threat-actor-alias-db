#!/usr/bin/env python3
"""Fetch raw source data for Threat Actor Alias DB.

This script intentionally uses only Python's standard library.
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw"

SOURCES = {
    "mitre": {
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "filename": "enterprise-attack.json",
        "content_type": "json",
    },
    "misp": {
        "url": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
        "filename": "threat-actor.json",
        "content_type": "json",
    },
    "microsoft": {
        "url": "https://raw.githubusercontent.com/microsoft/mstic/master/PublicFeeds/ThreatActorNaming/MicrosoftMapping.json",
        "filename": "MicrosoftMapping.json",
        "content_type": "text",
    },
}


def fetch_text(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "threat-actor-alias-db/0.4 (+https://github.com/piyokango/threat-actor-alias-db)"
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(charset)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"failed to fetch {url}: {exc}") from exc


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not text.endswith("\n"):
        text += "\n"
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, text: str) -> None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"fetched content is not valid JSON: {path.name}") from exc

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    today = dt.date.today().isoformat()

    for source_id, info in SOURCES.items():
        print(f"Fetching {source_id}: {info['url']}", file=sys.stderr)
        text = fetch_text(info["url"])

        source_dir = RAW_DIR / source_id
        source_dir.mkdir(parents=True, exist_ok=True)

        dated_path = source_dir / f"{today}_{info['filename']}"
        latest_path = source_dir / "latest.json"

        if info["content_type"] == "json":
            write_json(dated_path, text)
        else:
            write_text(dated_path, text)

        shutil.copyfile(dated_path, latest_path)

        print(f"Wrote {dated_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
