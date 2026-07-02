#!/usr/bin/env python3
"""Generate a static REST-like JSON API for GitHub Pages.

GitHub Pages cannot execute dynamic server-side search, so this script creates
static JSON endpoints under docs/api/v1.

Supported endpoints:

- GET /api/v1/index.json
- GET /api/v1/actors.json
- GET /api/v1/actors/<actor_id>.json
- GET /api/v1/search-index.json
- GET /api/v1/search/<query-key>.json
- GET /api/v1/names/<name-key>.json

The search and names endpoints are precomputed from actor names, aliases,
variants, MITRE IDs, MISP UUIDs, and source IDs.
"""

from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = ROOT / "docs"
PUBLIC_INDEX = DOCS_DIR / "data" / "search-index.json"
API_ROOT = DOCS_DIR / "api" / "v1"


def normalize_text(value: str) -> str:
    text = str(value or "").casefold().strip()
    text = re.sub(r"[\s_\-./]+", " ", text)
    text = re.sub(r"[^a-z0-9\u3040-\u30ff\u3400-\u9fff ]+", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def compact_normalize(value: str) -> str:
    return re.sub(r"[\s_\-./]+", "", normalize_text(value))


def api_key(value: str) -> str:
    compact = compact_normalize(value)
    if compact:
        return compact
    return normalize_text(value).replace(" ", "-")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_index() -> list[dict[str, Any]]:
    if not PUBLIC_INDEX.exists():
        raise FileNotFoundError(f"Missing {PUBLIC_INDEX}. Run scripts/build_index.py first.")
    return json.loads(PUBLIC_INDEX.read_text(encoding="utf-8"))


def actor_summary(actor: dict[str, Any]) -> dict[str, Any]:
    return {
        "actor_id": actor.get("actor_id"),
        "canonical_name": actor.get("canonical_name"),
        "mitre_id": actor.get("mitre_id"),
        "misp_uuid": actor.get("misp_uuid"),
        "primary_source": actor.get("primary_source"),
        "source_ids": actor.get("source_ids", []),
        "naming_sources": actor.get("naming_sources", []),
        "search_names": actor.get("search_names", []),
        "url": f"api/v1/actors/{actor.get('actor_id')}.json",
        "web_url": f"?actor={actor.get('actor_id')}",
    }


def collect_keys(actor: dict[str, Any]) -> dict[str, set[str]]:
    keys: dict[str, set[str]] = {
        "search": set(),
        "names": set(),
    }

    for value in [
        actor.get("actor_id"),
        actor.get("mitre_id"),
        actor.get("misp_uuid"),
        *(actor.get("source_ids") or []),
    ]:
        if value:
            keys["search"].add(api_key(value))

    for name in actor.get("names", []) or []:
        for value in [name.get("name"), *(name.get("variants") or [])]:
            if value:
                keys["search"].add(api_key(value))
                keys["names"].add(api_key(value))

    for value in actor.get("search_names") or []:
        if value:
            keys["search"].add(api_key(value))
            keys["names"].add(api_key(value))

    return keys


def build_lookup(index: list[dict[str, Any]]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    search_lookup: dict[str, list[dict[str, Any]]] = {}
    name_lookup: dict[str, list[dict[str, Any]]] = {}

    for actor in index:
        summary = actor_summary(actor)
        keys = collect_keys(actor)

        for key in keys["search"]:
            if key:
                search_lookup.setdefault(key, []).append(summary)
        for key in keys["names"]:
            if key:
                name_lookup.setdefault(key, []).append(summary)

    for lookup in [search_lookup, name_lookup]:
        for key, rows in lookup.items():
            deduped = {}
            for row in rows:
                deduped[row["actor_id"]] = row
            lookup[key] = sorted(deduped.values(), key=lambda item: (item.get("canonical_name") or "").casefold())

    return search_lookup, name_lookup


def main() -> int:
    index = load_index()

    if API_ROOT.exists():
        shutil.rmtree(API_ROOT)
    API_ROOT.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    actor_summaries = [actor_summary(actor) for actor in index]
    search_lookup, name_lookup = build_lookup(index)

    write_json(
        API_ROOT / "index.json",
        {
            "api_version": "v1",
            "generated_at": now,
            "description": "Static REST-like JSON API for Threat Actor Alias DB.",
            "endpoints": {
                "actors": "api/v1/actors.json",
                "actor_detail": "api/v1/actors/<actor_id>.json",
                "search_index": "api/v1/search-index.json",
                "precomputed_search": "api/v1/search/<query-key>.json",
                "precomputed_name_lookup": "api/v1/names/<name-key>.json",
            },
            "notes": [
                "This is a static API for GitHub Pages. Dynamic ?q= server-side search is not available.",
                "Use compact normalized query keys. Example: APT 28, APT28, and APT-28 map to apt28.",
            ],
        },
    )

    write_json(
        API_ROOT / "actors.json",
        {
            "generated_at": now,
            "count": len(actor_summaries),
            "actors": actor_summaries,
        },
    )

    actors_dir = API_ROOT / "actors"
    for actor in index:
        write_json(
            actors_dir / f"{actor['actor_id']}.json",
            {
                "generated_at": now,
                "actor": actor,
            },
        )

    write_json(
        API_ROOT / "search-index.json",
        {
            "generated_at": now,
            "count": len(index),
            "actors": index,
        },
    )

    search_dir = API_ROOT / "search"
    for key, rows in search_lookup.items():
        write_json(
            search_dir / f"{quote(key, safe='')}.json",
            {
                "generated_at": now,
                "query_key": key,
                "count": len(rows),
                "results": rows,
            },
        )

    names_dir = API_ROOT / "names"
    for key, rows in name_lookup.items():
        write_json(
            names_dir / f"{quote(key, safe='')}.json",
            {
                "generated_at": now,
                "name_key": key,
                "count": len(rows),
                "results": rows,
            },
        )

    write_json(
        API_ROOT / "lookup-keys.json",
        {
            "generated_at": now,
            "search_keys": sorted(search_lookup),
            "name_keys": sorted(name_lookup),
        },
    )

    print(
        f"Generated static API under {API_ROOT} "
        f"({len(index)} actors, {len(search_lookup)} search keys, {len(name_lookup)} name keys)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
