#!/usr/bin/env python3
"""Generate a static REST-like JSON API for GitHub Pages.

This hardened version limits file names, file counts, and public fields.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = ROOT / "docs"
PUBLIC_INDEX = DOCS_DIR / "data" / "search-index.json"
API_ROOT = DOCS_DIR / "api" / "v1"

MAX_KEY_LENGTH = 100
MAX_SEARCH_FILES = 20000
MAX_NAME_FILES = 20000


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


def safe_api_filename_key(value: str) -> str:
    key = api_key(value)
    if not key:
        return ""
    if len(key) <= MAX_KEY_LENGTH:
        return key
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"long-{digest}"


def is_safe_url(value: str) -> bool:
    try:
        parsed = urlsplit(str(value or ""))
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def clean_urls(urls: list[str]) -> list[str]:
    return sorted({url for url in urls if is_safe_url(url)})


def scrub_for_public(value: Any) -> Any:
    """Remove unsafe URL schemes recursively and keep JSON serializable data."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key in {"url"} and isinstance(item, str):
                out[key] = item if is_safe_url(item) else ""
            elif key in {"source_urls"} and isinstance(item, list):
                out[key] = clean_urls([str(row) for row in item])
            else:
                out[key] = scrub_for_public(item)
        return out
    if isinstance(value, list):
        return [scrub_for_public(item) for item in value]
    if isinstance(value, str):
        return value[:10000]
    return value


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
            key = safe_api_filename_key(str(value))
            if key:
                keys["search"].add(key)

    for name in actor.get("names", []) or []:
        for value in [name.get("name"), *(name.get("variants") or [])]:
            if value:
                key = safe_api_filename_key(str(value))
                if key:
                    keys["search"].add(key)
                    keys["names"].add(key)

    for value in actor.get("search_names") or []:
        if value:
            key = safe_api_filename_key(str(value))
            if key:
                keys["search"].add(key)
                keys["names"].add(key)

    return keys


def build_lookup(index: list[dict[str, Any]]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    search_lookup: dict[str, list[dict[str, Any]]] = {}
    name_lookup: dict[str, list[dict[str, Any]]] = {}

    for actor in index:
        summary = actor_summary(actor)
        keys = collect_keys(actor)

        for key in keys["search"]:
            search_lookup.setdefault(key, []).append(summary)
        for key in keys["names"]:
            name_lookup.setdefault(key, []).append(summary)

    for lookup in [search_lookup, name_lookup]:
        for key, rows in lookup.items():
            deduped = {}
            for row in rows:
                deduped[row["actor_id"]] = row
            lookup[key] = sorted(deduped.values(), key=lambda item: (item.get("canonical_name") or "").casefold())

    if len(search_lookup) > MAX_SEARCH_FILES:
        raise RuntimeError(f"Too many search lookup files: {len(search_lookup)} > {MAX_SEARCH_FILES}")
    if len(name_lookup) > MAX_NAME_FILES:
        raise RuntimeError(f"Too many name lookup files: {len(name_lookup)} > {MAX_NAME_FILES}")

    return search_lookup, name_lookup


def main() -> int:
    index = scrub_for_public(load_index())

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
            "limits": {
                "max_key_length": MAX_KEY_LENGTH,
                "max_search_files": MAX_SEARCH_FILES,
                "max_name_files": MAX_NAME_FILES,
            },
            "endpoints": {
                "actors": "api/v1/actors.json",
                "actor_detail": "api/v1/actors/<actor_id>.json",
                "search_index": "api/v1/search-index.json",
                "precomputed_search": "api/v1/search/<query-key>.json",
                "precomputed_name_lookup": "api/v1/names/<name-key>.json",
            },
            "notes": [
                "This is a static API for GitHub Pages. Dynamic server-side search is not available.",
                "Use compact normalized query keys. Example: APT 28, APT28, and APT-28 map to apt28.",
            ],
        },
    )

    write_json(API_ROOT / "actors.json", {"generated_at": now, "count": len(actor_summaries), "actors": actor_summaries})

    actors_dir = API_ROOT / "actors"
    for actor in index:
        actor_id = str(actor.get("actor_id") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", actor_id):
            raise RuntimeError(f"Unsafe actor_id for file path: {actor_id}")
        write_json(actors_dir / f"{actor_id}.json", {"generated_at": now, "actor": actor})

    write_json(API_ROOT / "search-index.json", {"generated_at": now, "count": len(index), "actors": index})

    search_dir = API_ROOT / "search"
    for key, rows in search_lookup.items():
        write_json(search_dir / f"{quote(key, safe='')}.json", {"generated_at": now, "query_key": key, "count": len(rows), "results": rows})

    names_dir = API_ROOT / "names"
    for key, rows in name_lookup.items():
        write_json(names_dir / f"{quote(key, safe='')}.json", {"generated_at": now, "name_key": key, "count": len(rows), "results": rows})

    write_json(API_ROOT / "lookup-keys.json", {"generated_at": now, "search_keys": sorted(search_lookup), "name_keys": sorted(name_lookup)})

    print(f"Generated static API under {API_ROOT} ({len(index)} actors, {len(search_lookup)} search keys, {len(name_lookup)} name keys)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
