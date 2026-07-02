#!/usr/bin/env python3
"""Build the public static search index.

This script also performs presentation-layer consolidation so the public UI does
not show duplicate cards when normalized data still contains duplicate actors.

Rules:
- Merge actors with the same normalized canonical name into one public card.
- Prefer MITRE actors as the representative actor ID and metadata.
- Merge source IDs, naming sources, names, and references.
- Canonicalize reference URLs so variants such as
  https://attack.mitre.org/groups/G0007 and
  https://attack.mitre.org/groups/G0007/ are displayed once.
"""

from __future__ import annotations

import json
import re
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parents[1]
NORMALIZED_DIR = ROOT / "data" / "normalized"
PUBLIC_DIR = ROOT / "data" / "public"
DOCS_DATA_DIR = ROOT / "docs" / "data"


def load_json(path: Path) -> Any:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def normalize_text(value: str) -> str:
    text = str(value or "").casefold().strip()
    text = re.sub(r"[\s_\-./]+", " ", text)
    text = re.sub(r"[^a-z0-9\u3040-\u30ff\u3400-\u9fff ]+", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def canonicalize_url(url: str) -> str:
    """Return a display-stable URL for de-duplication.

    The intent is not to rewrite all URLs aggressively. It only removes common
    presentation duplicates:
    - lower-case scheme and host
    - remove fragments
    - remove tracking query parameters
    - remove trailing slash from non-root paths
    """
    raw = str(url or "").strip()
    if not raw:
        return raw

    try:
        parsed = urlsplit(raw)
    except ValueError:
        return raw.rstrip("/")

    scheme = parsed.scheme.lower() or "https"
    netloc = parsed.netloc.lower()
    path = parsed.path or ""

    if path != "/":
        path = path.rstrip("/")

    tracking_prefixes = ("utm_",)
    drop_params = {"fbclid", "gclid", "msclkid"}
    query_items = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        lowered = key.lower()
        if lowered in drop_params or any(lowered.startswith(prefix) for prefix in tracking_prefixes):
            continue
        query_items.append((key, value))

    query = urlencode(query_items, doseq=True)

    return urlunsplit((scheme, netloc, path, query, ""))


def actor_preference(actor: dict[str, Any]) -> tuple[int, str]:
    source = actor.get("primary_source")
    if source == "mitre-attack":
        source_score = 0
    elif source == "misp-galaxy":
        source_score = 1
    else:
        source_score = 2

    mitre_score = 0 if actor.get("mitre_id") else 1
    return (source_score, mitre_score, actor.get("id", ""))


def merge_actor_group(group: list[dict[str, Any]]) -> dict[str, Any]:
    representative = sorted(group, key=actor_preference)[0]
    merged = dict(representative)

    source_ids = set()
    naming_sources = set()
    actor_ids = []

    for actor in group:
        actor_ids.append(actor["id"])
        source_ids.update(actor.get("source_ids", []))

        if not merged.get("mitre_id") and actor.get("mitre_id"):
            merged["mitre_id"] = actor.get("mitre_id")
        if not merged.get("misp_uuid") and actor.get("misp_uuid"):
            merged["misp_uuid"] = actor.get("misp_uuid")
        if not merged.get("suspected_country") and actor.get("suspected_country"):
            merged["suspected_country"] = actor.get("suspected_country")
        if not merged.get("microsoft_origin_or_threat") and actor.get("microsoft_origin_or_threat"):
            merged["microsoft_origin_or_threat"] = actor.get("microsoft_origin_or_threat")

    merged["source_ids"] = sorted(source_ids)
    merged["merged_actor_ids"] = sorted(set(actor_ids))
    merged["actor_id"] = representative["id"]

    return merged


def dedupe_names(names: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    for item in names:
        normalized_name = item.get("normalized_name") or normalize_text(item.get("name", ""))
        key = (
            normalized_name,
            item.get("naming_org") or item.get("source_id") or "",
            item.get("source_id") or "",
            item.get("name_type") or "",
        )

        source_urls = [canonicalize_url(url) for url in item.get("source_urls", []) if url]
        source_urls = sorted({url for url in source_urls if url})

        if key not in deduped:
            copied = dict(item)
            copied["normalized_name"] = normalized_name
            copied["source_urls"] = source_urls
            deduped[key] = copied
            continue

        existing = deduped[key]
        existing["source_urls"] = sorted(set(existing.get("source_urls", [])) | set(source_urls))

        # Prefer shorter/canonical-looking display if duplicate differs only by case/punctuation.
        if len(str(item.get("name", ""))) < len(str(existing.get("name", ""))):
            existing["name"] = item.get("name", existing.get("name"))

    return sorted(
        deduped.values(),
        key=lambda item: (
            item.get("naming_org") or "",
            item.get("name_type") or "",
            normalize_text(item.get("name", "")),
        ),
    )


def dedupe_references(references: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}

    for ref in references:
        canonical_url = canonicalize_url(ref.get("url", ""))
        if not canonical_url:
            continue

        if canonical_url not in deduped:
            copied = dict(ref)
            copied["url"] = canonical_url
            deduped[canonical_url] = copied
            continue

        existing = deduped[canonical_url]
        if existing.get("source_id") == "external-reference" and ref.get("source_id"):
            existing["source_id"] = ref.get("source_id")

    return sorted(deduped.values(), key=lambda item: item.get("url", ""))


def main() -> int:
    actors = load_json(NORMALIZED_DIR / "actors.json")
    names = load_json(NORMALIZED_DIR / "names.json")
    references = load_json(NORMALIZED_DIR / "references.json")

    actor_by_id = {actor["id"]: actor for actor in actors}

    grouped_actor_ids: dict[str, list[str]] = defaultdict(list)
    for actor in actors:
        key = normalize_text(actor.get("canonical_name", ""))
        if not key:
            key = actor.get("id", "")
        grouped_actor_ids[key].append(actor["id"])

    public_actor_by_original_id: dict[str, str] = {}
    public_actors: list[dict[str, Any]] = []

    for key, actor_ids in grouped_actor_ids.items():
        group = [actor_by_id[actor_id] for actor_id in actor_ids]
        merged_actor = merge_actor_group(group)
        public_actor_id = merged_actor["actor_id"]
        for actor_id in actor_ids:
            public_actor_by_original_id[actor_id] = public_actor_id
        public_actors.append(merged_actor)

    names_by_public_actor: dict[str, list[dict[str, Any]]] = defaultdict(list)
    refs_by_public_actor: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for name in names:
        original_actor_id = name.get("actor_id")
        public_actor_id = public_actor_by_original_id.get(original_actor_id, original_actor_id)
        copied = dict(name)
        copied["actor_id"] = public_actor_id
        names_by_public_actor[public_actor_id].append(copied)

    for ref in references:
        original_actor_id = ref.get("actor_id")
        public_actor_id = public_actor_by_original_id.get(original_actor_id, original_actor_id)
        copied = dict(ref)
        copied["actor_id"] = public_actor_id
        copied["url"] = canonicalize_url(copied.get("url", ""))
        refs_by_public_actor[public_actor_id].append(copied)

    index = []
    for actor in public_actors:
        actor_id = actor["actor_id"]
        actor_names = dedupe_names(names_by_public_actor.get(actor_id, []))
        actor_refs = dedupe_references(refs_by_public_actor.get(actor_id, []))

        search_names = sorted({item["name"] for item in actor_names if item.get("name")}, key=str.casefold)
        naming_sources = sorted({item["naming_org"] for item in actor_names if item.get("naming_org")})
        source_ids = sorted(set(actor.get("source_ids", [])) | {item.get("source_id") for item in actor_refs if item.get("source_id")})

        index.append(
            {
                "actor_id": actor_id,
                "merged_actor_ids": actor.get("merged_actor_ids", [actor_id]),
                "canonical_name": actor["canonical_name"],
                "mitre_id": actor.get("mitre_id"),
                "misp_uuid": actor.get("misp_uuid"),
                "primary_source": actor.get("primary_source"),
                "source_ids": source_ids,
                "naming_sources": naming_sources,
                "search_names": search_names,
                "names": actor_names,
                "references": actor_refs,
                "status": actor.get("status", "active"),
                "confidence": actor.get("confidence", "unknown"),
                "updated_at": actor.get("updated_at"),
            }
        )

    index = sorted(index, key=lambda item: (item["canonical_name"].casefold(), item["actor_id"]))

    output_path = PUBLIC_DIR / "search-index.json"
    docs_path = DOCS_DATA_DIR / "search-index.json"
    write_json(output_path, index)
    docs_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(output_path, docs_path)

    duplicate_group_count = sum(1 for actor in index if len(actor.get("merged_actor_ids", [])) > 1)
    print(f"Built search index with {len(index)} actors ({duplicate_group_count} duplicate canonical groups merged for display)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
