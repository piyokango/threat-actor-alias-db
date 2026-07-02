#!/usr/bin/env python3
"""Normalize MITRE ATT&CK and MISP Galaxy threat actor data.

The merge logic is intentionally conservative:
- MITRE records become primary actors when available.
- MISP records are merged into a MITRE actor only on exact normalized name/alias match.
- Otherwise, MISP records remain separate actors.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "raw"
OUT_DIR = ROOT / "data" / "normalized"


def load_json(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"Missing input file: {path}. Run scripts/fetch_sources.py first.")
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def normalize_name(name: str) -> str:
    value = name.casefold().strip()
    value = re.sub(r"[\s_\-./]+", " ", value)
    value = re.sub(r"[^a-z0-9\u3040-\u30ff\u3400-\u9fff ]+", "", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def stable_id(prefix: str, value: str) -> str:
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def external_reference_url(ref: dict[str, Any]) -> str | None:
    url = ref.get("url")
    if isinstance(url, str) and url:
        return url
    return None


def get_mitre_group_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def get_mitre_group_url(group_id: str | None) -> str | None:
    if not group_id:
        return None
    return f"https://attack.mitre.org/groups/{group_id}/"


def add_name(
    names: list[dict[str, Any]],
    seen: set[tuple[str, str, str]],
    actor_id: str,
    name: str,
    name_type: str,
    source_id: str,
    naming_org: str,
    confidence: str,
    source_urls: list[str] | None = None,
) -> None:
    clean = name.strip()
    if not clean:
        return
    key = (actor_id, normalize_name(clean), source_id)
    if key in seen:
        return
    seen.add(key)
    names.append(
        {
            "actor_id": actor_id,
            "name": clean,
            "normalized_name": normalize_name(clean),
            "name_type": name_type,
            "source_id": source_id,
            "naming_org": naming_org,
            "confidence": confidence,
            "source_urls": sorted(set(source_urls or [])),
        }
    )


def normalize_mitre(
    mitre_data: dict[str, Any],
    actors: list[dict[str, Any]],
    names: list[dict[str, Any]],
    source_links: dict[str, set[str]],
    name_index: dict[str, set[str]],
    seen_names: set[tuple[str, str, str]],
) -> None:
    for obj in mitre_data.get("objects", []):
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        group_id = get_mitre_group_id(obj)
        actor_id = f"mitre-{group_id.lower()}" if group_id else stable_id("mitre", obj.get("id", obj.get("name", "")))
        canonical_name = obj.get("name", "").strip()
        aliases = [a.strip() for a in obj.get("aliases", []) if isinstance(a, str) and a.strip()]
        references = sorted(
            {url for ref in obj.get("external_references", []) if (url := external_reference_url(ref))}
        )
        group_url = get_mitre_group_url(group_id)
        if group_url:
            references.append(group_url)
            references = sorted(set(references))

        actors.append(
            {
                "id": actor_id,
                "canonical_name": canonical_name,
                "description": obj.get("description", ""),
                "primary_source": "mitre-attack",
                "mitre_id": group_id,
                "misp_uuid": None,
                "status": "active",
                "confidence": "source-provided",
                "source_ids": ["mitre-attack"],
                "updated_at": date.today().isoformat(),
            }
        )

        source_links[actor_id].update(references)
        add_name(names, seen_names, actor_id, canonical_name, "canonical", "mitre-attack", "MITRE ATT&CK", "source-provided", [group_url] if group_url else [])
        for alias in aliases:
            add_name(names, seen_names, actor_id, alias, "alias", "mitre-attack", "MITRE ATT&CK", "source-provided", [group_url] if group_url else [])

        for value in [canonical_name, *aliases]:
            norm = normalize_name(value)
            if norm:
                name_index[norm].add(actor_id)


def normalize_misp(
    misp_data: dict[str, Any],
    actors: list[dict[str, Any]],
    names: list[dict[str, Any]],
    source_links: dict[str, set[str]],
    name_index: dict[str, set[str]],
    seen_names: set[tuple[str, str, str]],
) -> None:
    actor_by_id = {actor["id"]: actor for actor in actors}

    for value in misp_data.get("values", []):
        if not isinstance(value, dict):
            continue
        actor_name = str(value.get("value", "")).strip()
        if not actor_name:
            continue

        meta = value.get("meta", {}) if isinstance(value.get("meta"), dict) else {}
        synonyms = [s.strip() for s in meta.get("synonyms", []) if isinstance(s, str) and s.strip()]
        refs = [r.strip() for r in meta.get("refs", []) if isinstance(r, str) and r.strip()]
        country = meta.get("country")
        uuid = value.get("uuid")

        candidate_ids: set[str] = set()
        for candidate_name in [actor_name, *synonyms]:
            candidate_ids.update(name_index.get(normalize_name(candidate_name), set()))

        if len(candidate_ids) == 1:
            actor_id = next(iter(candidate_ids))
            actor_by_id[actor_id]["source_ids"] = sorted(set(actor_by_id[actor_id].get("source_ids", [])) | {"misp-galaxy"})
            actor_by_id[actor_id]["misp_uuid"] = actor_by_id[actor_id].get("misp_uuid") or uuid
            if country and not actor_by_id[actor_id].get("suspected_country"):
                actor_by_id[actor_id]["suspected_country"] = country
        else:
            actor_id = f"misp-{uuid}" if uuid else stable_id("misp", actor_name)
            if actor_id not in actor_by_id:
                actor = {
                    "id": actor_id,
                    "canonical_name": actor_name,
                    "description": value.get("description", ""),
                    "primary_source": "misp-galaxy",
                    "mitre_id": None,
                    "misp_uuid": uuid,
                    "status": "active",
                    "confidence": "source-provided",
                    "source_ids": ["misp-galaxy"],
                    "updated_at": date.today().isoformat(),
                }
                if country:
                    actor["suspected_country"] = country
                actors.append(actor)
                actor_by_id[actor_id] = actor

        source_links[actor_id].update(refs)
        add_name(names, seen_names, actor_id, actor_name, "canonical" if actor_by_id[actor_id]["primary_source"] == "misp-galaxy" else "alias", "misp-galaxy", "MISP Galaxy", "source-provided", refs)
        for synonym in synonyms:
            add_name(names, seen_names, actor_id, synonym, "alias", "misp-galaxy", "MISP Galaxy", "source-provided", refs)

        for candidate_name in [actor_name, *synonyms]:
            norm = normalize_name(candidate_name)
            if norm:
                name_index[norm].add(actor_id)


def build_references(actors: list[dict[str, Any]], source_links: dict[str, set[str]]) -> list[dict[str, Any]]:
    references = []
    for actor in actors:
        for url in sorted(source_links.get(actor["id"], set())):
            references.append(
                {
                    "actor_id": actor["id"],
                    "url": url,
                    "source_id": infer_source_id(url),
                }
            )
    return references


def infer_source_id(url: str) -> str:
    lowered = url.lower()
    if "attack.mitre.org" in lowered:
        return "mitre-attack"
    if "misp-galaxy" in lowered or "github.com/misp/" in lowered:
        return "misp-galaxy"
    return "external-reference"


def main() -> int:
    mitre_data = load_json(RAW_DIR / "mitre" / "latest.json")
    misp_data = load_json(RAW_DIR / "misp" / "latest.json")

    actors: list[dict[str, Any]] = []
    names: list[dict[str, Any]] = []
    source_links: dict[str, set[str]] = defaultdict(set)
    name_index: dict[str, set[str]] = defaultdict(set)
    seen_names: set[tuple[str, str, str]] = set()

    normalize_mitre(mitre_data, actors, names, source_links, name_index, seen_names)
    normalize_misp(misp_data, actors, names, source_links, name_index, seen_names)

    actors = sorted(actors, key=lambda item: (item["canonical_name"].casefold(), item["id"]))
    names = sorted(names, key=lambda item: (item["normalized_name"], item["actor_id"], item["source_id"]))
    references = build_references(actors, source_links)

    write_json(OUT_DIR / "actors.json", actors)
    write_json(OUT_DIR / "names.json", names)
    write_json(OUT_DIR / "relations.json", [])
    write_json(OUT_DIR / "references.json", references)

    print(f"Normalized {len(actors)} actors, {len(names)} names, {len(references)} references")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
