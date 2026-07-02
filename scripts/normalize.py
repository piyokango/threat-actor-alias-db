#!/usr/bin/env python3
"""Normalize MITRE ATT&CK, MISP Galaxy, and Microsoft threat actor naming data.

The merge logic is intentionally conservative:
- MITRE records become primary actors when available.
- MISP records are merged into an existing actor on exact normalized canonical name match or a single exact name/alias match.
- Microsoft records are added as vendor names when exactly one existing actor can be matched.
- Otherwise, Microsoft records are emitted as review candidates rather than automatically creating same-as mappings.
- A final narrow de-duplication pass merges records with the same normalized canonical name.
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


MICROSOFT_MAPPING_URL = "https://learn.microsoft.com/en-us/unified-secops/microsoft-threat-actor-naming"
MICROSOFT_JSON_URL = "https://raw.githubusercontent.com/microsoft/mstic/master/PublicFeeds/ThreatActorNaming/MicrosoftMapping.json"


def load_json(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"Missing input file: {path}. Run scripts/fetch_sources.py first.")
    return json.loads(path.read_text(encoding="utf-8"))


def load_microsoft_mapping(path: Path) -> list[dict[str, Any]]:
    """Load MicrosoftMapping.json.

    Microsoft documents the file for KQL externaldata with format="multijson".
    This loader accepts normal JSON arrays, newline-delimited JSON, and adjacent JSON objects.
    """
    if not path.exists():
        return []

    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass

    records: list[dict[str, Any]] = []
    decoder = json.JSONDecoder()
    idx = 0
    length = len(text)

    while idx < length:
        while idx < length and text[idx].isspace():
            idx += 1
        if idx >= length:
            break
        try:
            obj, end = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    records.append(item)
            return records
        if isinstance(obj, dict):
            records.append(obj)
        idx = end

    return records


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


def split_names(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        raw_values = value
    else:
        raw_values = [str(value)]

    names: list[str] = []
    for raw in raw_values:
        if not isinstance(raw, str):
            raw = str(raw)
        for part in raw.split(","):
            cleaned = part.strip()
            if cleaned:
                names.append(cleaned)

    seen = set()
    output = []
    for name in names:
        key = normalize_name(name)
        if key and key not in seen:
            seen.add(key)
            output.append(name)
    return output


def add_name(
    names: list[dict[str, Any]],
    seen: set[tuple[str, str, str, str]],
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
    key = (actor_id, normalize_name(clean), source_id, name_type)
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
    seen_names: set[tuple[str, str, str, str]],
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


def choose_existing_actor_for_misp_record(
    actor_name: str,
    synonyms: list[str],
    actors: list[dict[str, Any]],
    name_index: dict[str, set[str]],
) -> str | None:
    norm_actor_name = normalize_name(actor_name)

    canonical_matches = [
        actor["id"]
        for actor in actors
        if normalize_name(actor.get("canonical_name", "")) == norm_actor_name
    ]
    if len(set(canonical_matches)) == 1:
        return canonical_matches[0]

    candidate_ids: set[str] = set()
    for candidate_name in [actor_name, *synonyms]:
        candidate_ids.update(name_index.get(normalize_name(candidate_name), set()))

    if len(candidate_ids) == 1:
        return next(iter(candidate_ids))

    return None


def normalize_misp(
    misp_data: dict[str, Any],
    actors: list[dict[str, Any]],
    names: list[dict[str, Any]],
    source_links: dict[str, set[str]],
    name_index: dict[str, set[str]],
    seen_names: set[tuple[str, str, str, str]],
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

        actor_id = choose_existing_actor_for_misp_record(actor_name, synonyms, actors, name_index)

        if actor_id:
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


def normalize_microsoft(
    microsoft_records: list[dict[str, Any]],
    actors: list[dict[str, Any]],
    names: list[dict[str, Any]],
    source_links: dict[str, set[str]],
    name_index: dict[str, set[str]],
    seen_names: set[tuple[str, str, str, str]],
) -> list[dict[str, Any]]:
    actor_by_id = {actor["id"]: actor for actor in actors}
    review_candidates: list[dict[str, Any]] = []

    for record in microsoft_records:
        new_name = str(record.get("New name") or record.get("NewName") or "").strip()
        previous_name = str(record.get("Previous name") or record.get("PreviousName") or "").strip()
        origin = str(record.get("Origin/Threat") or record.get("Origin") or "").strip()
        other_names = split_names(record.get("Other names") or record.get("OtherNames"))

        candidate_names = [new_name, previous_name, *other_names]
        candidate_ids: set[str] = set()
        for candidate_name in candidate_names:
            if candidate_name:
                candidate_ids.update(name_index.get(normalize_name(candidate_name), set()))

        source_urls = [MICROSOFT_MAPPING_URL, MICROSOFT_JSON_URL]

        if len(candidate_ids) != 1:
            review_candidates.append(
                {
                    "source_id": "microsoft-threat-actor-naming",
                    "new_name": new_name,
                    "previous_name": previous_name,
                    "other_names": other_names,
                    "origin_or_threat": origin,
                    "candidate_actor_ids": sorted(candidate_ids),
                    "reason": "no unique existing actor match",
                    "source_urls": source_urls,
                }
            )
            continue

        actor_id = next(iter(candidate_ids))
        actor = actor_by_id[actor_id]
        actor["source_ids"] = sorted(set(actor.get("source_ids", [])) | {"microsoft-threat-actor-naming"})
        if origin:
            actor.setdefault("microsoft_origin_or_threat", origin)

        source_links[actor_id].update(source_urls)

        if new_name:
            add_name(names, seen_names, actor_id, new_name, "vendor_name", "microsoft-threat-actor-naming", "Microsoft", "source-provided", source_urls)
        if previous_name:
            add_name(names, seen_names, actor_id, previous_name, "former", "microsoft-threat-actor-naming", "Microsoft", "source-provided", source_urls)
        for other_name in other_names:
            add_name(names, seen_names, actor_id, other_name, "alias", "microsoft-threat-actor-naming", "Microsoft", "source-provided", source_urls)

        for candidate_name in candidate_names:
            norm = normalize_name(candidate_name)
            if norm:
                name_index[norm].add(actor_id)

    return review_candidates


def actor_preference(actor: dict[str, Any]) -> tuple[int, int, str]:
    source = actor.get("primary_source")
    if source == "mitre-attack":
        source_score = 0
    elif source == "misp-galaxy":
        source_score = 1
    else:
        source_score = 2

    mitre_bonus = 0 if actor.get("mitre_id") else 1
    return (source_score, mitre_bonus, actor.get("id", ""))


def merge_actor_metadata(target: dict[str, Any], duplicate: dict[str, Any]) -> None:
    target["source_ids"] = sorted(set(target.get("source_ids", [])) | set(duplicate.get("source_ids", [])))

    if not target.get("misp_uuid") and duplicate.get("misp_uuid"):
        target["misp_uuid"] = duplicate.get("misp_uuid")
    if not target.get("mitre_id") and duplicate.get("mitre_id"):
        target["mitre_id"] = duplicate.get("mitre_id")
    if not target.get("suspected_country") and duplicate.get("suspected_country"):
        target["suspected_country"] = duplicate.get("suspected_country")
    if not target.get("microsoft_origin_or_threat") and duplicate.get("microsoft_origin_or_threat"):
        target["microsoft_origin_or_threat"] = duplicate.get("microsoft_origin_or_threat")

    duplicate_description = duplicate.get("description")
    if duplicate_description and duplicate_description not in target.get("description", ""):
        if target.get("description"):
            target["description"] = f"{target['description']}\n\nAdditional source description:\n{duplicate_description}"
        else:
            target["description"] = duplicate_description


def deduplicate_names(names: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    for name in names:
        key = (
            name["actor_id"],
            name["normalized_name"],
            name["source_id"],
            name["name_type"],
        )
        if key not in deduped:
            deduped[key] = dict(name)
            deduped[key]["source_urls"] = sorted(set(name.get("source_urls", [])))
        else:
            existing = deduped[key]
            existing["source_urls"] = sorted(set(existing.get("source_urls", [])) | set(name.get("source_urls", [])))
            if len(name.get("name", "")) < len(existing.get("name", "")):
                existing["name"] = name["name"]

    return list(deduped.values())


def consolidate_duplicate_actors(
    actors: list[dict[str, Any]],
    names: list[dict[str, Any]],
    source_links: dict[str, set[str]],
    review_candidates: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, set[str]], list[dict[str, Any]]]:
    by_canonical: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for actor in actors:
        canonical_norm = normalize_name(actor.get("canonical_name", ""))
        if canonical_norm:
            by_canonical[canonical_norm].append(actor)

    actor_redirect: dict[str, str] = {}
    duplicate_report: list[dict[str, Any]] = []

    for canonical_norm, group in by_canonical.items():
        if len(group) < 2:
            continue

        preferred = sorted(group, key=actor_preference)[0]
        duplicate_ids = []

        for duplicate in group:
            if duplicate["id"] == preferred["id"]:
                continue
            actor_redirect[duplicate["id"]] = preferred["id"]
            duplicate_ids.append(duplicate["id"])
            merge_actor_metadata(preferred, duplicate)
            source_links[preferred["id"]].update(source_links.get(duplicate["id"], set()))

        duplicate_report.append(
            {
                "canonical_name": preferred.get("canonical_name"),
                "normalized_canonical_name": canonical_norm,
                "surviving_actor_id": preferred["id"],
                "merged_actor_ids": duplicate_ids,
                "reason": "same normalized canonical name",
            }
        )

    if not actor_redirect:
        write_json(OUT_DIR / "dedup-report.json", [])
        return actors, names, source_links, review_candidates

    new_actors = [actor for actor in actors if actor["id"] not in actor_redirect]

    for name in names:
        if name["actor_id"] in actor_redirect:
            name["actor_id"] = actor_redirect[name["actor_id"]]

    new_source_links: dict[str, set[str]] = defaultdict(set)
    for actor_id, links in source_links.items():
        new_actor_id = actor_redirect.get(actor_id, actor_id)
        new_source_links[new_actor_id].update(links)

    for candidate in review_candidates:
        redirected_ids = sorted({actor_redirect.get(actor_id, actor_id) for actor_id in candidate.get("candidate_actor_ids", [])})
        candidate["candidate_actor_ids"] = redirected_ids

    names = deduplicate_names(names)
    write_json(OUT_DIR / "dedup-report.json", duplicate_report)

    return new_actors, names, new_source_links, review_candidates


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
    if "microsoft.com" in lowered or "githubusercontent.com/microsoft/" in lowered or "github.com/microsoft/" in lowered:
        return "microsoft-threat-actor-naming"
    return "external-reference"


def main() -> int:
    mitre_data = load_json(RAW_DIR / "mitre" / "latest.json")
    misp_data = load_json(RAW_DIR / "misp" / "latest.json")
    microsoft_records = load_microsoft_mapping(RAW_DIR / "microsoft" / "latest.json")

    actors: list[dict[str, Any]] = []
    names: list[dict[str, Any]] = []
    source_links: dict[str, set[str]] = defaultdict(set)
    name_index: dict[str, set[str]] = defaultdict(set)
    seen_names: set[tuple[str, str, str, str]] = set()

    normalize_mitre(mitre_data, actors, names, source_links, name_index, seen_names)
    normalize_misp(misp_data, actors, names, source_links, name_index, seen_names)
    microsoft_review_candidates = normalize_microsoft(
        microsoft_records,
        actors,
        names,
        source_links,
        name_index,
        seen_names,
    )

    actors, names, source_links, microsoft_review_candidates = consolidate_duplicate_actors(
        actors,
        names,
        source_links,
        microsoft_review_candidates,
    )

    actors = sorted(actors, key=lambda item: (item["canonical_name"].casefold(), item["id"]))
    names = sorted(names, key=lambda item: (item["normalized_name"], item["actor_id"], item["source_id"], item["name_type"]))
    references = build_references(actors, source_links)

    write_json(OUT_DIR / "actors.json", actors)
    write_json(OUT_DIR / "names.json", names)
    write_json(OUT_DIR / "relations.json", [])
    write_json(OUT_DIR / "references.json", references)
    write_json(OUT_DIR / "review-candidates.json", microsoft_review_candidates)

    dedup_report_path = OUT_DIR / "dedup-report.json"
    dedup_count = 0
    if dedup_report_path.exists():
        try:
            dedup_count = len(json.loads(dedup_report_path.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            dedup_count = 0

    print(
        f"Normalized {len(actors)} actors, {len(names)} names, {len(references)} references, "
        f"{len(microsoft_review_candidates)} Microsoft review candidates, {dedup_count} duplicate actor groups merged"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
