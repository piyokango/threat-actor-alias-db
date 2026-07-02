#!/usr/bin/env python3
"""Build the public static search index.

This script performs presentation-layer consolidation so the public UI does not
show duplicate actor cards or duplicate alias rows.

It also attaches actor profile fields:
- overview
- reported attribution
- observed MITRE ATT&CK techniques
- review-published recent activity
"""

from __future__ import annotations

import json
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parents[1]
NORMALIZED_DIR = ROOT / "data" / "normalized"
PUBLIC_DIR = ROOT / "data" / "public"
DOCS_DATA_DIR = ROOT / "docs" / "data"
ACTIVITY_DIR = ROOT / "data" / "activity"


NAME_TYPE_PRIORITY = {
    "canonical": 0,
    "vendor_name": 1,
    "former": 2,
    "alias": 3,
    "temporary_cluster": 4,
}


TACTIC_LABELS = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def load_json(path: Path) -> Any:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    return json.loads(text)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def normalize_text(value: str) -> str:
    text = str(value or "").casefold().strip()
    text = re.sub(r"[\s_\-./]+", " ", text)
    text = re.sub(r"[^a-z0-9\u3040-\u30ff\u3400-\u9fff ]+", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def shorten_text(value: str, limit: int = 650) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].strip()
    return f"{cut}..." if cut else text[:limit] + "..."


def canonicalize_url(url: str) -> str:
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


def actor_preference(actor: dict[str, Any]) -> tuple[int, int, str]:
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


def choose_display_name(candidates: list[str], normalized_name: str) -> str:
    cleaned = [str(value).strip() for value in candidates if str(value).strip()]
    if not cleaned:
        return normalized_name

    mixed_case = [value for value in cleaned if any(ch.islower() for ch in value)]
    pool = mixed_case or cleaned

    return sorted(pool, key=lambda value: (len(value), value.casefold(), value))[0]


def aggregate_names(names: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for item in names:
        normalized_name = item.get("normalized_name") or normalize_text(item.get("name", ""))
        if not normalized_name:
            continue
        copied = dict(item)
        copied["normalized_name"] = normalized_name
        grouped[normalized_name].append(copied)

    aggregated: list[dict[str, Any]] = []

    for normalized_name, items in grouped.items():
        display_name = choose_display_name([item.get("name", "") for item in items], normalized_name)

        name_types = sorted(
            {item.get("name_type") or "alias" for item in items},
            key=lambda value: NAME_TYPE_PRIORITY.get(value, 99),
        )
        primary_name_type = name_types[0] if name_types else "alias"

        sources_by_org: dict[str, dict[str, Any]] = {}
        source_urls = set()
        source_ids = set()

        for item in items:
            org = item.get("naming_org") or item.get("source_id") or "Unknown"
            source_id = item.get("source_id") or org
            source_ids.add(source_id)

            relation = item.get("source_relation")

            # Backward-compatible Microsoft relation inference.
            # Newer normalize.py writes source_relation explicitly:
            #   current_name / previous_name / other_name
            # Older generated data may only have name_type. In that case infer
            # enough to display Forest Blizzard as Microsoft current rather than
            # a generic Microsoft source.
            if org == "Microsoft" and not relation:
                if item.get("name_type") == "vendor_name":
                    relation = "current_name"
                elif item.get("name_type") == "former":
                    relation = "previous_name"
                elif item.get("name_type") == "alias":
                    relation = "other_name"

            display_org = org
            if org == "Microsoft" and relation == "current_name":
                display_org = "Microsoft current"
            elif org == "Microsoft" and relation == "previous_name":
                display_org = "Microsoft previous"
            elif org == "Microsoft" and relation == "other_name":
                display_org = "Microsoft other"

            entry = sources_by_org.setdefault(
                display_org,
                {
                    "naming_org": display_org,
                    "source_ids": set(),
                    "name_types": set(),
                    "source_urls": set(),
                    "source_relations": set(),
                },
            )
            entry["source_ids"].add(source_id)
            entry["name_types"].add(item.get("name_type") or "alias")
            if relation:
                entry["source_relations"].add(relation)

            for url in item.get("source_urls", []):
                canonical_url = canonicalize_url(url)
                if canonical_url:
                    entry["source_urls"].add(canonical_url)
                    source_urls.add(canonical_url)

        sources = []
        for org, source in sources_by_org.items():
            sources.append(
                {
                    "naming_org": org,
                    "source_ids": sorted(source["source_ids"]),
                    "name_types": sorted(source["name_types"], key=lambda value: NAME_TYPE_PRIORITY.get(value, 99)),
                    "source_relations": sorted(source["source_relations"]),
                    "source_urls": sorted(source["source_urls"]),
                }
            )

        sources = sorted(sources, key=lambda item: item["naming_org"].casefold())

        aggregated.append(
            {
                "name": display_name,
                "normalized_name": normalized_name,
                "name_type": primary_name_type,
                "name_types": name_types,
                "source_id": ",".join(sorted(source_ids)),
                "naming_org": ", ".join(source["naming_org"] for source in sources),
                "sources": sources,
                "confidence": "source-provided",
                "source_urls": sorted(source_urls),
            }
        )

    return sorted(
        aggregated,
        key=lambda item: (
            NAME_TYPE_PRIORITY.get(item.get("name_type"), 99),
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
            copied["source_ids"] = sorted({ref.get("source_id")} if ref.get("source_id") else set())
            deduped[canonical_url] = copied
            continue

        existing = deduped[canonical_url]
        source_ids = set(existing.get("source_ids", []))
        if ref.get("source_id"):
            source_ids.add(ref.get("source_id"))
        existing["source_ids"] = sorted(source_ids)

        if existing.get("source_id") == "external-reference" and ref.get("source_id"):
            existing["source_id"] = ref.get("source_id")

    return sorted(deduped.values(), key=lambda item: item.get("url", ""))


def build_activity_by_actor(public_actor_by_original_id: dict[str, str]) -> dict[str, list[dict[str, Any]]]:
    published = load_json(ACTIVITY_DIR / "published.json")
    activity_by_actor: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen: set[tuple[str, str]] = set()

    for item in published:
        if item.get("review_status") not in {None, "", "published"}:
            continue

        original_actor_id = item.get("actor_id")
        actor_id = public_actor_by_original_id.get(original_actor_id, original_actor_id)
        url = canonicalize_url(item.get("url", ""))
        if not actor_id or not url:
            continue

        key = (actor_id, url)
        if key in seen:
            continue
        seen.add(key)

        copied = dict(item)
        copied["actor_id"] = actor_id
        copied["url"] = url
        activity_by_actor[actor_id].append(copied)

    for actor_id, items in activity_by_actor.items():
        items.sort(key=lambda row: row.get("published_date") or "", reverse=True)

    return activity_by_actor


def build_rows_by_public_actor(rows: list[dict[str, Any]], public_actor_by_original_id: dict[str, str]) -> dict[str, list[dict[str, Any]]]:
    by_actor: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        original_actor_id = row.get("actor_id")
        public_actor_id = public_actor_by_original_id.get(original_actor_id, original_actor_id)
        if not public_actor_id:
            continue
        copied = dict(row)
        copied["actor_id"] = public_actor_id
        by_actor[public_actor_id].append(copied)
    return by_actor


def build_overview(descriptions: list[dict[str, Any]], actor: dict[str, Any]) -> dict[str, Any] | None:
    if not descriptions and not actor.get("description"):
        return None

    preferred = None
    for source_id in ["mitre-attack", "misp-galaxy"]:
        for row in descriptions:
            if row.get("source_id") == source_id and row.get("text"):
                preferred = row
                break
        if preferred:
            break

    if preferred:
        text = preferred.get("text", "")
        source_rows = descriptions
    else:
        text = actor.get("description", "")
        source_rows = []

    if not text:
        return None

    sources = []
    seen = set()
    for row in source_rows:
        source_name = row.get("source_name") or row.get("source_id")
        if not source_name or source_name in seen:
            continue
        seen.add(source_name)
        sources.append(
            {
                "source_id": row.get("source_id"),
                "source_name": source_name,
                "source_urls": row.get("source_urls", []),
            }
        )

    return {
        "text": shorten_text(text, 700),
        "sources": sources,
        "generated": False,
    }


COUNTRY_ALIASES = {
    "russia": ("Russia", "RU", "🇷🇺"),
    "russian federation": ("Russia", "RU", "🇷🇺"),
    "ru": ("Russia", "RU", "🇷🇺"),
    "china": ("China", "CN", "🇨🇳"),
    "prc": ("China", "CN", "🇨🇳"),
    "people s republic of china": ("China", "CN", "🇨🇳"),
    "people's republic of china": ("China", "CN", "🇨🇳"),
    "north korea": ("North Korea", "KP", "🇰🇵"),
    "dprk": ("North Korea", "KP", "🇰🇵"),
    "democratic people's republic of korea": ("North Korea", "KP", "🇰🇵"),
    "iran": ("Iran", "IR", "🇮🇷"),
    "islamic republic of iran": ("Iran", "IR", "🇮🇷"),
    "vietnam": ("Vietnam", "VN", "🇻🇳"),
    "viet nam": ("Vietnam", "VN", "🇻🇳"),
    "india": ("India", "IN", "🇮🇳"),
    "pakistan": ("Pakistan", "PK", "🇵🇰"),
    "turkey": ("Turkey", "TR", "🇹🇷"),
    "türkiye": ("Turkey", "TR", "🇹🇷"),
    "israel": ("Israel", "IL", "🇮🇱"),
    "lebanon": ("Lebanon", "LB", "🇱🇧"),
    "syria": ("Syria", "SY", "🇸🇾"),
    "belarus": ("Belarus", "BY", "🇧🇾"),
    "ukraine": ("Ukraine", "UA", "🇺🇦"),
    "united states": ("United States", "US", "🇺🇸"),
    "usa": ("United States", "US", "🇺🇸"),
    "u s": ("United States", "US", "🇺🇸"),
    "united kingdom": ("United Kingdom", "GB", "🇬🇧"),
    "uk": ("United Kingdom", "GB", "🇬🇧"),
}


def normalize_country_value(value: str) -> dict[str, Any] | None:
    raw = str(value or "").strip()
    if not raw:
        return None

    key = normalize_text(raw)
    if key in COUNTRY_ALIASES:
        display, code, flag = COUNTRY_ALIASES[key]
        return {
            "display_value": display,
            "country_code": code,
            "flag": flag,
            "normalized_country": normalize_text(display),
        }

    # Microsoft Origin/Threat sometimes contains simple country names with punctuation variants.
    compact = key.replace(" the ", " ")
    if compact in COUNTRY_ALIASES:
        display, code, flag = COUNTRY_ALIASES[compact]
        return {
            "display_value": display,
            "country_code": code,
            "flag": flag,
            "normalized_country": normalize_text(display),
        }

    return None


def source_entry_from_attribution(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_id": row.get("source_id"),
        "source_name": row.get("source_name") or row.get("source_id"),
        "confidence": row.get("confidence", "source-provided"),
        "source_urls": sorted({canonicalize_url(url) for url in row.get("source_urls", []) if url}),
        "types": sorted({row.get("type")} if row.get("type") else set()),
    }


def merge_source_entries(existing: list[dict[str, Any]], new_source: dict[str, Any]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for source in existing:
        key = source.get("source_id") or source.get("source_name") or "unknown"
        by_id[key] = dict(source)
        by_id[key]["source_urls"] = sorted(set(by_id[key].get("source_urls", [])))
        by_id[key]["types"] = sorted(set(by_id[key].get("types", [])))

    key = new_source.get("source_id") or new_source.get("source_name") or "unknown"
    if key not in by_id:
        by_id[key] = dict(new_source)
    else:
        by_id[key]["source_urls"] = sorted(set(by_id[key].get("source_urls", [])) | set(new_source.get("source_urls", [])))
        by_id[key]["types"] = sorted(set(by_id[key].get("types", [])) | set(new_source.get("types", [])))

    return sorted(by_id.values(), key=lambda item: (item.get("source_name") or item.get("source_id") or "").casefold())


def build_attribution(attribution_rows: list[dict[str, Any]]) -> dict[str, Any]:
    countries_by_key: dict[str, dict[str, Any]] = {}
    classifications_by_key: dict[tuple[str, str], dict[str, Any]] = {}

    for row in attribution_rows:
        value = str(row.get("value") or "").strip()
        if not value:
            continue

        row_type = row.get("type") or "classification"
        country = normalize_country_value(value)
        source_entry = source_entry_from_attribution(row)

        # Treat explicit country rows and Microsoft Origin/Threat values that normalize to a country as country attribution.
        if row_type == "country" or country:
            if country:
                display_value = country["display_value"]
                country_code = country["country_code"]
                flag = country["flag"]
                key = country["normalized_country"]
            else:
                display_value = value
                country_code = None
                flag = None
                key = normalize_text(value)

            item = countries_by_key.setdefault(
                key,
                {
                    "type": "country",
                    "value": display_value,
                    "display_value": display_value,
                    "country_code": country_code,
                    "flag": flag,
                    "sources": [],
                },
            )
            item["sources"] = merge_source_entries(item["sources"], source_entry)
            if not item.get("country_code") and country_code:
                item["country_code"] = country_code
                item["flag"] = flag
            continue

        class_key = (row_type, normalize_text(value))
        item = classifications_by_key.setdefault(
            class_key,
            {
                "type": row_type,
                "value": value,
                "display_value": value,
                "sources": [],
            },
        )
        item["sources"] = merge_source_entries(item["sources"], source_entry)

    countries = sorted(countries_by_key.values(), key=lambda item: item.get("display_value", "").casefold())
    classifications = sorted(
        classifications_by_key.values(),
        key=lambda item: (item.get("type") or "", item.get("display_value", "").casefold()),
    )

    # Backward-compatible flattened list for callers that still expect rows.
    flattened = []
    for item in countries:
        flattened.append(item)
    for item in classifications:
        flattened.append(item)

    return {
        "countries": countries,
        "classifications": classifications,
        "items": flattened,
    }


def build_technique_summary(techniques: list[dict[str, Any]], max_techniques: int = 12) -> dict[str, Any]:
    if not techniques:
        return {
            "items": [],
            "tactics": [],
            "tactic_groups": [],
            "total": 0,
        }

    seen = set()
    unique = []
    for technique in techniques:
        key = (technique.get("technique_id"), technique.get("name"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(technique)

    tactic_counter = Counter()
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for technique in unique:
        tactic_values = technique.get("tactics", []) or ["unknown"]
        for tactic in tactic_values:
            tactic_counter[tactic] += 1
            grouped[tactic].append(technique)

    sorted_items = sorted(
        unique,
        key=lambda item: (
            -(max([tactic_counter[tactic] for tactic in item.get("tactics", [])] or [0])),
            item.get("technique_id") or "",
            item.get("name") or "",
        ),
    )

    tactic_summary = [
        {
            "tactic": tactic,
            "label": TACTIC_LABELS.get(tactic, tactic),
            "count": count,
        }
        for tactic, count in tactic_counter.most_common()
    ]

    tactic_groups = []
    for tactic, count in tactic_counter.most_common():
        items = sorted(
            grouped[tactic],
            key=lambda item: (item.get("technique_id") or "", item.get("name") or ""),
        )
        tactic_groups.append(
            {
                "tactic": tactic,
                "label": TACTIC_LABELS.get(tactic, tactic),
                "count": count,
                "items": items,
            }
        )

    return {
        "items": sorted_items[:max_techniques],
        "tactics": tactic_summary,
        "tactic_groups": tactic_groups,
        "total": len(unique),
    }


def main() -> int:
    actors = load_json(NORMALIZED_DIR / "actors.json")
    names = load_json(NORMALIZED_DIR / "names.json")
    references = load_json(NORMALIZED_DIR / "references.json")
    descriptions = load_json(NORMALIZED_DIR / "descriptions.json")
    attribution = load_json(NORMALIZED_DIR / "attribution.json")
    techniques = load_json(NORMALIZED_DIR / "techniques.json")

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

    activity_by_actor = build_activity_by_actor(public_actor_by_original_id)
    descriptions_by_actor = build_rows_by_public_actor(descriptions, public_actor_by_original_id)
    attribution_by_actor = build_rows_by_public_actor(attribution, public_actor_by_original_id)
    techniques_by_actor = build_rows_by_public_actor(techniques, public_actor_by_original_id)

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
        actor_names = aggregate_names(names_by_public_actor.get(actor_id, []))
        actor_refs = dedupe_references(refs_by_public_actor.get(actor_id, []))
        actor_overview = build_overview(descriptions_by_actor.get(actor_id, []), actor)
        actor_attribution = build_attribution(attribution_by_actor.get(actor_id, []))
        actor_techniques = build_technique_summary(techniques_by_actor.get(actor_id, []))

        search_names = sorted({item["name"] for item in actor_names if item.get("name")}, key=str.casefold)
        naming_sources = sorted(
            {
                source["naming_org"]
                for item in actor_names
                for source in item.get("sources", [])
                if source.get("naming_org")
            }
        )
        source_ids = sorted(
            set(actor.get("source_ids", []))
            | {
                source_id
                for item in actor_names
                for source in item.get("sources", [])
                for source_id in source.get("source_ids", [])
            }
            | {source_id for ref in actor_refs for source_id in ref.get("source_ids", [])}
        )

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
                "overview": actor_overview,
                "reported_attribution": actor_attribution,
                "observed_techniques": actor_techniques,
                "names": actor_names,
                "references": actor_refs,
                "recent_activity": activity_by_actor.get(actor_id, [])[:10],
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
    activity_count = sum(len(actor.get("recent_activity", [])) for actor in index)
    overview_count = sum(1 for actor in index if actor.get("overview"))
    attribution_count = sum(len((actor.get("reported_attribution") or {}).get("items", [])) for actor in index)
    technique_count = sum((actor.get("observed_techniques") or {}).get("total", 0) for actor in index)
    print(
        f"Built search index with {len(index)} actors "
        f"({duplicate_group_count} duplicate canonical groups merged for display, "
        f"{overview_count} overviews, {attribution_count} attribution rows, "
        f"{technique_count} technique links, {activity_count} published activity rows attached)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
