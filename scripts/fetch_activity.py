#!/usr/bin/env python3
"""Fetch recent public activity candidates for threat actors.

This script is intentionally conservative.

What it does:
- Loads the public actor search index from docs/data/search-index.json.
- Loads RSS/Atom sources from data/activity/sources.json.
- Fetches recent feed items.
- Matches actor canonical names and aliases against title, summary, and link.
- Writes auto candidates to data/activity/candidates.json.
- Preserves published/rejected review decisions by URL.

What it does not do:
- It does not automatically publish candidates to the public UI.
- It does not claim attribution based only on name matching.
- It does not scrape full article bodies.

The public UI should display only data/activity/published.json.
"""

from __future__ import annotations

import email.utils
import html
import json
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


ROOT = Path(__file__).resolve().parents[1]
ACTIVITY_DIR = ROOT / "data" / "activity"
DOCS_DATA_DIR = ROOT / "docs" / "data"

SOURCES_PATH = ACTIVITY_DIR / "sources.json"
CANDIDATES_PATH = ACTIVITY_DIR / "candidates.json"
PUBLISHED_PATH = ACTIVITY_DIR / "published.json"
REJECTED_PATH = ACTIVITY_DIR / "rejected.json"
SEARCH_INDEX_PATH = DOCS_DATA_DIR / "search-index.json"

LOOKBACK_DAYS = 30
MAX_ITEMS_PER_SOURCE = 50
MIN_NAME_LENGTH = 4


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return default
    return json.loads(text)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def normalize_text(value: str) -> str:
    text = str(value or "").casefold()
    text = html.unescape(text)
    text = re.sub(r"[\s_\-./]+", " ", text)
    text = re.sub(r"[^a-z0-9\u3040-\u30ff\u3400-\u9fff ]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


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


def fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "threat-actor-alias-db/0.5 (+https://github.com/piyokango/threat-actor-alias-db)",
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        return response.read()


def parse_datetime(value: str | None) -> str | None:
    if not value:
        return None

    value = value.strip()
    if not value:
        return None

    # RFC 2822 style dates used in RSS.
    try:
        dt = email.utils.parsedate_to_datetime(value)
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).date().isoformat()
    except (TypeError, ValueError, IndexError):
        pass

    # ISO dates used in Atom.
    for candidate in [value, value.replace("Z", "+00:00")]:
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).date().isoformat()
        except ValueError:
            continue

    # YYYY-MM-DD fallback.
    match = re.search(r"\d{4}-\d{2}-\d{2}", value)
    if match:
        return match.group(0)

    return None


def strip_html(value: str | None) -> str:
    if not value:
        return ""
    text = re.sub(r"(?is)<script.*?</script>", " ", value)
    text = re.sub(r"(?is)<style.*?</style>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def child_text(element: ET.Element, names: set[str]) -> str:
    for child in list(element):
        if local_name(child.tag) in names:
            return "".join(child.itertext()).strip()
    return ""


def child_attr(element: ET.Element, tag_name: str, attr_name: str) -> str:
    for child in list(element):
        if local_name(child.tag) == tag_name:
            value = child.attrib.get(attr_name)
            if value:
                return value.strip()
    return ""


def parse_feed(xml_bytes: bytes, source: dict[str, Any]) -> list[dict[str, Any]]:
    parser = ET.XMLParser(encoding="utf-8")
    root = ET.fromstring(xml_bytes, parser=parser)
    root_name = local_name(root.tag)

    items: list[dict[str, Any]] = []

    if root_name == "rss" or root_name == "rdf":
        for item in root.iter():
            if local_name(item.tag) != "item":
                continue
            title = child_text(item, {"title"})
            link = child_text(item, {"link"})
            description = child_text(item, {"description", "summary", "encoded"})
            published_raw = child_text(item, {"pubDate", "published", "updated", "date"})
            items.append(
                {
                    "title": strip_html(title),
                    "url": canonicalize_url(link),
                    "summary": strip_html(description),
                    "published_date": parse_datetime(published_raw),
                    "publisher": source.get("name", ""),
                    "source_type": source.get("source_type", "unknown"),
                    "feed_url": source.get("url", ""),
                }
            )

    elif root_name == "feed":
        for entry in root.iter():
            if local_name(entry.tag) != "entry":
                continue
            title = child_text(entry, {"title"})
            link = child_attr(entry, "link", "href") or child_text(entry, {"link"})
            summary = child_text(entry, {"summary", "content"})
            published_raw = child_text(entry, {"published", "updated"})
            items.append(
                {
                    "title": strip_html(title),
                    "url": canonicalize_url(link),
                    "summary": strip_html(summary),
                    "published_date": parse_datetime(published_raw),
                    "publisher": source.get("name", ""),
                    "source_type": source.get("source_type", "unknown"),
                    "feed_url": source.get("url", ""),
                }
            )

    return [item for item in items if item.get("title") and item.get("url")]


def build_alias_index(actors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []

    for actor in actors:
        actor_id = actor.get("actor_id")
        canonical_name = actor.get("canonical_name")
        names = set()

        if canonical_name:
            names.add(canonical_name)

        for name in actor.get("names", []):
            if name.get("name"):
                names.add(name["name"])

        for search_name in actor.get("search_names", []):
            if search_name:
                names.add(search_name)

        for name in sorted(names, key=str.casefold):
            normalized = normalize_text(name)
            if len(normalized) < MIN_NAME_LENGTH:
                continue
            entries.append(
                {
                    "actor_id": actor_id,
                    "canonical_name": canonical_name,
                    "name": name,
                    "normalized_name": normalized,
                }
            )

    # Longer names first avoids weaker matches winning visually.
    entries.sort(key=lambda item: (-len(item["normalized_name"]), item["normalized_name"]))
    return entries


def find_matches(item: dict[str, Any], alias_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    haystack = normalize_text(
        " ".join(
            [
                item.get("title", ""),
                item.get("summary", ""),
                item.get("url", ""),
            ]
        )
    )

    if not haystack:
        return []

    matches_by_actor: dict[str, dict[str, Any]] = {}

    for entry in alias_entries:
        name = entry["normalized_name"]
        if not name:
            continue

        # Word-ish boundary match after normalization.
        pattern = rf"(^| ){re.escape(name)}( |$)"
        if not re.search(pattern, haystack):
            continue

        actor_id = entry["actor_id"]
        actor_match = matches_by_actor.setdefault(
            actor_id,
            {
                "actor_id": actor_id,
                "canonical_name": entry["canonical_name"],
                "matched_names": [],
            },
        )
        if entry["name"] not in actor_match["matched_names"]:
            actor_match["matched_names"].append(entry["name"])

    return sorted(matches_by_actor.values(), key=lambda item: item["canonical_name"] or "")


def make_candidate_id(url: str, actor_id: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9]+", "-", canonicalize_url(url)).strip("-").lower()
    return f"{actor_id}-{safe[:80]}"


def is_recent(published_date: str | None, lookback_days: int) -> bool:
    if not published_date:
        # Keep undated items as candidates; many feeds are inconsistent.
        return True

    try:
        published = datetime.fromisoformat(published_date).date()
    except ValueError:
        return True

    cutoff = datetime.now(timezone.utc).date() - timedelta(days=lookback_days)
    return published >= cutoff


def main() -> int:
    sources = load_json(SOURCES_PATH, [])
    actors = load_json(SEARCH_INDEX_PATH, [])
    published = load_json(PUBLISHED_PATH, [])
    rejected = load_json(REJECTED_PATH, [])
    existing_candidates = load_json(CANDIDATES_PATH, [])

    if not actors:
        print(f"No actor index found at {SEARCH_INDEX_PATH}. Run scripts/build_index.py first.", file=sys.stderr)
        return 1

    alias_entries = build_alias_index(actors)
    published_keys = {(item.get("actor_id"), canonicalize_url(item.get("url", ""))) for item in published}
    rejected_keys = {(item.get("actor_id"), canonicalize_url(item.get("url", ""))) for item in rejected}

    candidates_by_key: dict[tuple[str, str], dict[str, Any]] = {}

    # Preserve old candidates unless already reviewed.
    for candidate in existing_candidates:
        key = (candidate.get("actor_id"), canonicalize_url(candidate.get("url", "")))
        if key[0] and key[1] and key not in published_keys and key not in rejected_keys:
            candidates_by_key[key] = candidate

    fetched_count = 0
    matched_count = 0

    for source in sources:
        if not source.get("enabled", True):
            continue

        url = source.get("url")
        if not url:
            continue

        try:
            feed_bytes = fetch_bytes(url)
            items = parse_feed(feed_bytes, source)
        except (urllib.error.URLError, TimeoutError, ET.ParseError, ValueError) as exc:
            print(f"[WARN] failed to fetch/parse {url}: {exc}", file=sys.stderr)
            continue

        for item in items[:MAX_ITEMS_PER_SOURCE]:
            fetched_count += 1

            if not is_recent(item.get("published_date"), LOOKBACK_DAYS):
                continue

            matches = find_matches(item, alias_entries)
            if not matches:
                continue

            for match in matches:
                key = (match["actor_id"], canonicalize_url(item["url"]))
                if key in published_keys or key in rejected_keys:
                    continue

                matched_count += 1
                candidates_by_key[key] = {
                    "id": make_candidate_id(item["url"], match["actor_id"]),
                    "actor_id": match["actor_id"],
                    "canonical_name": match["canonical_name"],
                    "title": item["title"],
                    "publisher": item["publisher"],
                    "published_date": item.get("published_date"),
                    "url": canonicalize_url(item["url"]),
                    "source_type": item.get("source_type", "unknown"),
                    "matched_names": sorted(match["matched_names"], key=str.casefold),
                    "summary": item.get("summary", "")[:500],
                    "review_status": "auto_candidate",
                    "feed_url": item.get("feed_url"),
                    "collected_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                }

    candidates = sorted(
        candidates_by_key.values(),
        key=lambda item: (
            item.get("canonical_name") or "",
            item.get("published_date") or "",
            item.get("title") or "",
        ),
    )

    write_json(CANDIDATES_PATH, candidates)

    print(f"Fetched feed items: {fetched_count}")
    print(f"New/retained activity candidates: {len(candidates)}")
    print(f"Matched candidate rows this run: {matched_count}")
    print(f"Wrote {CANDIDATES_PATH}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
