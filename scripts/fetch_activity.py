#!/usr/bin/env python3
"""Fetch recent activity candidates from RSS/Atom feeds.

Hardened against malformed feeds, non-XML responses, oversized responses, and
unsafe URL schemes. This script keeps failures as warnings so a single bad feed
does not break the entire update job.
"""

from __future__ import annotations

import email.utils
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from hashlib import sha1
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


ROOT = Path(__file__).resolve().parents[1]
DOCS_INDEX = ROOT / "docs" / "data" / "search-index.json"
ACTIVITY_DIR = ROOT / "data" / "activity"

MAX_FEED_BYTES = 2_000_000
TIMEOUT_SECONDS = 20
LOOKBACK_DAYS = 30


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


def is_safe_url(url: str) -> bool:
    try:
        parsed = urlsplit(str(url or ""))
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def canonicalize_url(url: str) -> str:
    if not is_safe_url(url):
        return ""
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/") or "/", parsed.query, ""))


def fetch_bytes(url: str) -> bytes:
    if not is_safe_url(url):
        raise ValueError(f"unsafe feed URL: {url}")

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ThreatActorAliasDB/1.0 (+https://github.com/piyokango/threat-actor-alias-db)",
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.1",
        },
    )

    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as response:
        final_url = response.geturl()
        if not is_safe_url(final_url):
            raise ValueError(f"unsafe redirected feed URL: {final_url}")

        content_type = response.headers.get("Content-Type", "")
        data = response.read(MAX_FEED_BYTES + 1)
        if len(data) > MAX_FEED_BYTES:
            raise ValueError(f"feed too large: > {MAX_FEED_BYTES} bytes")
        if b"<" not in data[:256]:
            raise ValueError(f"response does not look like XML; Content-Type={content_type!r}")
        return data


def parse_date(value: str) -> str:
    if not value:
        return ""
    try:
        dt = email.utils.parsedate_to_datetime(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).date().isoformat()
    except Exception:
        pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()
    except Exception:
        return ""


def text_of(element: ET.Element | None) -> str:
    if element is None or element.text is None:
        return ""
    return re.sub(r"\s+", " ", element.text).strip()


def strip_tags(value: str) -> str:
    text = re.sub(r"<[^>]+>", " ", value or "")
    return re.sub(r"\s+", " ", text).strip()


def parse_feed(data: bytes) -> list[dict[str, str]]:
    root = ET.fromstring(data)
    items: list[dict[str, str]] = []

    # RSS
    for item in root.findall(".//item"):
        title = text_of(item.find("title"))
        link = text_of(item.find("link"))
        published = text_of(item.find("pubDate")) or text_of(item.find("published")) or text_of(item.find("updated"))
        summary = text_of(item.find("description"))
        if title and link and is_safe_url(link):
            items.append({
                "title": title,
                "url": canonicalize_url(link),
                "published_date": parse_date(published),
                "summary": strip_tags(summary)[:500],
            })

    # Atom
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    for entry in root.findall(".//atom:entry", ns) + root.findall(".//entry"):
        title = text_of(entry.find("atom:title", ns)) or text_of(entry.find("title"))
        link = ""
        for link_el in entry.findall("atom:link", ns) + entry.findall("link"):
            href = link_el.attrib.get("href")
            rel = link_el.attrib.get("rel", "alternate")
            if href and rel in {"alternate", ""}:
                link = href
                break
        published = (
            text_of(entry.find("atom:published", ns))
            or text_of(entry.find("atom:updated", ns))
            or text_of(entry.find("published"))
            or text_of(entry.find("updated"))
        )
        summary = text_of(entry.find("atom:summary", ns)) or text_of(entry.find("summary")) or text_of(entry.find("content"))
        if title and link and is_safe_url(link):
            items.append({
                "title": title,
                "url": canonicalize_url(link),
                "published_date": parse_date(published),
                "summary": strip_tags(summary)[:500],
            })

    return items


def normalize(value: str) -> str:
    text = str(value or "").casefold()
    text = re.sub(r"[\s_\-./]+", " ", text)
    text = re.sub(r"[^a-z0-9\u3040-\u30ff\u3400-\u9fff ]+", "", text)
    return re.sub(r"\s+", " ", text).strip()


def actor_terms(actor: dict[str, Any]) -> list[str]:
    terms = [actor.get("canonical_name", ""), actor.get("mitre_id", "")]
    for name in actor.get("names", []):
        terms.append(name.get("name", ""))
        terms.extend(name.get("variants", []) or [])
    return sorted({term for term in terms if term and len(normalize(term)) >= 4}, key=len, reverse=True)


def main() -> int:
    sources = load_json(ACTIVITY_DIR / "sources.json", [])
    index = load_json(DOCS_INDEX, [])
    existing_candidates = load_json(ACTIVITY_DIR / "candidates.json", [])
    published = load_json(ACTIVITY_DIR / "published.json", [])
    rejected = load_json(ACTIVITY_DIR / "rejected.json", [])

    blocked = {(item.get("actor_id"), canonicalize_url(item.get("url", ""))) for item in published + rejected}
    by_key = {(item.get("actor_id"), canonicalize_url(item.get("url", ""))): item for item in existing_candidates}

    cutoff = datetime.now(timezone.utc).date() - timedelta(days=LOOKBACK_DAYS)
    warnings = []

    actors = [{"actor": actor, "terms": actor_terms(actor)} for actor in index]

    for source in sources:
        if source.get("enabled") is False:
            continue
        feed_url = source.get("url", "")
        try:
            data = fetch_bytes(feed_url)
            items = parse_feed(data)
        except Exception as exc:
            warning = f"failed to fetch/parse {feed_url}: {exc}"
            print(f"[WARN] {warning}")
            warnings.append({"source": source.get("id"), "url": feed_url, "error": str(exc)})
            continue

        for item in items:
            url = canonicalize_url(item.get("url", ""))
            if not url:
                continue
            published_date = item.get("published_date") or ""
            if published_date:
                try:
                    if datetime.fromisoformat(published_date).date() < cutoff:
                        continue
                except Exception:
                    pass

            haystack = normalize(" ".join([item.get("title", ""), item.get("summary", ""), url]))
            matched_actor_rows = []
            for actor_row in actors:
                matched_terms = [term for term in actor_row["terms"] if normalize(term) and normalize(term) in haystack]
                if matched_terms:
                    matched_actor_rows.append((actor_row["actor"], matched_terms))

            for actor, matched_terms in matched_actor_rows:
                key = (actor.get("actor_id"), url)
                if key in blocked:
                    continue
                row = {
                    "id": sha1(f"{actor.get('actor_id')}|{url}".encode("utf-8")).hexdigest()[:20],
                    "actor_id": actor.get("actor_id"),
                    "canonical_name": actor.get("canonical_name"),
                    "title": item.get("title", "")[:300],
                    "publisher": source.get("name") or source.get("id"),
                    "published_date": published_date,
                    "url": url,
                    "source_type": source.get("source_type", "vendor_report"),
                    "matched_names": sorted(set(matched_terms), key=str.casefold),
                    "summary": item.get("summary", "")[:500],
                    "review_status": "auto_candidate",
                    "feed_url": feed_url,
                    "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
                by_key[key] = row

    candidates = sorted(by_key.values(), key=lambda row: (row.get("canonical_name", ""), row.get("published_date", ""), row.get("title", "")))
    write_json(ACTIVITY_DIR / "candidates.json", candidates)
    write_json(ACTIVITY_DIR / "fetch-warnings.json", warnings)

    print(f"Fetched activity candidates: {len(candidates)} ({len(warnings)} feed warnings)")
    return 0


if __name__ == "__main__":
    socket.setdefaulttimeout(TIMEOUT_SECONDS)
    raise SystemExit(main())
