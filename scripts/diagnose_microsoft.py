#!/usr/bin/env python3
"""Diagnose Microsoft Threat Actor Naming ingestion."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    raw_path = ROOT / "data" / "raw" / "microsoft" / "latest.json"
    names_path = ROOT / "data" / "normalized" / "names.json"
    review_path = ROOT / "data" / "normalized" / "review-candidates.json"
    index_path = ROOT / "docs" / "data" / "search-index.json"

    print("Microsoft ingestion diagnostics")
    print("=" * 40)

    if raw_path.exists():
        text = raw_path.read_text(encoding="utf-8", errors="replace")
        print(f"[OK] raw Microsoft file exists: {raw_path}")
        print(f"     size: {len(text):,} bytes")
        print(f"     contains 'Forest Blizzard': {'Forest Blizzard' in text}")
        print(f"     contains 'Midnight Blizzard': {'Midnight Blizzard' in text}")
    else:
        print(f"[NG] raw Microsoft file is missing: {raw_path}")
        print("     Run: python scripts\\fetch_sources.py")

    names = load_json(names_path)
    if isinstance(names, list):
        microsoft_names = [item for item in names if item.get("source_id") == "microsoft-threat-actor-naming"]
        print(f"[OK] normalized names loaded: {len(names):,}")
        print(f"     Microsoft names: {len(microsoft_names):,}")
        type_counts = Counter(item.get("name_type") for item in microsoft_names)
        print(f"     Microsoft name types: {dict(type_counts)}")
        examples = microsoft_names[:10]
        if examples:
            print("     Microsoft examples:")
            for item in examples:
                print(f"       - {item.get('name')} -> {item.get('actor_id')} ({item.get('name_type')})")
    else:
        print(f"[NG] normalized names missing or invalid: {names_path}")
        print("     Run: python scripts\\normalize.py")

    review = load_json(review_path)
    if isinstance(review, list):
        print(f"[OK] review candidates loaded: {len(review):,}")
        if review[:10]:
            print("     First review candidates:")
            for item in review[:10]:
                display = item.get("new_name") or item.get("previous_name") or "(no name)"
                candidates = ", ".join(item.get("candidate_actor_ids") or [])
                print(f"       - {display}: {item.get('reason')} {f'({candidates})' if candidates else ''}")
    else:
        print(f"[WARN] review candidates file missing or invalid: {review_path}")

    index = load_json(index_path)
    if isinstance(index, list):
        ms_cards = [actor for actor in index if "Microsoft" in actor.get("naming_sources", [])]
        print(f"[OK] public search index loaded: {len(index):,}")
        print(f"     cards with Microsoft naming source: {len(ms_cards):,}")

        for query in ["Forest Blizzard", "STRONTIUM", "Midnight Blizzard", "NOBELIUM"]:
            hits = [
                actor for actor in index
                if any(query.casefold() == str(name).casefold() for name in actor.get("search_names", []))
            ]
            print(f"     exact search-name hits for {query!r}: {len(hits)}")
            for actor in hits[:5]:
                print(f"       - {actor.get('canonical_name')} / {actor.get('actor_id')}")
    else:
        print(f"[NG] public search index missing or invalid: {index_path}")
        print("     Run: python scripts\\build_index.py")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
