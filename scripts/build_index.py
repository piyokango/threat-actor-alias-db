#!/usr/bin/env python3
"""Build the public static search index."""

from __future__ import annotations

import json
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any


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


def main() -> int:
    actors = load_json(NORMALIZED_DIR / "actors.json")
    names = load_json(NORMALIZED_DIR / "names.json")
    references = load_json(NORMALIZED_DIR / "references.json")

    names_by_actor: dict[str, list[dict[str, Any]]] = defaultdict(list)
    refs_by_actor: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for name in names:
        names_by_actor[name["actor_id"]].append(name)
    for ref in references:
        refs_by_actor[ref["actor_id"]].append(ref)

    index = []
    for actor in actors:
        actor_id = actor["id"]
        actor_names = names_by_actor.get(actor_id, [])
        search_names = sorted({item["name"] for item in actor_names}, key=str.casefold)
        naming_sources = sorted({item["naming_org"] for item in actor_names})
        source_ids = sorted(set(actor.get("source_ids", [])))

        index.append(
            {
                "actor_id": actor_id,
                "canonical_name": actor["canonical_name"],
                "mitre_id": actor.get("mitre_id"),
                "misp_uuid": actor.get("misp_uuid"),
                "primary_source": actor.get("primary_source"),
                "source_ids": source_ids,
                "naming_sources": naming_sources,
                "search_names": search_names,
                "names": actor_names,
                "references": refs_by_actor.get(actor_id, []),
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

    print(f"Built search index with {len(index)} actors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
