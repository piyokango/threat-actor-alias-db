#!/usr/bin/env python3
"""Generate a simple update report for review."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
NORMALIZED_DIR = ROOT / "data" / "normalized"
REPORT_DIR = ROOT / "reports"


def load_json(path: Path) -> Any:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    actors = load_json(NORMALIZED_DIR / "actors.json")
    names = load_json(NORMALIZED_DIR / "names.json")
    references = load_json(NORMALIZED_DIR / "references.json")

    source_counts = Counter()
    for actor in actors:
        for source_id in actor.get("source_ids", []):
            source_counts[source_id] += 1

    ambiguous_names = []
    actor_ids_by_name = {}
    for name in names:
        actor_ids_by_name.setdefault(name["normalized_name"], set()).add(name["actor_id"])
    for normalized_name, actor_ids in actor_ids_by_name.items():
        if len(actor_ids) > 1:
            ambiguous_names.append((normalized_name, sorted(actor_ids)))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# Threat Actor Alias DB update report",
        "",
        f"Generated: {now}",
        "",
        "## Summary",
        "",
        f"- Actors: {len(actors)}",
        f"- Names: {len(names)}",
        f"- References: {len(references)}",
        "",
        "## Actors by source",
        "",
    ]

    for source_id, count in sorted(source_counts.items()):
        lines.append(f"- {source_id}: {count}")

    lines.extend(["", "## Ambiguous normalized names", ""])

    if not ambiguous_names:
        lines.append("- None detected")
    else:
        for normalized_name, actor_ids in ambiguous_names[:100]:
            lines.append(f"- `{normalized_name}` appears under {len(actor_ids)} actors: {', '.join(actor_ids)}")
        if len(ambiguous_names) > 100:
            lines.append(f"- ...and {len(ambiguous_names) - 100} more")

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORT_DIR / "latest-update-report.md"
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Wrote {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
