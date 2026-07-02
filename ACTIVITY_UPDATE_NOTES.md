# Weekly activity update

This package adds weekly recent-activity candidate collection.

## Policy

- RSS/Atom feeds are checked weekly by GitHub Actions.
- Matching is based on actor canonical names and aliases.
- Automatically matched items are written to `data/activity/candidates.json`.
- Public UI displays only reviewed items in `data/activity/published.json`.
- False positives can be moved to `data/activity/rejected.json`.

## Review workflow

1. Check `reports/latest-activity-candidates.md`.
2. Confirm whether each item is really relevant to the actor.
3. Move confirmed items from `data/activity/candidates.json` to `data/activity/published.json`.
4. Move false positives to `data/activity/rejected.json`.
5. Run:

```powershell
python scripts\build_index.py
```

## Full rebuild

```powershell
python scripts\fetch_sources.py
python scripts\normalize.py
python scripts\build_index.py
python scripts\fetch_activity.py
python scripts\generate_activity_report.py
python scripts\build_index.py
python scripts\generate_report.py
```
