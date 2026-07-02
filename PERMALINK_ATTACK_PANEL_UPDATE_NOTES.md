# Permalink and ATT&CK selected panel update

This update implements:

- Stable actor permalinks using `?actor=<actor_id>`.
- Search URL sharing using `?q=<query>`.
- A copy-link button on each actor card.
- Merged actor IDs are also accepted when opening `?actor=`.
- ATT&CK technique lists are hidden by default.
- Clicking a Tactic label displays only the corresponding Technique list in a selected panel.

## Updated files

- `docs/app.js`
- `docs/style.css`
- `scripts/build_index.py`

`build_index.py` is included from the previous ATT&CK tactic ID / country flag update.

## Rebuild

For permalink-only behavior, data rebuild is not required.  
Because this package includes the ATT&CK tactic ID build script, rebuild if you have not already done so:

```powershell
python scripts\normalize.py
python scripts\build_index.py
python scripts\fetch_activity.py
python scripts\generate_activity_report.py
python scripts\build_index.py
python scripts\generate_report.py
```

## URL examples

```text
?actor=mitre-g0007
?q=APT28
?q=APT28&extended=1
```
