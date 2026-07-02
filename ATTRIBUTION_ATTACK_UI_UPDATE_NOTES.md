# Attribution and ATT&CK display update

This update implements:

- Reported attribution aggregation by value.
- Country normalization and flag display when the country can be identified.
- Multiple sources shown on the same country row.
- Non-country attribution/classification shown separately.
- ATT&CK technique display changed to tactic summary + collapsible tactic groups.

## Updated files

- `scripts/build_index.py`
- `docs/app.js`
- `docs/style.css`

## Rebuild

This update changes the generated public JSON structure. Rebuild data after applying it.

```powershell
python scripts\normalize.py
python scripts\build_index.py
python scripts\fetch_activity.py
python scripts\generate_activity_report.py
python scripts\build_index.py
python scripts\generate_report.py
```

## Notes

- Source organization names remain unchanged.
- Country flags are shown only when the country can be normalized.
- The first ATT&CK tactic group is expanded by default; other groups are collapsed.
