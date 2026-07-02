# ATT&CK ID, flag, and match reason fix

This update implements:

- ATT&CK Tactic IDs in tactic labels and group headers.
- Clickable ATT&CK tactic labels that open and scroll to the corresponding technique group.
- Fallback country flag rendering in the UI.
- Stronger country normalization in `build_index.py`.
- Suppression of redundant match reason rows such as `名称・別称: APT28` when the matched name badge already shows the same information.

## Updated files

- `scripts/build_index.py`
- `docs/app.js`
- `docs/style.css`

## Rebuild

This update changes generated public JSON for ATT&CK tactic IDs and country flag metadata. Rebuild the public index:

```powershell
python scripts\normalize.py
python scripts\build_index.py
python scripts\fetch_activity.py
python scripts\generate_activity_report.py
python scripts\build_index.py
python scripts\generate_report.py
```

Then force refresh the browser with Ctrl+F5.
