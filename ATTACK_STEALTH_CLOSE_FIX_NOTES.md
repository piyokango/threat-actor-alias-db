# ATT&CK Stealth and close behavior fix

This update fixes the following issues:

- `Stealth` now receives `TA0005`.
- `Defense Impairment` now receives `TA0112`.
- Clicking the currently selected ATT&CK label again closes the Technique panel.
- A `閉じる` button is added to the Technique panel.
- The guidance text shown before selecting a label is removed.

## Why Stealth had no ID

The previous `TACTIC_IDS` mapping did not include the current Enterprise tactic key `stealth`. MITRE ATT&CK Enterprise Tactics currently lists `TA0005 Stealth`, so the mapping has been updated.

## Updated files

- `scripts/build_index.py`
- `docs/app.js`
- `docs/style.css`

## Rebuild

Because tactic IDs are generated into the public index, rebuild after applying:

```powershell
python scripts\normalize.py
python scripts\build_index.py
python scripts\fetch_activity.py
python scripts\generate_activity_report.py
python scripts\build_index.py
python scripts\generate_report.py
```

Then force-refresh the browser with Ctrl+F5.
