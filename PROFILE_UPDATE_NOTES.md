# Actor profile update

This update adds the remaining actor profile fields:

- Overview
- Reported attribution
- Observed ATT&CK techniques
- Recent activity remains supported

## Added / updated files

- `scripts/normalize.py`
- `scripts/build_index.py`
- `scripts/generate_report.py`
- `docs/app.js`
- `docs/style.css`

## Full rebuild on Windows PowerShell

```powershell
python scripts\fetch_sources.py
python scripts\normalize.py
python scripts\build_index.py
python scripts\fetch_activity.py
python scripts\generate_activity_report.py
python scripts\build_index.py
python scripts\generate_report.py
```

## Generated normalized files

```text
data\normalized\descriptions.json
data\normalized\attribution.json
data\normalized\techniques.json
data\normalized\tactics.json
```

## UI sections

Actor cards can now show:

- Overview
- Reported attribution
- Observed ATT&CK techniques
- Recent activity
- Names and aliases
- References
```
