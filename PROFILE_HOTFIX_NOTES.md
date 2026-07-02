# Profile hotfix

Fixes `KeyError: 'actor_id'` in `scripts/normalize.py`.

## Cause

MITRE ATT&CK technique rows were added without `actor_id`, then the final sort expected every technique row to contain `actor_id`.

## Fixed file

- `scripts/normalize.py`

## Re-run

```powershell
python scripts\normalize.py
python scripts\build_index.py
python scripts\fetch_activity.py
python scripts\generate_activity_report.py
python scripts\build_index.py
python scripts\generate_report.py
```
