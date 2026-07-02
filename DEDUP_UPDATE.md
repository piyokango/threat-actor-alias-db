# Duplicate actor de-duplication update

This update fixes cases where the same canonical actor name appears as separate cards, such as `Lazarus Group`.

## Changes

- Prefer exact canonical-name matching when merging MISP records into existing MITRE/MISP actors.
- Add a final conservative de-duplication pass for actors with the same normalized canonical name.
- Prefer MITRE records as the surviving actor when duplicate canonical groups are merged.
- Preserve aliases, source IDs, MISP UUIDs, references, and source URLs from merged records.
- Write merged duplicate information to `data/normalized/dedup-report.json`.
- Include duplicate merge counts in `reports/latest-update-report.md`.

## Files

- `scripts/normalize.py`
- `scripts/generate_report.py`
