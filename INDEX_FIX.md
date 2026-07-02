# Index and reference de-duplication fix

This update fixes display-level duplicate cards and duplicate reference URLs.

## Changes

- Merge public search cards by normalized canonical actor name.
- Preserve all source IDs and naming organizations in the merged card.
- De-duplicate names within each card.
- Canonicalize reference URLs before display.
  - Example: `https://attack.mitre.org/groups/G0007` and `https://attack.mitre.org/groups/G0007/` are shown once.
- Add `scripts/diagnose_microsoft.py` to verify whether Microsoft naming data was fetched, normalized, and included in the public search index.

## Files

- `scripts/build_index.py`
- `scripts/diagnose_microsoft.py`
