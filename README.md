# Threat Actor Alias DB

Threat Actor Alias DB is a lightweight public database for looking up threat actor names, aliases, naming sources, and source references.

The initial MVP focuses on two redistribution-friendly sources:

- MITRE ATT&CK Groups
- MISP Galaxy Threat Actor clusters

The project is designed as an alias/reference index, not as a definitive attribution database. A name match or alias mapping does not always mean perfect one-to-one equivalence. Some names may refer to overlapping activity clusters, temporary tracking names, campaigns, or vendor-specific classifications.

## Goals

- Search threat actor names and aliases from a single web page
- Preserve source information for each name and reference
- Keep raw source snapshots for traceability
- Generate normalized JSON and a static search index
- Support reviewed updates through GitHub history and pull requests

## Current architecture

```text
scripts/fetch_sources.py      Fetches MITRE ATT&CK and MISP Galaxy source data
scripts/normalize.py          Converts raw source data into normalized actor/name/source records
scripts/build_index.py        Builds the public search index used by the static UI
scripts/generate_report.py    Creates a simple update summary report

data/raw/                     Source snapshots fetched by scripts
data/normalized/              Normalized internal JSON records
docs/                         GitHub Pages static search UI
```

## Quick start

```bash
python scripts/fetch_sources.py
python scripts/normalize.py
python scripts/build_index.py
python scripts/generate_report.py
```

Then open `docs/index.html` locally, or enable GitHub Pages using the `docs/` directory.

## GitHub Pages

After the first data update has run, enable GitHub Pages from:

`Settings` -> `Pages` -> `Build and deployment` -> `Deploy from a branch` -> `main` / `docs`

## Update policy

This database should not fully auto-merge all new aliases. Low-risk source updates can be automated, but mappings that imply `same-as` relationships should be reviewed. The current MVP performs conservative exact-name matching between MITRE and MISP records and preserves source-level attribution.

## Disclaimer

This project aggregates public threat actor naming and alias information for research and reference purposes only. It does not imply definitive attribution, endorsement, or official confirmation by any referenced organization.

See [license and source notices](docs/license-notice.md).
