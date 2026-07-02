# Threat Actor Alias DB

Threat Actor Alias DB is a lightweight public database for looking up threat actor names, aliases, naming sources, and source references.

The current MVP focuses on three public sources:

- MITRE ATT&CK Groups
- MISP Galaxy Threat Actor clusters
- Microsoft Threat Actor Naming public mapping

The project is designed as an alias/reference index, not as a definitive attribution database. A name match or alias mapping does not always mean perfect one-to-one equivalence. Some names may refer to overlapping activity clusters, temporary tracking names, campaigns, or vendor-specific classifications.

## Goals

- Search threat actor names and aliases from a single web page
- Preserve source information for each name and reference
- Show which organizations use or publish each name
- Show the matched alias when a searched name resolves to a different canonical actor
- Generate normalized JSON and a static search index
- Support reviewed updates through GitHub history and pull requests

## Current architecture

```text
scripts/fetch_sources.py        Fetches MITRE ATT&CK, MISP Galaxy, and Microsoft mapping data
scripts/normalize.py            Converts raw source data into normalized actor/name/source records
scripts/build_index.py          Builds the public search index used by the static UI
scripts/generate_report.py      Creates a simple update summary report
scripts/diagnose_microsoft.py   Checks Microsoft ingestion status

data/raw/                       Source snapshots fetched by scripts
data/normalized/                Normalized internal JSON records
data/public/                    Public search index copy
docs/                           GitHub Pages static search UI
```

## Quick start on Windows PowerShell

```powershell
python scripts\fetch_sources.py
python scripts\normalize.py
python scripts\build_index.py
python scripts\generate_report.py
python scripts\diagnose_microsoft.py
```

Then run a local web server:

```powershell
python -m http.server 8000
```

Open:

```text
http://localhost:8000/docs/
```

## GitHub Pages

Enable GitHub Pages from:

`Settings` -> `Pages` -> `Build and deployment` -> `Deploy from a branch` -> `main` / `docs`

The public URL will be:

```text
https://piyokango.github.io/threat-actor-alias-db/
```

## Update policy

This database should not fully auto-merge all new aliases. Low-risk source updates can be automated, but mappings that imply `same-as` relationships should be reviewed. The current MVP performs conservative matching between MITRE, MISP, and Microsoft records and preserves source-level attribution.

## Display behavior

The public search index performs display-level consolidation:

- Same canonical actor names are shown as one card.
- Identical alias names across sources are shown as one row with multiple source badges.
- Reference URLs are canonicalized to avoid duplicates such as trailing slash variants.
- If a searched alias resolves to a different canonical actor, the matched alias is shown near the top of the card.

## Disclaimer

This project aggregates public threat actor naming and alias information for research and reference purposes only. It does not imply definitive attribution, endorsement, or official confirmation by any referenced organization.

See [license and source notices](docs/license-notice.md).
