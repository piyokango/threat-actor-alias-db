# Full replacement notes

This package contains the current integrated implementation.

Included fixes:

- MITRE ATT&CK import
- MISP Galaxy import
- Microsoft Threat Actor Naming import
- Conservative Microsoft matching with review candidates
- Duplicate canonical actor de-duplication
- Display-level duplicate actor card consolidation
- Reference URL canonicalization
- Alias row aggregation by name
- Search-match UI that highlights the matched alias when the canonical actor differs
- Microsoft ingestion diagnostics

## Windows rebuild

```powershell
python scripts\fetch_sources.py
python scripts\normalize.py
python scripts\build_index.py
python scripts\generate_report.py
python scripts\diagnose_microsoft.py
```

## Local UI check

```powershell
python -m http.server 8000
```

Open:

```text
http://localhost:8000/docs/
```

Test queries:

```text
APT28
FANCY BEAR
STRONTIUM
Forest Blizzard
Lazarus Group
Midnight Blizzard
NOBELIUM
```
