# Security hardened full set

This package includes the regex hotfix and the security review findings.

## Included fixes

### Build / regex

- Fixes `re.PatternError: bad character range \\-.`
- Keeps alias variant absorption for `Black Shadow / BlackShadow` etc.

### URL safety

- UI-side `safeUrl()` added.
- Links are rendered only when URL scheme is `http:` or `https:`.
- Python-side `canonicalize_url()` rejects non-http(s) URLs.

### CSP

- `docs/index.html` includes a meta Content Security Policy.

### Local flags

- Removes runtime dependency on `flagcdn.com`.
- Adds local SVG flags under `docs/assets/flags/`.

### API generation hardening

- `scripts/generate_api.py` limits lookup key length.
- Long lookup keys use a stable SHA-256 short hash.
- Search/name API file counts are capped.
- Public API JSON is scrubbed for unsafe URL schemes.

### Output validation

- Adds `scripts/validate_output.py`.
- Validates:
  - JSON parseability
  - unsafe URL schemes
  - string length limits
  - actor count and per-actor limits
  - API file count and file name length
  - CSP presence

### RSS/activity hardening

- Hardened `scripts/fetch_activity.py` included when present.
- Adds:
  - timeout
  - response size limit
  - XML shape check
  - safe URL and redirect scheme check
  - warning file output

### GitHub Actions

- Adds validation step before commit.
- Adds job timeout.

## Updated / added files

```text
scripts/build_index.py
scripts/generate_api.py
scripts/validate_output.py
scripts/fetch_activity.py
docs/app.js
docs/style.css
docs/index.html
docs/api.md
docs/assets/flags/*.svg
.github/workflows/update-data.yml
SECURITY_HARDENED_FULLSET_NOTES.md
```

## Rebuild

```powershell
python scripts\normalize.py
python scripts\build_index.py
python scripts\fetch_activity.py
python scripts\generate_activity_report.py
python scripts\build_index.py
python scripts\generate_api.py
python scripts\validate_output.py
python scripts\generate_report.py
```

## Notes

- GitHub Actions still uses `actions/checkout@v4` and `actions/setup-python@v5`; SHA pinning is recommended but not included because it increases maintenance burden.
- The CSP is delivered via meta tag because GitHub Pages cannot easily set custom headers.
