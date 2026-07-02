# Alias variant absorption and static API update

This update implements:

## Alias variant absorption

Within the same actor card, display aggregation now absorbs separator variants such as:

- Black Shadow / BlackShadow
- Dark Halo / DarkHalo
- APT 28 / APT28
- TA-505 / TA505
- UNC-2452 / UNC2452
- STORM-0978 / Storm 0978 / STORM0978

Important: this is only used for display aggregation **within the same actor**.
It is not used to merge separate actor records.

The public JSON now includes:

```json
{
  "name": "Black Shadow",
  "variants": ["Black Shadow", "BlackShadow"],
  "compact_normalized_name": "blackshadow"
}
```

## Static REST-like API

A new script generates API JSON under:

```text
docs/api/v1/
```

Supported endpoints:

```text
GET /api/v1/index.json
GET /api/v1/actors.json
GET /api/v1/actors/{actor_id}.json
GET /api/v1/search-index.json
GET /api/v1/search/{query_key}.json
GET /api/v1/names/{name_key}.json
GET /api/v1/lookup-keys.json
```

Because GitHub Pages is static hosting, dynamic server-side `?q=` search is not available.
Precomputed lookup files are generated for known names, aliases, variants, actor IDs, MITRE IDs, MISP UUIDs, and source IDs.

Example:

```text
/api/v1/search/apt28.json
/api/v1/actors/mitre-g0007.json
```

## Updated files

- `scripts/build_index.py`
- `scripts/generate_api.py`
- `docs/app.js`
- `docs/style.css`
- `docs/api.md`
- `.github/workflows/update-data.yml`

## Rebuild

```powershell
python scripts\normalize.py
python scripts\build_index.py
python scripts\fetch_activity.py
python scripts\generate_activity_report.py
python scripts\build_index.py
python scripts\generate_api.py
python scripts\generate_report.py
```
