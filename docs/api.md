# Threat Actor Alias DB API

This repository publishes a static REST-like JSON API under GitHub Pages.

Because GitHub Pages is static hosting, arbitrary server-side query parameters such as
`/api/search?q=APT28` cannot be executed on the server.

Instead, the API provides:

- full JSON indexes
- actor detail JSON files
- precomputed search JSON files for known names, aliases, IDs, and source IDs

## Base path

```text
/api/v1/
```

On GitHub Pages:

```text
https://piyokango.github.io/threat-actor-alias-db/api/v1/
```

## Endpoints

### API metadata

```text
GET /api/v1/index.json
```

### Actor list

```text
GET /api/v1/actors.json
```

### Actor detail

```text
GET /api/v1/actors/{actor_id}.json
```

Example:

```text
GET /api/v1/actors/mitre-g0007.json
```

### Full search index

```text
GET /api/v1/search-index.json
```

### Precomputed search

```text
GET /api/v1/search/{query_key}.json
```

Examples:

```text
GET /api/v1/search/apt28.json
GET /api/v1/search/fancybear.json
GET /api/v1/search/forestblizzard.json
```

The query key is compact-normalized.

The following values map to the same key:

```text
APT28
APT 28
APT-28
```

All become:

```text
apt28
```

### Name lookup only

```text
GET /api/v1/names/{name_key}.json
```

This is stricter than `search/` and is intended for name/alias lookup.

## Response examples

### Actor detail

```json
{
  "generated_at": "2026-07-02T00:00:00Z",
  "actor": {
    "actor_id": "mitre-g0007",
    "canonical_name": "APT28",
    "names": [],
    "overview": {},
    "reported_attribution": {},
    "observed_techniques": {},
    "references": []
  }
}
```

### Precomputed search

```json
{
  "generated_at": "2026-07-02T00:00:00Z",
  "query_key": "apt28",
  "count": 1,
  "results": [
    {
      "actor_id": "mitre-g0007",
      "canonical_name": "APT28",
      "web_url": "?actor=mitre-g0007"
    }
  ]
}
```

## Notes

- This API is static JSON.
- It does not independently confirm attribution.
- Actor names and aliases are derived from public sources.
- For dynamic search, consume `/api/v1/search-index.json` client-side and filter locally.
