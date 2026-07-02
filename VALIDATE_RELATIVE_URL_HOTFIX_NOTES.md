# validate_output.py relative URL hotfix

Fixes this validation error:

```text
Unsafe URL at api/actors.json.actors[0].url: api/v1/actors/....json
```

## Cause

The validator treated every JSON field named `url` as an external URL and required `http` or `https`.

However, the generated API intentionally contains safe local relative URLs such as:

```text
api/v1/actors/mitre-g0007.json
```

## Fix

The validator now allows safe local relative API URLs only when they:

- start with `api/v1/`
- end with `.json`
- do not contain `..`
- do not contain backslashes
- do not contain protocol-like prefixes

It also allows safe local query links such as:

```text
?actor=mitre-g0007
```

The following remain rejected:

```text
javascript:alert(1)
data:text/html,...
//evil.example/path
../secret.json
api/v1/../secret.json
```

## Updated file

```text
scripts/validate_output.py
```

## Re-run

```powershell
python scripts\validate_output.py
```
