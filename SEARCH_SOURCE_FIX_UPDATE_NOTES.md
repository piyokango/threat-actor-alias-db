# Search and source display fix update

This update implements all requested fixes:

## Search behavior

Normal search now targets only:

- Canonical name
- Names / aliases
- MITRE ID
- MISP UUID
- Source IDs

It no longer matches actor overview text, attribution, ATT&CK techniques, or recent activity unless the user enables the extended search checkbox.

This prevents searches such as `APT28` from returning unrelated-looking actors merely because their descriptions mention APT28.

## Extended search

A checkbox is added under the search box:

```text
概要・帰属・ATT&CK・最近の動向も検索対象にする
```

When enabled, extended search includes:

- Overview
- Reported attribution
- ATT&CK tactics / techniques
- Recent activity
- Naming source organizations

## Match reason display

Search result cards now show why the item matched, for example:

```text
検索一致
名称・別称: APT28
```

or in extended mode:

```text
概要: APT28
ATT&CK Technique: Spearphishing Attachment
```

## Microsoft naming display

`build_index.py` now infers Microsoft relation labels from `name_type` when older normalized data lacks `source_relation`.

This helps ensure:

```text
Forest Blizzard -> Microsoft現行名
STRONTIUM -> Microsoft旧称
FANCY BEAR -> Microsoft掲載名
APT28 -> Microsoft掲載名
```

## Updated files

- `scripts/build_index.py`
- `docs/app.js`
- `docs/style.css`
- `scripts/normalize.py`

## Rebuild

Because `build_index.py` changed, rebuild the public index:

```powershell
python scripts\normalize.py
python scripts\build_index.py
python scripts\fetch_activity.py
python scripts\generate_activity_report.py
python scripts\build_index.py
python scripts\generate_report.py
```

Then force refresh the browser with Ctrl+F5.
