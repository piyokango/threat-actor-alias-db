# Japanese country names and reliable flag icons

This update fixes country display in the attribution section.

## What changed

- Country names are displayed in Japanese.
  - Russia -> ロシア
  - China -> 中国
  - North Korea -> 北朝鮮
  - Iran -> イラン
  - United States -> 米国
  - United Kingdom -> 英国
- Country flags are rendered using small flag images when `country_code` is available.
- This avoids the Windows/browser issue where flag emoji can render as plain regional letters such as `RU`.

## Updated files

- `docs/app.js`
- `docs/style.css`
- `docs/index.html`
- `scripts/build_index.py` included unchanged from the previous package

## Note

Flag images are loaded from `flagcdn.com` using ISO 3166-1 alpha-2 country codes.
If you want a fully self-contained site with no external image dependency, the next step would be to add local SVG/PNG flag assets for the countries you support.

## Rebuild

This update is UI-side. Data rebuild is not required if `country_code` already exists in `docs/data/search-index.json`.

If flags still do not appear because `country_code` is missing, rebuild:

```powershell
python scripts\normalize.py
python scripts\build_index.py
python scripts\fetch_activity.py
python scripts\generate_activity_report.py
python scripts\build_index.py
python scripts\generate_report.py
```
