# Mobile and empty ATT&CK panel fix

This update fixes two issues:

## 1. Empty ATT&CK panel box

Previously, the ATT&CK section always rendered the technique panel container, even when no Tactic was selected.  
Because of whitespace/template rendering, an empty bordered box could still appear.

Now, the panel container itself is rendered **only when a Tactic is selected**.

## 2. Mobile / smartphone support

This update improves smartphone usability by:

- adding `<meta name="viewport" content="width=device-width, initial-scale=1">`
- making cards and search UI fit smaller screens
- allowing tactic badges and source badges to wrap cleanly
- stacking ATT&CK panel header/actions vertically on narrow screens
- preventing iOS Safari zoom on the search input
- making action buttons easier to tap

## Updated files

- `docs/app.js`
- `docs/style.css`
- `docs/index.html`
- `scripts/build_index.py` (included unchanged from previous package)

## Rebuild

This update is mainly UI-side.  
If only this package is applied on top of the previous one, data rebuild is not strictly required.

However, if you have not yet rebuilt after the previous ATT&CK fixes, run:

```powershell
python scripts\normalize.py
python scripts\build_index.py
python scripts\fetch_activity.py
python scripts\generate_activity_report.py
python scripts\build_index.py
python scripts\generate_report.py
```

Then force-refresh the browser with Ctrl+F5.
