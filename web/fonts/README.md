# SentinelFS Forensic Ledger Typography Assets

This directory can hold offline `.woff2` font files:
- `InstrumentSerif-Regular.woff2` (Open Font License)
- `IBMPlexMono-Regular.woff2` (Open Font License)
- `IBMPlexMono-SemiBold.woff2` (Open Font License)

If the local font files are not present, `app.css` automatically and cleanly falls back to:
- Heading Display: `Georgia, serif`
- Data, Counters, and Labels: `ui-monospace, Menlo, Monaco, Consolas, monospace`
Both fallback stacks provide the intended high-contrast "forensic ledger" aesthetic with tabular numerals.
