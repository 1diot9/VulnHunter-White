# Showcase seed

`db-seed.json` holds the SQLite rows needed for the frontend to list this
bundled MemoBoard project (`id=11`). Workspace files under `../` are already
tracked; runtime `data/app.db` is not.

On backend startup, `seed_bundled_demo_project()` imports these rows when
missing. Disable with `VULNHUNTER_DEMO_SEED=0`.
