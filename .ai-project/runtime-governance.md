# Runtime governance

All real project commands use `project_command.py`, which runs preflight then selects the platform-specific project entrypoint argv without a shell.

- Python: require `pyproject.toml`, `uv.lock`, `.python-version`; run `uv run --locked`.
- Node: require `package.json`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`, a version file, and exact `packageManager`; run fixed-version pnpm with `--frozen-lockfile`.
- `uv lock --check`, `uv python find <.python-version>`, `node --version`, and `pnpm --version` must match committed locks and pins before a command runs. Missing tools, locks, or matching runtime versions stop work. Never fall back to system Python, Conda base/shared codex, bare pip, global npm, yarn, or bun.
- Worktree creation does not install dependencies. First project entrypoint use performs locked lazy sync into an isolated environment. Caches may be shared on the same filesystem; `.venv` and `node_modules` cannot be shared or cloud-synced.
- Cloud setup and branch maintenance install fixed uv/pnpm and execute locked sync/install in separate Cloud environment steps.
