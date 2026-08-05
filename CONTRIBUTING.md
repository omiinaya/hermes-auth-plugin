# Contributing to hermes-id

Thank you for contributing! This is a **security-sensitive** project — your
care with keys, tokens, and cryptographic correctness is appreciated.

## Ground rules

- **No security vulnerabilities in GitHub issues.** Report privately via
  [SECURITY.md](./SECURITY.md).
- **Code quality is enforced by CI**: ruff lint + `pytest` with a **100%
  coverage gate** (`--cov-fail-under=85`, branch coverage). New code must
  ship with tests; regressions below the gate fail the build.
- **Never commit secrets.** Private keys, passphrases, tokens, and admin
  keys are gitignored. A committed `private.enc` or `.env` is a release
  blocker.

## Development setup

```bash
# Clone
git clone https://github.com/omiinaya/hermes-auth-plugin.git
cd hermes-auth-plugin

# Install with all extras + dev tools
pip install -e ".[all,dev]"

# Run tests
make test

# Run with coverage gate (same as CI)
make coverage

# Lint
make lint
```

## Project layout

- `src/hermes_id/` — the Python package (CLI + library)
  - `cli.py` / `admin_cli.py` — command-line interfaces
  - `crypto.py` / `identity.py` / `storage.py` — key generation, identity
    cards, secure key storage
  - `handshake.py` — mutual-auth handshake protocol
  - `server.py` — FastAPI auth server + agent registry
  - `sdk.py` / `fastapi_middleware.py` / `fastapi_plugin.py` — app-side
    integration (offline verification, FastAPI dependency)
  - `mcp_server.py` — MCP server exposing auth tools
- `plugins/hermes-id/` — the Hermes Agent plugin
- `docs/` — architecture, protocol, integration, threat model
- `tests/` — the test suite (529+ tests, 100% branch coverage)

## Before submitting

1. Run `make lint` — clean ruff.
2. Run `make test` — all tests pass.
3. Run `make coverage` — **or `make check`** (lint + tests + the 100%
   coverage gate in one command). The gate is 85 but the project sits at
   100; keep it there.
4. (Optional) `pip install pre-commit && pre-commit install` for
   commit-time ruff + whitespace checks.
5. If you changed crypto, handshake, or auth logic, review `docs/THREAT_MODEL.md`
   and update it if your change affects the threat surface.
6. Update `CHANGELOG.md` under "Unreleased".

## Branching

Work on `master`, or a short-lived feature branch. Rebase cleanly and keep
commits focused. Don't force-push shared branches.

## Testing guidance

The full suite is fast (~2 min with `-n auto`) but the CLI/scrypt tests are
the slowest. Run a targeted subset while iterating:

```bash
pytest tests/test_crypto.py tests/test_identity.py -q
pytest tests/test_server.py -q
```

Then run the full suite + coverage gate before pushing — CI enforces it, so
save yourself the round-trip.

## Releasing

Releases are version bumps + CHANGELOG sections + deploy (no git tags —
the version lives in `pyproject.toml` / `__version__` / plugin files):

1. Move the `## Unreleased` CHANGELOG block to a dated `## X.Y.Z` section.
2. Bump the version in **all four** places (they must match):
   - `pyproject.toml` (`version = ...`)
   - `src/hermes_id/__init__.py` (`__version__ = ...`)
   - `plugins/hermes-id/plugin.yaml`
   - `plugins/hermes-id/__init__.py` docstring
3. Push, let CI go green.
4. Build: `.venv/bin/python -m build`
5. Deploy (see past `release:` commits):
   - user-site PROD: `/usr/bin/python3 -m pip install --user
     --break-system-packages --force-reinstall --no-deps dist/*.whl`
   - gateway venv + spacetime-code venv (the MCP host)
   - plugin files: `cp plugins/hermes-id/* ~/.hermes/plugins/hermes-id/`
   - restart the auth service (`su-run "systemctl restart hermes-id-auth"`)
6. Verify: `curl -sk https://192.168.1.10:9488/health` reports the new
   version; MCP `serverInfo` reports it too; identity DID unchanged.