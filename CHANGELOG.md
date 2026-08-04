# Changelog

## Unreleased

### Fixed — MCP server crashed with mcp SDK >= 2.0

`register_tools()` used the legacy decorator API (`@app.list_tools()`,
`@app.call_tool()`) that mcp 2.0 removed in favour of
`add_request_handler` + low-level params types. With the modern SDK the
server aborted at startup with `AttributeError: 'Server' object has no
attribute 'list_tools'` — so `hermes-id mcp` was completely broken on
fresh installs. Now `register_tools()` detects the SDK API at import
time and registers tools either way: decorator mode for mcp < 2.0,
`add_request_handler("tools/list" / "tools/call")` for mcp >= 2.0. Tool
definitions and dispatch were factored into `_tool_definitions()` /
`_dispatch()` shared by both paths. Verified end-to-end against the
installed mcp 2.0 SDK (tools list + call + unknown-tool + error paths).

### Fixed — startup banner / health endpoint reported stale versions

`SERVER_VERSION` preferred `importlib.metadata` (the installed
distribution's dist-info) over the package's own `__version__`. In
editable installs the dist-info can go stale after a version bump, so
the banner and `/health` reported an old version (e.g. `v1.3.0`) while
the running code was 1.4.0. The package's own `__version__` is now the
source of truth; a mismatch with distribution metadata logs a warning
and reports the running code's version.

### Tests — CLI + MCP coverage up, server.py at 100%

- `tests/test_server_edges.py` (+63) — rate-limiter unit + 429 endpoint
  path, keypair-loading errors, admin-key auto-generation, scoped-admin
  env parsing, every `/authenticate` failure mode, refresh/revoke edge
  cases, register validation, scoped-admin denials, list query
  validation, standalone `verify_auth_token`, `run_server`, and internal
  branches. Uses in-process TestClient + per-test env fixture. server.py
  86% → 100%.
- `tests/test_cli.py` (+30) — handshake listen/connect (success, peer-DID
  mismatch, default port, password prompt, unlock failure, fallthrough),
  server/register/mcp dispatchers (missing extra, starts, import errors,
  project handling, no-project warning), prompt branches (init/sign
  fallback, short/mismatch password retry, rotate confirm + EOF cancel),
  verify-sig error paths, export-no-identity. cli.py 70% → 100%.
- `tests/test_mcp_server.py` (+23) — register_tools against the real mcp
  2.0 SDK (registration + list/call handlers), the legacy decorator path
  (fake SDK), dispatch routing for all 7 tools, exception wrapping on both
  APIs, auth_client login/verify-token-required/import-error,
  verify_signature/verify_rotation error branches, sign failure,
  main() guards (no-SDK exit, entrypoint wiring), stdio run() wiring, and
  the module import-error branch. mcp_server.py 68% → 98%.

## 1.4.0 — 2026-08-04

### Fixed — key derivation was unusably slow (scrypt N=2^20 ≈ 1 GiB)

Every interactive operation (`hermes-id init`, unlock, sign, handshake,
cold auth-server start) paid a **9–18 second** scrypt derivation because
the historical default was N=2^20, r=8 — a 1 GiB working set (OWASP's
high-security file-encryption tier, not an interactive-login tier).
`hermes-id init` took ~18s; each unlock ~10s; the test suite effectively
hung (194 tests × repeated derivations).

### Security fix — `/authenticate` audience scoping (P0)

An agent approved ONLY for project X could previously mint tokens scoped
for **any** project Y by passing `aud=Y` to `/authenticate` — the request
audience was never checked against the agent's approved `projects` list,
defeating the per-project approval workflow. Now `/authenticate` rejects
with 403 any non-empty `aud` outside the agent's approved projects
(global agents with no projects are unaffected; unscoped tokens still
allowed). Regression tests: `TestAudienceScoping` (unapproved-aud 403,
approved-aud success, unscoped allowed, global-agent any-aud).

### Fixed — `_unb64` was lenient (silently decoded garbage to empty bytes)

Python's `urlsafe_b64decode` drops non-alphabet characters by default, so
`_unb64("%%%")` returned `b""` instead of raising — malformed signatures/
messages were accepted as empty instead of failing loudly. `_unb64` now
uses `b64decode(altchars=b"-_", validate=True)` (the strict form).

### Fixed — stale hardcoded version in the server startup banner

`server.run()` printed `hermes-id Auth Server v1.2.0` while the package is
at 1.4.0 — the same stale-version bug class previously fixed in the
health endpoint. Now prints `SERVER_VERSION`. The Hermes plugin
(`plugin.yaml`, docstring, help text) was also bumped 1.1.0 → 1.4.0.
Whole-repo ruff now passes (src, tests, plugins, examples) with justified
per-file-ignores (N999 for hyphenated plugin dirs, B008 for FastAPI
`Depends` idiom in examples).

### Tests — CLI / admin CLI / MCP surfaces went 0% → covered

- `tests/test_cli.py` (+30) — init/show/export/status/verify/sign/
  verify-sig/rotate flows, error paths, force-overwrite, transition-proof
  rotation with backup, dispatcher ImportError paths. Uses a fast-KDF
  fixture (pbkdf2) so the suite stays fast.
- `tests/test_admin_cli.py` (+10) — all five subcommands via a fake
  AuthClient, env/admin-key precedence, error path, close-on-exit.
- `tests/test_mcp_server.py` (+18) — status/export/verify_card/sign/
  verify_signature/verify_rotation handlers + auth_client actions with
  fake clients.

### Changed — v3 blob format (self-describing KDF + parameters)

- **New blob format `HID3`**: `magic(4) + kdf_id(1) + params(12) + salt(16)
  + nonce(12) + ct+tag`. The 12-byte params block (big-endian u32 triple)
  records the exact KDF parameters — argon2id (time, memory, lanes),
  scrypt (n, r, p), pbkdf2 (iterations). Blobs are now fully
  self-describing: they decrypt correctly on any host, **even after code
  defaults change in the future**.
- **scrypt default lowered to N=2^17, r=8, p=1** (~128 MiB, OWASP 2024
  interactive) — `create`/`unlock` drop from ~10-18s to ~1s.
- **Legacy blobs keep working**: v2 (`HID2`) and v1 (headerless) blobs are
  decrypted with **pinned historical parameters** (`_SCRYPT_N_LEGACY =
  2**20`, argon2id 3/65536/4, pbkdf2 600k). `_legacy_params_for()` is the
  single source of truth and is guarded by a test so it can never be
  accidentally changed.
- **`_kdf_id()` probe made instant + cached** — it used to run a full-cost
  scrypt derivation on every encrypt just to check availability; now it
  probes with minimal parameters (n=2) and caches the result per-process.
- `_scrypt_maxmem_for(n, r)` computes the OpenSSL maxmem cap from the
  actual parameters (needed because OpenSSL 3.x defaults to 32 MiB).

### Tests

- Blob-format tests updated/added: v3 header + params present, v3 uses
  *recorded* params (blob with unusual scrypt params decrypts even though
  code defaults differ), v2 legacy blob still decrypts, legacy scrypt
  params are pinned (guards the migration), v1 cross-KDF fallback builds
  blobs with the historical params.
- Full suite completes in ~90s (previously hung indefinitely).

### Migration notes

- No action needed: existing identities (v1/v2 blobs) decrypt unchanged.
- New `init`/`rotate` writes v3 blobs with the faster scrypt default.
- Production identity (argon2id v2 blob, /opt/hermes-id/identity) is
  unaffected — argon2 parameters are historically unchanged.

## 1.3.0 — 2026-07-31

### Added — App-Side SDK (`hermes_id.sdk`)

The consumable foundation for integrating every spacetime-x project with the
hermes-id Auth Server. Closes the verified v1.2 gaps (audit 2026-07-30):

- **Offline-first verification** — `load_server_card()` fetches the auth
  server's identity card once, verifies its self-signature, and caches it to
  disk (`~/.hermes/auth/server-card-<hash>.json`). `verify_token_offline()`
  then verifies tokens **locally** (Ed25519 signature + expiry) with zero
  per-request round-trips. Fresh cache short-circuits the network; stale
  cache falls back when the server is unreachable.
- **Audience enforcement (the P2 fix)** — tokens now carry `aud` (project
  name). `verify_token_offline(..., project=...)` and `HermesIDAuth` reject
  tokens whose audience doesn't match. A token minted for `spacetime-tv` is
  worthless on `spacetime-air`.
- **Env contract** — `HERMES_AUTH_SERVER_URL` + `HERMES_AUTH_PROJECT`
  drive `HermesIDAuth` by default. Both are **required**; the middleware
  refuses to start without a project (no silent unscoped mode).
- **FastAPI-free path** — `verify_token_offline()` works in CLI tools, cron
  jobs, and scripts without FastAPI/httpx.
- **Best-effort online revocation** — `RevocationChecker` asks the auth
  server whether a token was revoked, caches answers per token_id (5 min),
  and fails **open** when the server is unreachable.
- **Per-project token cache** — `TokenCache` persists tokens at
  `~/.hermes/auth-tokens/<project>.json` for script/agent reuse.
- **Server `aud` support** — `/authenticate` accepts `aud`; issued and
  refreshed tokens carry it; `/verify` echoes it.
- `AuthFlow.login(aud=...)` / `AuthClient.authenticate(..., aud=...)` scope
  tokens to a project.

### Removed (landmines)

- **`require_auth` decorator deleted** — it attached a `__fastapi_dependency__`
  attribute FastAPI silently ignores, producing unauthenticated routes with
  no error. Use `Depends(auth.verify)`.
- **`get_agent_did` helper deleted** — it read an `X-Agent-DID` header
  nothing ever set (always 401). Read `payload["did"]` from the verify
  dependency instead.
- `HermesIDAuth(cache_ttl=...)` param replaced by `card_max_age` /
  `revocation_ttl`; `HermesIDAuth(server_url=...)` alone now raises unless
  `project`/`HERMES_AUTH_PROJECT` is provided.

### Tests

- `tests/test_sdk.py` added — 32 tests: offline verify (signature/expiry/
  audience/tamper/malformed), server-card load + cache + stale fallback,
  revocation (revoked/valid/cached/fail-open), FastAPI dependency
  (env contract, 401 paths, wrong-audience 401, offline-first when server
  down), TokenCache round-trip.
- Test servers bind **ephemeral ports** (port 0) with `should_exit` teardown
  — no port collisions or orphaned listeners between runs.
- `HERMES_ID_PASSPHRASE` is set inside the module fixture (restored after),
  not at import — no cross-module env clobbering.
- Full suite: **192 passed** (was 140).

### Deploy & operations (this release)

- **Self-describing encrypted-blob header** (`HID2` + kdf id) — identity
  files are portable across environments. Fixed the production failure
  where an identity created with argon2-cffi installed (Argon2id KDF) could
  not be decrypted on a host without it (scrypt/PBKDF2 fallback → InvalidTag
  on every /challenge). Legacy v1 blobs try each available KDF, validated by
  the GCM tag. scrypt now passes `maxmem` (OpenSSL 3.x silently rejected the
  N=2^20,r=8 ~1 GiB allocation with its 32 MiB default).
- **`HERMES_AUTH_VERIFY` env** — CA bundle path (or true/false) for TLS
  servers, honored by the SDK, `HermesIDAuth`, `AuthClient`, `AuthFlow`.
- **`hermes_id.fastapi_plugin`** — `install_agent_auth(app)` mounts
  `/hermes-id/agent/me` (auth-required) + `/hermes-id/agent/status`
  (public) in 3 lines — the fleet rollout enabler.
- **Registration merges projects** — re-registering the same DID unions its
  requested projects (one agent, many projects); scope growth resets an
  approved agent to pending for re-approval. No-op duplicates still 409.

## 1.2.0 — 2026-07-31

### Added
- **Key rotation** (`hermes-id rotate`) — generates a new Ed25519 keypair and
  identity card carrying a **transition proof** signed by the previous key:
  - `verify_key_rotation(card)` confirms rotations were authorized by the previous controller
  - Previous key auto-backed up to `~/.hermes/identity/rotated/<old-did>/` (skip with `--no-backup`)
  - Rotation metadata merged into the new card (`rotations` counter, `note`, prior card metadata)
  - Confirmation prompt (skip with `--force`), passphrase via env var or prompt
- **TLS support for the Auth Server** — `--tls-cert` / `--tls-key` serve HTTPS
  (verified: HTTPS works, plain HTTP on the TLS port is rejected)
- Malformed base64 in rotation proofs now returns `None` (treated as invalid)
  instead of raising — hardened against malicious cards

### Changed
- Version bumped to 1.2.0
- `status` shows a "Rotated: ✅" line when the card carries a transition proof
- **CI migrated to self-hosted runner** (`runner-hermes-id` on Debian 12 LXC) —
  GitHub Free Actions minutes budget was exhausted, blocking all hosted jobs
  (`runner_id: 0` instant failures). `runs-on: [self-hosted, ubuntu-latest]`
  bypasses the billing gate
- **CI Python setup uses system python3.11 + job-local venv** —
  `actions/setup-python@v5` has no prebuilt builds for Debian 12, and the
  system python is a root-owned hermes venv that rejects pip writes
- **New `[dev]` extra** (`pytest`, `ruff`, `build`, `twine`) — CI installs
  `.[all,dev]`
- **Ruff lint fixed end-to-end**: added `[tool.ruff]` config (E,F,W,I,N,UP,B,SIM,
  ignore E501; tests exempt from B017/BLE001), fixed 247 violations (import
  sorting, unused imports, UP045 annotations, F541 f-strings, B904 raise-from,
  SIM102/105/108, N812, F841, RUF059)
- Docker build job removed from CI (no Docker daemon on the runner)
- `.github/workflows/publish.yml` added — PyPI trusted publishing (OIDC,
  no token); requires one-time PyPI project + trusted publisher setup

## 1.1.0 — 2026-07-30

### Added
- **HTTP Auth Server** (`hermes-id server`) — FastAPI-based challenge-response auth server with:
  - `POST /challenge` + `POST /authenticate` for Ed25519 challenge-response auth
  - `POST /verify` for signed auth token verification
  - `POST /token/refresh` to extend expiring tokens
  - `POST /token/revoke` for token blacklisting
  - SQLite-backed agent registry with `pending → approved → denied` workflow
  - `GET /agents` with pagination, search, and status filtering
  - Admin API key (`X-Admin-Key` header) protection on admin endpoints
  - Rate limiting on auth endpoints (configurable)
  - Configurable CORS origins
  - Structured logging
  - Auto-generated OpenAPI docs at `/docs`

- **Python AuthClient** (`hermes_id.auth_client.AuthClient`) — client library for services
- **AuthFlow** (`hermes_id.auth_client.AuthFlow`) — one-liner agent authentication
- **FastAPI Auth Middleware** (`hermes_id.fastapi_middleware.HermesIDAuth`) — drop-in dependency for any FastAPI service
- **MCP Server** (`hermes-id mcp`) — 6 MCP tools for agent-to-agent identity operations
- **Admin CLI** (`hermes-id-admin`) — manage agent registry from terminal
- **Example integrations** (`examples/`) — protected service and agent client examples

### Changed
- `HERMES_ID_PASSPHRASE` env var now consumed as fallback by all CLI commands
- CLI now supports `server`, `mcp`, and `admin` subcommands
- Hermes plugin updated with auth server and agent registry admin commands

### Infrastructure
- Dockerfile + docker-compose.yml for containerized deployment
- systemd service file (`deploy/hermes-id-auth.service`)
- GitHub Actions CI (lint, test, docker build)
- 123 tests across core crypto, identity, storage, CLI, handshake, and HTTP server

## 1.0.0 — 2026-07-28

### Added
- Ed25519 keypair generation and management
- Self-signed identity cards (DID-compatible Verifiable Credentials)
- Encrypted private key storage (AES-256-GCM with scrypt/Argon2id)
- CLI: `init`, `status`, `show`, `export`, `verify`, `sign`, `verify-sig`
- Mutual auth handshake protocol (TCP, challenge-response)
- Hermes Agent plugin with `/hermes-id` slash commands
- Secure memory zeroing (`secure_zero`)
- X25519 ephemeral key exchange with forward secrecy
