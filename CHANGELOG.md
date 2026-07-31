# Changelog

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
