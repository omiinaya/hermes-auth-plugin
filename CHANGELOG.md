# Changelog

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
