# hermes-id Improvement Plan

## Security (high priority)
- [ ] Add admin API key auth for approve/deny/delete endpoints
- [ ] Rate limiting on /challenge and /authenticate
- [ ] Token blacklisting (logout/revoke)
- [ ] CORS configurable origin

## Testing
- [ ] Tests for server.py (FastAPI endpoints)
- [ ] Tests for auth_client.py
- [ ] Tests for mcp_server.py
- [ ] Tests for CLI server/mcp subcommands

## Infrastructure
- [ ] Dockerfile for auth server
- [ ] Systemd service file
- [ ] Makefile targets (server, mcp, docker)
- [ ] GitHub Actions CI

## Polish
- [ ] Graceful shutdown (signal handling)
- [ ] Structured logging
- [ ] Admin CLI subcommands
- [ ] Token refresh endpoint
- [ ] Agent registry with updated_at
- [ ] Pagination on /agents list
- [ ] Changelog
- [ ] Improved error responses
- [ ] Add /docs (FastAPI auto docs) endpoint docs
- [ ] Integration guide for FastAPI middleware pattern
- [ ] Example app integration
