# Security Policy

hermes-id is a **self-sovereign identity and authentication** project — the
whole point is handling keys, tokens, and cryptographic handshakes. Security
is not a feature here; it is the product. We take reports seriously.

## Supported Versions

Only the latest release on `master` is supported. Security fixes land on
master and are released as new versions (see `CHANGELOG.md`).

| Version | Supported          |
|---------|--------------------|
| latest  | ✅                 |
| older   | ❌ (upgrade)       |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Report privately to the maintainer:

- **GitHub**: use the private vulnerability reporting form at
  https://github.com/omiinaya/hermes-auth-plugin/security/advisories/new
  (preferred — it creates a draft advisory and we can collaborate in private)
- **Matrix**: message `@omiinaya` directly
- **Email**: `omiinaya@gmail.com`

Please include:

1. **Impact** — what an attacker can do (with/without prior access)
2. **Reproduction** — minimal steps or a small script
3. **Environment** — version, Python version, platform
4. **Suggested fix** (optional)

### Response timeline

- **Acknowledgement**: within 48 hours
- **Triage / first assessment**: within 1 week
- **Fix + release**: typically 1–2 weeks for high-severity issues (may be
  faster for critical remote-execution-class bugs)
- **Public disclosure**: after a fix is released, or 90 days after report
  if the issue is accepted but unfixable — we coordinate disclosure with
  you before going public

## Scope

In scope (this repo):

- `src/hermes_id/` — key generation, storage encryption, handshake
  protocol, auth server endpoints, token issuance/verification
- The Hermes plugin bridge (`plugins/hermes-id/`)
- Build / release pipeline (`.github/workflows/`)

Out of scope (report to the respective project):

- Hermes Agent core — report via the Hermes Agent security process
- The `cryptography` / `fastapi` / `starlette` / `pydantic` libraries
  themselves — report upstream

## Security-relevant design notes

- Private keys are encrypted at rest with **AES-256-GCM**; the passphrase
  never touches disk unencrypted (unless `--no-encrypt` is used in a
  controlled environment).
- Handshake uses Ed25519 challenge-response; the private key never leaves
  the machine performing the handshake.
- Server tokens are signed (Ed25519) and scoped to a project audience
  (`aud`); services verify offline against the server's public identity.
- Rate limiting is enforced on all token endpoints (`/verify`,
  `/token/refresh`, `/token/revoke`) to slow credential stuffing.
- See `docs/THREAT_MODEL.md` for the full threat model and assumptions.

## Secure development

- CI runs the full test suite (parallel) + ruff lint on every push
  (`.github/workflows/ci.yml`), gated on 100% branch coverage
- Dependabot watches `pip` and `github-actions` dependencies weekly
- All new code paths must ship with tests; coverage is tracked in CI
