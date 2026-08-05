# Threat Model for hermes-id

> **Document version:** 1.2
> **Scope:** Ed25519-based self-sovereign identity for Hermes Agent instances
> **Review date:** August 2026

## Assumptions

1. **The host OS is trusted.** The private key is encrypted at rest, but a
   kernel-level attacker (rootkit, kernel module) can read memory while the
   key is decrypted. We mitigate by keeping the decryption window as short as
   possible (decrypt → use → clear from memory).
2. **The `cryptography` library is trusted.** We rely on PyCA/cryptography's
   Ed25519, X25519, and AES-GCM implementations. A vulnerability in any of
   these would compromise the protocol.
3. **The CSPRNG is trusted.** `os.urandom()` on Linux reads from the kernel's
   ChaCha20-based CSPRNG (``getrandom()`` syscall). We assume it produces
   unpredictable output.
4. **No quantum computer exists yet.** Ed25519 is not post-quantum secure. A
   CRQC running Shor's algorithm could recover the private key from the public
   key. This is an accepted limitation for v1; the protocol version field
   allows future PQ-scheme upgrades.
5. **The passphrase has sufficient entropy.** The security of encrypted key
   storage depends on the passphrase. A weak passphrase (e.g., dictionary
   word) can be brute-forced offline regardless of KDF strength.

## Threat Table

| # | Threat | Likelihood | Impact | Mitigation |
|---|--------|-----------|--------|------------|
| T1 | **Private key file stolen from disk** | Medium (malware, misconfigured backup) | **Critical** — attacker can impersonate the instance | AES-256-GCM encryption with memory-hard KDF (scrypt/Argon2id). File permissions 0600. Directory 0700. |
| T2 | **Private key file stolen and brute-forced** | Low (if passphrase is strong) | **Critical** | Memory-hard KDF (Argon2id preferred, scrypt fallback) makes offline brute-force economically infeasible (~100 guesses/sec with Argon2id at 64MiB) |
| T3 | **Replay attack** (replay an old AUTH message) | Low | **High** — attacker could impersonate a previously authenticated peer | Fresh 256-bit random challenge per handshake. Challenge bound to responder DID in signature. Old AUTH messages have zero reuse value. |
| T4 | **Man-in-the-Middle (MITM)** during handshake | Low (on LAN or localhost) | **High** — attacker could impersonate both sides | Mutual authentication: both sides sign the challenge. Initiator's signature is bound to responder's DID. No way for MITM to complete either proof without the private keys. |
| T5 | **Self-signature forgery** (tamper with identity card) | Low | **High** — attacker modifies claims in a card | Identity card is self-signed with Ed25519. Any field modification breaks the signature. Verification always checks the self-signature first. |
| T6 | **Private key leaked via side-channel** | Very low (local process only) | **Medium** | Ed25519 in `cryptography` is implemented with constant-time operations. X25519 similarly. AES-GCM is DPA-resistant by design. |
| T7 | **Weak random challenge** (predictable nonce) | Very low | **High** — replay becomes possible | `os.urandom(32)` from kernel CSPRNG. Tested for statistical randomness. |
| T8 | **Passphrase brute-force (online)** | Medium | **Medium** — attacker repeatedly tries passphrases | Auth server rate-limits every token/challenge/register endpoint per IP (sliding window, default 30 req/60s). CLI prompts with 3-second delay after wrong guess. |
| T9 | **Identity card confusion** (card from one peer used to claim another's identity) | Low | **Low** — the DID is content-addressed from the public key. A card is intrinsically tied to its key. | DID derivation: `sha256(pubkey)`. Swapping public keys changes the DID. The card's self-signature uses the matching private key. |
| T10 | **Forward secrecy failure** | Very low | **Low** — past sessions exposed if long-term key compromised | Ephemeral X25519 keys per session. HKDF-derived session keys. Long-term Ed25519 key only used for signing, never for encryption. |
| T11 | **Memory exposure** (private key left in memory after use) | Medium (core dumps, swap) | **High** | `secure_zero()` (via `ctypes` `memset`) clears the raw DER/session key buffers we control on every unlock/use/rotate. The `cryptography` object itself may survive in Python's GC, but the serialized bytes we hold are overwritten. |
| T12 | **Denial of service** (handshake server resource exhaustion) | Medium (public-facing server) | **Medium** | The auth server (FastAPI/uvicorn) rate-limits per IP. The TCP handshake server is single-threaded, one connection at a time; for production, wrap with a reverse proxy (nginx) for connection limits. |
| T13 | **Revoked-token reuse** (stolen token used after revocation) | Medium | **High** — attacker reuses a token past its revocation | The auth server keeps an `invalidated_tokens` blacklist; `/verify` (and the offline SDK revocation checker) consult it. Blacklist rows are opportunistically pruned once their tokens have expired, keeping the table bounded. |
| T14 | **Admin-key timing side-channel** (recover the admin key by measuring comparison time) | Very low (needs network timing analysis over TLS) | **High** — admin key grants full registry control | The admin key is compared with `hmac.compare_digest` (constant time), so an attacker cannot infer the key from response timing. Combined with TLS and rate limiting, timing exfiltration is not practical. |

## Security Controls Summary

| Control | Where | What it protects |
|---------|-------|-----------------|
| AES-256-GCM encryption | Storage (`private.enc`) | T1 — key theft from disk |
| Argon2id / scrypt KDF | Storage | T2 — brute-force on stolen blob |
| Fresh random challenge | Handshake | T3 — replay attack |
| Mutual authentication | Handshake | T4 — MITM |
| Self-signature verification | Identity card | T5 — card tampering |
| Constant-time crypto | `cryptography` library | T6 — side channels |
| Constant-time admin key compare | `hmac.compare_digest` | T14 — admin-key timing |
| Kernel CSPRNG | `os.urandom()` | T7 — weak randomness |
| File permissions (0600/0700) | Filesystem | T1 — unauthorized file access |
| Ephemeral X25519 keys | Handshake (optional) | T10 — forward secrecy |
| `secure_zero()` memset | Storage / handshake buffers | T11 — memory exposure |
| Per-IP rate limiting | Auth server | T8, T12 — online brute-force / DoS |
| Token blacklist + prune | Auth server `invalidated_tokens` | T13 — revoked-token reuse |

## Out-of-Scope (accepted risks for v1)

- **Post-quantum security:** Ed25519 is PQ-vulnerable. Future versions may add
  Dilithium or FALCON support via the protocol extension mechanism.
- **DID-level revocation:** Tokens can be revoked server-side (the auth
  server maintains an invalidation blacklist), but there is no mechanism to
  revoke a *long-term identity card* itself. If a key is compromised, the
  operator must generate a new identity and re-establish trust. A future
  revocation registry (SpacetimeDB-based) could address this.
- **Automatic key rotation:** Rotation exists (`hermes-id rotate`, with
  transition proofs so verifiers can confirm authorization), but it is a
  manual operator action — there is no scheduled/time-based auto-rotation.
- **Smart contract / on-chain verification:** No blockchain integration. Trust
  is purely peer-to-peer.
- **Human-friendly identity:** DIDs are hash-derived strings. No human-readable
  names (ENS, etc.) in v1. Applications can add name lookup independently.

## Security Recommendations for Operators

1. **Use a strong passphrase** (≥ 16 characters, mixed case + digits + symbols,
   not a dictionary word).
2. **Install argon2-cffi** for the strongest KDF: `pip install hermes-id[argon2]`.
3. **Back up `~/.hermes/identity/`** after creation. Losing the passphrase OR
   the encrypted blob means losing the identity permanently.
4. **Do not share `private.enc`** or your passphrase with anyone.
5. **Do not run handshake server** on a public-facing network without a
   firewall or reverse proxy rate-limiting.
6. **Monitor for unexpected handshakes** — if you see authentication requests
   you didn't initiate, your identity may have been exposed.
7. **Use `mlock()` on Linux** if available (future enhancement) to prevent
   the private key from being swapped to disk.
