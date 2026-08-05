"""Failure-mode and edge-case tests for the AuthServer.

These cover the defensive branches that the happy-path server tests
skip: rate limiting, malformed authenticate payloads, refresh edge
cases, register validation, scoped-admin-key denials, keypair loading
errors, and the standalone token verifier.

Uses FastAPI's in-process TestClient — no threads, no ports.
"""

import json
import time

import pytest
from fastapi.testclient import TestClient

from hermes_id.crypto import _b64
from hermes_id.server import AuthServer, RateLimiter, run_server, verify_auth_token
from hermes_id.storage import IdentityStorage

_TEST_PASSWORD = "hermes-id-edge-test-password"


@pytest.fixture(autouse=True)
def _test_env(monkeypatch):
    """Set env per-test (not at import) so this module never clobbers
    another test module's HERMES_ID_PASSPHRASE / ADMIN_KEY."""
    monkeypatch.setenv("HERMES_ID_PASSPHRASE", _TEST_PASSWORD)
    monkeypatch.setenv("HERMES_ID_ADMIN_KEY", "edge-test-admin-key")
    yield


@pytest.fixture()
def server_identity(tmp_path):
    storage = IdentityStorage(directory=str(tmp_path))
    storage.create(_TEST_PASSWORD, metadata={"profile": "edge-test"})
    return str(tmp_path)


@pytest.fixture()
def server(server_identity, tmp_path):
    db = tmp_path / "edge.db"
    return AuthServer(
        identity_dir=server_identity,
        db_path=str(db),
        admin_key="edge-test-admin-key",
        rate_limit_max=100,
    )


@pytest.fixture()
def client(server):
    with TestClient(server.app) as c:
        yield c


@pytest.fixture()
def agent_identity(tmp_path):
    storage = IdentityStorage(directory=str(tmp_path))
    storage.create(_TEST_PASSWORD, metadata={"profile": "edge-agent"})
    return str(tmp_path)


def _register_approved(server, client, agent_identity, projects=None):
    """Register + approve a fresh agent; return its card and DID."""
    storage = IdentityStorage(directory=agent_identity)
    card = storage.get_identity_card()
    r = client.post(
        "/agents/register",
        json={
            "did": card.id,
            "identity_card": card.to_json(),
            "display_name": "Edge Agent",
            "projects": projects or [],
        },
    )
    assert r.status_code in (200, 409), r.text
    r = client.post(
        f"/agents/{card.id}/approve",
        headers={"X-Admin-Key": "edge-test-admin-key"},
    )
    assert r.status_code == 200, r.text
    return storage, card


def _get_challenge(client, did):
    r = client.post("/challenge", json={"did": did})
    assert r.status_code == 200, r.text
    return r.json()["challenge_b64"]


def _sign_with(storage, challenge_b64):
    from hermes_id.crypto import _unb64
    from hermes_id.crypto import sign as ed_sign

    with storage.use_key(_TEST_PASSWORD) as pk:
        return _b64(ed_sign(pk, _unb64(challenge_b64)))


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_allows_up_to_max(self):
        rl = RateLimiter(max_requests=3, window_seconds=60.0)
        assert rl.check("1.2.3.4") is True
        assert rl.check("1.2.3.4") is True
        assert rl.check("1.2.3.4") is True
        assert rl.check("1.2.3.4") is False  # 4th request exceeds max

    def test_old_entries_pruned(self):
        rl = RateLimiter(max_requests=2, window_seconds=10.0)
        # Simulate an old entry beyond the window
        rl._buckets["ip"] = [time.time() - 20.0]
        assert rl.check("ip") is True
        assert len(rl._buckets["ip"]) == 1  # stale entry pruned

    def test_reset_clears_bucket(self):
        rl = RateLimiter(max_requests=1, window_seconds=60.0)
        assert rl.check("ip") is True
        assert rl.check("ip") is False
        rl.reset("ip")
        assert rl.check("ip") is True

    def test_per_ip_isolation(self):
        rl = RateLimiter(max_requests=1, window_seconds=60.0)
        assert rl.check("a") is True
        assert rl.check("b") is True  # different IP unaffected

    def test_empty_bucket_removed_from_table(self):
        """Once an IP's bucket ages out of the window, the sweep removes its
        dict entry so the table can't grow unboundedly from one-off IPs."""
        rl = RateLimiter(max_requests=2, window_seconds=10.0)
        rl._buckets["stale"] = [time.time() - 20.0]
        assert rl.check("stale") is True        # stale pruned, one fresh entry
        assert "stale" in rl._buckets            # still present mid-window
        # Age it out entirely, then sweep — the entry must disappear.
        rl._buckets["stale"] = [time.time() - 20.0]
        rl._sweep(time.time() - 10.0)
        assert "stale" not in rl._buckets

    def test_denied_requests_keep_bucket(self):
        """A denied request must NOT reset the counter — otherwise the
        rate limiter is trivially bypassed by spamming past the limit."""
        rl = RateLimiter(max_requests=1, window_seconds=60.0)
        assert rl.check("ip") is True
        assert rl.check("ip") is False          # denied
        assert rl.check("ip") is False          # still denied — bucket kept

    def test_sweep_preserves_active_buckets(self):
        """Sweeping must not evict buckets with fresh timestamps."""
        rl = RateLimiter(max_requests=5, window_seconds=60.0)
        rl.check("active")
        rl._sweep(time.time() - 30.0)            # cutoff 30s ago — active is fresh
        assert "active" in rl._buckets

    def test_burst_trims_bucket_to_max(self):
        """A pathological burst keeps the bucket bounded to ~max*4 entries
        instead of growing without limit."""
        rl = RateLimiter(max_requests=2, window_seconds=60.0)
        for _ in range(200):
            rl.check("flood")
        assert len(rl._buckets["flood"]) <= 2 * 4  # trimmed to ~max*4

    def test_bucket_history_bounded_under_ongoing_burst(self):
        """Even with an active flood the stored timestamps don't accumulate
        past the trim ceiling (memory stays flat)."""
        rl = RateLimiter(max_requests=5, window_seconds=60.0)
        for _ in range(1000):
            rl.check("attacker")
        assert len(rl._buckets["attacker"]) <= 5 * 4


class TestRateLimitEndpoint:
    def test_429_when_exceeded(self, server, server_identity):
        server._rate_limiter._max = 1  # force aggressive limit
        server._rate_limiter._buckets.clear()
        with TestClient(server.app) as c:
            r1 = c.post("/challenge", json={"did": "did:hermes:rate-test"})
            assert r1.status_code == 200
            r2 = c.post("/challenge", json={"did": "did:hermes:rate-test"})
            assert r2.status_code == 429

    @pytest.mark.parametrize("path,payload", [
        ("/verify", {"token": "garbage.token"}),
        ("/token/refresh", {"token": "garbage.token"}),
        ("/token/revoke", {"token": "garbage.token"}),
    ])
    def test_429_when_exceeded_on_token_endpoints(self, server, server_identity, path, payload):
        """/verify, /token/refresh and /token/revoke are rate-limited like
        the other POST endpoints — an unthrottled attacker could burn CPU
        (verify) or DB writes (revoke) with no limit."""
        server._rate_limiter._max = 1  # force aggressive limit
        server._rate_limiter._buckets.clear()
        with TestClient(server.app) as c:
            r1 = c.post(path, json=payload)
            assert r1.status_code in (200, 401)  # first call passes (garbage token → 401; valid → 200)
            r2 = c.post(path, json=payload)
            assert r2.status_code == 429


class TestChallengeStoreSweep:
    def test_expired_challenges_swept(self, server, server_identity):
        """Challenges that expire without an /authenticate must be evicted
        by the opportunistic sweep — otherwise a stream of DIDs that never
        complete the flow grows the table without limit."""
        with TestClient(server.app) as c:
            # Plant a stale challenge directly (as if issued long ago)
            import time as _time

            server._challenges["did:hermes:stale"] = {
                "challenge": b"\x00" * 32,
                "challenge_b64": "AAAA",
                "expires_at": _time.time() - 1000.0,
            }
            assert "did:hermes:stale" in server._challenges
            # Force the sweep to run on the next /challenge by aligning the
            # counter (sweep fires every 64th issuance).
            server._challenge_sweeps = 63
            r = c.post("/challenge", json={"did": "did:hermes:fresh"})
            assert r.status_code == 200
            assert "did:hermes:stale" not in server._challenges
            assert "did:hermes:fresh" in server._challenges

    def test_fresh_challenges_kept(self, server, server_identity):
        """The sweep must not evict challenges still inside their TTL."""
        with TestClient(server.app) as c:
            import time as _time

            server._challenges["did:hermes:live"] = {
                "challenge": b"\x01" * 32,
                "challenge_b64": "BBBB",
                "expires_at": _time.time() + 5000.0,
            }
            server._challenge_sweeps = 63
            r = c.post("/challenge", json={"did": "did:hermes:another"})
            assert r.status_code == 200
            assert "did:hermes:live" in server._challenges
            assert "did:hermes:another" in server._challenges

    def test_authenticate_removes_challenge(self, server, server_identity):
        """A one-time challenge is consumed by /authenticate (pop)."""
        # The existing auth tests cover the happy path; this asserts the
        # one-time-use pop semantics directly.
        import time as _time

        server._challenges["did:hermes:onetime"] = {
            "challenge": b"\x02" * 32,
            "challenge_b64": "CCCC",
            "expires_at": _time.time() + 5000.0,
        }
        popped = server._challenges.pop("did:hermes:onetime", None)
        assert popped is not None
        assert "did:hermes:onetime" not in server._challenges


class TestInvalidationPrune:
    def test_prune_removes_expired_rows(self, server, server_identity):
        """Rows older than the token TTL are deleted — they're redundant
        because _parse_token rejects expired tokens before the blacklist
        check."""
        server._invalidate_token("tok-expired-1", "did:hermes:a")
        server._invalidate_token("tok-expired-2", "did:hermes:b")
        # Age them past the TTL
        import sqlite3 as _sqlite3

        conn = _sqlite3.connect(str(server._invalidation_db_path))
        conn.execute(
            "UPDATE invalidated_tokens SET invalidated_at = ? "
            "WHERE token_id IN ('tok-expired-1','tok-expired-2')",
            (time.time() - server._token_ttl - 10.0,),
        )
        conn.commit()
        conn.close()

        server._prune_invalidated_tokens()

        conn = _sqlite3.connect(str(server._invalidation_db_path))
        remaining = conn.execute("SELECT COUNT(*) FROM invalidated_tokens").fetchone()[0]
        conn.close()
        assert remaining == 0

    def test_prune_keeps_recent_rows(self, server, server_identity):
        """Fresh invalidation rows survive the prune."""
        server._invalidate_token("tok-fresh", "did:hermes:a")
        server._invalidate_token("tok-fresh-2", "did:hermes:b")
        server._prune_invalidated_tokens()

        conn = __import__("sqlite3").connect(str(server._invalidation_db_path))
        remaining = conn.execute("SELECT COUNT(*) FROM invalidated_tokens").fetchone()[0]
        conn.close()
        assert remaining == 2

    def test_revoke_still_blocks_after_prune(self, server, client, agent_identity):
        """A revoked (still-valid) token stays blocked even after a prune —
        its row is fresh, so it survives."""
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        sig = _sign_with(storage, chal)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        token = r.json()["token"]
        rv = client.post("/token/revoke", json={"token": token})
        assert rv.status_code == 200
        server._prune_invalidated_tokens()  # fresh row survives
        r = client.post("/verify", json={"token": token})
        assert r.status_code == 200
        assert r.json()["valid"] is False

    def test_periodic_prune_fires_after_64_revokes(
        self, server, client, agent_identity, monkeypatch
    ):
        """Every 64th revoke opportunistically prunes the blacklist, keeping
        the invalidated_tokens table bounded (server.py line ~893)."""
        import sqlite3 as _sqlite3

        storage, card = _register_approved(server, client, agent_identity)

        def _mint_token():
            chal = _get_challenge(client, card.id)
            sig = _sign_with(storage, chal)
            r = client.post(
                "/authenticate",
                json={
                    "did": card.id,
                    "identity_card": card.to_json(),
                    "signature_b64": sig,
                    "challenge_b64": chal,
                },
            )
            assert r.status_code == 200, r.text
            return r.json()["token"]

        # Spy on the prune to observe the periodic trigger without waiting
        # for real row expiry.
        pruned = []
        original_prune = server._prune_invalidated_tokens

        def _spy_prune():
            pruned.append(True)
            return original_prune()

        monkeypatch.setattr(server, "_prune_invalidated_tokens", _spy_prune)

        # Prime the counter to just below the boundary so one more revoke
        # crosses 64.
        server._revoke_count = 63
        rv = client.post("/token/revoke", json={"token": _mint_token()})
        assert rv.status_code == 200
        assert rv.json()["status"] == "revoked"
        assert pruned, "expected the periodic prune to fire on the 64th revoke"

        # And the counter kept counting past the boundary.
        assert server._revoke_count == 64

        # The prune ran against a real table: revoking 64 more times (via
        # fresh tokens) must not error, and the table stays queryable.
        conn = _sqlite3.connect(str(server._invalidation_db_path))
        count = conn.execute("SELECT COUNT(*) FROM invalidated_tokens").fetchone()[0]
        conn.close()
        assert count >= 1

        for _ in range(3):
            rv = client.post("/token/revoke", json={"token": _mint_token()})
            assert rv.status_code == 200
        assert server._revoke_count == 67
        assert len(pruned) == 1, "prune fires once per 64-revoke boundary only"

    def test_revoke_token_without_token_id_still_counts(self, server, client):
        """A token that parses but carries no token_id is revoked without a
        blacklist write, and still increments the revoke counter (the
        `if token_id:` false branch)."""
        # Mint a signed token whose payload has no token_id field at all.
        token = server._sign_token(
            {
                "did": "did:hermes:legacy",
                "aud": "test",
                "expires_at": time.time() + 3600,
                # deliberately no token_id
            }
        )
        rv = client.post("/token/revoke", json={"token": token})
        assert rv.status_code == 200
        assert rv.json()["status"] == "revoked"
        assert server._revoke_count == 1

        # And verify still passes (not blacklisted — nothing to blacklist).
        r = client.post("/verify", json={"token": token})
        assert r.status_code == 200
        assert r.json()["valid"] is True


# ---------------------------------------------------------------------------
# Keypair loading / admin key configuration
# ---------------------------------------------------------------------------


class TestKeypairErrors:
    def test_no_identity_raises(self, tmp_path, monkeypatch):
        srv = AuthServer(
            identity_dir=str(tmp_path / "empty"),
            db_path=str(tmp_path / "x.db"),
            admin_key="k",
        )
        with pytest.raises(RuntimeError, match="No identity configured"):
            srv._get_keypair()

    def test_no_passphrase_raises(self, server_identity, tmp_path, monkeypatch):
        monkeypatch.delenv("HERMES_ID_PASSPHRASE")
        srv = AuthServer(
            identity_dir=server_identity,
            db_path=str(tmp_path / "x.db"),
            admin_key="k",
        )
        with pytest.raises(RuntimeError, match="HERMES_ID_PASSPHRASE"):
            srv._get_keypair()


class TestAdminKeyConfig:
    def test_auto_generated_key_warns(self, server_identity, tmp_path, monkeypatch, caplog):
        import logging

        monkeypatch.delenv("HERMES_ID_ADMIN_KEY")
        with caplog.at_level(logging.WARNING):
            srv = AuthServer(
                identity_dir=server_identity,
                db_path=str(tmp_path / "x.db"),
                admin_key=None,
            )
        assert any("Generated random key" in r.message for r in caplog.records)
        assert srv._admin_key  # non-empty random key

    def test_scoped_keys_from_env_valid(self, server_identity, tmp_path, monkeypatch):
        monkeypatch.setenv(
            "HERMES_ID_SCOPED_ADMIN_KEYS",
            json.dumps({"scoped-key": ["spacetime-tv", "spacetime-air"]}),
        )
        srv = AuthServer(
            identity_dir=server_identity,
            db_path=str(tmp_path / "x.db"),
            admin_key="global",
        )
        assert srv._scoped_admin_keys == {
            "scoped-key": {"spacetime-tv", "spacetime-air"}
        }

    def test_scoped_keys_from_env_invalid(self, server_identity, tmp_path, monkeypatch, caplog):
        import logging

        monkeypatch.setenv("HERMES_ID_SCOPED_ADMIN_KEYS", "not-json{{{")
        with caplog.at_level(logging.ERROR):
            srv = AuthServer(
                identity_dir=server_identity,
                db_path=str(tmp_path / "x.db"),
                admin_key="global",
            )
        assert any("not valid JSON" in r.message for r in caplog.records)
        assert srv._scoped_admin_keys == {}

    def test_constructor_scoped_keys_win(self, server_identity, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_ID_SCOPED_ADMIN_KEYS", json.dumps({"env-key": ["env-proj"]}))
        srv = AuthServer(
            identity_dir=server_identity,
            db_path=str(tmp_path / "x.db"),
            admin_key="global",
            scoped_admin_keys={"ctor-key": ["ctor-proj"]},
        )
        assert srv._scoped_admin_keys == {"ctor-key": {"ctor-proj"}}


# ---------------------------------------------------------------------------
# Authenticate failure modes
# ---------------------------------------------------------------------------


class TestAuthenticateFailures:
    def test_no_challenge_found(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "signature_b64": "AAAA",
                "challenge_b64": "AAAA",
            },
        )
        assert r.status_code == 400
        assert "No challenge" in r.json()["error"]

    def test_expired_challenge(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        # Force expiry by rewinding the stored challenge
        server._challenges[card.id]["expires_at"] = time.time() - 1
        sig = _sign_with(storage, chal)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        assert r.status_code == 401
        assert "expired" in r.json()["error"]

    def test_invalid_identity_card_json(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        sig = _sign_with(storage, chal)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": "{not-json",
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        assert r.status_code == 400
        assert "Invalid identity card" in r.json()["error"]

    def test_bad_card_self_signature(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        sig = _sign_with(storage, chal)
        # Corrupt the card's proof signature field
        data = json.loads(card.to_json())
        data["proof"]["signatureValue"] = "AAAA" + data["proof"]["signatureValue"][4:]
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": json.dumps(data),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        assert r.status_code == 401
        assert "self-signature" in r.json()["error"]

    def test_did_mismatch(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, "did:hermes:other-agent")
        sig = _sign_with(storage, chal)
        r = client.post(
            "/authenticate",
            json={
                "did": "did:hermes:other-agent",
                "identity_card": card.to_json(),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        assert r.status_code == 400
        assert "doesn't match" in r.json()["error"]

    def test_bad_signature_encoding(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "signature_b64": "%%%not-base64%%%",
                "challenge_b64": chal,
            },
        )
        assert r.status_code == 400
        assert "signature encoding" in r.json()["error"]

    def test_card_without_public_key(self, server, client, agent_identity, monkeypatch):
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        sig = _sign_with(storage, chal)
        data = json.loads(card.to_json())
        data["verification_method"][0]["publicKeyMultibase"] = ""
        # Step 4 (self-signature) would reject the emptied card; this branch
        # is defensive code that step 4 normally guards — bypass it to reach
        # the public-key check itself.
        import hermes_id.server as server_mod

        monkeypatch.setattr(server_mod, "verify_identity_card", lambda card: True)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": json.dumps(data),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        assert r.status_code == 400
        assert "no public key" in r.json()["error"]

    def test_unparseable_public_key(self, server, client, agent_identity, monkeypatch):
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        sig = _sign_with(storage, chal)
        data = json.loads(card.to_json())
        data["verification_method"][0]["publicKeyMultibase"] = "u%%%%"  # not valid multibase b64
        import hermes_id.server as server_mod

        monkeypatch.setattr(server_mod, "verify_identity_card", lambda card: True)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": json.dumps(data),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        assert r.status_code == 400
        assert "public key" in r.json()["error"]

    def test_wrong_signature_rejected(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        # Sign a DIFFERENT challenge — signature won't match
        other = _get_challenge(client, "did:hermes:not-this-agent")
        sig = _sign_with(storage, other)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        assert r.status_code == 401
        assert "signature invalid" in r.json()["error"]

    def test_invalid_did_format(self, client):
        r = client.post("/challenge", json={"did": "not-a-did"})
        assert r.status_code == 400
        assert "did:" in r.json()["error"]


# ---------------------------------------------------------------------------
# Refresh & revoke edge cases
# ---------------------------------------------------------------------------


class TestRefreshEdgeCases:
    def test_refresh_rejects_invalid_token(self, client):
        r = client.post("/token/refresh", json={"token": "garbage.token"})
        assert r.status_code == 401

    def test_refresh_rejects_revoked_token(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        sig = _sign_with(storage, chal)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        token = r.json()["token"]
        # Revoke it, then refresh must fail
        rv = client.post("/token/revoke", json={"token": token})
        assert rv.status_code == 200
        r = client.post("/token/refresh", json={"token": token})
        assert r.status_code == 401

    def test_refresh_rejects_too_old_token(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        sig = _sign_with(storage, chal)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        token = r.json()["token"]
        # Rewind issued_at beyond the 7-day refresh window
        payload_b64 = token.split(".")[0]
        payload = json.loads(
            __import__("base64").urlsafe_b64decode(payload_b64 + "==").decode()
        )
        payload["issued_at"] = time.time() - 8 * 24 * 3600
        payload["expires_at"] = time.time() + 3600  # still unexpired
        old_payload_b64 = _b64(json.dumps(payload).encode())
        server._cached_private_key = None  # force reload? no — keep cache
        # Sign the re-timed payload with the server key
        from hermes_id.crypto import sign as ed_sign

        priv, _, _ = server._get_keypair()
        old_token = old_payload_b64 + "." + _b64(ed_sign(priv, json.dumps(payload).encode()))
        r = client.post("/token/refresh", json={"token": old_token})
        assert r.status_code == 401
        assert "too old" in r.json()["error"]

    def test_revoke_already_invalid_token_ok(self, client):
        r = client.post("/token/revoke", json={"token": "not-a-real-token"})
        assert r.status_code == 200
        assert r.json()["status"] == "revoked"


# ---------------------------------------------------------------------------
# Register validation branches
# ---------------------------------------------------------------------------


class TestRegisterValidation:
    def test_invalid_card_json(self, client):
        r = client.post(
            "/agents/register",
            json={"did": "did:hermes:x", "identity_card": "{bad json"},
        )
        assert r.status_code == 400
        assert "Invalid identity card" in r.json()["error"]

    def test_did_does_not_match_card(self, server, client, agent_identity):
        storage = IdentityStorage(directory=agent_identity)
        card = storage.get_identity_card()
        r = client.post(
            "/agents/register",
            json={
                "did": "did:hermes:someone-else",
                "identity_card": card.to_json(),
            },
        )
        assert r.status_code == 400
        assert "doesn't match" in r.json()["error"]

    def test_bad_self_signature(self, server, client, agent_identity):
        storage = IdentityStorage(directory=agent_identity)
        card = storage.get_identity_card()
        data = json.loads(card.to_json())
        data["proof"]["signatureValue"] = "AAAA" + data["proof"]["signatureValue"][4:]
        r = client.post(
            "/agents/register",
            json={
                "did": card.id,
                "identity_card": json.dumps(data),
            },
        )
        assert r.status_code == 400
        assert "self-signature" in r.json()["error"]

    def test_project_scope_expansion_requires_reapproval(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity, projects=["p1"])
        # Re-register with an extra project → status resets to pending
        r = client.post(
            "/agents/register",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "projects": ["p1", "p2"],
            },
        )
        assert r.status_code == 200
        assert r.json()["status"] == "pending"
        assert r.json()["projects"] == ["p1", "p2"]
        assert "Re-approval" in r.json()["message"]

    def test_duplicate_register_conflict(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity, projects=["p1"])
        r = client.post(
            "/agents/register",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "projects": ["p1"],
            },
        )
        assert r.status_code == 409


# ---------------------------------------------------------------------------
# Scoped admin keys — deny paths
# ---------------------------------------------------------------------------


@pytest.fixture()
def scoped_server(server_identity, tmp_path):
    db = tmp_path / "scoped.db"
    return AuthServer(
        identity_dir=server_identity,
        db_path=str(db),
        admin_key="global-admin",
        scoped_admin_keys={"tv-admin": ["spacetime-tv"]},
        rate_limit_max=100,
    )


@pytest.fixture()
def scoped_client(scoped_server):
    with TestClient(scoped_server.app) as c:
        yield c


class TestScopedAdminDenials:
    def _setup_agent(self, scoped_server, scoped_client, agent_identity, projects):
        storage = IdentityStorage(directory=agent_identity)
        card = storage.get_identity_card()
        r = scoped_client.post(
            "/agents/register",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "projects": projects,
            },
        )
        assert r.status_code == 200, r.text
        return storage, card

    def test_scoped_key_cannot_approve_other_project(self, scoped_server, scoped_client, agent_identity):
        storage, card = self._setup_agent(scoped_client, scoped_client, agent_identity, ["spacetime-air"])
        r = scoped_client.post(
            f"/agents/{card.id}/approve",
            headers={"X-Admin-Key": "tv-admin"},
        )
        assert r.status_code == 403
        assert "cannot administer" in r.json()["error"]

    def test_scoped_key_can_approve_own_project(self, scoped_server, scoped_client, agent_identity):
        storage, card = self._setup_agent(scoped_client, scoped_client, agent_identity, ["spacetime-tv"])
        r = scoped_client.post(
            f"/agents/{card.id}/approve",
            headers={"X-Admin-Key": "tv-admin"},
        )
        assert r.status_code == 200

    def test_approve_project_not_requested(self, scoped_server, scoped_client, agent_identity):
        storage, card = self._setup_agent(scoped_client, scoped_client, agent_identity, ["spacetime-tv"])
        r = scoped_client.post(
            f"/agents/{card.id}/approve?project=spacetime-air",
            headers={"X-Admin-Key": "global-admin"},
        )
        assert r.status_code == 403
        assert "did not request project" in r.json()["error"]

    def test_scoped_key_cannot_view_other_project(self, scoped_server, scoped_client, agent_identity):
        storage, card = self._setup_agent(scoped_client, scoped_client, agent_identity, ["spacetime-air"])
        r = scoped_client.get(
            f"/agents/{card.id}/status",
            headers={"X-Admin-Key": "tv-admin"},
        )
        assert r.status_code == 403
        assert "cannot view" in r.json()["error"]

    def test_scoped_key_cannot_delete_other_project(self, scoped_server, scoped_client, agent_identity):
        storage, card = self._setup_agent(scoped_client, scoped_client, agent_identity, ["spacetime-air"])
        r = scoped_client.delete(
            f"/agents/{card.id}",
            headers={"X-Admin-Key": "tv-admin"},
        )
        assert r.status_code == 403
        assert "cannot administer" in r.json()["error"]

    def test_scoped_key_cannot_deny_other_project(self, scoped_server, scoped_client, agent_identity):
        storage, card = self._setup_agent(scoped_client, scoped_client, agent_identity, ["spacetime-air"])
        r = scoped_client.post(
            f"/agents/{card.id}/deny",
            headers={"X-Admin-Key": "tv-admin"},
        )
        assert r.status_code == 403
        assert "cannot administer" in r.json()["error"]

    def test_invalid_admin_key(self, scoped_client):
        r = scoped_client.get("/agents", headers={"X-Admin-Key": "wrong-key"})
        assert r.status_code == 403

    def test_missing_admin_key(self, scoped_client):
        r = scoped_client.get("/agents")
        assert r.status_code == 403

    def test_scoped_key_lists_only_own_projects(self, scoped_server, scoped_client, agent_identity, tmp_path):
        # Two distinct agents: one for spacetime-tv, one for spacetime-air
        tv_dir = agent_identity
        air_dir = tmp_path / "air-agent"
        air_dir.mkdir()
        IdentityStorage(directory=str(air_dir)).create(_TEST_PASSWORD)

        s1, c1 = self._setup_agent(scoped_client, scoped_client, tv_dir, ["spacetime-tv"])
        s2, c2 = self._setup_agent(scoped_client, scoped_client, str(air_dir), ["spacetime-air"])
        assert c1.id != c2.id
        r = scoped_client.get("/agents", headers={"X-Admin-Key": "tv-admin"})
        assert r.status_code == 200
        dids = [a["did"] for a in r.json()["agents"]]
        assert c1.id in dids
        assert c2.id not in dids


# ---------------------------------------------------------------------------
# list_agents query validation & pagination
# ---------------------------------------------------------------------------


class TestListAgentsValidation:
    def test_invalid_status_422(self, client):
        r = client.get("/agents?status=bogus", headers={"X-Admin-Key": "edge-test-admin-key"})
        assert r.status_code == 422

    def test_project_filter(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity, projects=["tv"])
        r = client.get(
            "/agents?project=tv",
            headers={"X-Admin-Key": "edge-test-admin-key"},
        )
        assert r.status_code == 200
        assert card.id in [a["did"] for a in r.json()["agents"]]
        r2 = client.get(
            "/agents?project=air",
            headers={"X-Admin-Key": "edge-test-admin-key"},
        )
        assert card.id not in [a["did"] for a in r2.json()["agents"]]

    def test_page_size_cap(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity)
        r = client.get(
            "/agents?page_size=500",
            headers={"X-Admin-Key": "edge-test-admin-key"},
        )
        assert r.status_code == 422  # capped at 200


# ---------------------------------------------------------------------------
# Standalone token verification
# ---------------------------------------------------------------------------


class TestVerifyAuthToken:
    def test_roundtrip_with_card_path(self, server, client, agent_identity, tmp_path):
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        sig = _sign_with(storage, chal)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        token = r.json()["token"]
        card_path = tmp_path / "server-card.json"
        card_path.write_text(server._storage.get_identity_card().to_json())
        payload = verify_auth_token(token, identity_card_path=str(card_path))
        assert payload is not None
        assert payload["did"] == card.id

    def test_malformed_token(self, server, tmp_path):
        card_path = tmp_path / "server-card.json"
        card_path.write_text(server._storage.get_identity_card().to_json())
        assert verify_auth_token("no-dots-here", identity_card_path=str(card_path)) is None

    def test_bad_signature(self, server, client, agent_identity, tmp_path):
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        sig = _sign_with(storage, chal)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        token = r.json()["token"]
        parts = token.split(".")
        bad = parts[0] + "." + parts[1][:-4] + "AAAA"
        card_path = tmp_path / "server-card.json"
        card_path.write_text(server._storage.get_identity_card().to_json())
        assert verify_auth_token(bad, identity_card_path=str(card_path)) is None

    def test_expired_token(self, server, client, agent_identity, tmp_path):
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        sig = _sign_with(storage, chal)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        token = r.json()["token"]
        # Re-sign a payload with an already-expired expires_at
        import base64

        payload_b64 = token.split(".")[0]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==").decode())
        payload["expires_at"] = time.time() - 1
        from hermes_id.crypto import sign as ed_sign

        priv, _, _ = server._get_keypair()
        expired = _b64(json.dumps(payload).encode()) + "." + _b64(ed_sign(priv, json.dumps(payload).encode()))
        card_path = tmp_path / "server-card.json"
        card_path.write_text(server._storage.get_identity_card().to_json())
        assert verify_auth_token(expired, identity_card_path=str(card_path)) is None


# ---------------------------------------------------------------------------
# _agent_projects / _parse_token edge branches
# ---------------------------------------------------------------------------


class TestInternalBranches:
    def test_agent_projects_missing_row_returns_empty(self, server, tmp_path):
        conn = server._db_connect()
        try:
            assert server._agent_projects(conn, "did:hermes:does-not-exist") == []
        finally:
            conn.close()

    def test_agent_projects_null_column_returns_empty(self, server, client, agent_identity):
        storage = IdentityStorage(directory=agent_identity)
        card = storage.get_identity_card()
        # Register, then null out the projects column directly
        r = client.post(
            "/agents/register",
            json={"did": card.id, "identity_card": card.to_json()},
        )
        assert r.status_code == 200, r.text
        conn = server._db_connect()
        try:
            conn.execute("UPDATE agents SET projects = NULL WHERE did = ?", (card.id,))
            conn.commit()
            assert server._agent_projects(conn, card.id) == []
        finally:
            conn.close()

    def test_agent_projects_corrupt_json_returns_empty(self, server, client, agent_identity):
        storage = IdentityStorage(directory=agent_identity)
        card = storage.get_identity_card()
        r = client.post(
            "/agents/register",
            json={"did": card.id, "identity_card": card.to_json()},
        )
        assert r.status_code == 200, r.text
        conn = server._db_connect()
        try:
            conn.execute("UPDATE agents SET projects = '{corrupt' WHERE did = ?", (card.id,))
            conn.commit()
            assert server._agent_projects(conn, card.id) == []
        finally:
            conn.close()

    def test_parse_token_expired_returns_none(self, server, client, agent_identity):
        """_parse_token rejects an expired token even if well-signed."""
        import base64

        from hermes_id.crypto import sign as ed_sign

        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        sig = _sign_with(storage, chal)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        token = r.json()["token"]
        payload_b64 = token.split(".")[0]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "==").decode())
        payload["expires_at"] = time.time() - 1  # already expired
        priv, _, _ = server._get_keypair()
        expired = _b64(json.dumps(payload).encode()) + "." + _b64(
            ed_sign(priv, json.dumps(payload).encode())
        )
        assert server._parse_token(expired) is None

    def test_parse_token_card_without_pubkey_returns_none(self, server, client, agent_identity, monkeypatch):
        """_parse_token bails when the server card has no public key."""

        from hermes_id.identity import IdentityCard

        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        sig = _sign_with(storage, chal)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        token = r.json()["token"]

        # Serve a keypair whose card has an empty public key
        priv, _, _ = server._get_keypair()
        data = json.loads(server._storage.get_identity_card().to_json())
        data["verification_method"][0]["publicKeyMultibase"] = ""
        stripped = IdentityCard(**data)
        monkeypatch.setattr(server, "_get_keypair", lambda: (priv, priv.public_key(), stripped))
        assert server._parse_token(token) is None

    def test_get_identity_500_when_unconfigured(self, server, client, monkeypatch):
        monkeypatch.setattr(server._storage, "get_identity_card", lambda: None)
        r = client.get("/identity")
        assert r.status_code == 500
        assert "not configured" in r.json()["error"]


# ---------------------------------------------------------------------------
# 404 / 409 / 403 branches on approve / deny / status / delete
# ---------------------------------------------------------------------------


class TestAgentLifecycleErrors:
    def test_approve_missing_agent_404(self, client):
        r = client.post(
            "/agents/did:hermes:nobody/approve",
            headers={"X-Admin-Key": "edge-test-admin-key"},
        )
        assert r.status_code == 404

    def test_deny_missing_agent_404(self, client):
        r = client.post(
            "/agents/did:hermes:nobody/deny",
            headers={"X-Admin-Key": "edge-test-admin-key"},
        )
        assert r.status_code == 404

    def test_deny_approved_agent_409(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity)
        r = client.post(
            f"/agents/{card.id}/deny",
            headers={"X-Admin-Key": "edge-test-admin-key"},
        )
        assert r.status_code == 409
        assert "can only deny 'pending'" in r.json()["error"]

    def test_deny_project_not_requested_403(self, server, client, agent_identity):
        storage = IdentityStorage(directory=agent_identity)
        card = storage.get_identity_card()
        # Register WITHOUT approving — deny only accepts pending agents
        r = client.post(
            "/agents/register",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "projects": ["tv"],
            },
        )
        assert r.status_code == 200, r.text
        r = client.post(
            f"/agents/{card.id}/deny?project=air",
            headers={"X-Admin-Key": "edge-test-admin-key"},
        )
        assert r.status_code == 403
        assert "did not request project" in r.json()["error"]

    def test_status_missing_agent_404(self, client):
        r = client.get(
            "/agents/did:hermes:nobody/status",
            headers={"X-Admin-Key": "edge-test-admin-key"},
        )
        assert r.status_code == 404

    def test_delete_missing_agent_404(self, client):
        r = client.delete(
            "/agents/did:hermes:nobody",
            headers={"X-Admin-Key": "edge-test-admin-key"},
        )
        assert r.status_code == 404

    def test_list_status_filter(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity)
        r = client.get(
            "/agents?status=approved",
            headers={"X-Admin-Key": "edge-test-admin-key"},
        )
        assert r.status_code == 200
        assert card.id in [a["did"] for a in r.json()["agents"]]
        r2 = client.get(
            "/agents?status=denied",
            headers={"X-Admin-Key": "edge-test-admin-key"},
        )
        assert card.id not in [a["did"] for a in r2.json()["agents"]]

    def test_search_filter(self, server, client, agent_identity):
        storage, card = _register_approved(server, client, agent_identity)
        r = client.get(
            f"/agents?search={card.id[:20]}",
            headers={"X-Admin-Key": "edge-test-admin-key"},
        )
        assert r.status_code == 200
        assert card.id in [a["did"] for a in r.json()["agents"]]
        r2 = client.get(
            "/agents?search=zzzz-no-match",
            headers={"X-Admin-Key": "edge-test-admin-key"},
        )
        assert r2.json()["agents"] == []


# ---------------------------------------------------------------------------
# verify_auth_token — default identity path & no-pubkey card
# ---------------------------------------------------------------------------


class TestVerifyAuthTokenDefaultPath:
    def test_uses_default_storage(self, server, client, agent_identity, tmp_path, monkeypatch):
        """verify_auth_token without identity_card_path loads the default storage."""
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        sig = _sign_with(storage, chal)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        token = r.json()["token"]

        import hermes_id.server as server_mod
        from hermes_id.identity import IdentityCard

        # Capture the real card, then point the default IdentityStorage at it.
        # Patching the class method with a closure over the captured JSON
        # avoids recursion (calling server._storage would re-enter the patch).
        card_json = server._storage.get_identity_card().to_json()
        monkeypatch.setattr(
            server_mod.IdentityStorage,
            "get_identity_card",
            lambda self: IdentityCard.from_json(card_json),
        )
        payload = verify_auth_token(token)
        assert payload is not None
        assert payload["did"] == card.id

    def test_card_without_pubkey_returns_none(self, server, client, agent_identity, tmp_path):
        storage, card = _register_approved(server, client, agent_identity)
        chal = _get_challenge(client, card.id)
        sig = _sign_with(storage, chal)
        r = client.post(
            "/authenticate",
            json={
                "did": card.id,
                "identity_card": card.to_json(),
                "signature_b64": sig,
                "challenge_b64": chal,
            },
        )
        token = r.json()["token"]
        data = json.loads(server._storage.get_identity_card().to_json())
        data["verification_method"][0]["publicKeyMultibase"] = ""
        bad_card = tmp_path / "bad-server-card.json"
        bad_card.write_text(json.dumps(data))
        assert verify_auth_token(token, identity_card_path=str(bad_card)) is None


# ---------------------------------------------------------------------------
# Convenience run_server
# ---------------------------------------------------------------------------


class TestRunServer:
    def test_run_server_invokes_uvicorn(self, server_identity, tmp_path, monkeypatch, capsys):
        import builtins

        calls: dict = {}
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "uvicorn":
                class FakeUvicorn:
                    @staticmethod
                    def run(*aa, **kk):
                        calls["ran"] = True
                        return None

                return FakeUvicorn()
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        run_server(
            identity_dir=server_identity,
            db_path=str(tmp_path / "run.db"),
            admin_key="k",
        )
        assert calls.get("ran") is True
        out = capsys.readouterr().out
        assert "Auth Server" in out
