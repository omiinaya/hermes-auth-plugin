"""
Tests for project-scoped agent registry + scoped admin keys (v1.3.0).

Covers:
- Registration records requested projects.
- ``?project=`` list filter.
- Approve/deny ``?project=`` guard (the CLI ``--for`` flag).
- Scoped admin keys: only agents requesting one of the key's projects can be
  listed, viewed, approved, denied, or deleted.
- The global admin key is unaffected by scoping.

Each test registers its own fresh agent identity, so tests are
order-independent.
"""

import contextlib
import threading
import time

import httpx
import pytest

from hermes_id.auth_client import AuthClient
from hermes_id.storage import IdentityStorage

_TEST_PASSWORD = "hermes-id-test-password-2026"  # same as test_server.py
_GLOBAL_KEY = "registry-global-admin-key"
_TV_KEY = "registry-scoped-tv-key"       # scoped to spacetime-tv
_AIR_KEY = "registry-scoped-air-key"     # scoped to spacetime-air


def _start_uvicorn(app, host: str = "127.0.0.1"):
    """Start uvicorn on an ephemeral port; returns (base_url, stop_fn)."""
    import uvicorn

    config = uvicorn.Config(app, host=host, port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError("uvicorn failed to start")
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]

    def stop():
        server.should_exit = True
        thread.join(timeout=5)

    return f"http://{host}:{port}", stop


@pytest.fixture(scope="module")
def server_env(tmp_path_factory):
    """One server with a global key + two scoped keys."""
    from hermes_id.server import AuthServer

    identity_dir = tmp_path_factory.mktemp("scoped-identity")
    IdentityStorage(directory=str(identity_dir)).create(_TEST_PASSWORD)
    db_path = tmp_path_factory.mktemp("scoped-data") / "registry.db"

    server = AuthServer(
        identity_dir=str(identity_dir),
        db_path=str(db_path),
        token_ttl=3600,
        admin_key=_GLOBAL_KEY,
        scoped_admin_keys={_TV_KEY: ["spacetime-tv"], _AIR_KEY: ["spacetime-air"]},
        rate_limit_max=500,
    )
    base_url, stop = _start_uvicorn(server.app)
    yield {"url": base_url, "stop": stop, "db_path": db_path}
    stop()


@pytest.fixture
def make_agent(server_env, tmp_path_factory):
    """Factory: register a brand-new agent identity requesting projects.

    Returns ``(did, client)``. Each call creates a fresh identity so tests
    never step on each other's registry rows.
    """
    counter = {"n": 0}

    def _make(projects: list[str]) -> tuple[str, AuthClient]:
        counter["n"] += 1
        d = tmp_path_factory.mktemp(f"agent-{counter['n']}")
        IdentityStorage(directory=str(d)).create(_TEST_PASSWORD)
        client = AuthClient(server_env["url"], identity_dir=str(d))
        card = client._storage.get_identity_card()
        assert card is not None
        with contextlib.suppress(httpx.HTTPStatusError):
            client.register_agent(card.id, display_name="agent", projects=projects)
        return card.id, client

    return _make


class TestProjectRegistry:
    def test_register_records_projects(self, server_env, make_agent):
        did, _ = make_agent(["spacetime-tv"])
        admin = AuthClient(server_env["url"], admin_key=_GLOBAL_KEY)
        status = admin.get_agent_status(did)
        assert status["projects"] == ["spacetime-tv"]

    def test_register_merges_projects(self, server_env, make_agent):
        """Re-registering the same DID merges requested projects."""
        did, client = make_agent(["spacetime-tv"])
        card = client._storage.get_identity_card()
        assert card is not None
        # Register again with an additional project
        result = client.register_agent(card.id, projects=["spacetime-tv", "spacetime-air"])
        assert set(result["projects"]) == {"spacetime-tv", "spacetime-air"}
        admin = AuthClient(server_env["url"], admin_key=_GLOBAL_KEY)
        assert set(admin.get_agent_status(did)["projects"]) == {"spacetime-tv", "spacetime-air"}

    def test_register_scope_growth_requires_reapproval(self, server_env, make_agent):
        """Approved agent that gains projects resets to pending."""
        did, client = make_agent(["spacetime-tv"])
        admin = AuthClient(server_env["url"], admin_key=_GLOBAL_KEY)
        admin.approve_agent(did)
        card = client._storage.get_identity_card()
        assert card is not None
        result = client.register_agent(card.id, projects=["spacetime-tv", "spacetime-air"])
        assert result["status"] == "pending"
        assert "Re-approval" in result["message"]

    def test_list_filter_by_project(self, server_env, make_agent):
        tv_did, _ = make_agent(["spacetime-tv"])
        air_did, _ = make_agent(["spacetime-air"])
        admin = AuthClient(server_env["url"], admin_key=_GLOBAL_KEY)

        tv_list = admin.list_agents(project="spacetime-tv")
        tv_dids = {a["did"] for a in tv_list["agents"]}
        assert tv_did in tv_dids
        assert air_did not in tv_dids

        air_list = admin.list_agents(project="spacetime-air")
        air_dids = {a["did"] for a in air_list["agents"]}
        assert air_did in air_dids
        assert tv_did not in air_dids

    def test_approve_with_project_guard(self, server_env, make_agent):
        did, _ = make_agent(["spacetime-tv"])
        admin = AuthClient(server_env["url"], admin_key=_GLOBAL_KEY)

        # Approving with the right --for succeeds
        result = admin.approve_agent(did, project="spacetime-tv")
        assert result["status"] == "approved"

        # Approved agent cannot be re-approved
        with pytest.raises(httpx.HTTPStatusError) as exc:
            admin.approve_agent(did, project="spacetime-tv")
        assert exc.value.response.status_code == 409

    def test_approve_wrong_project_rejected(self, server_env, make_agent):
        did, _ = make_agent(["spacetime-air"])
        admin = AuthClient(server_env["url"], admin_key=_GLOBAL_KEY)

        # --for spacetime-tv on an agent that only requested spacetime-air
        with pytest.raises(httpx.HTTPStatusError) as exc:
            admin.approve_agent(did, project="spacetime-tv")
        assert exc.value.response.status_code == 403


class TestScopedAdminKeys:
    def test_scoped_key_approves_own_project(self, server_env, make_agent):
        did, _ = make_agent(["spacetime-tv"])
        admin = AuthClient(server_env["url"], admin_key=_TV_KEY)
        result = admin.approve_agent(did)
        assert result["status"] == "approved"

    def test_scoped_key_cannot_approve_other_project(self, server_env, make_agent):
        did, _ = make_agent(["spacetime-air"])
        admin = AuthClient(server_env["url"], admin_key=_TV_KEY)  # tv-scoped key
        with pytest.raises(httpx.HTTPStatusError) as exc:
            admin.approve_agent(did)
        assert exc.value.response.status_code == 403

    def test_scoped_key_list_only_sees_own_project(self, server_env, make_agent):
        tv_did, _ = make_agent(["spacetime-tv"])
        air_did, _ = make_agent(["spacetime-air"])

        tv_admin = AuthClient(server_env["url"], admin_key=_TV_KEY)
        tv_dids = {a["did"] for a in tv_admin.list_agents()["agents"]}
        assert tv_did in tv_dids
        assert air_did not in tv_dids

        air_admin = AuthClient(server_env["url"], admin_key=_AIR_KEY)
        air_dids = {a["did"] for a in air_admin.list_agents()["agents"]}
        assert air_did in air_dids
        assert tv_did not in air_dids

    def test_scoped_key_cannot_view_other_project(self, server_env, make_agent):
        did, _ = make_agent(["spacetime-air"])
        admin = AuthClient(server_env["url"], admin_key=_TV_KEY)
        with pytest.raises(httpx.HTTPStatusError) as exc:
            admin.get_agent_status(did)
        assert exc.value.response.status_code == 403

    def test_scoped_key_cannot_delete_other_project(self, server_env, make_agent):
        did, _ = make_agent(["spacetime-air"])
        admin = AuthClient(server_env["url"], admin_key=_TV_KEY)
        with pytest.raises(httpx.HTTPStatusError) as exc:
            admin.delete_agent(did)
        assert exc.value.response.status_code == 403

    def test_global_key_unrestricted(self, server_env, make_agent):
        tv_did, _ = make_agent(["spacetime-tv"])
        air_did, _ = make_agent(["spacetime-air"])
        admin = AuthClient(server_env["url"], admin_key=_GLOBAL_KEY)
        dids = {a["did"] for a in admin.list_agents()["agents"]}
        assert tv_did in dids and air_did in dids

    def test_invalid_key_rejected(self, server_env):
        bad = AuthClient(server_env["url"], admin_key="not-a-real-key")
        with pytest.raises(httpx.HTTPStatusError) as exc:
            bad.list_agents()
        assert exc.value.response.status_code == 403
