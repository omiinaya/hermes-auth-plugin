"""
Tests for the hermes-id Admin CLI (`hermes_id.admin_cli`).

Uses a fake AuthClient injected via monkeypatch — no network, no server.
Covers parser wiring, all five subcommands, missing admin key, and the
error path.
"""

import json

import pytest

from hermes_id.admin_cli import main


class FakeAuthClient:
    """In-memory stand-in for AuthClient."""

    def __init__(self, *args, **kwargs):
        self.closed = False
        self.calls = []

    def list_agents(self, **kwargs):
        self.calls.append(("list", kwargs))
        return {"agents": [], "total": 0}

    def approve_agent(self, did, project=None):
        self.calls.append(("approve", did, project))
        return {"did": did, "status": "approved"}

    def deny_agent(self, did, project=None):
        self.calls.append(("deny", did, project))
        return {"did": did, "status": "denied"}

    def get_agent_status(self, did):
        self.calls.append(("status", did))
        return {"did": did, "status": "approved"}

    def delete_agent(self, did):
        self.calls.append(("delete", did))
        return {"did": did, "deleted": True}

    def close(self):
        self.closed = True


@pytest.fixture
def fake_client(monkeypatch):
    import hermes_id.admin_cli as admin_cli

    client = FakeAuthClient()
    monkeypatch.setattr(admin_cli, "AuthClient", lambda *a, **kw: client)
    return client


class TestAdminCLI:
    def test_missing_admin_key_exits(self, capsys, monkeypatch):
        monkeypatch.delenv("HERMES_ID_ADMIN_KEY", raising=False)
        with pytest.raises(SystemExit) as exc:
            main(["--server", "http://localhost:9488", "list"])
        assert exc.value.code == 1
        assert "Admin key required" in capsys.readouterr().err

    def test_admin_key_from_env(self, monkeypatch, capsys):
        import hermes_id.admin_cli as admin_cli

        client = FakeAuthClient()
        monkeypatch.setattr(admin_cli, "AuthClient", lambda *a, **kw: client)
        monkeypatch.setenv("HERMES_ID_ADMIN_KEY", "env-key")
        assert main(["--server", "http://localhost:9488", "list"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out == {"agents": [], "total": 0}
        assert client.calls[0][0] == "list"

    def test_list_with_filters(self, fake_client, capsys):
        rc = main([
            "--server", "http://localhost:9488", "--admin-key", "k",
            "list", "--status", "pending", "--page", "2", "--page-size", "10",
            "--search", "foo", "--project", "spacetime-tv",
        ])
        assert rc == 0
        assert fake_client.calls[0][0] == "list"
        kwargs = fake_client.calls[0][1]
        assert kwargs["status"] == "pending"
        assert kwargs["page"] == 2
        assert kwargs["page_size"] == 10
        assert kwargs["search"] == "foo"
        assert kwargs["project"] == "spacetime-tv"

    def test_approve(self, fake_client, capsys):
        rc = main(["--server", "s", "--admin-key", "k", "approve", "did:hermes:abc", "--for", "spacetime-crm"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["status"] == "approved"
        assert fake_client.calls[0] == ("approve", "did:hermes:abc", "spacetime-crm")

    def test_deny(self, fake_client, capsys):
        rc = main(["--server", "s", "--admin-key", "k", "deny", "did:hermes:def"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["status"] == "denied"

    def test_status(self, fake_client, capsys):
        rc = main(["--server", "s", "--admin-key", "k", "status", "did:hermes:abc"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["did"] == "did:hermes:abc"

    def test_delete(self, fake_client, capsys):
        rc = main(["--server", "s", "--admin-key", "k", "delete", "did:hermes:abc"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["deleted"] is True

    def test_client_closed_after_success(self, fake_client):
        main(["--server", "s", "--admin-key", "k", "list"])
        assert fake_client.closed is True

    def test_error_path_returns_1(self, capsys, monkeypatch):
        import hermes_id.admin_cli as admin_cli

        class ExplodingClient(FakeAuthClient):
            def list_agents(self, **kwargs):
                raise RuntimeError("boom")

        monkeypatch.setattr(admin_cli, "AuthClient", lambda *a, **kw: ExplodingClient())
        rc = main(["--server", "s", "--admin-key", "k", "list"])
        assert rc == 1
        assert "boom" in capsys.readouterr().err

    def test_requires_command(self):
        with pytest.raises(SystemExit):
            main(["--server", "s", "--admin-key", "k"])
