"""
Hermes Agent plugin for hermes-id v1.4.4.

This plugin registers a ``/hermes-id`` slash command that provides
identity management, auth server management, and agent registry admin
directly from within a Hermes session.

The plugin shells out to the ``hermes-id`` CLI tool for all operations.
Interactive commands (init, handshake) provide instructions instead.
"""

import contextlib
import json
import os
import shutil
import subprocess
import sys

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_HERMES_HOME = os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes"))
_IDENTITY_DIR = os.path.join(_HERMES_HOME, "identity")
_PLUGIN_NAME = "hermes-id"

# The CLI binary
def _find_cli() -> str:
    """Locate the ``hermes-id`` CLI binary."""
    cli = shutil.which("hermes-id")
    if cli:
        return cli
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "hermes_id", "cli.py"),
        os.path.expanduser("~/.local/bin/hermes-id"),
        os.path.join(sys.prefix, "bin", "hermes-id"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return "hermes-id"


# ---------------------------------------------------------------------------
# Help text
# ---------------------------------------------------------------------------

_HELP_TEXT = """\
🔐 **hermes-id v1.4** — Self-Sovereign Identity for this Hermes instance.

**Identity:**
  `/hermes-id status`         — Show identity status
  `/hermes-id show`           — Display full identity card
  `/hermes-id export`         — Get identity card as JSON
  `/hermes-id init`           — Create a new identity (requires terminal)

**Verification:**
  `/hermes-id verify <file>`  — Verify an identity card file
  `/hermes-id sign <file>`    — Sign a file (requires terminal)
  `/hermes-id verify-sig <file> <sig>` — Verify a signature

**Handshake:**
  `/hermes-id connect <host:port>`  — Handshake with a peer
  `/hermes-id listen [--port N]`    — Start handshake server

**Auth Server:**
  `/hermes-id server start [--port 9488]` — Start auth server (background)
  `/hermes-id server stop`              — Stop the auth server

**Agent Registry (requires admin key):**
  `/hermes-id admin list [--status pending]`  — List agents
  `/hermes-id admin approve <did>`            — Approve agent
  `/hermes-id admin deny <did>`               — Deny agent
  `/hermes-id admin status <did>`             — Check agent status

**Help:**
  `/hermes-id help`           — Show this help

**What is hermes-id?**
  Every Hermes instance gets a unique Ed25519 keypair — like a driver's
  license for agents. Present your *identity card* to prove who you are,
  and authenticate with a *challenge-response* protocol.
"""


# ---------------------------------------------------------------------------
# Slash command handler
# ---------------------------------------------------------------------------

def _handle(raw_args: str) -> str:
    """Handle the /hermes-id slash command."""
    args = raw_args.strip().split()
    if not args or args[0] in ("help", "--help", "-h"):
        return _HELP_TEXT

    cmd = args[0]
    cmd_args = args[1:]

    cli = _find_cli()

    # ------------------------------------------------------------------
    # Identity commands
    # ------------------------------------------------------------------

    if cmd == "status":
        result = subprocess.run(
            [cli, "status", "--dir", _IDENTITY_DIR],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return "❌ No identity configured. Use `/hermes-id init`."
        return result.stdout.strip()

    if cmd == "show":
        result = subprocess.run(
            [cli, "show", "--dir", _IDENTITY_DIR],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return f"❌ {result.stderr.strip()}"
        return f"```\n{result.stdout.strip()}\n```"

    if cmd == "export":
        result = subprocess.run(
            [cli, "export", "--dir", _IDENTITY_DIR],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return f"❌ {result.stderr.strip()}"
        return f"```json\n{result.stdout.strip()}\n```"

    if cmd == "init":
        result = subprocess.run(
            [cli, "status", "--dir", _IDENTITY_DIR],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            return (
                "⚠️  Identity already exists. To overwrite:\n"
                f"```\nhermes-id init --force --dir {_IDENTITY_DIR}\n```"
            )
        return (
            "🔑 To create a new identity:\n\n"
            f"```\nhermes-id init --dir {_IDENTITY_DIR}\n```\n\n"
            "You'll be prompted for a passphrase (min 8 chars).\n"
            "⚠️  **SAVE YOUR PASSPHRASE** — it cannot be recovered!"
        )

    # ------------------------------------------------------------------
    # Verification commands
    # ------------------------------------------------------------------

    if cmd == "verify":
        if not cmd_args:
            return "Usage: `/hermes-id verify <file>` — verify an identity card JSON file."
        file_path = cmd_args[0]
        if not os.path.exists(file_path):
            return f"❌ File not found: {file_path}"
        result = subprocess.run(
            [cli, "verify", file_path],
            capture_output=True, text=True, timeout=15,
        )
        return result.stdout.strip() or f"❌ {result.stderr.strip()}"

    if cmd == "sign":
        if not cmd_args:
            return "Usage: `/hermes-id sign <file>` — sign a file (requires terminal)."
        return (
            f"🔑 To sign {cmd_args[0]}, run in terminal:\n\n"
            f"```\nhermes-id sign {cmd_args[0]} --dir {_IDENTITY_DIR}\n```"
        )

    if cmd in ("verify-sig", "verify_sig"):
        if len(cmd_args) < 2:
            return "Usage: `/hermes-id verify-sig <file> <sig_file>`"
        return (
            f"To verify, run in terminal:\n\n"
            f"```\nhermes-id verify-sig {cmd_args[0]} {cmd_args[1]} --identity {_IDENTITY_DIR}/identity.json\n```"
        )

    # ------------------------------------------------------------------
    # Handshake commands
    # ------------------------------------------------------------------

    if cmd == "connect":
        if not cmd_args:
            return (
                "Usage: `/hermes-id connect <host:port>`\n\n"
                "Perform mutual auth handshake with another Hermes instance."
            )
        target = cmd_args[0]
        return (
            f"🔗 To handshake with {target}:\n\n"
            f"```\nhermes-id handshake connect {target} --dir {_IDENTITY_DIR}\n```\n\n"
            "You'll be prompted for your passphrase."
        )

    if cmd == "listen":
        port = 9487
        if len(cmd_args) >= 2 and cmd_args[0] == "--port":
            with contextlib.suppress(ValueError):
                port = int(cmd_args[1])
        return (
            "🎧 To start the handshake server:\n\n"
            f"```\nhermes-id handshake listen --dir {_IDENTITY_DIR} --port {port}\n```\n\n"
            "Press Ctrl+C to stop."
        )

    # ------------------------------------------------------------------
    # Auth server commands
    # ------------------------------------------------------------------

    if cmd == "server":
        sub_cmd = cmd_args[0] if cmd_args else "help"

        if sub_cmd == "start":
            port = 9488
            host = "0.0.0.0"
            rest = cmd_args[1:]
            for i, arg in enumerate(rest):
                if arg == "--port" and i + 1 < len(rest):
                    port = int(rest[i + 1])
                if arg == "--host" and i + 1 < len(rest):
                    host = rest[i + 1]

            return (
                "🔐 To start the auth server:\n\n"
                f"```\nhermes-id server --host {host} --port {port} --dir {_IDENTITY_DIR}\n```\n\n"
                f"Server DID: `{_get_did()}`\n"
                f"API docs: http://{host}:{port}/docs\n"
                "⚠️  Requires HERMES_ID_PASSPHRASE and HERMES_ID_ADMIN_KEY in environment."
            )

        if sub_cmd == "stop":
            return (
                "🛑 To stop the auth server, find its PID:\n\n"
                "```\nps aux | grep 'hermes-id server'\nkill <PID>\n```"
            )

        if sub_cmd in ("status", "health"):
            port = cmd_args[1] if len(cmd_args) > 1 else "9488"
            try:
                import httpx
                r = httpx.get(f"http://127.0.0.1:{port}/health", timeout=5)
                if r.status_code == 200:
                    data = r.json()
                    return (
                        f"✅ Auth server running on port {port}\n"
                        f"   DID: {data.get('did', 'unknown')}\n"
                        f"   Status: {data.get('status', 'unknown')}"
                    )
                return f"❌ Server responded with {r.status_code}"
            except ImportError:
                return f"Run `curl http://127.0.0.1:{port}/health` to check."
            except Exception as e:
                return f"❌ Server not reachable: {e}"

        if sub_cmd == "help":
            return (
                "**Auth Server commands:**\n\n"
                "  `/hermes-id server start [--port N] [--host HOST]`\n"
                "  `/hermes-id server stop`\n"
                "  `/hermes-id server health [port]`\n"
            )

        return f"Unknown server subcommand: {sub_cmd}\n\n{_HELP_TEXT}"

    # ------------------------------------------------------------------
    # Admin registry commands
    # ------------------------------------------------------------------

    if cmd == "admin":
        sub_cmd = cmd_args[0] if cmd_args else "help"
        rest = cmd_args[1:]

        # Get admin key from env or prompt user
        admin_key = os.environ.get("HERMES_ID_ADMIN_KEY", "")
        if not admin_key:
            return (
                "⚠️  HERMES_ID_ADMIN_KEY not set.\n"
                "Set it in the environment or use the `hermes-id-admin` CLI:\n\n"
                "```\nexport HERMES_ID_ADMIN_KEY=your-key\nhermes-id admin ...\n```"
            )

        server_url = os.environ.get("HERMES_ID_SERVER_URL", "http://127.0.0.1:9488")

        # Delegate to hermes-id-admin CLI
        admin_cli = shutil.which("hermes-id-admin")
        if not admin_cli:
            return "❌ hermes-id-admin CLI not found. Install with `pip install hermes-id[all]`."

        if sub_cmd == "list":
            filt = ""
            search = ""
            for i, a in enumerate(rest):
                if a == "--status" and i + 1 < len(rest):
                    filt = rest[i + 1]
                if a == "--search" and i + 1 < len(rest):
                    search = rest[i + 1]

            cmd_parts = [admin_cli, "--server", server_url, "--admin-key", admin_key, "list"]
            if filt:
                cmd_parts.extend(["--status", filt])
            if search:
                cmd_parts.extend(["--search", search])

            result = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                return f"❌ {result.stderr.strip()}"
            data = json.loads(result.stdout)
            agents = data.get("agents", [])
            if not agents:
                return f"No agents found (total: {data.get('total', 0)})."
            lines = [f"**Agents** ({data.get('total', 0)} total, page {data.get('page', 1)}/{data.get('pages', 1)})"]
            for a in agents:
                status_icon = {"pending": "⏳", "approved": "✅", "denied": "❌"}.get(a["status"], "❓")
                name = a.get("display_name", "") or a["did"][:20]
                lines.append(f"  {status_icon} `{a['did'][:24]}...` — {a['status']} — {name}")
            return "\n".join(lines)

        if sub_cmd == "approve":
            if not rest:
                return "Usage: `/hermes-id admin approve <did>`"
            did = rest[0]
            result = subprocess.run(
                [admin_cli, "--server", server_url, "--admin-key", admin_key, "approve", did],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                return f"❌ {result.stderr.strip()}"
            return f"✅ Approved `{did}`"

        if sub_cmd == "deny":
            if not rest:
                return "Usage: `/hermes-id admin deny <did>`"
            did = rest[0]
            result = subprocess.run(
                [admin_cli, "--server", server_url, "--admin-key", admin_key, "deny", did],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                return f"❌ {result.stderr.strip()}"
            return f"✅ Denied `{did}`"

        if sub_cmd == "status":
            if not rest:
                return "Usage: `/hermes-id admin status <did>`"
            did = rest[0]
            result = subprocess.run(
                [admin_cli, "--server", server_url, "--admin-key", admin_key, "status", did],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                return f"❌ {result.stderr.strip()}"
            data = json.loads(result.stdout)
            return (
                f"**Agent Status:** `{data['did'][:24]}...`\n"
                f"  Status: {data.get('status', 'unknown')}\n"
                f"  Name: {data.get('display_name', '-')}\n"
                f"  Registered: {data.get('registered_at', '-')}\n"
                f"  Approved: {data.get('approved_at', '-')}"
            )

        if sub_cmd == "help":
            return (
                "**Admin commands:**\n\n"
                "  `/hermes-id admin list [--status pending] [--search term]`\n"
                "  `/hermes-id admin approve <did>`\n"
                "  `/hermes-id admin deny <did>`\n"
                "  `/hermes-id admin status <did>`\n\n"
                "Requires `HERMES_ID_ADMIN_KEY` and `HERMES_ID_SERVER_URL` env vars."
            )

        return f"Unknown admin subcommand: {sub_cmd}\n\n{_HELP_TEXT}"

    return f"Unknown command: {cmd}\n\n{_HELP_TEXT}"


def _get_did() -> str:
    """Get the current identity's DID."""
    try:
        result = subprocess.run(
            [_find_cli(), "status", "--dir", _IDENTITY_DIR],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.split("\n"):
            if "DID:" in line:
                return line.strip()
        return "unknown"
    except Exception:
        return "not configured"


# ---------------------------------------------------------------------------
# Hermes plugin registration
# ---------------------------------------------------------------------------

def register(ctx) -> None:
    """Register the hermes-id plugin with the Hermes Agent."""
    ctx.register_command(
        _PLUGIN_NAME,
        handler=_handle,
        description="Identity management, auth server control, and agent registry admin.",
        args_hint="<status|show|init|export|verify|sign|connect|listen|server|admin|help>",
    )
