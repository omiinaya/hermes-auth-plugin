"""
Hermes Agent plugin for hermes-id.

This plugin registers a ``/hermes-id`` slash command that provides
identity management directly from within a Hermes session.

The plugin is **self-contained** (stdlib only). It shells out to the
``hermes-id`` CLI tool for all cryptographic operations.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_HERMES_HOME = os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes"))
_IDENTITY_DIR = os.path.join(_HERMES_HOME, "identity")
_PLUGIN_NAME = "hermes-id"

# The CLI binary — we search PATH + project locations.
def _find_cli() -> str:
    """Locate the ``hermes-id`` CLI binary."""
    # Check PATH first
    cli = shutil.which("hermes-id")
    if cli:
        return cli

    # Check project-relative locations (dev / pip install -e)
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "hermes_id", "cli.py"),
        os.path.expanduser("~/.local/bin/hermes-id"),
        os.path.join(sys.prefix, "bin", "hermes-id"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c

    return "hermes-id"  # fallback — let subprocess raise FileNotFoundError


# ---------------------------------------------------------------------------
# Help text
# ---------------------------------------------------------------------------

_HELP_TEXT = """\
🔐 **hermes-id** — Self-Sovereign Identity for this Hermes instance.

**Subcommands:**

  `/hermes-id status`         — Show identity status
  `/hermes-id show`           — Display full identity card
  `/hermes-id init`           — Create a new identity (requires passphrase)
  `/hermes-id verify <file>`  — Verify an identity card file
  `/hermes-id export`         — Get identity card as JSON
  `/hermes-id connect <host:port>`  — Handshake with a peer
  `/hermes-id listen [--port N]`    — Start handshake server
  `/hermes-id help`           — Show this help

**What is hermes-id?**

Every Hermes instance gets a unique Ed25519 keypair — like a driver's
license for agents.  You can present your *identity card* to other agents
or services, and prove ownership by signing a challenge.

The handshake protocol provides mutual authentication:
  1. Both sides exchange identity cards
  2. One generates a random challenge
  3. The other signs it with their private key
  4. Both sides verify — trust is established

No central registry needed. Pure peer-to-peer.
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

    # Commands that don't need a passphrase
    no_password = ("status", "show", "export", "help", "verify", "check")

    cli = _find_cli()

    if cmd == "status":
        result = subprocess.run(
            [cli, "status", "--dir", _IDENTITY_DIR],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return f"❌ No identity configured. Use `/hermes-id init`."
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
        # Check if identity already exists
        result = subprocess.run(
            [cli, "status", "--dir", _IDENTITY_DIR],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            return (
                "⚠️  Identity already exists. To overwrite, use the CLI directly:\n"
                f"```\nhermes-id init --force --dir {_IDENTITY_DIR}\n```"
            )

        return (
            "🔑 To create a new identity, run this command in your terminal:\n\n"
            f"```\nhermes-id init --dir {_IDENTITY_DIR}\n```\n\n"
            "You'll be prompted for a passphrase (min 8 chars).\n"
            "⚠️  **SAVE YOUR PASSPHRASE** — it cannot be recovered!"
        )

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

    if cmd == "connect":
        if not cmd_args:
            return (
                "Usage: `/hermes-id connect <host:port>`\n\n"
                "Perform a mutual authentication handshake with another "
                "Hermes instance or compatible service."
            )
        target = cmd_args[0]
        return (
            f"🔗 To handshake with {target}, run:\n\n"
            f"```\nhermes-id handshake connect {target} --dir {_IDENTITY_DIR}\n```\n\n"
            "You'll be prompted for your passphrase to unlock the identity key."
        )

    if cmd == "listen":

        return (
            "🎧 To start the handshake server, run:\n\n"
            f"```\nhermes-id handshake listen --dir {_IDENTITY_DIR}\n```\n\n"
            f"Default port: 9487 (HERM on a phone keypad).\n"
            "Press Ctrl+C to stop."
        )

    return f"Unknown subcommand: {cmd}\n\n{_HELP_TEXT}"


# ---------------------------------------------------------------------------
# Hermes plugin registration
# ---------------------------------------------------------------------------

def register(ctx) -> None:
    """Register the hermes-id plugin with the Hermes Agent."""
    ctx.register_command(
        _PLUGIN_NAME,
        handler=_handle,
        description="Self-Sovereign Identity — manage your instance ID, verify cards, and handshake with peers.",
        args_hint="<status|show|init|export|verify|connect|listen|help>",
    )
