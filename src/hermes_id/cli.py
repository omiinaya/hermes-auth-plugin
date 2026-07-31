"""
hermes-id CLI — command-line interface for identity management.

Usage::

    hermes-id init                    Create a new identity
    hermes-id show                    Display identity card
    hermes-id export                  Export identity card (JSON)
    hermes-id status                  Show identity status
    hermes-id verify <file>           Verify an identity card
    hermes-id sign <file>             Sign a file/message
    hermes-id verify-sig <file> <sig> Verify a signature
    hermes-id handshake listen        Start handshake server
    hermes-id handshake connect <host:port>  Connect for handshake
"""

import argparse
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from hermes_id.crypto import (
    generate_keypair,
    sign,
    verify,
    public_key_bytes,
    _b64,
    _unb64,
)
from hermes_id.identity import (
    IdentityCard,
    create_identity,
    verify_identity_card,
    verify_key_rotation,
    format_identity_card,
)
from hermes_id.storage import IdentityStorage
from hermes_id.handshake import (
    run_handshake_server,
    run_handshake_client,
)


from hermes_id import __version__ as VERSION


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    # Parent parser with shared arguments
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--dir", help="Identity storage directory")

    parser = argparse.ArgumentParser(
        prog="hermes-id",
        description="Self-Sovereign Identity for Hermes Agent instances",
    )
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    sub = parser.add_subparsers(dest="command")

    # init
    init_p = sub.add_parser("init", parents=[parent], help="Create a new identity card + keypair")
    init_p.add_argument("--password", help="Encryption passphrase (prompts if omitted)")
    init_p.add_argument("--profile", help="Profile name (stored in metadata)")
    init_p.add_argument("--force", action="store_true", help="Overwrite existing identity")

    # rotate
    rotate_p = sub.add_parser(
        "rotate", parents=[parent],
        help="Rotate the identity keypair (new key + transition proof signed by old key)",
    )
    rotate_p.add_argument("--password", help="Passphrase for the current private key (prompts if omitted)")
    rotate_p.add_argument("--note", help="Optional note stored in new identity metadata")
    rotate_p.add_argument("--no-backup", action="store_true", help="Skip backing up the previous key")
    rotate_p.add_argument("--force", action="store_true", help="Skip the confirmation prompt")

    # show
    sub.add_parser("show", parents=[parent], help="Display your identity card")

    # export
    export_p = sub.add_parser("export", parents=[parent], help="Export identity card as JSON")
    export_p.add_argument("output", nargs="?", help="Output file (default: stdout)")

    # status
    sub.add_parser("status", parents=[parent], help="Show identity status")

    # verify
    verify_p = sub.add_parser("verify", parents=[parent], help="Verify an identity card file")
    verify_p.add_argument("file", help="Path to identity card JSON")

    # sign
    sign_p = sub.add_parser("sign", parents=[parent], help="Sign a file with your identity")
    sign_p.add_argument("file", help="File to sign")
    sign_p.add_argument("--password", help="Passphrase for private key")

    # verify-sig
    vs_p = sub.add_parser("verify-sig", parents=[parent], help="Verify a signature against an identity card")
    vs_p.add_argument("file", help="Original file")
    vs_p.add_argument("signature", help="Signature file or base64 string")
    vs_p.add_argument("--identity", help="Identity card JSON file (required)")

    # handshake
    hs_p = sub.add_parser("handshake", parents=[parent], help="Perform a mutual authentication handshake")
    hs_sub = hs_p.add_subparsers(dest="handshake_cmd", required=True)

    hs_listen = hs_sub.add_parser("listen", parents=[parent], help="Start handshake server (responder)")
    hs_listen.add_argument("--port", type=int, default=9487, help="TCP port")
    hs_listen.add_argument("--host", default="127.0.0.1", help="Bind address")
    hs_listen.add_argument("--password", help="Passphrase for private key")

    hs_connect = hs_sub.add_parser("connect", parents=[parent], help="Connect to a handshake server")
    hs_connect.add_argument("target", help="host:port to connect to")
    hs_connect.add_argument("--password", help="Passphrase for private key")
    hs_connect.add_argument("--peer-did", help="Expected peer DID")

    # server
    server_p = sub.add_parser(
        "server", parents=[parent],
        help="Start the HTTP Auth Server (FastAPI) — challenge-response auth, agent registry, token issuance",
    )
    server_p.add_argument("--port", type=int, default=9488, help="TCP port (default: 9488)")
    server_p.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    server_p.add_argument("--db", help="Path to agent registry database (default: agent_registry.db)")
    server_p.add_argument("--token-ttl", type=int, default=86400, help="Token lifetime in seconds (default: 86400)")
    server_p.add_argument("--admin-key", help="Admin API key for approving/denying agents (default: random)")
    server_p.add_argument("--cors-origins", default="*", help="Comma-separated CORS allowed origins (default: *)")
    server_p.add_argument("--tls-cert", help="Path to TLS certificate (PEM) — enables HTTPS")
    server_p.add_argument("--tls-key", help="Path to TLS private key (PEM) for the certificate")

    # mcp
    sub.add_parser(
        "mcp", parents=[parent],
        help="Start the MCP stdio server for agent-to-agent auth tools",
    )

    args = parser.parse_args(argv)
    return _dispatch(args)


def _dispatch(args: argparse.Namespace) -> int:
    """Route parsed args to the correct handler."""
    try:
        if getattr(args, "version", False):
            print(f"hermes-id {VERSION}")
            return 0

        command = getattr(args, "command", None)
        if not command:
            print("Usage: hermes-id <command> [options]\n"
                  "Run `hermes-id --help` for available commands.", file=sys.stderr)
            return 2

        if command == "init":
            return _cmd_init(args)
        elif command == "rotate":
            return _cmd_rotate(args)
        elif args.command == "show":
            return _cmd_show(args)
        elif args.command == "export":
            return _cmd_export(args)
        elif args.command == "status":
            return _cmd_status(args)
        elif args.command == "verify":
            return _cmd_verify(args)
        elif args.command == "sign":
            return _cmd_sign(args)
        elif args.command == "verify-sig":
            return _cmd_verify_sig(args)
        elif args.command == "handshake":
            return _cmd_handshake(args)
        elif args.command == "server":
            return _cmd_server(args)
        elif args.command == "mcp":
            return _cmd_mcp(args)
        else:
            print(f"Unknown command: {args.command}")
            return 1
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

def _get_storage(args: argparse.Namespace) -> IdentityStorage:
    """Build storage object from CLI args."""
    directory = getattr(args, "dir", None)
    return IdentityStorage(directory=directory)


def _prompt_password(prompt: str = "Passphrase: ") -> str:
    """Prompt for a passphrase with confirmation."""
    import getpass
    while True:
        p1 = getpass.getpass(prompt)
        if len(p1) < 8:
            print("❌ Passphrase must be at least 8 characters.", file=sys.stderr)
            continue
        p2 = getpass.getpass("Confirm: ")
        if p1 != p2:
            print("❌ Passphrases don't match.", file=sys.stderr)
            continue
        return p1


def _cmd_init(args: argparse.Namespace) -> int:
    """Initialize a new identity."""
    storage = _get_storage(args)

    if storage.exists() and not args.force:
        print(
            "❌ Identity already exists. Use --force to overwrite.",
            file=sys.stderr,
        )
        return 1

    password = args.password
    if not password:
        password = os.environ.get("HERMES_ID_PASSPHRASE") or ""
    if not password:
        password = _prompt_password()

    metadata = {}
    if args.profile:
        metadata["profile"] = args.profile

    card = storage.create(password, metadata=metadata)
    print()
    print(format_identity_card(card))
    print()
    print(f"✅ Identity created at {storage._dir}")
    print(f"   DID: {card.id}")
    print(f"   Card valid: ✅")
    print()
    print("⚠️  KEEP YOUR PASSPHRASE SAFE. It cannot be recovered.")
    print("   Your identity card (public) can be shared freely.")
    return 0


def _cmd_rotate(args: argparse.Namespace) -> int:
    """Rotate the identity keypair."""
    storage = _get_storage(args)

    if not storage.exists():
        print(
            "❌ No identity configured. Run `hermes-id init` first.",
            file=sys.stderr,
        )
        return 1

    password = args.password
    if not password:
        password = os.environ.get("HERMES_ID_PASSPHRASE") or ""
    if not password:
        password = _prompt_password("Current passphrase: ")

    old_card = storage.get_identity_card()

    if not args.force:
        print(f"⚠️  This will replace your current identity:")
        print(f"      Old DID: {old_card.did_short}")
        print(f"      New DID: (generated)")
        try:
            answer = input("   Continue? [y/N] ").strip().lower()
        except EOFError:
            answer = "n"
        if answer not in ("y", "yes"):
            print("❌ Rotation cancelled.")
            return 1

    metadata = {}
    if getattr(args, "note", None):
        metadata["note"] = args.note

    card = storage.rotate(
        password=password,
        metadata=metadata,
        keep_backup=not args.no_backup,
    )

    print()
    print(format_identity_card(card))
    print()
    print(f"✅ Key rotated. New DID: {card.id}")
    print(f"   Previous: {old_card.id}")
    print(f"   Transition proof: {'✅ valid' if verify_key_rotation(card) else '❌ missing'}")
    if not args.no_backup:
        print(f"   Backup of old key: {storage._dir / 'rotated'}")
    print()
    print("⚠️  Update every service that pins your DID to the new one.")
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    """Display identity card."""
    storage = _get_storage(args)
    if not storage.exists():
        print("❌ No identity configured. Run `hermes-id init` first.", file=sys.stderr)
        return 1
    card = storage.get_identity_card()
    print()
    print(format_identity_card(card))
    print()
    if card.metadata:
        print("Metadata:")
        for k, v in card.metadata.items():
            print(f"  {k}: {v}")
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    """Export identity card as JSON."""
    storage = _get_storage(args)
    if not storage.exists():
        print("❌ No identity configured.", file=sys.stderr)
        return 1
    card = storage.get_identity_card()
    output = card.to_json()
    if args.output:
        Path(args.output).write_text(output)
        print(f"✅ Identity card exported to {args.output}")
    else:
        print(output)
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    """Show identity status."""
    storage = _get_storage(args)
    print(storage.show_status())
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify an identity card file."""
    try:
        raw = Path(args.file).read_text()
        card = IdentityCard.from_json(raw)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"❌ Cannot read identity card: {e}", file=sys.stderr)
        return 1

    valid = verify_identity_card(card)
    print()
    print(format_identity_card(card))
    print()
    if valid:
        print(f"✅ Identity card is VALID (self-signature verified)")
        return 0
    else:
        print(f"❌ Identity card is INVALID (signature mismatch or missing)")
        return 1


def _cmd_sign(args: argparse.Namespace) -> int:
    """Sign a file with your identity."""
    storage = _get_storage(args)
    if not storage.exists():
        print("❌ No identity configured. Run `hermes-id init` first.", file=sys.stderr)
        return 1

    password = args.password
    if not password:
        password = os.environ.get("HERMES_ID_PASSPHRASE") or ""
    if not password:
        import getpass
        password = getpass.getpass("Passphrase: ")

    try:
        with storage.use_key(password) as private_key:
            file_path = Path(args.file)
            data = file_path.read_bytes()
            signature = sign(private_key, data)
    except Exception as e:
        print(f"❌ Cannot unlock identity: {e}", file=sys.stderr)
        return 1

    sig_b64 = _b64(signature)

    # Write signature alongside file
    sig_path = file_path.with_suffix(file_path.suffix + ".sig")
    sig_path.write_text(sig_b64)
    print(f"✅ Signed {args.file}")
    print(f"   Signature: {sig_b64[:32]}...")
    print(f"   Saved to:  {sig_path}")
    return 0


def _cmd_verify_sig(args: argparse.Namespace) -> int:
    """Verify a signature."""
    if not args.identity:
        print("❌ --identity is required to verify a signature.", file=sys.stderr)
        return 1

    try:
        raw = Path(args.identity).read_text()
        card = IdentityCard.from_json(raw)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"❌ Cannot read identity card: {e}", file=sys.stderr)
        return 1

    # Read signature (parameter can be base64 string or file path)
    sig_param = args.signature
    if Path(sig_param).exists():
        sig_b64 = Path(sig_param).read_text().strip()
    else:
        sig_b64 = sig_param

    try:
        sig_bytes = _unb64(sig_b64)
    except Exception as e:
        print(f"❌ Invalid signature encoding: {e}", file=sys.stderr)
        return 1

    # Recover public key from identity card
    pub_b64 = card.public_key_multibase
    if not pub_b64:
        print("❌ Identity card has no public key.", file=sys.stderr)
        return 1

    try:
        pub_raw = _unb64(pub_b64[1:])  # strip multibase prefix 'u'
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
    except Exception as e:
        print(f"❌ Cannot parse public key: {e}", file=sys.stderr)
        return 1

    data = Path(args.file).read_bytes()
    if verify(public_key, data, sig_bytes):
        print(f"✅ Signature VALID")
        print(f"   Signed by: {card.did_short}")
        print(f"   Key type:  Ed25519")
        return 0
    else:
        print(f"❌ Signature INVALID")
        return 1


def _cmd_handshake(args: argparse.Namespace) -> int:
    """Handle handshake subcommands."""
    storage = _get_storage(args)

    if not storage.exists():
        print("❌ No identity configured. Run `hermes-id init` first.", file=sys.stderr)
        return 1

    password = args.password
    if not password:
        password = os.environ.get("HERMES_ID_PASSPHRASE") or ""
    if not password:
        import getpass
        password = getpass.getpass("Passphrase: ")

    try:
        private_key = storage.unlock(password)
    except Exception as e:
        print(f"❌ Cannot unlock identity: {e}", file=sys.stderr)
        return 1

    identity_card = storage.get_identity_card()

    if args.handshake_cmd == "listen":
        print(f"🎧 Starting handshake server...")
        run_handshake_server(
            identity_card=identity_card,
            private_key=private_key,
            host=getattr(args, "host", "127.0.0.1"),
            port=args.port,
        )
        return 0

    elif args.handshake_cmd == "connect":
        target = args.target
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            port = int(port_str)
        else:
            host = target
            port = 9487

        print(f"🔗 Connecting to {host}:{port}...")

        def _on_verify(peer_card: IdentityCard) -> bool:
            if args.peer_did:
                if peer_card.id != args.peer_did:
                    print(f"❌ Peer DID mismatch: expected {args.peer_did}, got {peer_card.id}")
                    return False
            return True

        success, peer_card, session_key = run_handshake_client(
            identity_card=identity_card,
            private_key=private_key,
            peer_did="",
            host=host,
            port=port,
            on_verify=_on_verify,
        )

        if success:
            print(f"✅ Handshake successful!")
            if session_key:
                print(f"   Session key: {_b64(session_key)[:16]}...")
            return 0
        else:
            return 1

    return 1


def _cmd_server(args: argparse.Namespace) -> int:
    """Start the HTTP Auth Server."""
    try:
        from hermes_id.server import AuthServer
    except ImportError as e:
        print(f"❌ Cannot start server: {e}", file=sys.stderr)
        print("   Install: pip install 'hermes-id[server]'", file=sys.stderr)
        return 1

    server = AuthServer(
        identity_dir=args.dir,
        db_path=args.db,
        token_ttl=args.token_ttl,
        admin_key=args.admin_key,
        cors_origins=args.cors_origins.split(",") if args.cors_origins else None,
    )
    server.run(
        host=args.host,
        port=args.port,
        ssl_certfile=args.tls_cert,
        ssl_keyfile=args.tls_key,
    )
    return 0


def _cmd_mcp(args: argparse.Namespace) -> int:
    """Start the MCP stdio server."""
    try:
        from hermes_id.mcp_server import main as mcp_main
    except ImportError as e:
        print(f"❌ Cannot start MCP server: {e}", file=sys.stderr)
        print("   Install: pip install 'hermes-id[mcp]'", file=sys.stderr)
        return 1

    mcp_main()
    return 0


if __name__ == "__main__":
    sys.exit(main())

__all__ = ["main"]
