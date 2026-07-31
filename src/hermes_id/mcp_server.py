"""
hermes-id MCP Server — exposes identity and authentication tools
for other Hermes agents via MCP (Model Context Protocol).

Usage::

    # Run as a stdio MCP server
    hermes-id mcp

    # In Hermes config.yaml:
    # mcp_servers:
    #   hermes-id:
    #     command: "hermes-id"
    #     args: ["mcp"]
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

from hermes_id.crypto import _b64, _unb64, sign, verify
from hermes_id.identity import IdentityCard, verify_identity_card, verify_key_rotation
from hermes_id.server import verify_auth_token
from hermes_id.storage import IdentityStorage

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
    HAS_MCP = True
except ImportError:
    HAS_MCP = False


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

class HermesIDMCPServer:
    """MCP server exposing hermes-id tools for agent-to-agent authentication."""

    def __init__(self, identity_dir: Optional[str] = None):
        self._storage = IdentityStorage(directory=identity_dir)
        self._app = Server("hermes-id")

    def _get_card(self) -> Optional[IdentityCard]:
        """Get the identity card if configured."""
        try:
            return self._storage.get_identity_card()
        except (FileNotFoundError, Exception):
            return None

    def _get_password(self) -> str:
        return os.environ.get("HERMES_ID_PASSPHRASE") or ""

    def register_tools(self) -> None:
        """Register all MCP tools."""
        app = self._app

        @app.list_tools()
        async def list_tools() -> list[Tool]:
            return [
                Tool(
                    name="hermes_id_status",
                    description="Get the identity status of this Hermes instance (DID, key type, card validity)",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                    },
                ),
                Tool(
                    name="hermes_id_export",
                    description="Export the identity card as JSON",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                    },
                ),
                Tool(
                    name="hermes_id_verify_card",
                    description="Verify an identity card's self-signature",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "identity_card_json": {
                                "type": "string",
                                "description": "JSON-encoded identity card to verify",
                            },
                        },
                        "required": ["identity_card_json"],
                    },
                ),
                Tool(
                    name="hermes_id_sign",
                    description="Sign a message with this instance's private key",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "message_b64": {
                                "type": "string",
                                "description": "Base64-encoded message to sign",
                            },
                        },
                        "required": ["message_b64"],
                    },
                ),
                Tool(
                    name="hermes_id_verify_signature",
                    description="Verify a signature against a public key from an identity card",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "message_b64": {
                                "type": "string",
                                "description": "Base64-encoded original message",
                            },
                            "signature_b64": {
                                "type": "string",
                                "description": "Base64-encoded signature",
                            },
                            "identity_card_json": {
                                "type": "string",
                                "description": "JSON-encoded identity card of the signer",
                            },
                        },
                        "required": ["message_b64", "signature_b64", "identity_card_json"],
                    },
                ),
                Tool(
                    name="hermes_id_verify_rotation",
                    description="Verify the key-rotation transition proof on an identity card (was the rotation authorized by the previous key?)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "identity_card_json": {
                                "type": "string",
                                "description": "JSON-encoded identity card with rotation metadata",
                            },
                        },
                        "required": ["identity_card_json"],
                    },
                ),
                Tool(
                    name="hermes_id_auth_client",
                    description="Full auth client against a hermes-id Auth Server: challenge → sign → authenticate",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "server_url": {
                                "type": "string",
                                "description": "URL of the hermes-id Auth Server (e.g. http://localhost:9488)",
                            },
                            "action": {
                                "type": "string",
                                "enum": ["login", "register", "status", "verify_token"],
                                "description": "Auth action to perform",
                            },
                            "token": {
                                "type": "string",
                                "description": "Auth token to verify (for verify_token action)",
                            },
                            "display_name": {
                                "type": "string",
                                "description": "Display name for registration",
                            },
                        },
                        "required": ["server_url", "action"],
                    },
                ),
            ]

        @app.call_tool()
        async def call_tool(name: str, arguments: dict) -> list[TextContent]:
            try:
                if name == "hermes_id_status":
                    return [TextContent(type="text", text=self._handle_status())]
                elif name == "hermes_id_export":
                    return [TextContent(type="text", text=self._handle_export())]
                elif name == "hermes_id_verify_card":
                    return [TextContent(type="text", text=self._handle_verify_card(arguments))]
                elif name == "hermes_id_sign":
                    return [TextContent(type="text", text=self._handle_sign(arguments))]
                elif name == "hermes_id_verify_signature":
                    return [TextContent(type="text", text=self._handle_verify_signature(arguments))]
                elif name == "hermes_id_verify_rotation":
                    return [TextContent(type="text", text=self._handle_verify_rotation(arguments))]
                elif name == "hermes_id_auth_client":
                    return [TextContent(type="text", text=self._handle_auth_client(arguments))]
                else:
                    return [TextContent(type="text", text=f"Unknown tool: {name}")]
            except Exception as e:
                return [TextContent(type="text", text=f"Error: {e}")]

    def _handle_status(self) -> str:
        card = self._get_card()
        if not card:
            return json.dumps({
                "status": "not_configured",
                "error": "No identity configured. Run `hermes-id init`.",
            })
        valid = verify_identity_card(card)
        return json.dumps({
            "status": "ok" if valid else "invalid",
            "did": card.id,
            "created": card.created,
            "card_valid": valid,
            "metadata": card.metadata,
        })

    def _handle_export(self) -> str:
        card = self._get_card()
        if not card:
            return json.dumps({"error": "No identity configured"})
        return card.to_json()

    def _handle_verify_card(self, args: dict) -> str:
        identity_card_json = args.get("identity_card_json", "")
        try:
            card_data = json.loads(identity_card_json)
            card = IdentityCard(**card_data)
        except (json.JSONDecodeError, TypeError) as e:
            return json.dumps({"valid": False, "error": f"Invalid card JSON: {e}"})

        valid = verify_identity_card(card)
        return json.dumps({
            "valid": valid,
            "did": card.id,
            "created": card.created,
        })

    def _handle_sign(self, args: dict) -> str:
        card = self._get_card()
        if not card:
            return json.dumps({"error": "No identity configured"})

        password = self._get_password()
        if not password:
            return json.dumps({"error": "HERMES_ID_PASSPHRASE not set"})

        message_b64 = args.get("message_b64", "")
        try:
            message = _unb64(message_b64)
        except Exception as e:
            return json.dumps({"error": f"Invalid base64 message: {e}"})

        try:
            with self._storage.use_key(password) as private_key:
                sig = sign(private_key, message)
        except Exception as e:
            return json.dumps({"error": f"Cannot sign: {e}"})

        return json.dumps({
            "did": card.id,
            "signature_b64": _b64(sig),
            "message_b64": message_b64,
        })

    def _handle_verify_signature(self, args: dict) -> str:
        message_b64 = args.get("message_b64", "")
        signature_b64 = args.get("signature_b64", "")
        identity_card_json = args.get("identity_card_json", "")

        try:
            message = _unb64(message_b64)
            signature = _unb64(signature_b64)
        except Exception as e:
            return json.dumps({"valid": False, "error": f"Invalid base64: {e}"})

        try:
            card_data = json.loads(identity_card_json)
            card = IdentityCard(**card_data)
        except (json.JSONDecodeError, TypeError) as e:
            return json.dumps({"valid": False, "error": f"Invalid card JSON: {e}"})

        pub_b64 = card.public_key_multibase
        if not pub_b64:
            return json.dumps({"valid": False, "error": "No public key in card"})

        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            pub_raw = _unb64(pub_b64[1:])
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_raw)
        except Exception as e:
            return json.dumps({"valid": False, "error": f"Cannot parse key: {e}"})

        valid = verify(public_key, message, signature)
        return json.dumps({
            "valid": valid,
            "did": card.id,
            "signed_by": card.did_short,
        })

    def _handle_verify_rotation(self, args: dict) -> str:
        identity_card_json = args.get("identity_card_json", "")
        try:
            card_data = json.loads(identity_card_json)
            card = IdentityCard(**card_data)
        except (json.JSONDecodeError, TypeError) as e:
            return json.dumps({"valid": False, "error": f"Invalid card JSON: {e}"})

        rotation = verify_key_rotation(card)
        if rotation is None:
            # Distinguish "no rotation metadata" from "failed proof"
            if (card.metadata or {}).get("rotation"):
                return json.dumps({"valid": False, "did": card.id,
                                   "error": "Rotation transition proof invalid"})
            return json.dumps({"valid": False, "did": card.id,
                               "error": "Card has no rotation metadata"})
        return json.dumps({
            "valid": True,
            "did": card.id,
            "previous_did": rotation.get("previous_did"),
            "rotated_at": rotation.get("rotated_at"),
        })

    def _handle_auth_client(self, args: dict) -> str:
        server_url = args.get("server_url", "")
        action = args.get("action", "")

        if not server_url:
            return json.dumps({"error": "server_url is required"})

        try:
            from hermes_id.auth_client import AuthClient
        except ImportError:
            return json.dumps({"error": "auth_client module not available (httpx required)"})

        client = AuthClient(server_url, identity_dir=str(self._storage._dir))
        try:
            if action == "login":
                from hermes_id.auth_client import AuthFlow
                flow = AuthFlow(server_url, identity_dir=str(self._storage._dir))
                token = flow.login()
                return json.dumps({"token": token, "did": self._get_card().id})
            elif action == "register":
                card = self._get_card()
                display_name = args.get("display_name", "") or card.id
                result = client.register_agent(card.id, display_name=display_name)
                return json.dumps(result)
            elif action == "status":
                card = self._get_card()
                if card:
                    result = client.get_agent_status(card.id)
                    return json.dumps(result)
                return json.dumps({"error": "No identity configured"})
            elif action == "verify_token":
                token = args.get("token", "")
                if not token:
                    return json.dumps({"error": "token is required for verify_token"})
                payload = client.verify_token(token)
                if payload:
                    return json.dumps({"valid": True, **payload})
                return json.dumps({"valid": False, "error": "Token invalid or expired"})
            else:
                return json.dumps({"error": f"Unknown action: {action}"})
        finally:
            client.close()

    async def run(self) -> None:
        """Run the MCP server over stdio."""
        self.register_tools()
        async with stdio_server() as (read_stream, write_stream):
            await self._app.run(read_stream, write_stream, self._app.create_initialization_options())


def main() -> None:
    """Entry point for `hermes-id mcp`."""
    if not HAS_MCP:
        print("MCP SDK not installed. Run: pip install mcp")
        sys.exit(1)

    import asyncio
    server = HermesIDMCPServer()
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
