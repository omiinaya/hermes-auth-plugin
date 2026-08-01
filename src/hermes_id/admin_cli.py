"""
hermes-id Admin CLI — manage the agent registry from the terminal.

Usage::

    hermes-id-admin --server http://localhost:9488 --admin-key KEY list
    hermes-id-admin --server http://localhost:9488 --admin-key KEY approve did:hermes:abc123
    hermes-id-admin --server http://localhost:9488 --admin-key KEY deny did:hermes:abc123
    hermes-id-admin --server http://localhost:9488 --admin-key KEY status did:hermes:abc123
    hermes-id-admin --server http://localhost:9488 --admin-key KEY delete did:hermes:abc123
"""

import argparse
import json
import os
import sys

from hermes_id.auth_client import AuthClient


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hermes-id-admin",
        description="Admin CLI for the hermes-id Auth Server agent registry.",
    )
    parser.add_argument("--server", required=True, help="Auth server URL (e.g. http://localhost:9488)")
    parser.add_argument("--admin-key", help="Admin API key (default: HERMES_ID_ADMIN_KEY env var)")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout")

    sub = parser.add_subparsers(dest="command", required=True)

    list_p = sub.add_parser("list", help="List registered agents")
    list_p.add_argument("--status", choices=["pending", "approved", "denied"], help="Filter by status")
    list_p.add_argument("--page", type=int, default=1, help="Page number")
    list_p.add_argument("--page-size", type=int, default=50, help="Items per page")
    list_p.add_argument("--search", help="Search DID or display name")
    list_p.add_argument("--project", help="Filter by requested project (audience)")

    approve_p = sub.add_parser("approve", help="Approve a pending agent")
    approve_p.add_argument("did", help="Agent DID to approve")
    approve_p.add_argument("--for", dest="project", metavar="PROJECT",
                           help="Require the agent to have requested this project")

    deny_p = sub.add_parser("deny", help="Deny a pending agent")
    deny_p.add_argument("did", help="Agent DID to deny")
    deny_p.add_argument("--for", dest="project", metavar="PROJECT",
                        help="Require the agent to have requested this project")

    status_p = sub.add_parser("status", help="Check an agent's status")
    status_p.add_argument("did", help="Agent DID to check")

    delete_p = sub.add_parser("delete", help="Remove an agent from the registry")
    delete_p.add_argument("did", help="Agent DID to remove")

    return parser


def _get_client(args: argparse.Namespace) -> AuthClient:
    admin_key = args.admin_key or os.environ.get("HERMES_ID_ADMIN_KEY", "")
    if not admin_key:
        print("❌ Admin key required. Pass --admin-key or set HERMES_ID_ADMIN_KEY.", file=sys.stderr)
        sys.exit(1)
    return AuthClient(args.server, admin_key=admin_key, timeout=args.timeout)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    client = _get_client(args)

    try:
        if args.command == "list":
            result = client.list_agents(
                status=args.status,
                page=args.page,
                page_size=args.page_size,
                search=args.search,
                project=args.project,
            )
            print(json.dumps(result, indent=2))

        elif args.command == "approve":
            result = client.approve_agent(args.did, project=args.project)
            print(json.dumps(result, indent=2))

        elif args.command == "deny":
            result = client.deny_agent(args.did, project=args.project)
            print(json.dumps(result, indent=2))

        elif args.command == "status":
            result = client.get_agent_status(args.did)
            print(json.dumps(result, indent=2))

        elif args.command == "delete":
            result = client.delete_agent(args.did)
            print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1
    finally:
        client.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
