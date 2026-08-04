"""
Agent client example — demonstrates how an agent authenticates with
the hermes-id Auth Server and calls a protected service.

Usage::

    python examples/agent_client.py [--token-only]

Requires running:
    1. hermes-id auth server (``hermes-id server``)
    2. Example protected service (``python examples/protected_service.py``)
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import httpx

from hermes_id.auth_client import AuthFlow

AUTH_SERVER = os.environ.get("HERMES_AUTH_SERVER_URL", "http://127.0.0.1:9488")
EXAMPLE_SERVICE = os.environ.get("EXAMPLE_SERVICE_URL", "http://127.0.0.1:8000")
AUTH_PROJECT = os.environ.get("HERMES_AUTH_PROJECT", "demo-service")


def main():
    parser = argparse.ArgumentParser(description="hermes-id Agent Client Example")
    parser.add_argument("--token-only", action="store_true", help="Only get the token")
    parser.add_argument("--auth-server", default=AUTH_SERVER)
    parser.add_argument("--service-url", default=EXAMPLE_SERVICE)
    parser.add_argument(
        "--project",
        default=AUTH_PROJECT,
        help="Audience to scope the token to (must match the service's HERMES_AUTH_PROJECT)",
    )
    args = parser.parse_args()

    # Step 1: Authenticate with the hermes-id Auth Server
    print(f"🔐 Authenticating with {args.auth_server}...")
    flow = AuthFlow(args.auth_server)
    try:
        token, result = flow.login(aud=args.project)
    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        print("   Make sure the auth server is running and this agent is")
        print("   registered and approved.")
        sys.exit(1)
    finally:
        flow.close()

    print(f"✅ Authenticated as {result['did'][:24]}...")
    print(f"   Audience: {result.get('aud', '(none)')}")
    print(f"   Token expires at: {result['expires_at']}")

    if args.token_only:
        print(f"\nToken: {token}")
        return

    # Step 2: Call the protected service
    print(f"\n📡 Calling protected service at {args.service_url}...")

    with httpx.Client() as client:
        # First try without auth (should fail)
        r = client.get(f"{args.service_url}/api/protected")
        print(f"   Without auth: {r.status_code} {'✅' if r.status_code == 403 or r.status_code == 401 else '❌'}")

        # Now with auth
        r = client.get(
            f"{args.service_url}/api/protected",
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code == 200:
            data = r.json()
            print(f"   With auth:    {r.status_code} ✅")
            print(f"   Response: {data['message']}")
            print(f"   Agent DID: {data['agent_did']}")
        else:
            print(f"   With auth:    {r.status_code} ❌ {r.text}")

        # Call /api/me
        r = client.get(
            f"{args.service_url}/api/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code == 200:
            print(f"\n👤 /api/me: {r.json()['did'][:24]}...")
        else:
            print(f"\n👤 /api/me: {r.status_code} {r.text}")

    print(f"\n🎉 Done! Token can be reused for {result['expires_at'] - __import__('time').time():.0f}s")


if __name__ == "__main__":
    main()
