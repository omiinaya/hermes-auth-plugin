# Examples

Two runnable examples showing the hermes-id Auth Server integration:

## 1. `protected_service.py` — FastAPI service (offline-first)

A minimal FastAPI app protected by `HermesIDAuth`:

```bash
# 1. Start the auth server (separate terminal)
hermes-id server --port 9488

# 2. Run the example service
pip install 'hermes-id[server]'
HERMES_AUTH_SERVER_URL=http://127.0.0.1:9488 \
HERMES_AUTH_PROJECT=demo-service \
python examples/protected_service.py
```

## 2. `agent_client.py` — agent that authenticates

An agent that signs in and gets a scoped token:

```bash
python examples/agent_client.py \
  --auth-server http://127.0.0.1:9488 \
  --project demo-service
```

Use `--token-only` to just print the token (handy for `curl`):

```bash
python examples/agent_client.py --auth-server http://127.0.0.1:9488 \
  --project demo-service --token-only
```

## Both together

Agent → service auth, end to end:

1. Start the auth server
2. Run `protected_service.py` (service)
3. Register + approve the agent, then run `agent_client.py` (agent)
4. The agent's token authenticates against the service

See `docs/INTEGRATION.md` for the full walkthrough and API reference.
