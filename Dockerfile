FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir 'hermes-id[server]'

VOLUME /app/identity
VOLUME /app/data

EXPOSE 9488

CMD ["hermes-id", "server", "--host", "0.0.0.0", "--port", "9488", "--dir", "/app/identity", "--db", "/app/data/agent_registry.db"]
