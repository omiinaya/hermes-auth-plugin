# hermes-id Auth Server — self-contained image.
#
# Builds from the local source tree (the package is not published to PyPI
# yet; `pip install hermes-id[server]` would fail until it is). Once it is
# published, switch the RUN line to `pip install --no-cache-dir
# 'hermes-id[server]'` or use an ARG-based install.
FROM python:3.11-slim

WORKDIR /app

# Copy the whole source tree (pyproject + src) and install from it.
COPY . /app/src-tree
RUN pip install --no-cache-dir "/app/src-tree[server]" && rm -rf /app/src-tree

VOLUME /app/identity
VOLUME /app/data

EXPOSE 9488

# TLS: mount cert/key PEMs and pass --tls-cert/--tls-key via CMD overrides.
CMD ["hermes-id", "server", "--host", "0.0.0.0", "--port", "9488", "--dir", "/app/identity", "--db", "/app/data/agent_registry.db"]
