#!/usr/bin/env bash
# publish-local.sh — build hermes-id and publish to the local PEP 503 package index.
#
# Serves a PyPI-compatible simple index at:
#   http://192.168.1.10:9499/simple/            (systemd: hermes-id-index.service)
#
# Any project on the box/LAN can then install with:
#   pip install --index-url http://192.168.1.10:9499/simple/ \
#               --extra-index-url https://pypi.org/simple    \
#               hermes-id
#
# (local index first so hermes-id resolves here; every other dep falls
#  through to PyPI. Public PyPI publication is the only external step —
#  requires a PyPI API token or trusted-publisher setup on the account.)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="/opt/hermes-id/dist"
INDEX_DIR="$DIST_DIR/simple/hermes-id"

if [ ! -d /opt/hermes-id ]; then
  echo "ERROR: /opt/hermes-id does not exist (this box is not the auth host)" >&2
  exit 1
fi

echo "==> Building sdist + wheel"
"$REPO_ROOT/.venv/bin/python" -m build "$REPO_ROOT" --outdir "$DIST_DIR" >/dev/null

echo "==> Refreshing PEP 503 simple index"
mkdir -p "$INDEX_DIR"
{
  echo "<!DOCTYPE html><html><head><title>hermes-id</title></head><body>"
  for f in "$DIST_DIR"/hermes_id-*.whl "$DIST_DIR"/hermes_id-*.tar.gz; do
    [ -e "$f" ] || continue
    b="$(basename "$f")"
    echo "<a href=\"../../$b\">$b</a><br/>"
  done
  echo "</body></html>"
} > "$INDEX_DIR/index.html"

{
  echo "<!DOCTYPE html><html><head><title>hermes-id index</title></head><body>"
  echo "<a href=\"hermes-id/\">hermes-id</a><br/>"
  echo "</body></html>"
} > "$DIST_DIR/simple/index.html"

echo "==> Published:"
ls -la "$DIST_DIR" | grep -E "whl|gz" | awk '{print "   " $NF " (" $5 " bytes)"}'
echo "Index: http://192.168.1.10:9499/simple/hermes-id/"
