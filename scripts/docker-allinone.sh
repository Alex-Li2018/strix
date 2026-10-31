#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE="strix-allinone"
TAG="${1:-dev}"
# The sandbox toolchain to layer on: the published image by default, or a
# locally built strix-sandbox:<tag> from scripts/docker.sh.
BASE="${2:-ghcr.io/usestrix/strix-sandbox:1.3.1}"

echo "Building $IMAGE:$TAG on top of $BASE ..."
docker build \
  -f "$PROJECT_ROOT/containers/Dockerfile.allinone" \
  --build-arg SANDBOX_BASE="$BASE" \
  -t "$IMAGE:$TAG" \
  "$PROJECT_ROOT"

echo "Done: $IMAGE:$TAG"
echo
echo "Run a scan (own server: socket + host network):"
echo "  docker run --rm --network host \\"
echo "    -v /var/run/docker.sock:/var/run/docker.sock \\"
echo "    -e STRIX_LLM='openrouter/z-ai/glm-5.3' -e LLM_API_KEY='...' \\"
echo "    -v \"\$PWD/strix_runs:/workspace/strix_runs\" \\"
echo "    $IMAGE:$TAG -n -t https://example.com --scan-mode quick"
