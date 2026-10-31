#!/bin/bash
# Entry point for the all-in-one image (containers/Dockerfile.allinone), which
# plays two roles:
#
# 1. Sandbox (spawned by the orchestrator once per scan): the sandbox manifest
#    injects STRIX_SANDBOX_ROLE=1, so delegate to the sandbox bootstrap
#    (caido sidecar, system-wide proxy, CA trust) and keep the container alive.
# 2. Orchestrator (started manually with `docker run`): detect this
#    container's own image so spawned sandboxes reuse it, then exec `strix`.
set -e

if [ -n "${STRIX_SANDBOX_ROLE:-}" ]; then
  exec /usr/local/bin/docker-entrypoint.sh "$@"
fi

# Orchestrator mode: the Docker daemon resolves bind-mount sources on the
# HOST filesystem, which this container's paths don't map to. Upload local
# sources into sandboxes instead (manifest entries, like remote backends).
export STRIX_RUNTIME_UPLOAD_SOURCES="${STRIX_RUNTIME_UPLOAD_SOURCES:-1}"

# Point STRIX_IMAGE at this very image: spawned sandboxes then reuse it, and
# the image already exists on the daemon, so nothing gets pulled. The image
# has no docker CLI; query the Engine API over the mounted socket instead.
if [ -z "${STRIX_IMAGE:-}" ] && [ -S /var/run/docker.sock ]; then
  self_image="$(curl -sf --unix-socket /var/run/docker.sock \
    "http://localhost/containers/$(hostname)/json" \
    | jq -r '.Config.Image // empty' 2>/dev/null || true)"
  if [ -n "${self_image:-}" ] && [ "$self_image" != "<no value>" ]; then
    export STRIX_IMAGE="$self_image"
    echo "Sandbox image: $STRIX_IMAGE (this image, reused for spawned sandboxes)"
  fi
fi
if [ -z "${STRIX_IMAGE:-}" ]; then
  echo "WARNING: could not detect this container's image from the Docker socket." >&2
  echo "         Set STRIX_IMAGE explicitly so sandbox containers use the right image." >&2
fi

# Artifacts (strix_runs/) are written relative to the working directory;
# /workspace is the conventional mount point.
cd /workspace 2>/dev/null || true

exec strix "$@"
