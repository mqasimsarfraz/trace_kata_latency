#!/usr/bin/env bash

set -euo pipefail

IG_IMAGE="${IG_IMAGE:-ghcr.io/mqasimsarfraz/ig:go-uprobe-symbols}"
GADGET_IMAGE="${GADGET_IMAGE:-ghcr.io/mqasimsarfraz/trace_kata_latency:latest}"
TIMEOUT="${TIMEOUT:-0}"
NODE="${1:-$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')}"

exec kubectl debug "node/${NODE}" \
	--image="${IG_IMAGE}" \
	--image-pull-policy=Always \
	--profile=sysadmin \
	--attach=true \
	--env=HOST_ROOT=/host \
	-- /usr/bin/ig run "${GADGET_IMAGE}" \
	--host \
	--verify-image=false \
	--timeout="${TIMEOUT}"
