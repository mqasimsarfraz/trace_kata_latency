# trace_kata_latency

Minimal Inspektor Gadget gadget that prints Kata Containers pod sandbox
request-to-response latency at the kubelet CRI boundary.

> Note: This gadget requires the `ig` image with stripped Go `.gopclntab` symbol resolution. See [ig](https://github.com/inspektor-gadget/inspektor-gadget/pull/5493/changes/ab03ef37ae901638ba8dfb69724991276487187e) for details.

The gadget traces:

- `RunPodSandbox`, which includes creation and startup of the Kata VM.
- `StopPodSandbox`, which stops the sandbox and its VM.
- `RemovePodSandbox`, which removes the sandbox resources.

## Requirements

- AKS kubelet at `/opt/bin/kubelet`.
- `ig` with stripped Go `.gopclntab` symbol resolution.
- Privileged node execution with host PID and filesystem access.

## Build

```bash
make build
```

Build and push the default
`ghcr.io/mqasimsarfraz/trace_kata_latency:latest` image:

```bash
make push
```

The image name and build parameters can be overridden:

```bash
make push \
  GADGET_REPOSITORY=ghcr.io/example \
  GADGET_TAG=test \
  GADGET_BUILD_PARAMS=--update-metadata
```

## Run on AKS

```bash
./run-aks.sh
```

The script selects the first node by default. Pass a node name to target a
specific node:

```bash
TIMEOUT=60 ./run-aks.sh aks-nodepool1-12345678-vmss000000
```

It uses:

- `ghcr.io/mqasimsarfraz/ig:go-uprobe-symbol`
- `ghcr.io/mqasimsarfraz/trace_kata_latency:latest`

Example output:

```text
OPERATION              LATENCY_NS   FAILED
SANDBOX_RUN            1.21s        0
SANDBOX_STOP           184.32ms     0
SANDBOX_REMOVE         42.76ms      0
```

This measures kubelet CRI RPC duration. `SANDBOX_RUN` captures the
runtime-visible Kata VM startup path, but not later image pulls,
`CreateContainer`, `StartContainer`, scheduling, or application readiness.

The CRI method names do not identify the selected runtime. Run the gadget on
nodes or workloads configured to use the Kata `RuntimeClass` so the sandbox
events correspond to Kata Containers.
