# trace_kata_latency

Minimal Inspektor Gadget gadget that prints Kata Containers pod sandbox
request-to-response latency at the kubelet CRI boundary.

> Note: This gadget requires the `ig` image with stripped Go `.gopclntab` symbol resolution. See [ig](https://github.com/inspektor-gadget/inspektor-gadget/pull/5493/changes/ab03ef37ae901638ba8dfb69724991276487187e) for details.

The gadget traces:

- Kata `RunPodSandbox` requests using the `kata` runtime handler,
  including creation and startup of the Kata VM.
- `StopPodSandbox` for Kata sandbox IDs observed by the gadget.
- `RemovePodSandbox` for Kata sandbox IDs observed by the gadget.

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
FAILED   OPERATION       LATENCY_NS      SANDBOX_ID
0        SANDBOX_RUN     1.314252181s    9c58a84...
0        SANDBOX_STOP    149.73ms        9c58a84...
0        SANDBOX_REMOVE  42.76ms         9c58a84...
```

## Interpreting the output

- `FAILED` is `0` when the CRI call succeeds and `1` when it returns an error.
- `OPERATION` identifies the CRI sandbox lifecycle call.
- `LATENCY_NS` is the request-to-response duration, rendered in a
  human-readable unit by `ig`.
- `SANDBOX_ID` is the ID returned by a successful `RunPodSandbox` call or
  supplied to a later stop or remove call.

A failed `SANDBOX_RUN` normally has an empty `SANDBOX_ID` because the runtime
did not return a usable sandbox. Repeated failed runs commonly indicate that
kubelet is retrying sandbox creation for the same Pod. The gadget records only
whether the call failed, not the error message; use `kubectl describe pod`,
Kubernetes events, and kubelet or containerd logs to find the cause.

## `RunPodSandbox` semantics and latency boundary

The CRI defines `RunPodSandbox` as a unary gRPC request and requires the
runtime to leave the sandbox in the ready state when the call succeeds.
Kubelet calls it directly and waits for either a sandbox ID or an error, so
each individual call is synchronous from kubelet's perspective. Kubelet can
still issue multiple calls concurrently for different Pods.

For Kata Containers, this duration captures the runtime-visible sandbox path,
which typically includes starting the Kata runtime shim, hypervisor, guest VM,
and guest agent. The exact work depends on the Kata, containerd, and platform
configuration.

The measurement does not include work performed after `RunPodSandbox`
returns, such as image pulls, `CreateContainer`, `StartContainer`, or
application readiness. It also does not include scheduler queueing before
kubelet starts the CRI request.

The gadget classifies successful `RunPodSandbox` calls by their `kata` runtime
handler (selected by the `kata-vm-isolation` RuntimeClass) and remembers the
returned sandbox ID.
Later stop and remove calls are emitted only when their ID belongs to a
remembered Kata sandbox. Sandboxes created before the gadget starts are not
known, so their stop and remove calls are not emitted.

## Runtime warnings

`run-aks.sh` passes `--verify-image=false`, so `ig` warns that gadget signature
verification is disabled. This permits unsigned gadget images but removes the
image authenticity check.

`ig` also warns when the gadget build version differs from the running `ig`
version. The gadget may work, but matching versions is recommended because
metadata, event schemas, and runtime APIs can change between releases.

## References

- [Kubernetes CRI `RuntimeService` definition](https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/cri-api/pkg/apis/runtime/v1/api.proto)
- [Kubelet `createPodSandbox` implementation](https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/kuberuntime/kuberuntime_sandbox.go)
- [gRPC core concepts and unary RPC lifecycle](https://grpc.io/docs/what-is-grpc/core-concepts/)
- [Kata Containers architecture](https://github.com/kata-containers/kata-containers/blob/main/docs/design/architecture/README.md)
- [Kata Containers and Kubernetes](https://github.com/kata-containers/kata-containers/blob/main/docs/design/architecture/kubernetes.md)
