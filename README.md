# trace_kata_latency

Minimal Inspektor Gadget gadget that prints Kata Containers sandbox and
container request-to-response latency at the kubelet CRI boundary.

> Note: This gadget requires the `ig` image with stripped Go `.gopclntab` symbol resolution. See [ig](https://github.com/inspektor-gadget/inspektor-gadget/pull/5493/changes/ab03ef37ae901638ba8dfb69724991276487187e) for details.

The gadget traces:

- Kata `RunPodSandbox` requests using the `kata` or `kata-preview` runtime
  handler,
  including creation and startup of the Kata VM.
- `StopPodSandbox` for Kata sandbox IDs observed by the gadget.
- `RemovePodSandbox` for Kata sandbox IDs observed by the gadget.
- `CreateContainer`, `StartContainer`, `StopContainer`, and `RemoveContainer`
  for containers belonging to those observed Kata sandboxes.

Events from both handlers are emitted into the same timestamped stream and
include the runtime handler label, so workloads using both runtime classes can
be traced concurrently.

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

## Continuous integration

GitHub Actions builds the gadget for pull requests. Pushes to `main` publish
both `sha-<commit>` and `latest` tags to
`ghcr.io/mqasimsarfraz/trace_kata_latency`. Tags matching `v*` publish both the
commit tag and the matching release tag.

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
FAILED   OPERATION         RUNTIME_HANDLER   LATENCY_NS      SANDBOX_ID   CONTAINER_ID
0        SANDBOX_RUN       kata              1.314252181s    9c58a84...
0        CONTAINER_CREATE  kata              486.21ms        9c58a84...  7f31c20...
0        CONTAINER_START   kata              231.48ms                     7f31c20...
0        SANDBOX_RUN       kata-preview      998.42ms        25b76dd...
0        CONTAINER_STOP    kata              18.32ms                      7f31c20...
0        CONTAINER_REMOVE  kata              12.11ms                      7f31c20...
0        SANDBOX_STOP      kata              149.73ms        9c58a84...
0        SANDBOX_REMOVE    kata              42.76ms         9c58a84...
```

## Interpreting the output

- `FAILED` is `0` when the CRI call succeeds and `1` when it returns an error.
- `OPERATION` identifies the CRI sandbox or container lifecycle call.
- `RUNTIME_HANDLER` identifies the `kata` or `kata-preview` handler.
- `LATENCY_NS` is the request-to-response duration, rendered in a
  human-readable unit by `ig`.
- `SANDBOX_ID` is the ID returned by a successful `RunPodSandbox` call or
  supplied to a later sandbox call. `CONTAINER_CREATE` includes its parent
  sandbox ID.
- `CONTAINER_ID` is the ID returned by a successful `CreateContainer` call or
  supplied to a later container call.

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

Each event measures one CRI call. Image pulls and application readiness remain
outside these boundaries, as does scheduler queueing before kubelet starts the
CRI request.

The gadget classifies `RunPodSandbox` calls by their `kata` or `kata-preview`
runtime handler and remembers the returned sandbox ID. It uses the parent
sandbox ID to classify `CreateContainer`, then remembers the returned container
ID for subsequent start, stop, and remove calls.

Later lifecycle calls are emitted only when their IDs belong to sandboxes or
containers observed by the gadget. Resources created before the gadget starts
are not known, so their later lifecycle calls are not emitted.

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

## Stable JSON output contract

For analysis, request these public fields explicitly:

```bash
ig run "$GADGET_IMAGE" --output json \
  --fields timestamp,runtime_handler,operation,latency_ns_raw,failed,sandbox_id,container_id
```

`operation` is an explicit stable CRI method name and `failed` is a JSON boolean and `latency_ns_raw` is nanoseconds. Later container events retain both their container ID and parent sandbox ID. Validate a capture with `./validate-output.py capture.jsonl`; the default extended profile requires successful Run/Create/Start/Stop/Remove operations and an intentional failure for each handler. Use `--profile core` only when teardown is outside the capture window. Zero events fail validation.

The `kata` and `kata-preview` strings are CRI handler names. Record RuntimeClass mappings and runtime configurations before interpreting results; two names may alias the same Kata implementation.

### Validator lifecycle policy

The validator processes events in timestamp and file order. It requires each
container to follow an observed successful `RunPodSandbox` and
`CreateContainer`, while preserving CRI teardown semantics:
`StopPodSandbox` may terminate remaining containers, `RemoveContainer` may
remove a running container, and stop/remove calls are idempotent. Failed calls
are permitted only when their referenced object is known; a failed call never
advances or removes state, so a later retry is validated against the same
prerequisite. A failed `RunPodSandbox` may have no returned sandbox ID because
no identity was learned. The validator intentionally does not infer objects
created before tracing started. Such partial streams fail and must be recaptured
from sandbox creation.
