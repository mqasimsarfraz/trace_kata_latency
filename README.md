# trace_kata_latency

Minimal Inspektor Gadget metrics gadget that aggregates Kata Containers sandbox
and container request-to-response latency at the kubelet CRI boundary.

> Note: This gadget requires the `ig` image with stripped Go `.gopclntab` symbol resolution. See [ig](https://github.com/inspektor-gadget/inspektor-gadget/pull/5493/changes/ab03ef37ae901638ba8dfb69724991276487187e) for details.

The gadget traces:

- Kata `RunPodSandbox` requests using the `kata` or `kata-preview` runtime
  handler,
  including creation and startup of the Kata VM.
- `StopPodSandbox` for Kata sandbox IDs observed by the gadget.
- `RemovePodSandbox` for Kata sandbox IDs observed by the gadget.
- `CreateContainer`, `StartContainer`, `StopContainer`, and `RemoveContainer`
  for containers belonging to those observed Kata sandboxes.

Metrics are grouped by CRI operation and runtime handler:

- A base-2 latency histogram suitable for percentile calculations.
- Successful request count through the histogram's `_count` metric.

Failed CRI calls are excluded because retry and timeout behavior can skew the
latency distribution away from successful operation performance.

The gadget does not print a histogram until it observes a successful matching
CRI call after startup. Existing sandboxes and containers are not backfilled.

Run without `-o json` to use IG's histogram renderer:

```bash
ig-custom run \
  --verify-image=false \
  ghcr.io/mqasimsarfraz/trace_kata_latency:latency-metrics
```

The CLI histogram renderer currently does not display the `operation` and
`runtime_handler` labels. Use the Prometheus endpoint for correctly labelled
per-operation and per-handler histograms.

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

## Export latency metrics

The `kata_latency_metrics` map iterator is collected as an OpenTelemetry metric
data source. Enable the Prometheus endpoint and assign the data source a unique
metric name when running the gadget:

```bash
sudo ig run \
  --otel-metrics-listen=true \
  --otel-metrics-name=kata_latency_metrics \
  ghcr.io/mqasimsarfraz/trace_kata_latency:latest
```

The Prometheus-compatible endpoint is available at
`http://127.0.0.1:2224/metrics` by default.

For example, calculate the five-minute p95 latency in seconds with:

```promql
histogram_quantile(
  0.95,
  sum by (le, operation, runtime_handler) (
    rate(kata_latency_metrics_latency_us_bucket[5m])
  )
) / 1000000
```

Use `0.90` for p90. Histogram percentiles are estimates whose precision depends
on the base-2 bucket boundaries.

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

Each histogram observation measures one CRI call. Image pulls and application
readiness remain outside these boundaries, as does scheduler queueing before
kubelet starts the CRI request.

The gadget classifies `RunPodSandbox` calls by their `kata` or `kata-preview`
runtime handler and remembers the returned sandbox ID. It uses the parent
sandbox ID to classify `CreateContainer`, then remembers the returned container
ID for subsequent start, stop, and remove calls.

Later lifecycle calls are counted only when their IDs belong to sandboxes or
containers observed by the gadget. Resources created before the gadget starts
are not known, so their later lifecycle calls are not counted.

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
