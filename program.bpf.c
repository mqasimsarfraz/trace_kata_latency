// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2026 The Inspektor Gadget authors */

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/macros.h>
#include <gadget/types.h>

#include "go-utils.h"

#define RUN_POD_SANDBOX_METHOD "/runtime.v1.RuntimeService/RunPodSandbox"
#define STOP_POD_SANDBOX_METHOD "/runtime.v1.RuntimeService/StopPodSandbox"
#define REMOVE_POD_SANDBOX_METHOD "/runtime.v1.RuntimeService/RemovePodSandbox"
#define MAX_CRI_METHOD_LEN (sizeof(REMOVE_POD_SANDBOX_METHOD) - 1)
#define MAX_INFLIGHT_RPCS 1024

enum gadget_sandbox_operation {
	SANDBOX_RUN,
	SANDBOX_STOP,
	SANDBOX_REMOVE,
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	gadget_duration latency_ns_raw;
	enum gadget_sandbox_operation operation_raw;
	__u8 failed;
};

struct gadget_rpc_state {
	__u64 start_ns;
	enum gadget_sandbox_operation operation;
};

GADGET_TRACER_MAP(events, 1024 * 64);
GADGET_TRACER(kata_latency, events, event);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	// 1024 entries cover concurrent sandbox RPCs without preallocating excessive memory.
	__uint(max_entries, MAX_INFLIGHT_RPCS);
	__type(key, __u64);
	__type(value, struct gadget_rpc_state);
} gadget_inflight_rpcs SEC(".maps");

static __always_inline int gadget_get_sandbox_operation(const char *method_ptr,
							 __u64 method_len)
{
	char method[MAX_CRI_METHOD_LEN] = {};

	if (method_len > sizeof(method))
		return -1;

	if (bpf_probe_read_user(method, method_len, method_ptr))
		return -1;

	if (method_len == sizeof(RUN_POD_SANDBOX_METHOD) - 1 &&
	    __builtin_memcmp(method, RUN_POD_SANDBOX_METHOD,
			     sizeof(RUN_POD_SANDBOX_METHOD) - 1) == 0)
		return SANDBOX_RUN;

	if (method_len == sizeof(STOP_POD_SANDBOX_METHOD) - 1 &&
	    __builtin_memcmp(method, STOP_POD_SANDBOX_METHOD,
			     sizeof(STOP_POD_SANDBOX_METHOD) - 1) == 0)
		return SANDBOX_STOP;

	if (method_len == sizeof(REMOVE_POD_SANDBOX_METHOD) - 1 &&
	    __builtin_memcmp(method, REMOVE_POD_SANDBOX_METHOD,
			     sizeof(REMOVE_POD_SANDBOX_METHOD) - 1) == 0)
		return SANDBOX_REMOVE;

	return -1;
}

// newClientStream receives the full gRPC method before a unary request starts.
SEC("uprobe//opt/bin/kubelet:google.golang.org/grpc.newClientStream")
int gadget_trace_container_rpc_start(struct pt_regs *ctx)
{
	const char *method_ptr = (const char *)GO_PARAM5(ctx);
	__u64 method_len = (__u64)GO_PARAM6(ctx);
	int operation = gadget_get_sandbox_operation(method_ptr, method_len);
	struct gadget_rpc_state state = {};
	__u64 goroutine;

	if (operation < 0)
		return 0;

	goroutine = (__u64)GOROUTINE_PTR(ctx);
	state.start_ns = bpf_ktime_get_boot_ns();
	state.operation = operation;

	// If the map is full, skip the RPC rather than emitting an uncorrelated result.
	if (bpf_map_update_elem(&gadget_inflight_rpcs, &goroutine, &state,
				BPF_ANY))
		return 0;

	return 0;
}

// clientStream.finish is invoked once after a unary RPC receives its response
// or terminates with an error. The Go error interface type is in GO_PARAM2.
SEC("uprobe//opt/bin/kubelet:google.golang.org/grpc.(*clientStream).finish")
int gadget_trace_container_rpc_finish(struct pt_regs *ctx)
{
	__u64 goroutine = (__u64)GOROUTINE_PTR(ctx);
	struct gadget_rpc_state *state;
	struct event *event;
	__u64 now;

	state = bpf_map_lookup_elem(&gadget_inflight_rpcs, &goroutine);
	if (!state)
		return 0;

	now = bpf_ktime_get_boot_ns();
	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		goto cleanup;

	__builtin_memset(event, 0, sizeof(*event));
	event->timestamp_raw = now;
	gadget_process_populate(&event->proc);
	event->latency_ns_raw = now - state->start_ns;
	event->operation_raw = state->operation;
	event->failed = (__u64)GO_PARAM2(ctx) != 0;

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

cleanup:
	bpf_map_delete_elem(&gadget_inflight_rpcs, &goroutine);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
