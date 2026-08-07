// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2026 The Inspektor Gadget authors */

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/bits.bpf.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/maps.bpf.h>
#include <gadget/types.h>

#include "go-utils.h"

#define RUN_POD_SANDBOX_METHOD "/runtime.v1.RuntimeService/RunPodSandbox"
#define STOP_POD_SANDBOX_METHOD "/runtime.v1.RuntimeService/StopPodSandbox"
#define REMOVE_POD_SANDBOX_METHOD "/runtime.v1.RuntimeService/RemovePodSandbox"
#define CREATE_CONTAINER_METHOD "/runtime.v1.RuntimeService/CreateContainer"
#define START_CONTAINER_METHOD "/runtime.v1.RuntimeService/StartContainer"
#define STOP_CONTAINER_METHOD "/runtime.v1.RuntimeService/StopContainer"
#define REMOVE_CONTAINER_METHOD "/runtime.v1.RuntimeService/RemoveContainer"
#define KATA_RUNTIME_HANDLER "kata"
#define KATA_PREVIEW_RUNTIME_HANDLER "kata-preview"
#define MAX_CRI_METHOD_LEN (sizeof(REMOVE_POD_SANDBOX_METHOD) - 1)
#define MAX_SANDBOX_ID_LEN 128
#define MAX_CONTAINER_ID_LEN 128
#define MAX_INFLIGHT_RPCS 1024
#define MAX_KATA_SANDBOXES 4096
#define MAX_KATA_CONTAINERS 8192
#define LATENCY_HISTOGRAM_SLOTS 32
#define MAX_LATENCY_METRIC_KEYS (7 * 2)

enum gadget_cri_operation {
	SANDBOX_RUN,
	SANDBOX_STOP,
	SANDBOX_REMOVE,
	CONTAINER_CREATE,
	CONTAINER_START,
	CONTAINER_STOP,
	CONTAINER_REMOVE,
};

enum gadget_kata_handler {
	GADGET_KATA_HANDLER_KATA,
	GADGET_KATA_HANDLER_PREVIEW,
};

struct gadget_go_string {
	const char *data;
	__u64 len;
};

// Kubernetes 1.35 generated messages keep one pointer-sized state field first.
struct gadget_run_pod_sandbox_request {
	__u64 state;
	const void *config;
	struct gadget_go_string runtime_handler;
};

struct gadget_id_message {
	__u64 state;
	struct gadget_go_string id;
};

struct gadget_create_container_request {
	__u64 state;
	struct gadget_go_string sandbox_id;
};

struct gadget_cri_id {
	char value[MAX_CONTAINER_ID_LEN];
};

struct gadget_rpc_state {
	__u64 start_ns;
	enum gadget_cri_operation operation;
	enum gadget_kata_handler handler;
	const void *reply;
	struct gadget_cri_id sandbox_id;
	struct gadget_cri_id container_id;
};

struct gadget_rpc_scratch {
	struct gadget_rpc_state state;
	struct gadget_cri_id id;
};

struct gadget_latency_key {
	char operation[sizeof("CONTAINER_REMOVE")];
	char runtime_handler[sizeof(KATA_PREVIEW_RUNTIME_HANDLER)];
};

struct gadget_latency_value {
	gadget_histogram_slot__u64 latency_us[LATENCY_HISTOGRAM_SLOTS];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	// 1024 entries cover concurrent sandbox RPCs without preallocating excessive memory.
	__uint(max_entries, MAX_INFLIGHT_RPCS);
	__type(key, __u64);
	__type(value, struct gadget_rpc_state);
} gadget_inflight_rpcs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	// 4096 entries use about 512 KiB and cover the Kata sandboxes on one node.
	__uint(max_entries, MAX_KATA_SANDBOXES);
	__type(key, struct gadget_cri_id);
	__type(value, __u8);
} gadget_kata_sandboxes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	// 8192 entries use about 1 MiB and cover active Kata containers on one node.
	__uint(max_entries, MAX_KATA_CONTAINERS);
	__type(key, struct gadget_cri_id);
	__type(value, __u8);
} gadget_kata_containers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct gadget_rpc_scratch);
} gadget_rpc_scratch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	// Seven operations and two handlers produce 14 stable metric series.
	__uint(max_entries, MAX_LATENCY_METRIC_KEYS);
	__type(key, struct gadget_latency_key);
	__type(value, struct gadget_latency_value);
} gadget_latency_metrics SEC(".maps");

GADGET_MAPITER(kata_latency_metrics, gadget_latency_metrics);

static struct gadget_latency_value gadget_empty_latency_metrics;

static __always_inline int gadget_get_sandbox_operation(const char *method_ptr,
							 __u64 method_len)
{
	char method[MAX_CRI_METHOD_LEN] = {};

	if (method_len > sizeof(method))
		return -1;

	for (__u32 i = 0; i < MAX_CRI_METHOD_LEN; i++) {
		if (i >= method_len)
			break;
		if (bpf_probe_read_user(&method[i], 1, method_ptr + i))
			return -1;
	}

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

	if (method_len == sizeof(CREATE_CONTAINER_METHOD) - 1 &&
	    __builtin_memcmp(method, CREATE_CONTAINER_METHOD,
			     sizeof(CREATE_CONTAINER_METHOD) - 1) == 0)
		return CONTAINER_CREATE;

	if (method_len == sizeof(START_CONTAINER_METHOD) - 1 &&
	    __builtin_memcmp(method, START_CONTAINER_METHOD,
			     sizeof(START_CONTAINER_METHOD) - 1) == 0)
		return CONTAINER_START;

	if (method_len == sizeof(STOP_CONTAINER_METHOD) - 1 &&
	    __builtin_memcmp(method, STOP_CONTAINER_METHOD,
			     sizeof(STOP_CONTAINER_METHOD) - 1) == 0)
		return CONTAINER_STOP;

	if (method_len == sizeof(REMOVE_CONTAINER_METHOD) - 1 &&
	    __builtin_memcmp(method, REMOVE_CONTAINER_METHOD,
			     sizeof(REMOVE_CONTAINER_METHOD) - 1) == 0)
		return CONTAINER_REMOVE;

	return -1;
}

static __always_inline int
gadget_read_go_string(struct gadget_cri_id *dst,
		      const struct gadget_go_string *src)
{
	__builtin_memset(dst, 0, sizeof(*dst));

	if (!src->data || !src->len || src->len >= sizeof(dst->value))
		return -1;

	for (__u32 i = 0; i < MAX_SANDBOX_ID_LEN; i++) {
		if (i >= src->len)
			break;
		if (bpf_probe_read_user(&dst->value[i], 1, src->data + i))
			return -1;
	}

	return 0;
}

static __always_inline int
gadget_get_kata_handler(const void *request_ptr)
{
	struct gadget_run_pod_sandbox_request request = {};
	char runtime_handler[sizeof(KATA_PREVIEW_RUNTIME_HANDLER)] = {};

	if (bpf_probe_read_user(&request, sizeof(request), request_ptr))
		return -1;

	if (request.runtime_handler.len == sizeof(KATA_RUNTIME_HANDLER) - 1) {
		if (bpf_probe_read_user(runtime_handler,
					sizeof(KATA_RUNTIME_HANDLER) - 1,
					request.runtime_handler.data))
			return -1;

		if (__builtin_memcmp(runtime_handler, KATA_RUNTIME_HANDLER,
				     sizeof(KATA_RUNTIME_HANDLER) - 1) == 0)
			return GADGET_KATA_HANDLER_KATA;
	}

	if (request.runtime_handler.len ==
	    sizeof(KATA_PREVIEW_RUNTIME_HANDLER) - 1) {
		if (bpf_probe_read_user(runtime_handler,
					sizeof(KATA_PREVIEW_RUNTIME_HANDLER) - 1,
					request.runtime_handler.data))
			return -1;

		if (__builtin_memcmp(runtime_handler,
				     KATA_PREVIEW_RUNTIME_HANDLER,
				     sizeof(KATA_PREVIEW_RUNTIME_HANDLER) - 1) == 0)
			return GADGET_KATA_HANDLER_PREVIEW;
	}

	return -1;
}

static __always_inline int
gadget_read_id_message(struct gadget_cri_id *id, const void *message_ptr)
{
	struct gadget_id_message message = {};

	if (bpf_probe_read_user(&message, sizeof(message), message_ptr))
		return -1;

	return gadget_read_go_string(id, &message.id);
}

static __always_inline int
gadget_read_create_container_request(struct gadget_cri_id *sandbox_id,
				     const void *request_ptr)
{
	struct gadget_create_container_request request = {};

	if (bpf_probe_read_user(&request, sizeof(request), request_ptr))
		return -1;

	return gadget_read_go_string(sandbox_id, &request.sandbox_id);
}

static __always_inline void
gadget_set_runtime_handler(char *runtime_handler,
			   enum gadget_kata_handler handler)
{
	if (handler == GADGET_KATA_HANDLER_PREVIEW)
		__builtin_memcpy(runtime_handler, KATA_PREVIEW_RUNTIME_HANDLER,
				 sizeof(KATA_PREVIEW_RUNTIME_HANDLER));
	else
		__builtin_memcpy(runtime_handler, KATA_RUNTIME_HANDLER,
				 sizeof(KATA_RUNTIME_HANDLER));
}

static __always_inline void
gadget_set_operation(char *operation, enum gadget_cri_operation value)
{
	switch (value) {
	case SANDBOX_RUN:
		__builtin_memcpy(operation, "SANDBOX_RUN", sizeof("SANDBOX_RUN"));
		break;
	case SANDBOX_STOP:
		__builtin_memcpy(operation, "SANDBOX_STOP",
				 sizeof("SANDBOX_STOP"));
		break;
	case SANDBOX_REMOVE:
		__builtin_memcpy(operation, "SANDBOX_REMOVE",
				 sizeof("SANDBOX_REMOVE"));
		break;
	case CONTAINER_CREATE:
		__builtin_memcpy(operation, "CONTAINER_CREATE",
				 sizeof("CONTAINER_CREATE"));
		break;
	case CONTAINER_START:
		__builtin_memcpy(operation, "CONTAINER_START",
				 sizeof("CONTAINER_START"));
		break;
	case CONTAINER_STOP:
		__builtin_memcpy(operation, "CONTAINER_STOP",
				 sizeof("CONTAINER_STOP"));
		break;
	case CONTAINER_REMOVE:
		__builtin_memcpy(operation, "CONTAINER_REMOVE",
				 sizeof("CONTAINER_REMOVE"));
		break;
	}
}

static __always_inline void
gadget_record_latency(const struct gadget_rpc_state *state, __u64 latency_ns)
{
	struct gadget_latency_key key = {};
	struct gadget_latency_value *metrics;
	__u64 latency_us = latency_ns / 1000;
	__u64 slot;

	gadget_set_operation(key.operation, state->operation);
	gadget_set_runtime_handler(key.runtime_handler, state->handler);

	metrics = bpf_map_lookup_or_try_init(&gadget_latency_metrics, &key,
					     &gadget_empty_latency_metrics);
	if (!metrics)
		return;

	slot = get_slot_idx(latency_us);
	if (slot >= LATENCY_HISTOGRAM_SLOTS)
		slot = LATENCY_HISTOGRAM_SLOTS - 1;

	__sync_fetch_and_add(&metrics->latency_us[slot], 1);
}

// Invoke exposes the request and response pointers before the unary RPC starts.
SEC("uprobe//opt/bin/kubelet:google.golang.org/grpc.(*ClientConn).Invoke")
int gadget_trace_container_rpc_start(struct pt_regs *ctx)
{
	const char *method_ptr = (const char *)GO_PARAM4(ctx);
	__u64 method_len = (__u64)GO_PARAM5(ctx);
	const void *request_ptr = GO_PARAM7(ctx);
	int operation = gadget_get_sandbox_operation(method_ptr, method_len);
	struct gadget_rpc_scratch *scratch;
	struct gadget_rpc_state *state;
	__u8 *known_handler;
	__u32 zero = 0;
	__u64 goroutine;
	int handler;

	if (gadget_should_discard_data_current())
		return 0;

	if (operation < 0)
		return 0;

	scratch = bpf_map_lookup_elem(&gadget_rpc_scratch, &zero);
	if (!scratch)
		return 0;

	state = &scratch->state;
	__builtin_memset(state, 0, sizeof(*state));

	if (operation == SANDBOX_RUN) {
		handler = gadget_get_kata_handler(request_ptr);
		if (handler < 0)
			return 0;
		state->handler = handler;
		state->reply = GO_PARAM9(ctx);
	} else if (operation == SANDBOX_STOP ||
		   operation == SANDBOX_REMOVE) {
		if (gadget_read_id_message(&state->sandbox_id, request_ptr))
			return 0;

		known_handler = bpf_map_lookup_elem(&gadget_kata_sandboxes,
						    &state->sandbox_id);
		if (!known_handler)
			return 0;
		state->handler = *known_handler;
	} else if (operation == CONTAINER_CREATE) {
		if (gadget_read_create_container_request(&state->sandbox_id,
							 request_ptr))
			return 0;

		known_handler = bpf_map_lookup_elem(&gadget_kata_sandboxes,
						    &state->sandbox_id);
		if (!known_handler)
			return 0;
		state->handler = *known_handler;
		state->reply = GO_PARAM9(ctx);
	} else {
		if (gadget_read_id_message(&state->container_id, request_ptr))
			return 0;

		known_handler = bpf_map_lookup_elem(&gadget_kata_containers,
						    &state->container_id);
		if (!known_handler)
			return 0;
		state->handler = *known_handler;
	}

	goroutine = (__u64)GOROUTINE_PTR(ctx);
	state->start_ns = bpf_ktime_get_boot_ns();
	state->operation = operation;

	if (bpf_map_update_elem(&gadget_inflight_rpcs, &goroutine, state,
				BPF_ANY)) {
		bpf_printk("kata latency: inflight RPC map is full");
		return 0;
	}

	return 0;
}

// clientStream.finish is invoked once after a unary RPC receives its response
// or terminates with an error. The Go error interface type is in GO_PARAM2.
SEC("uprobe//opt/bin/kubelet:google.golang.org/grpc.(*clientStream).finish")
int gadget_trace_container_rpc_finish(struct pt_regs *ctx)
{
	__u64 goroutine = (__u64)GOROUTINE_PTR(ctx);
	struct gadget_rpc_state *state;
	struct gadget_rpc_scratch *scratch;
	struct gadget_cri_id *response_id;
	__u8 handler;
	__u32 zero = 0;
	bool failed;
	__u64 now;

	state = bpf_map_lookup_elem(&gadget_inflight_rpcs, &goroutine);
	if (!state)
		return 0;

	scratch = bpf_map_lookup_elem(&gadget_rpc_scratch, &zero);
	if (!scratch)
		goto cleanup;

	response_id = &scratch->id;
	__builtin_memset(response_id, 0, sizeof(*response_id));

	now = bpf_ktime_get_boot_ns();
	failed = (__u64)GO_PARAM2(ctx) != 0;
	handler = state->handler;

	if (state->operation == SANDBOX_RUN && !failed) {
		if (gadget_read_id_message(response_id, state->reply))
			goto cleanup;

		if (bpf_map_update_elem(&gadget_kata_sandboxes, response_id,
					&handler, BPF_ANY))
			bpf_printk("kata latency: sandbox map is full");
	} else if (state->operation == CONTAINER_CREATE && !failed) {
		if (gadget_read_id_message(response_id, state->reply))
			goto cleanup;

		if (bpf_map_update_elem(&gadget_kata_containers, response_id,
					&handler, BPF_ANY))
			bpf_printk("kata latency: container map is full");
	}

	if (state->operation == SANDBOX_REMOVE && !failed)
		bpf_map_delete_elem(&gadget_kata_sandboxes, &state->sandbox_id);

	if (state->operation == CONTAINER_REMOVE && !failed)
		bpf_map_delete_elem(&gadget_kata_containers,
				    &state->container_id);

	if (!failed)
		gadget_record_latency(state, now - state->start_ns);

cleanup:
	bpf_map_delete_elem(&gadget_inflight_rpcs, &goroutine);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
