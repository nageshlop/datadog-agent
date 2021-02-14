#ifndef _SPAN_H
#define _SPAN_H

#define GOLANG 1
#define PYTHON 2

struct coroutine_ctx_t {
    u8 type;
    char data[230];
};

struct bpf_map_def SEC("maps/coroutine_ctx") coroutine_ctx = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct coroutine_ctx_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/coroutine_ids") coroutine_ids = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(u64),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct span_key_t {
    u64 coroutine_id;
    u32 id;
    u32 padding;
};

struct span_t {
    u64 span_id;
    u64 trace_id;
};

struct bpf_map_def SEC("maps/span_ids") span_ids = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct span_key_t),
    .value_size = sizeof(struct span_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

static __attribute__((always_inline)) struct span_t *get_current_span() {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    // select coroutine context
    struct coroutine_ctx_t *co_ctx = bpf_map_lookup_elem(&coroutine_ctx, &pid);
    if (co_ctx == NULL) {
        return NULL;
    }

    // select current goroutine id
    struct span_key_t key = {};
    u64 *coroutine_id = bpf_map_lookup_elem(&coroutine_ids, &id);
    if (coroutine_id != NULL) {
        key.coroutine_id = *coroutine_id;
    }

    // select span based on the type of coroutine
    switch (co_ctx->type) {
        case (GOLANG): {
            // for golang, use the pid of the process
            key.id = pid;
        }
        case (PYTHON): {
            key.id = id;
        }
    }

    return bpf_map_lookup_elem(&span_ids, &key);
}

int __attribute__((always_inline)) handle_span_id(void *data) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    struct span_key_t key = {};
    struct span_t span = {};
    struct coroutine_ctx_t co_ctx = {};

    // parse the provided data (span id, trace id, coroutine id, language specific data)
    bpf_probe_read(&span.span_id, sizeof(span.span_id), data);
    bpf_probe_read(&span.trace_id, sizeof(span.trace_id), data + 8);
    bpf_probe_read(&key.coroutine_id, sizeof(key.coroutine_id), data + 16);
    bpf_probe_read(&co_ctx.type, sizeof(co_ctx.type), data + 24);
    bpf_probe_read(&co_ctx.data, sizeof(co_ctx.data), data + 25);

    // set key id based on coroutine type
    switch (co_ctx.type) {
        case (GOLANG): {
            key.id = pid;
        }
        case (PYTHON): {
            key.id = id;
        }
    }
    bpf_printk("span_id:%d trace_id:%d\n", span.span_id, span.trace_id);

    // save span id and co_data context for future use
    bpf_map_update_elem(&span_ids, &key, &span, BPF_ANY);
    bpf_map_update_elem(&coroutine_ctx, &pid, &co_ctx, BPF_ANY);

    // update thread id <-> coroutine id mapping
    bpf_map_update_elem(&coroutine_ids, &id, &key.coroutine_id, BPF_ANY);
    return 0;
}

#endif
