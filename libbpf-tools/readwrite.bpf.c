// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Marek Chalupa, ISTA
//
// Based on syscount from Anton Protopopov
#include <vmlinux.h>

#include "readwrite.h"
#include "maps.bpf.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

const volatile pid_t filter_pid = 0;
const volatile int filter_fd = 0;
size_t dropped = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct syscall_data);
} syscall_data SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 64);
} buffer SEC(".maps");

struct loop_data {
    int syscall;
    int fd;
    size_t count;
    const char *user_buf;
};

static long submit_events(u32 index, struct loop_data *ctx) {
    size_t off = index * BUF_SIZE;
    size_t len =
        ((ctx->count - off) > BUF_SIZE) ? BUF_SIZE : (ctx->count - off);

    struct event *event = bpf_ringbuf_reserve(&buffer, sizeof(struct event), 0);
    if (!event) {
        bpf_printk("Failed reserving a slot in the buffer");
        ++dropped;
        return 1;
    }

    size_t dtmp = dropped;
    if (dtmp > 0) {
        event->syscall = 0;
        event->count = dtmp;
        event->len = -2;
        event->off = 0;
        dropped = 0;
        bpf_ringbuf_submit(event, 0);
        return 1;
    }

    int ret = bpf_probe_read_user(event->buf, len, ctx->user_buf + off);
    if (ret != 0) {
        bpf_printk("Failed reading user string");

        event->syscall = ctx->syscall;
        event->count = 1;
        event->len = -2;
        event->off = 0;

        bpf_ringbuf_submit(event, 0);
        return 1;
    } else {
        event->syscall = ctx->syscall;
        event->count = ctx->count - off;
        event->fd = ctx->fd;
        event->len = len;
        event->off = off;

        bpf_ringbuf_submit(event, 0);
        return 0;
    }
}

SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t req_pid = filter_pid;

    if (req_pid > 0 && pid != req_pid) {
        return 0;
    }

    struct syscall_data data = { .fd = ctx->args[0],
                                 .count = ctx->args[2],
                                 .buf = (void *)ctx->args[1]
                               };
    if (bpf_map_update_elem(&syscall_data, &pid, &data, BPF_ANY) != 0) {
        bpf_printk("sys_enter_write: failed updating data about syscall");
        return 0;
    }

    return 0;
}


SEC("tracepoint/syscalls/sys_exit_write")
int sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t req_pid = filter_pid;

    if (req_pid > 0 && pid != req_pid) {
        return 0;
    }

    struct syscall_data *data = bpf_map_lookup_elem(&syscall_data, &pid);
    if (!data) {
        bpf_printk("sys_exit_write: failed looking up the data about syscall");
        return 0;
    }

    if (data->count == 0)
        return 0;

    /* FIXME: allow arbitrary fds */
    int filt_fd = filter_fd;
    int fd = data->fd;
    if (fd > 2 || (filt_fd > 0 && fd != filt_fd)) {
        return 0;
    }

    int ret = ctx->ret;
    if (ret <= 0)
        return 0;

    struct loop_data loop_data = { .syscall = SYSCALL_WRITE,
                                   .fd = data->fd,
                                   .count = ret,
                                   .user_buf = data->buf};

    bpf_loop((ret / BUF_SIZE) + 1, submit_events, &loop_data, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t req_pid = filter_pid;

    if (req_pid > 0 && pid != req_pid) {
        return 0;
    }

    struct syscall_data data = { .fd = ctx->args[0],
                                 .count = ctx->args[2],
                                 .buf = (void *)ctx->args[1]
                               };
    if (bpf_map_update_elem(&syscall_data, &pid, &data, BPF_ANY) != 0) {
        bpf_printk("sys_enter_read: failed updating data about syscall");
        return 0;
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t req_pid = filter_pid;

    if (req_pid > 0 && pid != req_pid) {
        return 0;
    }

    struct syscall_data *data = bpf_map_lookup_elem(&syscall_data, &pid);
    if (!data) {
        bpf_printk("sys_exit_read: failed looking up the data about syscall");
        return 0;
    }

    if (data->count == 0)
        return 0;

    /* FIXME: allow arbitrary fds */
    int fd = data->fd;
    int filt_fd = filter_fd;
    if (fd > 2 || (filt_fd > 0 && fd != filt_fd)) {
        return 0;
    }

    int ret = ctx->ret;
    if (ret <= 0)
        return 0;

    struct loop_data loop_data = { .syscall = SYSCALL_READ,
                                   .fd = data->fd,
                                   .count = ret,
                                   .user_buf = data->buf};

    bpf_loop((ret / BUF_SIZE) + 1, submit_events, &loop_data, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
