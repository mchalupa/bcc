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
    } else {
        size_t dtmp = dropped;
        if (dtmp > 0) {
            event->count = dtmp;
            event->len = -2;
            event->off = 0;
            dropped = 0;
            bpf_ringbuf_submit(event, 0);
            return 1;
        }
    }

    int ret = bpf_probe_read_user(event->buf, len, ctx->user_buf + off);
    if (ret != 0) {
        bpf_printk("Failed reading user string");
        bpf_ringbuf_discard(event, 0);
        ++dropped;
        return 1;
    } else {
        event->count = ctx->count - off;
        event->fd = ctx->fd;
        event->len = len;
        event->off = off;
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}

/* FIXME: we should do this on exit_write, because we
 * do not know how many characters were actually written */
SEC("tracepoint/syscalls/sys_enter_write")
int sys_write(struct trace_event_raw_sys_enter *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t req_pid = filter_pid;

    if (req_pid > 0 && pid != req_pid) {
        return 0;
    }

    int fd = ctx->args[0];
    if (filter_fd > 0 && fd != filter_fd) {
        return 0;
    }

    size_t count = ctx->args[2];
    if (count == 0)
        return 0;

    const char *user_buf = (void *)ctx->args[1];

    /* bpf_printk("[PID %d] write(%d, %p, %lu).\n", pid, fd, user_buf, count); */

    struct loop_data data = { .syscall = SYSCALL_WRITE,
                              .fd = fd,
                              .count = count,
                              .user_buf = user_buf};

    bpf_loop((count / BUF_SIZE) + 1, submit_events, &data, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_read(struct trace_event_raw_sys_exit *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t req_pid = filter_pid;

    if (req_pid > 0 && pid != req_pid) {
        return 0;
    }

    int fd = ctx->args[0];
    if (filter_fd > 0 && fd != filter_fd) {
        return 0;
    }

    size_t count = ctx->args[2];
    if (count == 0)
        return 0;

    const char *user_buf = (void *)ctx->args[1];

    /* bpf_printk("[PID %d] write(%d, %p, %lu).\n", pid, fd, user_buf, count); */

    struct loop_data data = { .syscall = SYSCALL_READ,
                              .fd = fd,
                              .count = count,
                              .user_buf = user_buf};

    bpf_loop((count / BUF_SIZE) + 1, submit_events, &data, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
