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

const volatile int filter_fd_mask = 0;
size_t dropped = 0;

#define MAX_TRACED_PROCS 1000
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TRACED_PROCS);
    __type(key, u32);
    __type(value, u32);
} filter_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TRACED_PROCS);
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

static inline int trace_pid(pid_t p) {
    u32 *known = bpf_map_lookup_elem(&filter_pids, &p);
    if (known && *known == 1)
        return 1;
    return 0;
}

static inline void add_pid(pid_t pid) {
    u32 one = 1;
    if (bpf_map_update_elem(&filter_pids, &pid, &one, BPF_ANY) != 0) {
        bpf_printk("failed adding pid to traced set");
    } else {
        bpf_printk("added pid %d to traced set", pid);
    }
}

SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (!trace_pid(pid)) {
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

    if (!trace_pid(pid)) {
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
    int filt_fd = filter_fd_mask;
    int fd = data->fd;
    if (fd > 2 || ((1U << fd) & filt_fd)) {
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

    if (!trace_pid(pid)) {
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

    if (!trace_pid(pid)) {
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
    int filt_fd = filter_fd_mask;
    if (fd > 2 || ((1U << fd) & filt_fd)) {
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


/*
 * Tracing forks does not work... Dunno why.
 * Trace at least processes that follow fork->exec pattern,
 * that would be most of them. */
SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    pid_t pid = (pid_t)id;
    pid_t tgid = id >> 32;

    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    pid_t ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);

    /* bpf_printk("Execve in pid %d with ppid %d", pid, ppid); */

    if (trace_pid(ppid)) {
        /* pid is a child of some process that we trace */
        add_pid(pid);
    }

    return 0;
}

/* TODO: delete the PID from the map if the process exits */

char LICENSE[] SEC("license") = "GPL";
