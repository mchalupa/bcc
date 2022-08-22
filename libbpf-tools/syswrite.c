#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#include <regex.h>
#include <bpf/bpf.h>

#include "syswrite.h"
#include "syswrite.skel.h"
#include "errno_helpers.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#include "shamon/core/event.h"
#include "shamon/core/source.h"
#include "shamon/core/signatures.h"
#include "shamon/shmbuf/buffer.h"
#include "shamon/shmbuf/client.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static void usage_and_exit(int ret) {
    warn("Usage: syswrite shmkey name expr sig [name expr sig] ... -- program\n");
    exit(ret);
}

#define MAXMATCH 20

static size_t exprs_num;
static size_t events_num;

static char *tmpline = NULL;
static size_t tmpline_len = 0;

static char *current_line = NULL;
static size_t current_line_alloc_len = 0;
static size_t current_line_idx = 0;

/*
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur	= RLIM_INFINITY,
        .rlim_max	= RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}
*/

static size_t line_alloc_size(size_t x) {
    size_t n = 256; /* make it at least 256 bytes */
    while (n < x) {
        n <<= 1;
    }
    return n;
}

static regex_t *re;
static char **signatures;
struct event_record *events;
static size_t waiting_for_buffer;
static shm_event ev;

static struct buffer *shm;

static void parse_line(bool iswrite, const struct event *e, char *line) {
    int status;
    signature_operand op;
    ssize_t len;
    regmatch_t matches[MAXMATCH + 1];

    /* fprintf(stderr, "LINE: %s\n", line); */

    for (int i = 0; i < (int)exprs_num; ++i) {
        if (events[i].kind == 0)
            continue; /* monitor is not interested in this */

        status = regexec(&re[i], line, MAXMATCH, matches, 0);
        if (status != 0) {
            continue;
        }
        int m = 1;
        void *addr;

        while (!(addr = buffer_start_push(shm))) {
            ++waiting_for_buffer;
        }
        /* push the base info about event */
        ++ev.id;
        ev.kind = events[i].kind;
        addr = buffer_partial_push(shm, addr, &ev, sizeof(ev));

        /* push the arguments of the event */
        for (const char *o = signatures[i]; *o && m <= MAXMATCH; ++o, ++m) {
            if (*o == 'L') { /* user wants the whole line */
                addr = buffer_partial_push_str(shm, addr, ev.id, line);
                continue;
            }
            if (*o != 'M') {
                if ((int)matches[m].rm_so < 0) {
                    warn("warning: have no match for '%c' in signature %s\n", *o,
                         signatures[i]);
                    continue;
                }
                len = matches[m].rm_eo - matches[m].rm_so;
            } else {
                len = matches[0].rm_eo - matches[0].rm_so;
            }

            /* make sure we have big enough temporary buffer */
            if (tmpline_len < (size_t)len) {
                free(tmpline);
                tmpline = malloc(sizeof(char) * len + 1);
                assert(tmpline && "Memory allocation failed");
                tmpline_len = len;
            }

            if (*o == 'M') { /* user wants the whole match */
                assert(matches[0].rm_so >= 0);
                strncpy(tmpline, line + matches[0].rm_so, len);
                tmpline[len] = '\0';
                addr = buffer_partial_push_str(shm, addr, ev.id, tmpline);
                continue;
            } else {
                strncpy(tmpline, line + matches[m].rm_so, len);
                tmpline[len] = '\0';
            }

            switch (*o) {
            case 'c':
                assert(len == 1);
                addr = buffer_partial_push(
                    shm, addr, (char *)(line + matches[m].rm_eo), sizeof(op.c));
                break;
            case 'i':
                op.i = atoi(tmpline);
                addr = buffer_partial_push(shm, addr, &op.i, sizeof(op.i));
                break;
            case 'l':
                op.l = atol(tmpline);
                addr = buffer_partial_push(shm, addr, &op.l, sizeof(op.l));
                break;
            case 'f':
                op.f = atof(tmpline);
                addr = buffer_partial_push(shm, addr, &op.f, sizeof(op.f));
                break;
            case 'd':
                op.d = strtod(tmpline, NULL);
                addr = buffer_partial_push(shm, addr, &op.d, sizeof(op.d));
                break;
            case 'S':
                addr = buffer_partial_push_str(shm, addr, ev.id, tmpline);
                break;
            default:
                assert(0 && "Invalid signature");
            }
        }
        buffer_finish_push(shm);
    }
}


static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;

    if (e->len == -2) {
        fprintf(stderr, "\033[31mDROPPED %d\033[0m\n", e->count);
        return 0;
    }
    /*
    fprintf(stderr, "fd: %d, len: %d, off: %d, count: %d, str:\n\033[34m'%*s'\033[0m\n",
            e->fd, e->len, e->off, e->count, e->len, e->buf);
            */

    for (size_t i = 0; i < e->len; ++i) {
        if (current_line_idx >= current_line_alloc_len) {
            current_line_alloc_len += line_alloc_size(e->len);
            current_line = realloc(current_line, current_line_alloc_len);
            assert(current_line && "Allocation failed");
        }

        char c = e->buf[i];
        if (c == '\n' || c == '\0') {
            /* temporary end */
            assert(current_line_idx < current_line_alloc_len);
            current_line[current_line_idx] = '\0';
            /* start new line */
            current_line_idx = 0;

            parse_line(true, e, current_line);
            continue;
        }

        assert(current_line_idx < current_line_alloc_len);
        current_line[current_line_idx++] = c;
    }

    return 0;
}

static volatile sig_atomic_t running = 1;

void sig_int(int signo) {
    running = 0;
}


int main(int argc, char *argv[])
{
    if (argc < 5 && (argc - 2) % 3 != 0) {
        usage_and_exit(1);
    }

    exprs_num = (argc - 1) / 3;
    if (exprs_num == 0) {
        usage_and_exit(1);
    }

    const char *shmkey = argv[1];
    char *exprs[exprs_num];
    char *names[exprs_num];

    signatures = malloc(sizeof(char*)*exprs_num);
    re = malloc(exprs_num*sizeof(regex_t));

    int arg_i = 2;
    for (int i = 0; i < (int)exprs_num; ++i) {
        names[i] = (char *)argv[arg_i++];
        exprs[i] = (char *)argv[arg_i++];
        if (arg_i >= argc) {
            warn("Missing a signature for '%s'\n", exprs[i]);
            usage_and_exit(1);
        }
        signatures[i] = (char *)argv[arg_i++];

        /* compile the regex, use extended RE */
        int status = regcomp(&re[i], exprs[i], REG_EXTENDED);
        if (status != 0) {
            warn("Failed compiling regex '%s'\n", exprs[i]);
            /* FIXME: we leak the expressions compiled so far ... */
            exit(1);
        }
    }

    /* Initialize the info about this source */
    struct source_control *control = source_control_define_pairwise(
        exprs_num, (const char **)names, (const char **)signatures);
    assert(control);

    size_t max_size = source_control_max_event_size(control);
    if (max_size < sizeof(shm_event_dropped))
        max_size = sizeof(shm_event_dropped);
    shm = create_shared_buffer(shmkey, max_size, control);
    assert(shm);
    events = buffer_get_avail_events(shm, &events_num);
    free(control);

	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct syswrite_bpf *obj;
    int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    //libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = syswrite_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		err = 1;
        goto cleanup_core;
	}

    /*
	if (env.pid)
		obj->rodata->filter_pid = env.pid;
    */
	err = syswrite_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %s\n", strerror(-err));
		goto cleanup_obj;
	}

    warn("info: waiting for the monitor to attach\n");
    err = buffer_wait_for_monitor(shm);
    if (err < 0) {
        if (err != EINTR) {
            warn("failed waiting: %s\n", strerror(-err));
        }
        goto cleanup_obj;
    }

    obj->links.sys_write = bpf_program__attach(obj->progs.sys_write);
    if (!obj->links.sys_write) {
		err = -errno;
        warn("failed to attach sys_write program: %s\n", strerror(-err));
		goto cleanup_obj;
	}

    struct ring_buffer *buffer = ring_buffer__new(bpf_map__fd(obj->maps.buffer), handle_event, NULL, NULL);
    if (!buffer) {
        warn("Failed to create ring buffer\n");
        goto cleanup_obj;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        warn("can't set signal handler: %s\n", strerror(errno));
        goto cleanup_obj;
    }

    printf("Tracing write syscalls...\n");
    while (running) {
        err = ring_buffer__consume(buffer);
       //err = ring_buffer__poll(buffer,
       //                        100 /* timeout in ms */);
        if (err < 0 && err != -EINTR) {
            perror("polling");
        }
	}

    printf("Cleaning up...\n");
    ring_buffer__free(buffer);

cleanup_obj:
	syswrite_bpf__destroy(obj);
cleanup_core:
	cleanup_core_btf(&open_opts);

    warn("info: sent %lu events, busy waited on buffer %lu cycles\n",
          ev.id, waiting_for_buffer);
    for (int i = 0; i < (int)exprs_num; ++i) {
        regfree(&re[i]);
    }
    free(tmpline);
    free(current_line);
    free(signatures);
    free(re);

    warn("Destroying shared buffer\n");
    destroy_shared_buffer(shm);

	return err != 0;
}
