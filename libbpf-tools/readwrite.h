#ifndef __SYSWRITE_H
#define __SYSWRITE_H

enum syscalls {
        SYSCALL_WRITE = 1,
        SYSCALL_READ  = 2,
};

#define BUF_SIZE 255

struct event {
    char buf[BUF_SIZE];
    int syscall;
    int count;
    int len;
    int off;
    int fd;
};

#endif /* __SYSWRITE_H */
