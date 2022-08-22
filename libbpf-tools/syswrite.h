#ifndef __SYSWRITE_H
#define __SYSWRITE_H

#define BUF_SIZE 255

struct event {
    char buf[BUF_SIZE];
    int count;
    int len;
    int off;
    int fd;
};

#endif /* __SYSWRITE_H */
