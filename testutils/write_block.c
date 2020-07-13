#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define LOG(msg...) do { printf("%d: ", __LINE__); printf(msg); printf("\n"); } while (0);

int main(int argc, char **argv) {
    if (argc != 4) {
        LOG("Usage: %s <loop dev> <block> <char>", argv[0]);
        return 1;
    }

    size_t i;
    ssize_t ret;
    unsigned long block;

    char c;
    size_t bufsize;
    off_t offset;

    int fd = open(argv[1], O_DIRECT | O_WRONLY);
    if (fd < 0) {
        LOG("Failed to open file");
        return 1;
    }

    if (sscanf(argv[2], "%lu", &block) != 1) {
        LOG("failed to convert block %s to unsigned long", argv[3]);
    }

    bufsize = 4096;
    offset = block * 4096;

    void *buffer;
    if (posix_memalign(&buffer, 512, bufsize) != 0) {
        LOG("Failed to alloc buffer");
        return 1;
    }

    c = argv[3][0];
    char *buf = (char *) buffer;

    for(i=0; i < bufsize; i++) {
        buf[i] = c;
    }

    ret = pwrite(fd, (void *)buf, bufsize, offset);
    if (ret == -1) {
        LOG("failed to write, got ret=%ld", ret);
        LOG("errno is %d, %s", errno, strerror(errno));
    }
    else if ((size_t)ret != bufsize) {
        LOG("partial write, got ret=%ld", ret);
    }

    if (fsync(fd) != 0) {
        LOG("failed to fsync");
    }

    ret = close(fd);
    if (ret == -1) {
        LOG("Failed to close fd");
        return 1;
    }

    return 0;
}
