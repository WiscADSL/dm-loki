#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define LOG(msg...) do { printf("%d: ", __LINE__); printf(msg); printf("\n"); } while (0);

int main(int argc, char **argv) {
    if (argc != 3) {
        LOG("Usage: %s <loop dev> <block>", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_DIRECT | O_RDONLY);
    unsigned long block;
    off_t offset;
    int i, ret;

    if (fd < 0) {
        LOG("Failed to open file");
        return 1;
    }

    if (sscanf(argv[2], "%lu", &block) != 1) {
        LOG("failed to convert block %s to unsigned long", argv[2]);
    }
    offset = block * 4096;

    void *buffer;
    if (posix_memalign(&buffer, 512, 4096) != 0) {
        LOG("Failed to alloc buffer");
        return 1;
    }

    ret = pread(fd, (void *)buffer, 4096, offset);

    if (ret == -1) {
        LOG("failed to read, got ret=%d", ret);
        LOG("errno is %d, %s", errno, strerror(errno));
    }
    else if ((size_t)ret != 4096) {
        LOG("partial read, got ret=%d", ret);
    }

    char *buf = (char *) buffer;
    for(i=0; i < 4096; i++) {
        printf("%c", buf[i]);
    }
    printf("\n");

    ret = close(fd);
    if (ret == -1) {
        LOG("Failed to close fd");
        return 1;
    }

    return 0;
}
