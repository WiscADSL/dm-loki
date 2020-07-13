#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define LOG(msg...) do { printf("%d: ", __LINE__); printf(msg); printf("\n"); } while (0);

// 80 sectors in the image file
#define BUFSIZE (80 * 512)
int main(int argc, char **argv) {
    if (argc != 2) {
        LOG("Usage: %s <loop dev>", argv[0]);
        return 1;
    }

    int i,j, sector, byte_idx;
    char c;

    ssize_t ret;


    int fd = open(argv[1], O_DIRECT | O_RDONLY);
    if (fd < 0) {
        LOG("Failed to open file");
        return 1;
    }

    void *buffer;
    if (posix_memalign(&buffer, 512, BUFSIZE) != 0) {
        LOG("Failed to alloc buffer");
        return 1;
    }

    ret = read(fd, (void *)buffer, BUFSIZE);
    if (ret == -1) {
        LOG("failed to read, got ret=%ld", ret);
        LOG("errno is %d, %s", errno, strerror(errno));
    }
    else if ((size_t)ret != BUFSIZE) {
        LOG("partial read, got ret=%ld", ret);
    }

    char *buf = (char *) buffer;
    for(i=0; i < 10; i++) {
        for(j=0; j < 8; j++) {
            sector = (i * 8) + j;
            byte_idx = (sector * 512) + 256;
            c = buf[byte_idx];
            if (c == '\0') {
                c = '-';
            }
            printf("%3c\t", c);
        }
        printf("\n");
    }

    ret = close(fd);
    if (ret == -1) {
        LOG("Failed to close fd");
        return 1;
    }

    return 0;
}
