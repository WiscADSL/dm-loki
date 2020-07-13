#ifdef TBS_TEST_MODE_ON

// Testing as a standalone binary in userspace
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#define MALLOC(n) malloc(n)
#define FREE(p) free(p)
#define LOG_EROR(msg, ...) do {\
    printf("ERROR: twobitseq_test: %s:%d " msg "\n", \
        __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } while(0);

#else
// kernel
#include <linux/slab.h>
#include "dm-loki-common.h"

#define MALLOC(n) kmalloc(n, GFP_KERNEL)
#define FREE(p) kfree(p)

#endif

#include "twobitseq.h"

inline static int char_to_int(char c) 
{
    switch(c) {
        case ALLOW_ALL_WRITE_CHAR:
            return ALLOW_ALL_WRITE;
        case FAIL_ALL_WRITE_CHAR:
            return FAIL_ALL_WRITE;
        case ALLOW_ONE_WRITE_CHAR:
            return ALLOW_ONE_WRITE;
        case FAIL_ONE_WRITE_CHAR:
            return FAIL_ONE_WRITE;
    }

    // for safety, always return ALLOW_WRITE
    return ALLOW_ALL_WRITE;
}

inline static char int_to_char(int v) 
{
    switch(v) {
        case ALLOW_ALL_WRITE:
            return ALLOW_ALL_WRITE_CHAR;
        case FAIL_ALL_WRITE:
            return FAIL_ALL_WRITE_CHAR;
        case ALLOW_ONE_WRITE:
            return ALLOW_ONE_WRITE_CHAR;
        case FAIL_ONE_WRITE:
            return FAIL_ONE_WRITE_CHAR;
    }

    return '-';
}

int twobitseq_create(twobitseq_t **tbs_ret, const char *s, size_t len)
{
    size_t i;
    int val;
    int err = 0;
    twobitseq_t *tbs = NULL;

    if (*tbs_ret != NULL) {
        // Going to allocate a new thing here.
        // Replacing the old one might be a memory leak.
        return -EFAULT;
    }

    // validate string
    for(i=0; i < len; i++) {
        switch(s[i]) {
            case ALLOW_ALL_WRITE_CHAR:
            case FAIL_ALL_WRITE_CHAR:
            case ALLOW_ONE_WRITE_CHAR:
            case FAIL_ONE_WRITE_CHAR:
                continue;
            default:
                LOG_EROR("Invalid character %c", s[i]);
                return -EINVAL;
        }
    }

    tbs = (twobitseq_t *) MALLOC (sizeof(*tbs));
    if (tbs == NULL) {
        LOG_EROR("Failed to allocate tbs");
        err = -ENOMEM;
        goto bad;
    }

    // each character takes up 2 bits, so 4 in a byte.
    tbs->arr = NULL;
    tbs->len = len;
    tbs->idx = 0;

    tbs->arr = (uint8_t *) MALLOC ((len / 4) + 1);
    if (tbs->arr == NULL) {
        LOG_EROR("Failed to allocate tbs arr");
        err = -ENOMEM;
        goto bad;
    }

    for(i=0; i < (len / 4) + 1; i++) {
        tbs->arr[i] = ALLOW_ALL_WRITE_BYTE;
    }

    for(i=0; i < len; i++) {
        val = char_to_int(s[i]);
        if (twobitseq_write(tbs, val) != 0) {
            // TODO log failure on write
            LOG_EROR("Failed to write at idx %zd", i);
            err = -EIO;
            goto bad;
        }
    }

    if (twobitseq_seek(tbs, 0) != 0) {
        // TODO log failure to seek back to 0
        LOG_EROR("Failed to seek back to pos 0");
        err = -EIO;
        goto bad;
    }

    *tbs_ret = tbs;
    return 0;

bad:
    twobitseq_free(tbs);
    return err;
}

ssize_t twobitseq_seek(twobitseq_t *tbs, size_t pos) 
{
    if (pos >= tbs->len) {
        return -ESPIPE;
    }

    tbs->idx = pos;
    return (ssize_t) tbs->idx;
}

int twobitseq_read(twobitseq_t *tbs)
{
    size_t pos = tbs->idx;
    uint8_t arr;
    int val;

    if (pos == tbs->len) {
        return -EIO;
    }

    arr = *(tbs->arr + (pos / 4));

    // positions in the arr
    // 0 1  2 3  4 5  6 7
    //  0    1    2    3

    pos = (pos % 4) * 2;
    arr = arr >> pos;
    val = arr & 0x3;
    tbs->idx += 1;

    return val;
}

int twobitseq_read_next_or_last(twobitseq_t *tbs)
{
    size_t pos = tbs->idx;
    if (pos < tbs->len) {
        return twobitseq_read(tbs);
    }

    // we're at the end
    tbs->idx = tbs->len - 1;
    return twobitseq_read(tbs);
}

char twobitseq_read_next_or_last_as_char(twobitseq_t *tbs) {
    return int_to_char(twobitseq_read_next_or_last(tbs));
}

int twobitseq_write(twobitseq_t *tbs, int val) 
{
    size_t pos = tbs->idx;
    uint8_t *arr;

    if (pos == tbs->len) {
        return -ENOSPC;
    }

    arr = (tbs->arr + (pos / 4));
    pos = (pos % 4) * 2;
    val = val << pos;
    *arr = (*arr | val);
    tbs->idx += 1;
    return 0;
}

void twobitseq_free(twobitseq_t *tbs)
{
    if (tbs == NULL) {
        return;
    }

    if (tbs->arr != NULL) {
        FREE(tbs->arr);
    }

    FREE(tbs);
}

void twobitseq_dumpstr(twobitseq_t *tbs, char *buf, size_t len) {
    size_t i = 0;
    size_t old_idx = tbs->idx;
    tbs->idx = 0;
    while(i < len) {
        buf[i] = twobitseq_read_next_or_last_as_char(tbs);
        i += 1;
    }
    tbs->idx = old_idx;
}
