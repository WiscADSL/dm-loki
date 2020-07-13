#ifndef __twobitseq_h

#define __twobitseq_h

#ifdef TBS_TEST_MODE_ON
#include <stdint.h>
#else
#include <linux/types.h>
#endif

#define ALLOW_ALL_WRITE     0 // 00
#define FAIL_ALL_WRITE      1 // 01
#define ALLOW_ONE_WRITE     2 // 10
#define FAIL_ONE_WRITE      3 // 11

#define ALLOW_ALL_WRITE_CHAR 'A'
#define FAIL_ALL_WRITE_CHAR 'X'
#define ALLOW_ONE_WRITE_CHAR 'W'
#define FAIL_ONE_WRITE_CHAR 'F'

#define ALLOW_ALL_WRITE_BYTE    0   // 0b00000000
#define FAIL_ALL_WRITE_BYTE     85  // 0b01010101
#define ALLOW_ONE_WRITE_BYTE    170 // 0b10101010
#define FAIL_ONE_WRITE_BYTE     255 // 0b11111111

struct twobitseq_t {
    uint8_t *arr;
    size_t len;
    size_t idx;
};

typedef struct twobitseq_t twobitseq_t;

int twobitseq_create(twobitseq_t **tbs, const char *s, size_t len);
void twobitseq_free(twobitseq_t *tbs);

ssize_t twobitseq_seek(twobitseq_t *tbs, size_t pos);
int twobitseq_read(twobitseq_t *tbs);
int twobitseq_write(twobitseq_t *tbs, int val);
void twobitseq_dumpstr(twobitseq_t *tbs, char *buf, size_t len);
int twobitseq_read_next_or_last(twobitseq_t *tbs);
char twobitseq_read_next_or_last_as_char(twobitseq_t *tbs);

#endif
