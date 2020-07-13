#include <stdio.h>
#include "twobitseq.h"

/*
#define TBS_TEST(x, t) if (twobitseq_test(x, sizeof(x) - 1)) { \
    printf("Failed for " ##x "\n"); \
    t = 1; \
}*/

#define TBS_TEST(x, t) if (twobitseq_test(#x, sizeof(#x) - 1)) { printf("failed for " #x "\n"); t = 1; };
#define TBS_TEST_FAIL(x, t) if (twobitseq_test(#x, sizeof(#x) - 1) == 0) { printf("should have failed for " #x "\n"); t = 1; };

int twobitseq_test(const char *x, size_t len) 
{
    // read all characters back from tbs
    // make sure they are the same as x

    twobitseq_t *tbs = NULL;
    size_t i;
    char c;
    int fail = 0;
    int ret;

    ret = twobitseq_create(&tbs, x, len);
    if (ret < 0 || tbs == NULL) {
        printf("failed to create tbs\n");
        return 1;
    }

    for(i=0; i < len; i++) {
        c = twobitseq_read_next_or_last_as_char(tbs);
        if (c != x[i]) {
            printf("[%s] expected %c but got %c at position %zd\n", x, x[i], c, i);
            fail = 1;
            goto end;
        }
    }

    // read a little bit more after the end
    for(i=0; i < 5; i++) {
        c = twobitseq_read_next_or_last_as_char(tbs);
        if (c != x[len - 1]) {
            printf("[%s] expected %c but got %c for after last char\n", x, x[i], c);
            fail = 1;
            goto end;
        }
    }

end:
    twobitseq_free(tbs);
    return fail;
}

int main(int argc, char **argv) 
{
    (void) argc;
    (void) argv;

    int fail = 0;

    TBS_TEST(A, fail);
    TBS_TEST(X, fail);
    TBS_TEST(W, fail);
    TBS_TEST(F, fail);
    TBS_TEST(AAAAAAAAAAAAA, fail);
    TBS_TEST(XXXXXXXXXXXXX, fail);
    TBS_TEST(WWWWWWWWWWWWW, fail);
    TBS_TEST(FFFFFFFFFFFFF, fail);

    TBS_TEST(WWFFFFWWFFFFWX, fail);
    TBS_TEST(FFWWWWFFWWWWFA, fail);
    TBS_TEST(FFA, fail);
    TBS_TEST(WWX, fail);

    TBS_TEST_FAIL(AAY, fail);
    printf("Ignore above error. It meant to do that\n");
    if (fail) {
        printf("Twobitseq tests failed!\n");
    } else {
        printf("Twobitseq tests passed!\n");
    }

    return fail;
}
