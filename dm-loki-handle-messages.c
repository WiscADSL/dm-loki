#include "dm-loki-common.h"
#include "dm-loki.h"
#include "dm-loki-log.h"
#include "twobitseq.h"

#define ADD_FAULT_ITEM "add_fault_item"
#define DEL_FAULT_ITEM "del_fault_item"
#define DUMP_FAULT_LIST "dump_fault_list"
#define DISABLE_SECTOR_LOG "disable_sector_log"
#define ENABLE_SECTOR_LOG "enable_sector_log"
#define SET_LOG_TAG "set_log_tag"
#define ENABLE_DEV "enable_dev"
#define DISABLE_DEV "disable_dev"

#define CMD_EQ(x, y) (strncmp(x, y, sizeof(y) - 1) == 0)

// argv should be of the form [ADD_FAULT_ITEM start end faultstring]
static int _add_fault_item(struct loki_c *lc, unsigned argc, char **argv)
{
    unsigned long long start, end;
    struct loki_fault_item_t *fault_item = NULL;
    int ret;
    twobitseq_t *tbs = NULL;

    if (argc != 4) {
        LOG_EROR("[%s] Require arguments [start end faultstring]", lc->uuid);
        return -EINVAL;
    }

    if (sscanf(argv[1], "%llu", &start) != 1) {
        LOG_EROR("[%s] sscanf failed to get start sector from argv[1] = %s",
            lc->uuid, argv[1]);
        return -EINVAL;
    }

    if (sscanf(argv[2], "%llu", &end) != 1) {
        LOG_EROR("[%s] sscanf failed to get end sector from argv[2] = %s",
            lc->uuid, argv[2]);
        return -EINVAL;
    }

    if (end < start) {
        LOG_EROR("[%s] end %llu < start %llu !!!", lc->uuid, end, start);
        return -EINVAL;
    }

    ret = twobitseq_create(&tbs, argv[3], strlen(argv[3]));
    if (ret != 0) {
        LOG_EROR("[%s] failed to create twobitsequence, got return code %d", lc->uuid, ret);
        return ret;
    }

    fault_item = loki_fault_item_create(lc, (sector_t) start, (sector_t) end, tbs);
    if (fault_item == NULL) {
        LOG_EROR("[%s] failed to create fault item", lc->uuid);
        return -ENOMEM;
    }

    loki_fault_list_add_fault_item(lc, fault_item);
    return 0;
}

static int _del_fault_item(struct loki_c *lc, unsigned argc, char **argv)
{
    unsigned long long start, end;
    struct loki_fault_item_t *fault_item = NULL;

    if (argc != 3) {
        LOG_EROR("[%s] Require arguments start & end", lc->uuid);
        return -EINVAL;
    }

    if (sscanf(argv[1], "%llu", &start) != 1) {
        LOG_EROR("[%s] sscanf failed to get start sector from argv[1] = %s",
            lc->uuid, argv[1]);
        return -EINVAL;
    }

    if (sscanf(argv[2], "%llu", &end) != 1) {
        LOG_EROR("[%s] sscanf failed to get end sector from argv[2] = %s",
            lc->uuid, argv[2]);
        return -EINVAL;
    }

    if (end < start) {
        LOG_EROR("[%s] end %llu < start %llu !!!", lc->uuid, end, start);
        return -EINVAL;
    }

    fault_item = loki_fault_list_find(lc, (sector_t) start, (sector_t) end);
    if (fault_item == NULL) {
        LOG_EROR("[%s] could not find fault item to del: (%llu, %llu)",
            lc->uuid, start, end);
        return -ENXIO;
    }

    loki_fault_list_del_fault_item(lc, fault_item);
    return 0;
}

static int _enable_sector_log(struct loki_c *lc)
{
    LOG_INFO("[%s] enabled sector log", lc->uuid);
    lc->logconf->active = true;
    return 0;
}

static int _disable_sector_log(struct loki_c *lc)
{
    LOG_INFO("[%s] disabled sector log", lc->uuid);
    lc->logconf->active = false;
    return 0;
}

static int _set_log_tag(struct loki_c *lc, unsigned argc, char **argv)
{
    struct log_entry_t *log_entry = NULL;
    char tag[480];
    int i, j, k, arglen;

    if (argc < 2) {
        LOG_EROR("[%s] require tag", lc->uuid);
        return -EINVAL;
    }

    j = 0;
    for(i=1; i < argc; i++) {
        arglen = strlen(argv[i]);
        for(k=0; (k < arglen) && (j < 480); k++) {
            tag[j++] = argv[i][k];
        }
        if (j < 480) {
            tag[j++] = ' ';
        }
    }

    for(j = j - 1; (j >= 0) && (j < 480); j++) {
        tag[j] = '\0';
    }

    memcpy(lc->logconf->logtag, tag, 480);

    log_entry = kzalloc(sizeof(*log_entry), GFP_NOIO);
    if (log_entry != NULL) {
        log_entry->lc = lc;
        log_entry->log_entry_type = LOG_ENTRY_TAG;
        log_entry->entry.tag.tag_page = NULL;
        memcpy(log_entry->entry.tag.tag, tag, 480);
        log_entry->entry.tag.logdev_sector_start = (sector_t) atomic64_fetch_add(1, &(lc->logconf->logdev_next_sector));
        log_writer_enqueue(lc, log_entry);
    } else {
        LOG_EROR("[%s] failed to enqueue log entry for tag", lc->uuid);
    }

    LOG_INFO("[%s] new logtag : %s", lc->uuid, lc->logconf->logtag);
    return 0;
}

static int _enable_dev(struct loki_c *lc)
{
    lc->dev_enabled = 1;
    return 0;
}

static int _disable_dev(struct loki_c *lc)
{
    lc->dev_enabled = 0;
    return 0;
}

int loki_handle_message(struct loki_c *lc, unsigned argc, char **argv) 
{

    if (CMD_EQ(argv[0], ADD_FAULT_ITEM)) {
        return _add_fault_item(lc, argc, argv);
    }

    if (CMD_EQ(argv[0], DEL_FAULT_ITEM)) {
        return _del_fault_item(lc, argc, argv);
    }

    if (CMD_EQ(argv[0], DUMP_FAULT_LIST)) {
        loki_fault_list_dump(lc);
        return 0;
    }

    if (CMD_EQ(argv[0], ENABLE_SECTOR_LOG)) {
        return _enable_sector_log(lc);
    }

    if (CMD_EQ(argv[0], DISABLE_SECTOR_LOG)) {
        return _disable_sector_log(lc);
    }

    if (CMD_EQ(argv[0], SET_LOG_TAG)) {
        return _set_log_tag(lc, argc, argv);
    }

    if (CMD_EQ(argv[0], ENABLE_DEV)) {
        return _enable_dev(lc);
    }

    if (CMD_EQ(argv[0], DISABLE_DEV)) {
        return _disable_dev(lc);
    }

    LOG_EROR("[%s] Got unknown command %s", lc->uuid, argv[0]);
    return -EINVAL;
}
