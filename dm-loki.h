#ifndef __dm_loki_h

#define __dm_loki_h

#include <linux/version.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/types.h>

#include "twobitseq.h"

#define DM_MSG_PREFIX "loki"
#define DM_LOKI_MAX_UUID_LEN 1024

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define LOKI_SET_BDEV(bio, bdev) bio->bi_bdev = bdev;
#else
#define LOKI_SET_BDEV(bio, bdev) bio_set_dev(bio, bdev);
#endif

// loki_fault_item_t describes fault configs (valid only for WRITES)
struct loki_fault_item_t {
    sector_t start;
    sector_t end;
    twobitseq_t *tbs;
    struct list_head mylist;
};

#define FAULT_LIST_ITEM_REPR_FMT "loki_fault_item_t " \
    "{"\
        "\"start\": %llu, "\
        "\"end\": %llu, "\
        "\"tbs\": { \"str\": %s, \"idx\": %zu, \"len\": %zu } "\
    "}"

#define FAULT_LIST_ITEM_REPR_ARGS(f, buf) \
    (unsigned long long) f->start, (unsigned long long) f->end, \
    buf, f->tbs->idx, f->tbs->len

#define BIO_REPR_FMT "bio " \
    "{" \
        "\"bi_sector\": %llu, "\
        "\"bi_size\": %u, "\
        "\"bi_idx\": %u, "\
        "\"bi_bvec_done\": %u, "\
        "\"bio_has_data\": %d, "\
        "\"bio_op_is_write\": %d, "\
        "\"bio_op_is_flush\": %d, "\
        "\"bio_op_is_sync\": %d "\
    "}"

#define BIO_REPR_ARGS(bio) \
    (unsigned long long) bio->bi_iter.bi_sector, \
    bio->bi_iter.bi_size, \
    bio->bi_iter.bi_idx, \
    bio->bi_iter.bi_bvec_done, \
    bio_has_data(bio), \
    op_is_write(bio->bi_opf), \
    op_is_flush(bio->bi_opf), \
    op_is_sync(bio->bi_opf)

struct log_superblock_t {
    atomic64_t num_bios; // this is just bios regardless of data
    atomic64_t num_missing; // incase we had to stop midway
};

struct dm_loki_log_conf_t {
    struct dm_dev *dev;
    bool active;
    bool full;
    u64 magic_sb;
    u64 magic_bio;
    u64 magic_tag;
    sector_t logdev_sector_start;
    sector_t logdev_sector_end;
    atomic64_t logdev_next_sector;
    spinlock_t log_queue_lock;
    struct task_struct *log_writer_thread;
    struct list_head log_queue;
    wait_queue_head_t log_queue_wait;
    atomic_t active_log_entries;
    struct log_superblock_t superblock;
    char logtag[480]; // tag appended to every log entry
};

struct loki_c {
	struct dm_dev *dev;
    struct dm_loki_log_conf_t *logconf;
    char uuid[DM_LOKI_MAX_UUID_LEN + 1];
    int dev_enabled; // to simulate power failure, fail all requests if not enabled
    struct mutex fault_list_mutex;
    struct list_head fault_list;
};

struct log_entry_bio_t {
    sector_t logdev_sector_start;
    u64 flags;
    atomic_t bio_count;
    char tag[480];

    // all log entries have atleast a header page
    struct page *header_page;
    // When dealing with reads, we need to save this during the map phase
    sector_t bio_sector;
    unsigned int bio_size;
    // When dealing with writes, we need the vecs and vec count
    int vec_count;
    struct bio_vec *vecs;
};

struct log_entry_sb_t {
    struct page *sb_page;
};

struct log_entry_tag_t {
    sector_t logdev_sector_start;
    char tag[504];
    struct page *tag_page;
};

// TODO write helper functions to copy data from struct to page

#define LOG_ENTRY_SB 1
#define LOG_ENTRY_BIO 2
#define LOG_ENTRY_TAG 3

#define LOG_ENTRY_SB_MAGIC  0x4c4f4b495f5f5342
#define LOG_ENTRY_TAG_MAGIC 0x4c4f4b495f544147
#define LOG_ENTRY_BIO_MAGIC 0x4c4f4b495f42494f

struct log_entry_t {
    struct loki_c *lc;
    struct list_head list;

    int log_entry_type;
    union {
        struct log_entry_sb_t sb;
        struct log_entry_bio_t bio;
        struct log_entry_tag_t tag;
    } entry;
};

struct log_bio_header_t {
    u64 magic;
    u64 sector;
    u64 size;
    u64 flags;
    char msg[480];
};

struct log_sb_header_t {
    u64 magic;
    u64 num_bios;
    u64 last_sector;
    u64 num_missing;
};

struct log_tag_header_t {
    u64 magic;
    char tag[504];
};

struct per_bio_data {
    struct log_entry_t *log_entry;
};

/* dm-loki-fault-list.c */
struct loki_fault_item_t* loki_fault_item_create(struct loki_c *lc,
    sector_t start, sector_t end, twobitseq_t *tbs);

void loki_fault_item_free(struct loki_fault_item_t *fault_item);
void loki_fault_item_dump(struct loki_fault_item_t *fault_item);

void loki_fault_list_init(struct loki_c *lc);

void loki_fault_list_free(struct loki_c *lc);

void loki_fault_list_add_fault_item(struct loki_c *lc, 
    struct loki_fault_item_t *fault_item);

void loki_fault_list_del_fault_item(struct loki_c *lc,
    struct loki_fault_item_t *fault_item);

struct loki_fault_item_t* loki_fault_list_find(struct loki_c *lc,
    sector_t start, sector_t end);

void loki_fault_list_dump(struct loki_c *lc);

/* dm-loki-handle-messages.c */
int loki_handle_message(struct loki_c *lc, unsigned argc, char **argv);

#endif
