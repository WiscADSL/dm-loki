#ifndef __dm_loki_log_h

#define __dm_loki_log_h

#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/types.h>

#include "dm-loki-common.h"
#include "dm-loki.h"

// BIO specific
#define LOG_FLUSH_FLAG (1 << 0)
#define LOG_FUA_FLAG (1 << 1)
#define LOG_READ_FLAG (1 << 2)
#define LOG_WRITE_FLAG (1 << 3)
#define LOG_SYNC_FLAG (1 << 4)
#define LOG_DISCARD_FLAG (1 << 5)
#define LOG_HAS_MSG_FLAG (1 << 6)
#define LOG_IS_BIO_FLAG (1 << 7)
#define LOG_BIO_ERROR_FLAG (1 << 8)
#define LOG_HAS_DATA_FLAG (1 << 9)

// LOG specific
#define LOG_START_OF_LOG_FLAG (1 << 10)
#define LOG_END_OF_LOG_FLAG (1 << 11)
#define LOG_MARKER_FLAG (1 << 12)

#define LOG_BIO_ENTRY_REPR_FMT "log_entry_t " \
    "{" \
        "\"logdev_sector_start\": %llu, "\
        "\"bio_sector\": %llu, "\
        "\"bio_size\": %u, "\
    "}"

#define LOG_BIO_ENTRY_REPR_ARGS(log_entry) \
    (unsigned long long) log_entry->entry.bio.logdev_sector_start, \
    (unsigned long long) log_entry->entry.bio.bio_sector, \
    (unsigned int) log_entry->entry.bio.bio_size

void create_log_entry_for_bio(struct loki_c *lc, struct bio *bio);
void copy_write_data_to_log_entry(struct log_entry_t *log_entry, struct bio *bio);
int copy_read_data_to_log_entry(struct log_entry_t *log_entry, struct bio *bio);
int write_log_entry(struct log_entry_t *log_entry);
void log_entry_end_io(struct bio *bio);
void dealloc_log_entry(struct log_entry_t *log_entry);
int log_writer_init(struct loki_c *lc);
void log_writer_cleanup(struct loki_c *lc);
void log_writer_enqueue(struct loki_c *lc, struct log_entry_t *entry);
void mark_log_entry_completed(struct loki_c *lc);
#endif
