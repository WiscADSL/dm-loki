#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/atomic.h>
#include <linux/device-mapper.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/version.h>

#include "dm-loki-common.h"
#include "dm-loki.h"
#include "dm-loki-log.h"

static u64 flags_from_bio(struct bio *bio) {
    u64 flags = 0;
    if (bio_data_dir(bio) == READ) {
        flags |= LOG_READ_FLAG;
    }
    if (bio_data_dir(bio) == WRITE) {
        flags |= LOG_WRITE_FLAG;
    }
    if (bio_has_data(bio)) {
        flags |= LOG_HAS_DATA_FLAG;
    }
    if (bio->bi_opf & REQ_PREFLUSH) {
        flags |= LOG_FLUSH_FLAG;
    }
    if (bio->bi_opf & REQ_FUA) {
        flags |= LOG_FUA_FLAG;
    }
    if (bio_op(bio) == REQ_OP_DISCARD) {
        flags |= LOG_DISCARD_FLAG;
    }
    if (op_is_sync(bio->bi_opf)) {
        flags |= LOG_SYNC_FLAG;
    }
    if (bio->bi_status) {
        // TODO on error, maybe set an extra field in log header?
        flags |= LOG_BIO_ERROR_FLAG;
    }
    flags |= LOG_IS_BIO_FLAG;
    return flags;
}

void log_entry_end_io(struct bio *bio)
{
    struct log_entry_t *log_entry = bio->bi_private;
    struct loki_c *lc = NULL;

    if (log_entry == NULL) {
        goto usual;
    }

    lc = log_entry->lc;

    switch(log_entry->log_entry_type) {
        case LOG_ENTRY_SB:
        case LOG_ENTRY_TAG:
            dealloc_log_entry(log_entry);
            mark_log_entry_completed(lc);
            goto usual;

        case LOG_ENTRY_BIO:
        {
            int bio_count;

            bio_count = atomic_add_return(-1, &log_entry->entry.bio.bio_count);
            if (bio_count > 0) {
                goto usual;
            }

            if (bio_count < 0) {
                LOG_EROR("[%s] something went wrong, bio should not be negative %d",
                    lc->uuid, bio_count);
                goto usual;
            }

            // bio_count is 0, we can free this log entry
            dealloc_log_entry(log_entry);
            mark_log_entry_completed(lc);
            goto usual;
        }

        default:
            LOG_EROR("[%s] unknown log_entry type %d", lc->uuid, log_entry->log_entry_type);
            goto usual;
    }

usual:
    bio_put(bio);
}

void create_log_entry_for_bio(struct loki_c *lc, struct bio *bio) {
    struct per_bio_data *pb = dm_per_bio_data(bio, sizeof(struct per_bio_data));
    sector_t start, end;

    pb->log_entry = NULL;

    pb->log_entry = (struct log_entry_t *) kzalloc(sizeof(struct log_entry_t), GFP_NOIO);
    if (pb->log_entry == NULL) {
        LOG_EROR("[%s] failed to allocate mem for log entry", lc->uuid);
        return;
    }

    end = bio_sectors(bio) + 1; // just the length here
    /* Logs to figure out why there were holes in the logimg.
     * Using a new vm fixed the problem :|
    LOG_INFO("[%s] adding %llu to logdev_next_sector (%llu)", 
        lc->uuid, (unsigned long long) end, (unsigned long long) atomic64_read(&(lc->logconf->logdev_next_sector)));
    */

    start = (sector_t) atomic64_fetch_add(end, &(lc->logconf->logdev_next_sector));
    end += start; // actual end

    if (end > lc->logconf->logdev_sector_end) {
        LOG_EROR("[%s] cannot log upto sector %llu, end is %llu, disabling logging", lc->uuid,
            (unsigned long long) end, (unsigned long long) lc->logconf->logdev_sector_end);

        kfree(pb->log_entry);
        pb->log_entry = NULL;

        lc->logconf->full = true;
        return;
    }

    pb->log_entry->lc = lc;
    pb->log_entry->log_entry_type = LOG_ENTRY_BIO;
    pb->log_entry->entry.bio.logdev_sector_start = start;
    pb->log_entry->entry.bio.flags = flags_from_bio(bio);
    pb->log_entry->entry.bio.bio_sector = bio->bi_iter.bi_sector;
    pb->log_entry->entry.bio.bio_size = bio->bi_iter.bi_size;
    pb->log_entry->entry.bio.vec_count = 0;
    pb->log_entry->entry.bio.vecs = NULL;
    pb->log_entry->entry.bio.header_page = NULL;
    memcpy(pb->log_entry->entry.bio.tag, lc->logconf->logtag, 480);
    atomic_set(&pb->log_entry->entry.bio.bio_count, 0);

    if (pb->log_entry->entry.bio.flags & LOG_READ_FLAG) {
        return;
    }

    if (pb->log_entry->entry.bio.flags & LOG_WRITE_FLAG) {
        copy_write_data_to_log_entry(pb->log_entry, bio);
    }
}

void copy_write_data_to_log_entry(struct log_entry_t *log_entry, struct bio *bio)
{
    struct bvec_iter iter;
    struct bio_vec bv;

    struct loki_c *lc = log_entry->lc;
    unsigned int i;

    log_entry->entry.bio.vec_count = 0;
    log_entry->entry.bio.vecs = NULL;

    if (!bio_has_data(bio)) {
        return;
    }

    if (log_entry->entry.bio.flags & LOG_DISCARD_FLAG) {
        return;
    }

    log_entry->entry.bio.vecs = (struct bio_vec *) kzalloc(sizeof(struct bio_vec) * bio_segments(bio), GFP_NOIO);
    if (log_entry->entry.bio.vecs == NULL) {
        LOG_EROR("[%s] Failed to kzalloc bio_vecs", lc->uuid);
        return;
    }

    i = 0;
    bio_for_each_segment(bv, bio, iter) {
        struct page *page;
        void *src, *dst;

        page = alloc_page(GFP_NOIO);
        if (!page) {
            LOG_EROR("[%s] Failed to alloc page", lc->uuid);
            return;
        }

        src = kmap_atomic(bv.bv_page);
        dst = kmap_atomic(page);
        memcpy(dst, src + bv.bv_offset, bv.bv_len);
        kunmap_atomic(dst);
        kunmap_atomic(src);

        log_entry->entry.bio.vecs[i].bv_page = page;
        log_entry->entry.bio.vecs[i].bv_len = bv.bv_len;
        log_entry->entry.bio.vec_count++;
        i++;
    }

    return;
}

int copy_read_data_to_log_entry(struct log_entry_t *log_entry, struct bio *bio)
{
    struct bio_vec bv;
    struct bvec_iter iter, orig, start;
    struct loki_c *lc = log_entry->lc;
    unsigned int i, vec_count;

    orig.bi_sector = log_entry->entry.bio.bio_sector;
    orig.bi_size = log_entry->entry.bio.bio_size;
    orig.bi_idx = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
    orig.bi_done = 0;
#endif
    orig.bi_bvec_done = 0;

    vec_count = 0;
    start = orig;

    // TODO maybe there's a simpler way to find this?
    __bio_for_each_segment(bv, bio, iter, start) {
        vec_count++;
    }

    log_entry->entry.bio.vec_count = 0;
    log_entry->entry.bio.vecs = NULL;
    log_entry->entry.bio.vecs = (struct bio_vec *) kzalloc (sizeof(struct bio_vec) * vec_count, GFP_NOIO);
    if (log_entry->entry.bio.vecs == NULL) {
        LOG_EROR("[%s] Failed to kzalloc bio_vecs", lc->uuid);
        return 1;
    }

    start = orig;
    i = 0;
    __bio_for_each_segment(bv, bio, iter, start) {
        void *src, *dst;
        struct page *page;

        page = alloc_page(GFP_NOIO);
        if (!page) {
            LOG_EROR("[%s] Failed to alloc page", lc->uuid);
            return 1; // TODO make sure to free up this page
        }

        src = kmap_atomic(bv.bv_page);
        dst = kmap_atomic(page);
        memcpy(dst, src + bv.bv_offset, bv.bv_len);
        kunmap_atomic(dst);
        kunmap_atomic(src);

        log_entry->entry.bio.vecs[i].bv_page = page;
        log_entry->entry.bio.vecs[i].bv_len = bv.bv_len;
        log_entry->entry.bio.vec_count++;
        i++;
    }

    return 0;
}

static int write_bio_log_entry(struct log_entry_t *log_entry)
{
    int ret, i, bio_count, expected_bio_count;
    struct loki_c *lc = log_entry->lc;
    struct bio *data_bio = NULL;
    struct bio *header_bio = NULL;
    struct log_bio_header_t header;
    void *dst;

    header.magic = lc->logconf->magic_bio;
    header.sector = cpu_to_le64(log_entry->entry.bio.bio_sector);
    header.size = cpu_to_le64(log_entry->entry.bio.bio_size);
    header.flags = cpu_to_le64(log_entry->entry.bio.flags);
    memcpy(header.msg, log_entry->entry.bio.tag, 480);

    log_entry->entry.bio.header_page = NULL;
    log_entry->entry.bio.header_page = alloc_page(GFP_NOIO);
    if (!log_entry->entry.bio.header_page) {
        LOG_EROR("[%s] Failed to alloc header page", lc->uuid);
        goto fail;
    }

    header_bio = bio_alloc(GFP_NOIO, 1);
    if (header_bio == NULL) {
        LOG_EROR("[%s] Failed to alloc header bio", lc->uuid);
        goto fail;
    }

    header_bio->bi_iter.bi_size = 0;
    header_bio->bi_iter.bi_sector = log_entry->entry.bio.logdev_sector_start;
    header_bio->bi_end_io = log_entry_end_io;
    header_bio->bi_private = log_entry;
    LOKI_SET_BDEV(header_bio, lc->logconf->dev->bdev);
    bio_set_op_attrs(header_bio, REQ_OP_WRITE, 0);
    dst = kmap_atomic(log_entry->entry.bio.header_page);
    memcpy(dst, &header, 512);
    kunmap_atomic(dst);
    ret = bio_add_page(header_bio, log_entry->entry.bio.header_page, 512, 0);
    if (ret != 512) {
        LOG_EROR("[%s] Failed to add page for header bio", lc->uuid);
        goto fail;
    }

    if (log_entry->entry.bio.vec_count == 0) {
        goto submit;
    }

    data_bio = bio_alloc(GFP_NOIO, log_entry->entry.bio.vec_count);
    if (!data_bio) {
        LOG_EROR("[%s] Failed to allocate bio for data", lc->uuid);
        return 1;
    }

    data_bio->bi_iter.bi_size = 0;
    data_bio->bi_iter.bi_sector = log_entry->entry.bio.logdev_sector_start + 1;
    data_bio->bi_end_io = log_entry_end_io;
    data_bio->bi_private = log_entry;
    LOKI_SET_BDEV(data_bio, lc->logconf->dev->bdev);
    // TODO if this is deprecated, what to use?
    bio_set_op_attrs(data_bio, REQ_OP_WRITE, 0);

    for(i=0; i < log_entry->entry.bio.vec_count; i++) {
        ret = bio_add_page(data_bio, log_entry->entry.bio.vecs[i].bv_page,
            log_entry->entry.bio.vecs[i].bv_len, 0);

        if (ret != log_entry->entry.bio.vecs[i].bv_len) {
            LOG_EROR("[%s] failed to add page for bio", lc->uuid);
            goto fail;
        }
    }

submit:
    bio_count = 0;
    if (header_bio != NULL) bio_count++;
    if (data_bio != NULL) bio_count++;

    expected_bio_count = bio_count;
    bio_count = atomic_add_return(bio_count, &log_entry->entry.bio.bio_count);
    if (bio_count != expected_bio_count) {
        LOG_EROR("[%s] expected log_entry count to be %d, not %d", lc->uuid, expected_bio_count, bio_count);
    }

    // LOG_INFO("[%s] submitting bios for " LOG_BIO_ENTRY_REPR_FMT, lc->uuid, LOG_BIO_ENTRY_REPR_ARGS(log_entry));

    if (header_bio != NULL) {
        // LOG_INFO("[%s] writing log entry header" BIO_REPR_FMT, lc->uuid, BIO_REPR_ARGS(header_bio));
        submit_bio(header_bio);
    }

    if (data_bio != NULL) {
        // LOG_INFO("[%s] writing log entry data" BIO_REPR_FMT, lc->uuid, BIO_REPR_ARGS(data_bio));
        submit_bio(data_bio);
    } 
    // else {
    //    LOG_INFO("[%s] Only submitted header bio!!", lc->uuid);
    // }

    // regardless of whether it fails or not, it has been given a sector slot in the log
    // so it shows up here
    atomic64_inc(&(lc->logconf->superblock.num_bios));

    return 0;

fail:
    if (header_bio != NULL) {
        bio_put(header_bio);
    }

    if (data_bio != NULL) {
        bio_put(data_bio);
    }

    return 1;
}

static int write_sb_log_entry(struct log_entry_t *log_entry)
{
    struct loki_c *lc = log_entry->lc;
    struct bio *sb_bio = NULL;
    struct page *sb_page = NULL;
    struct log_sb_header_t header;
    unsigned long long num_bios, last_sector, num_missing;
    void *dst;
    int ret;

    num_bios = (unsigned long long) atomic64_read(&(lc->logconf->superblock.num_bios));
    last_sector = (unsigned long long) atomic64_read(&(lc->logconf->logdev_next_sector));
    num_missing = (unsigned long long) atomic64_read(&(lc->logconf->superblock.num_missing));

    header.magic = lc->logconf->magic_sb;
    header.num_bios = cpu_to_le64(num_bios);
    header.last_sector = cpu_to_le64(last_sector);
    header.num_missing = cpu_to_le64(num_missing);

    sb_page = alloc_page(GFP_NOIO);
    log_entry->entry.sb.sb_page = sb_page;

    if (sb_page == NULL) {
        LOG_EROR("[%s] Failed to allocate superblock page", lc->uuid);
        goto fail;
    }

    sb_bio = bio_alloc(GFP_NOIO, 1);
    if (sb_bio == NULL) {
        LOG_EROR("[%s] Failed to allocate superblock bio", lc->uuid);
        goto fail;
    }

    sb_bio->bi_iter.bi_size = 0;
    sb_bio->bi_iter.bi_sector = lc->logconf->logdev_sector_start;
    sb_bio->bi_end_io = log_entry_end_io;
    sb_bio->bi_private = log_entry;
    sb_bio->bi_opf = REQ_OP_WRITE;
    LOKI_SET_BDEV(sb_bio, lc->logconf->dev->bdev);

    dst = kmap_atomic(sb_page);
    // TODO do I need to worry about zeroing out the rest of it?
    memcpy(dst, &header, sizeof(header));
    kunmap_atomic(dst);

    ret = bio_add_page(sb_bio, log_entry->entry.sb.sb_page, 512, 0);
    if (ret != 512) {
        LOG_EROR("[%s] Failed to add page for superblock bio", lc->uuid);
        goto fail;
    }

    submit_bio(sb_bio);
    return 0;

fail:
    if (sb_bio != NULL) {
        bio_put(sb_bio);
    }

    return 1;
}

static int write_tag_log_entry(struct log_entry_t *log_entry)
{
    struct loki_c *lc = log_entry->lc;
    struct bio *tag_bio = NULL;
    struct page *tag_page = NULL;
    struct log_tag_header_t header;
    void *dst;
    int ret;

    header.magic = lc->logconf->magic_tag;
    memcpy(header.tag, log_entry->entry.tag.tag, 504);

    tag_page = alloc_page(GFP_NOIO);
    log_entry->entry.tag.tag_page = tag_page;

    if (tag_page == NULL) {
        LOG_EROR("[%s] Failed to allocate tag page", lc->uuid);
        goto fail;
    }

    tag_bio = bio_alloc(GFP_NOIO, 1);
    if (tag_bio == NULL) {
        LOG_EROR("[%s] Failed to allocate tag bio", lc->uuid);
        goto fail;
    }

    tag_bio->bi_iter.bi_size = 0;
    tag_bio->bi_iter.bi_sector = log_entry->entry.tag.logdev_sector_start;
    tag_bio->bi_end_io = log_entry_end_io;
    tag_bio->bi_private = log_entry;
    tag_bio->bi_opf = REQ_OP_WRITE;
    LOKI_SET_BDEV(tag_bio, lc->logconf->dev->bdev);

    dst = kmap_atomic(tag_page);
    memcpy(dst, &header, sizeof(header));
    kunmap_atomic(dst);

    ret = bio_add_page(tag_bio, log_entry->entry.tag.tag_page, 512, 0);
    if (ret != 512) {
        LOG_EROR("[%s] Failed to add page for tag bio", lc->uuid);
        goto fail;
    }

    submit_bio(tag_bio);
    return 0;

fail:
    if (tag_bio != NULL) {
        bio_put(tag_bio);
    }

    return 1;
}

int write_log_entry(struct log_entry_t *log_entry)
{
    if (log_entry->log_entry_type == LOG_ENTRY_BIO) {
        return write_bio_log_entry(log_entry);
    }

    if (log_entry->log_entry_type == LOG_ENTRY_SB) {
        return write_sb_log_entry(log_entry);
    }

    if (log_entry->log_entry_type == LOG_ENTRY_TAG) {
        return write_tag_log_entry(log_entry);
    }

    LOG_EROR("[%s] Unknown log entry type %d", log_entry->lc->uuid, log_entry->log_entry_type);
    return 0;
}

static void dealloc_bio_log_entry(struct log_entry_t *log_entry)
{
    int i;

    if (log_entry == NULL) {
        return;
    }

    if (log_entry->entry.bio.vecs == NULL) {
        goto end;
    }

    for(i=0; i < log_entry->entry.bio.vec_count; i++) {
        if (log_entry->entry.bio.vecs[i].bv_page) {
            __free_page(log_entry->entry.bio.vecs[i].bv_page);
            log_entry->entry.bio.vecs[i].bv_page = NULL;
        }
    }

    if (log_entry->entry.bio.header_page != NULL) {
        __free_page(log_entry->entry.bio.header_page);
        log_entry->entry.bio.header_page = NULL;
    }

end:
    kfree(log_entry);
}

static void dealloc_sb_log_entry(struct log_entry_t *log_entry)
{
    if (log_entry == NULL) {
        return;
    }

    if (log_entry->entry.sb.sb_page == NULL) {
        goto end;
    }

    __free_page(log_entry->entry.sb.sb_page);
    log_entry->entry.sb.sb_page = NULL;

end:
    kfree(log_entry);
}

static void dealloc_tag_log_entry(struct log_entry_t *log_entry)
{
    if (log_entry == NULL) {
        return;
    }

    if (log_entry->entry.tag.tag_page == NULL) {
        goto end;
    }

    __free_page(log_entry->entry.tag.tag_page);
    log_entry->entry.tag.tag_page = NULL;
end:
    kfree(log_entry);
}

void dealloc_log_entry(struct log_entry_t *log_entry)
{
    if (log_entry->log_entry_type == LOG_ENTRY_BIO) {
        return dealloc_bio_log_entry(log_entry);
    }

    if (log_entry->log_entry_type == LOG_ENTRY_SB) {
        return dealloc_sb_log_entry(log_entry);
    }

    if (log_entry->log_entry_type == LOG_ENTRY_TAG) {
        return dealloc_tag_log_entry(log_entry);
    }
}

static int dm_loki_log_writer_thread(void *arg)
{
    struct loki_c *lc = (struct loki_c *) arg;
    LOG_INFO("log writer thread started ... ");
    while(!kthread_should_stop()) {
        struct log_entry_t *log_entry = NULL;

        // get one element from the list
        spin_lock_irq(&lc->logconf->log_queue_lock);
        if (!list_empty(&lc->logconf->log_queue)) {
            log_entry = list_first_entry(&lc->logconf->log_queue, struct log_entry_t, list);
            list_del_init(&log_entry->list);
        }
        spin_unlock_irq(&lc->logconf->log_queue_lock);

        if (log_entry != NULL) {
            if (write_log_entry(log_entry) != 0) {
                dealloc_log_entry(log_entry);
                mark_log_entry_completed(lc);
            }
        }

        if (!try_to_freeze()) {
            set_current_state(TASK_INTERRUPTIBLE);
            if (!kthread_should_stop() &&
                    list_empty(&lc->logconf->log_queue)) {
                schedule();
            }
            __set_current_state(TASK_RUNNING);
        }
    }

    LOG_INFO("log writer thread stopped");
    return 0;
}

int log_writer_init(struct loki_c *lc)
{
    spin_lock_init(&lc->logconf->log_queue_lock);
    INIT_LIST_HEAD(&lc->logconf->log_queue);
    atomic_set(&lc->logconf->active_log_entries, 0);
    init_waitqueue_head(&lc->logconf->log_queue_wait);

    lc->logconf->log_writer_thread = kthread_run(dm_loki_log_writer_thread, lc, "log-writer-thread");
    if (IS_ERR(lc->logconf->log_writer_thread)) {
        return PTR_ERR(lc->logconf->log_writer_thread);
    }

    return 0;
}

void log_writer_cleanup(struct loki_c *lc)
{
    // TODO maybe write an end of file log entry
    wake_up_process(lc->logconf->log_writer_thread);

    LOG_INFO("waiting for all active log entries (%d) to be written", atomic_read(&lc->logconf->active_log_entries));
    wait_event(lc->logconf->log_queue_wait, atomic_read(&lc->logconf->active_log_entries) == 0);
    kthread_stop(lc->logconf->log_writer_thread);
}

void mark_log_entry_completed(struct loki_c *lc)
{
    if (atomic_dec_and_test(&lc->logconf->active_log_entries)) {
        smp_mb__after_atomic();
        if (waitqueue_active(&lc->logconf->log_queue_wait)) {
            wake_up(&lc->logconf->log_queue_wait);
        }
    }
}

void log_writer_enqueue(struct loki_c *lc, struct log_entry_t *entry)
{
    unsigned long flags;

    atomic_inc(&lc->logconf->active_log_entries);

    spin_lock_irqsave(&lc->logconf->log_queue_lock, flags);
    list_add_tail(&entry->list, &lc->logconf->log_queue);
    wake_up_process(lc->logconf->log_writer_thread);
    spin_unlock_irqrestore(&lc->logconf->log_queue_lock, flags);
}
