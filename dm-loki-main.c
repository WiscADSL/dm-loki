/*
 * dm_loki: Device mapper target that can receive messages
 * to enable faults on certain sectors.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/device-mapper.h>
#include <linux/mutex.h>

#include "dm-loki-common.h"
#include "dm-loki.h"
#include "twobitseq.h"
#include "dm-loki-log.h"

/*
 * Construct a loki mapping: <dev_path> <uuid> [<logdev_path> <logsector_start> <logsector_end>]
 */
static int loki_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	int ret;
    size_t uuid_len;
	struct loki_c *lc = NULL;
    char *dev_path = NULL, *uuid = NULL, *logdev_path = NULL, *c_lstart = NULL, *c_lend = NULL;
    unsigned long long lstart, lend;

    if ((argc != 3) && (argc != 5)) {
        ti->error = "Invalid argument count";
        LOG_EROR("Usage: <dev_path> <uuid> [<logdev_path> <logsector_start> <logsector_end>]");
        ret = -EINVAL;
        goto bad;
    }

    dev_path = argv[0]; uuid = argv[1];
    if (argc == 5) {
        logdev_path = argv[2]; c_lstart = argv[3]; c_lend = argv[4];
        if (sscanf(c_lstart, "%llu", &lstart) != 1) {
            ti->error = "Invalid argument";
            LOG_EROR("Error parsing logsector_start: unsigned long long, got %s", c_lstart);
            ret = -EINVAL;
            goto bad;
        }

        if (sscanf(c_lend, "%llu", &lend) != 1) {
            ti->error = "Invalid argument";
            LOG_EROR("Error parsing logsector_end: unsigned long long, got %s", c_lend);
            ret = -EINVAL;
            goto bad;
        }
    }

	lc = kmalloc(sizeof(*lc), GFP_KERNEL);
	if (lc == NULL) {
		ti->error = "Cannot allocate loki context";
		ret = -ENOMEM;
        goto bad;
	}

    lc->dev = NULL;

    // TODO logconf only if dev is provided?
    lc->logconf = NULL;
    lc->logconf = kmalloc(sizeof(struct dm_loki_log_conf_t), GFP_KERNEL);
    if (lc->logconf == NULL) {
        ti->error = "Cannot allocate logconf";
        ret = -ENOMEM;
        goto bad;
    }

    lc->logconf->dev = NULL;

    lc->logconf->magic_sb = cpu_to_le64(LOG_ENTRY_SB_MAGIC);
    lc->logconf->magic_tag = cpu_to_le64(LOG_ENTRY_TAG_MAGIC);
    lc->logconf->magic_bio = cpu_to_le64(LOG_ENTRY_BIO_MAGIC);

    lc->logconf->active = 0;
    lc->logconf->logdev_sector_start = (sector_t) lstart;
    lc->logconf->logdev_sector_end = (sector_t) lend;
    // start sector is used as super block so idx starts at lstart + 1
    atomic64_set(&(lc->logconf->logdev_next_sector), (u64)(lstart + 1));

    memset(lc->logconf->logtag, 0, 480);
    memcpy(lc->logconf->logtag, "default", sizeof("default") - 1);

    lc->logconf->full = false;
    atomic64_set(&(lc->logconf->superblock.num_bios), 0);
    atomic64_set(&(lc->logconf->superblock.num_missing), 0);

    uuid_len = strlen(uuid);
    if (uuid_len > DM_LOKI_MAX_UUID_LEN) {
        LOG_WARN("truncating uuid from length %zu to %d", uuid_len, DM_LOKI_MAX_UUID_LEN);
        uuid_len = DM_LOKI_MAX_UUID_LEN;
    }
    strncpy(lc->uuid, uuid, uuid_len);
    lc->uuid[uuid_len] = '\0';

    loki_fault_list_init(lc);

	ret = dm_get_device(ti, dev_path, dm_table_get_mode(ti->table), &lc->dev);
	if (ret) {
		ti->error = "Device lookup failed";
		goto bad;
	}

    if (logdev_path != NULL) {
        ret = dm_get_device(ti, logdev_path, dm_table_get_mode(ti->table), &lc->logconf->dev);
        if (ret) {
            ti->error = "Log device lookup failed";
            goto bad;
        }
    }

    ret = log_writer_init(lc);
    if (ret != 0) {
        ti->error = "Failed to init log writer thread";
        goto bad;
    }

    // dev enabled by default
    lc->dev_enabled = 1;

	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
	ti->num_write_same_bios = 1;
    ti->flush_supported = 1;
	ti->private = lc;
    LOG_INFO("[%s] initialized loki target", lc->uuid);

	return 0;

bad:
    if (lc != NULL) {
        if (lc->dev != NULL) {
            dm_put_device(ti, lc->dev);
            lc->dev = NULL;
        }

        if (lc->logconf != NULL) {
            if (lc->logconf->dev != NULL) {
                dm_put_device(ti, lc->logconf->dev);
                lc->logconf->dev = NULL;
            }

            kfree(lc->logconf);
            lc->logconf = NULL;
        }

        kfree(lc);
        lc = NULL;
        // NOTE: Not bothering to stop log_writer_init, since if it's the last thing and if it threw
        // an error, its probably because it couldn't start the log writer thread.
        // However, do add cleanup here if the log_writer kallocs anything.
    }

	return ret;
}

static void loki_dtr(struct dm_target *ti)
{
	struct loki_c *lc = (struct loki_c *) ti->private;
    struct log_entry_t *log_entry = NULL;

    LOG_INFO("[%s] .", lc->uuid);

    log_entry = kzalloc(sizeof(*log_entry), GFP_NOIO);
    if (log_entry != NULL) {
        log_entry->lc = lc;
        log_entry->log_entry_type = LOG_ENTRY_SB;
        log_entry->entry.sb.sb_page = NULL;
        log_writer_enqueue(lc, log_entry);
    } else {
        LOG_EROR("[%s] failed to allocate log entry for superblock", lc->uuid);
    }

    // TODO cleanup only if dev is provided?
    log_writer_cleanup(lc);

    loki_fault_list_free(lc);

	dm_put_device(ti, lc->dev);
    if (lc->logconf->dev != NULL) {
        dm_put_device(ti, lc->logconf->dev);
    }

    kfree(lc->logconf);
	kfree(lc);
}

static int loki_map(struct dm_target *ti, struct bio *bio)
{
    struct loki_c *lc = (struct loki_c *) ti->private;
    struct loki_fault_item_t *fault_item = NULL;
    unsigned long long start_in_bytes, end_in_bytes;
    sector_t start_sector, end_sector, num_sectors;
    int tbs_val;
    struct per_bio_data *pb = dm_per_bio_data(bio, sizeof(struct per_bio_data));
    if (pb == NULL) {
        LOG_WARN("[%s] !! Failed to get per bio data :( " BIO_REPR_FMT, lc->uuid, BIO_REPR_ARGS(bio));
        return DM_MAPIO_KILL;
    }

    pb->log_entry = NULL;

    LOKI_SET_BDEV(bio, lc->dev->bdev);

    // LOG_INFO("[%s] Got " BIO_REPR_FMT, lc->uuid, BIO_REPR_ARGS(bio));

    // log everything if logconf active
    if (lc->logconf->active) {
        if (lc->logconf->full) {
            atomic64_inc(&(lc->logconf->superblock.num_missing));
        } else {
            create_log_entry_for_bio(lc, bio);
        }
    }

    // if dev not enabled, throw err (but we've logged all of them!)
    if (!(lc->dev_enabled)) {
        bio_io_error(bio);
        return DM_MAPIO_SUBMITTED;
    }

    // we don't care about reads
    if (bio_data_dir(bio) == READ) {
        return DM_MAPIO_REMAPPED;
    }

    // LOG_INFO("[%s] " BIO_REPR_FMT, lc->uuid, BIO_REPR_ARGS(bio));

    start_in_bytes = (bio->bi_iter.bi_sector) << 9;
    end_in_bytes = start_in_bytes + bio->bi_iter.bi_size;
    if (bio->bi_iter.bi_size > 0) {
        end_in_bytes -= 1;
    }

    start_sector = bio->bi_iter.bi_sector;
    end_sector = (sector_t) (end_in_bytes >> 9);

    fault_item = loki_fault_list_find(lc, start_sector, end_sector);
    if (fault_item == NULL) {
        return DM_MAPIO_REMAPPED;
    }

    if ((end_sector < fault_item->start) || (start_sector > fault_item->end)) {
        return DM_MAPIO_REMAPPED;
    }

    // found fault item
    LOG_INFO("[%s] Found fault item!", lc->uuid);
    mutex_lock(&lc->fault_list_mutex);
    loki_fault_item_dump(fault_item);
    tbs_val = twobitseq_read_next_or_last(fault_item->tbs);
    mutex_unlock(&lc->fault_list_mutex);

    if (tbs_val == ALLOW_ALL_WRITE || tbs_val == ALLOW_ONE_WRITE) {
        // read goes through successfully
        return DM_MAPIO_REMAPPED;
    }

    // We're supposed to fail this write. It may overlap with something that doesn't fail
    // so we split bios if necessary using dm_accept_partial_bio

    if (start_sector < fault_item->start) {
        // only consider from start to fstart - 1
        end_sector = fault_item->start - 1;
        num_sectors = end_sector - start_sector + 1;
        dm_accept_partial_bio(bio, num_sectors);
        return DM_MAPIO_REMAPPED;
    }

    if (end_sector <= fault_item->end) {
        // this entire bio should fail
        bio_io_error(bio);
        return DM_MAPIO_SUBMITTED;
    }

    // start to fend should fail, the rest should go through
    end_sector = fault_item->end;
    num_sectors = end_sector - start_sector + 1;
    dm_accept_partial_bio(bio, num_sectors);
    bio_io_error(bio);
    return DM_MAPIO_SUBMITTED;
}

static int loki_end_io(struct dm_target *ti, struct bio *bio, blk_status_t *error)
{
    struct loki_c *lc = (struct loki_c *) ti->private;
    struct per_bio_data *pb = dm_per_bio_data(bio, sizeof(struct per_bio_data));
    struct log_entry_t *log_entry = NULL;

    if (pb == NULL) goto usual;

    // NOTE : this is always called on bios, so log_entry.type should always be bio
    log_entry = pb->log_entry;
    if (log_entry == NULL) goto usual;

    if (log_entry->log_entry_type != LOG_ENTRY_BIO) {
        LOG_EROR("Got unexpected type %d, expected LOG_ENTRY_BIO %d", log_entry->log_entry_type, LOG_ENTRY_BIO);
        goto usual;
    }

    if (bio->bi_status || *error) {
        log_entry->entry.bio.flags |= LOG_BIO_ERROR_FLAG;
    }

    if (log_entry->entry.bio.flags & LOG_READ_FLAG) {
        if (copy_read_data_to_log_entry(log_entry, bio) != 0) {
            goto cleanup;
        }
    }

    // LOG_INFO("[%s] inserting log record for bio " BIO_REPR_FMT, lc->uuid, BIO_REPR_ARGS(bio));
    log_writer_enqueue(lc, log_entry);

usual:
    return DM_ENDIO_DONE;

cleanup:
    // at this point we need to clean up log entry, and any pages it allocated
    dealloc_log_entry(log_entry);
    return DM_ENDIO_DONE;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
static int loki_message(struct dm_target *ti, unsigned argc, char **argv) 
#else
static int loki_message(struct dm_target *ti, unsigned argc, char **argv,
        char *result, unsigned maxlen)
#endif
{
    struct loki_c *lc = (struct loki_c *) ti->private;

    LOG_INFO("[%s] got message, argc: %u, argv[0]: %s", lc->uuid, argc, argv[0]);
    return loki_handle_message(lc, argc, argv);
}

static void loki_status(struct dm_target *ti, status_type_t type,
			  unsigned status_flags, char *result, unsigned maxlen)
{
	struct loki_c *lc = (struct loki_c *) ti->private;

    LOG_INFO("[%s] .", lc->uuid);

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;

	case STATUSTYPE_TABLE:
		snprintf(result, maxlen, "%s %s", lc->dev->name, lc->uuid);
		break;
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
static int loki_prepare_ioctl(struct dm_target *ti,
		struct block_device **bdev, fmode_t *mode)
#else
static int loki_prepare_ioctl(struct dm_target *ti,
		struct block_device **bdev)
#endif
{
	struct loki_c *lc = (struct loki_c *) ti->private;
	struct dm_dev *dev = lc->dev;
    LOG_INFO("[%s] .", lc->uuid);

	*bdev = dev->bdev;

	/*
	 * Only pass ioctls through if the device sizes match exactly.
	 */
	if (ti->len != i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT)
		return 1;
	return 0;
}

static int loki_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct loki_c *lc = ti->private;
    LOG_INFO("[%s] .", lc->uuid);
	return fn(ti, lc->dev, 0, ti->len, data);
}

static struct target_type loki_target = {
	.name   = "loki",
	.version = {0, 0, 1},
	.module = THIS_MODULE,
	.ctr    = loki_ctr,
	.dtr    = loki_dtr,
	.map    = loki_map,
    .end_io = loki_end_io,
	.status = loki_status,
    .message = loki_message,
	.prepare_ioctl = loki_prepare_ioctl,
	.iterate_devices = loki_iterate_devices,
};

static int dm_loki_init(void)
{
    int r;
    LOG_INFO(".");
	r = dm_register_target(&loki_target);

	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

static void dm_loki_exit(void)
{
    LOG_INFO(".");
	dm_unregister_target(&loki_target);
}

module_init(dm_loki_init);
module_exit(dm_loki_exit);
MODULE_LICENSE("GPL");
