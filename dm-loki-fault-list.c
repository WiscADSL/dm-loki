#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#include "dm-loki-common.h"
#include "dm-loki.h"
#include "twobitseq.h"

struct loki_fault_item_t* loki_fault_item_create(struct loki_c *lc, 
        sector_t start, sector_t end, twobitseq_t *tbs) 
{
    struct loki_fault_item_t *fault_item = NULL;

    fault_item = (struct loki_fault_item_t *) kmalloc (sizeof(*fault_item), GFP_KERNEL);
    if (fault_item == NULL) {
        LOG_EROR("[%s] Failed to allocate fault item", lc->uuid);
        return NULL;
    }

    fault_item->start = start;
    fault_item->end = end;
    fault_item->tbs = tbs;
    return fault_item;
}

void loki_fault_item_free(struct loki_fault_item_t *fault_item) 
{
    if (fault_item->tbs != NULL) {
        twobitseq_free(fault_item->tbs);
    }
    kfree(fault_item);
}

void loki_fault_item_dump(struct loki_fault_item_t *fault_item)
{
    char buf[100];
    size_t buflen = 99;
    int i = 0;

    for(i=0; i < buflen; i++) {
        buf[i] = '\0';
    }

    buflen = (fault_item->tbs->len < buflen) ? fault_item->tbs->len : buflen;
    twobitseq_dumpstr(fault_item->tbs, buf, buflen);
    LOG_INFO(FAULT_LIST_ITEM_REPR_FMT, FAULT_LIST_ITEM_REPR_ARGS(fault_item, buf));
}

void loki_fault_list_init(struct loki_c *lc) 
{
    mutex_init(&lc->fault_list_mutex);
    INIT_LIST_HEAD(&lc->fault_list);
}

void loki_fault_list_free(struct loki_c *lc) 
{
    int i = 0;
    struct loki_fault_item_t *fault_item = NULL;
    struct loki_fault_item_t *n = NULL;

    mutex_lock(&lc->fault_list_mutex);

    list_for_each_entry_safe(fault_item, n, &lc->fault_list, mylist) {
        loki_fault_item_free(fault_item);
        i += 1;
    }

    mutex_unlock(&lc->fault_list_mutex);

    LOG_INFO("[%s] Freed %d fault items", lc->uuid, i);
}

void loki_fault_list_add_fault_item(struct loki_c *lc, 
        struct loki_fault_item_t *fault_item) 
{
    mutex_lock(&lc->fault_list_mutex);
    list_add(&fault_item->mylist, &lc->fault_list);
    mutex_unlock(&lc->fault_list_mutex);
}

void loki_fault_list_del_fault_item(struct loki_c *lc, 
        struct loki_fault_item_t *fault_item) 
{
    mutex_lock(&lc->fault_list_mutex);
    list_del(&fault_item->mylist);
    mutex_unlock(&lc->fault_list_mutex);

    loki_fault_item_free(fault_item);
}

struct loki_fault_item_t* loki_fault_list_find(struct loki_c *lc, 
        sector_t start, sector_t end)
{
    struct loki_fault_item_t *entry = NULL;
    struct loki_fault_item_t *closest = NULL;
    sector_t estart, eend;

    // TODO maybe make sure this is always sorted or use a tree to speed up the search?
    // NOTE There is a chance of an item being returned which might be freed concurrently
    // but things are deleted only dmsetup messages which should happen when there are 
    // no requests to such faulty blocks.
    list_for_each_entry(entry, &lc->fault_list, mylist) {
        estart = entry->start;
        eend = entry->end;

        if ((estart > end) || (eend < start)) {
            continue;
        }

        // we have an overlap
        if (closest == NULL) {
            closest = entry;
            continue;
        }

        if (estart < closest->start) {
            closest = entry;
        }
    }

    return closest;
}

void loki_fault_list_dump(struct loki_c *lc) 
{
    struct loki_fault_item_t *fault_item;
    mutex_lock(&lc->fault_list_mutex);

    LOG_INFO("[%s] Dumping fault_list start", lc->uuid);
    list_for_each_entry(fault_item, &lc->fault_list, mylist) {
        loki_fault_item_dump(fault_item);
    }
    LOG_INFO("[%s] Dumping fault_list end", lc->uuid);

    mutex_unlock(&lc->fault_list_mutex);
}
