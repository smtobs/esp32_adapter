#include <linux/list.h>
#include <linux/slab.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>

#include "bss_info.h"
#include "utils.h"


#define HASH_TABLE_SIZE      32

static struct list_head bss_info_hash[HASH_TABLE_SIZE];

__inline static int mac_addr_hash(u8 *mac_addr)
{
	u32 x;

	x = mac_addr[0];
	x = (x << 2) ^ mac_addr[1];
	x = (x << 2) ^ mac_addr[2];
	x = (x << 2) ^ mac_addr[3];
	x = (x << 2) ^ mac_addr[4];
	x = (x << 2) ^ mac_addr[5];

	x ^= x >> 8;
	x  = x & (HASH_TABLE_SIZE - 1);

	return x;
}

void bss_info_entry_init(void)
{
    int i;
    for (i = 0; i < HASH_TABLE_SIZE; i++)
    {
        INIT_LIST_HEAD(&bss_info_hash[i]);
    }
}

struct bss_info_entry *get_bss_info(u8 *bssid)
{
    u32 index = mac_addr_hash(bssid);
    struct bss_info_entry *entry;

    if (!is_valid_ether_addr(bssid))
    {
        ERROR_PRINT("Invalid bssid : [%s]\n", bssid);
        return NULL;
    }

    list_for_each_entry(entry, &bss_info_hash[index], list)
    {
        if (memcmp(entry->bss_info->bssid, bssid, BSSID_LEN) == 0)
        {
            return entry;
        }
    }

    INFO_PRINT("Not found bssid\n");
    return NULL;
}

int bss_info_insert(struct bss_info *new_bss)
{
    u32 index;
    struct bss_info_entry *entry;
    struct bss_info *bss;

    TRACE_FUNC_ENTRY();

    if (!new_bss || new_bss->mgmt_len <= 0)
    {
        return -1;
    }

    if (!new_bss->bssid || !is_valid_ether_addr(new_bss->bssid))
    {
        ERROR_PRINT("invalid bssid [%s]\n", new_bss->bssid);
        return -1;
    }

    index = mac_addr_hash(new_bss->bssid);
    entry = get_bss_info(new_bss->bssid);

    if (!entry)
    {
        entry = kmalloc(sizeof(struct bss_info_entry), GFP_KERNEL);
        if (!entry)
        {
            return -ENOMEM;
        }
        list_add(&entry->list, &bss_info_hash[index]);
    }
    else if (entry->bss_info)
    {
        SAFE_FREE(entry->bss_info->mgmt_frame);
        SAFE_FREE(entry->bss_info);
    }

    entry->bss_info = kmalloc(sizeof(struct bss_info), GFP_KERNEL);
    if (!entry->bss_info)
    {
        SAFE_FREE(entry);
        return -ENOMEM;
    }

    entry->bss_info->mgmt_frame = kmalloc(new_bss->mgmt_len, GFP_KERNEL);
    if (!entry->bss_info->mgmt_frame)
    {
        SAFE_FREE(entry->bss_info);
        SAFE_FREE(entry);
        return -ENOMEM;
    }

    /* update bss info */
    bss = entry->bss_info;
    memcpy(bss->mgmt_frame, new_bss->mgmt_frame, new_bss->mgmt_len);
    memcpy(bss->bssid, new_bss->bssid, BSSID_LEN);
    bss->mgmt_len = new_bss->mgmt_len;
    bss->sub_type = new_bss->sub_type;
    bss->channel = new_bss->channel;

    TRACE_FUNC_EXIT();

    return 0;
}

void bss_info_entry_delete(void)
{
    struct bss_info_entry *pos, *q;
    int i;

    for (i = 0; i < HASH_TABLE_SIZE; i++)
    {
        if (list_empty(&bss_info_hash[i]))
        {
            continue;
        }

        list_for_each_entry_safe(pos, q, &bss_info_hash[i], list)
        {
            if (pos->bss_info)
            {
                if (pos->bss_info->mgmt_frame)
                {
                    SAFE_FREE(pos->bss_info->mgmt_frame);
                }
                SAFE_FREE(pos->bss_info);
            }
            list_del(&pos->list);
            SAFE_FREE(pos);
        }
    }
}
