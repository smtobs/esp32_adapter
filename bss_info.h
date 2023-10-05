#ifndef _BSS_INFO_H
#define _BSS_INFO_H

#define BSSID_LEN                6
#define BSSID_HASH_TABLE_SIZE    32

typedef struct bss_info
{
    u8 channel;
    u8 sub_type;
    int mgmt_len;
    u8 bssid[BSSID_LEN];
    u8 *mgmt_frame;
} bss_info;

typedef struct bss_info_entry
{
    struct bss_info *bss_info;
    struct list_head list;
} bss_info_entry;

void bss_info_entry_init(void);
struct bss_info_entry *get_bss_info(u8 *);
int bss_info_insert(struct bss_info *);
void bss_info_entry_delete(void);

#endif
