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

void scan_bss_info_entry_init(void);
struct bss_info_entry *scan_bss_info_get(u8 *);
int scan_bss_info_insert(struct bss_info *);
void scan_bss_info_entry_delete(void);

#endif
