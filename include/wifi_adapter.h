#ifndef _WIFI_ADAPTER_H
#define _WIFI_ADAPTER_H

struct net_device;
struct wiphy;
struct wireless_dev;

typedef struct scan_bssid
{
    u8 bssid[6];
    struct list_head list;
} scan_bssid;

typedef struct wireless_adapter
{
    struct net_device *net_dev;
    struct wiphy *wiphy;
    struct wireless_dev *wdev;
    u8 mac_addr[6];
    spinlock_t scan_lock;
    int scan_status;
    scan_bssid scan_bssid_list;
} wireless_adapter;

extern struct wireless_adapter wifi_adapter;

#endif

