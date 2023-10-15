#ifndef _PRIV_H
#define _PRIV_H

struct wireless_adapter;
struct wiphy;
struct net_device;

typedef struct private_data
{
   struct wireless_adapter *adapter;
} private_data;

void priv_data_register(struct wiphy *, struct wireless_adapter *);
u8 *priv_mac_addr_get(void);
void priv_scan_status_set(int);
int priv_scan_status_get(void);
void priv_scan_bssid_set(u8 *);
int priv_scan_bssid_get(u8 *);
void priv_scan_bssid_list_delete(void);
void priv_data_unregister(void);
struct net_device *priv_netdev_get(void);

#endif
