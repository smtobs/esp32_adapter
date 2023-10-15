#include <net/cfg80211.h>

#include "wifi_adapter.h"
#include "common.h"
#include "priv.h"

static struct wiphy *g_wiphy;

void priv_data_register(struct wiphy *wiphy, struct wireless_adapter *adapter)
{
    struct private_data *private_data;

	private_data = wiphy_priv(wiphy);
	private_data->adapter = adapter;

    g_wiphy = wiphy;
}

u8 *priv_mac_addr_get(void)
{
    struct private_data *private_data;

    if (g_wiphy)
    {
        private_data = wiphy_priv(g_wiphy);
        return private_data->adapter->mac_addr;
    }
    return NULL;
}

void priv_scan_status_set(int status)
{
    struct private_data *private_data;
    struct wireless_adapter *adapter;

    if (g_wiphy)
    {
        private_data = wiphy_priv(g_wiphy);
        adapter = private_data->adapter;

        spin_lock(&adapter->scan_lock);
        adapter->scan_status = status;
        spin_unlock(&adapter->scan_lock);
    }
}

int priv_scan_status_get(void)
{
    struct private_data *private_data;
    int scan_status = 0;

    if (g_wiphy)
    {
        private_data = wiphy_priv(g_wiphy);

        spin_lock(&private_data->adapter->scan_lock);
        scan_status = private_data->adapter->scan_status;
        spin_unlock(&private_data->adapter->scan_lock);

        return scan_status;
    }
    return scan_status;
}

void priv_scan_bssid_set(u8 *bssid)
{
    struct private_data *private_data;
    struct scan_bssid *new_entry, *scan_bssid_list;

    if (g_wiphy)
    {
        private_data = wiphy_priv(g_wiphy);

        scan_bssid_list = &private_data->adapter->scan_bssid_list;
        if (scan_bssid_list == NULL)
        {
            ERROR_PRINT("scan_bssid_list == NULL\n");
            return;
        }

        new_entry = kmalloc(sizeof(struct scan_bssid), GFP_KERNEL);
        if (!new_entry)
        {
            ERROR_PRINT("Failed to allocate memory for new BSSID entry\n");
            return;
        }

        memcpy(new_entry->bssid, bssid, ETH_ALEN);
    
        spin_lock(&private_data->adapter->scan_lock);
        list_add_tail(&new_entry->list, &scan_bssid_list->list);
        spin_unlock(&private_data->adapter->scan_lock);
    }
}

int priv_scan_bssid_get(u8 *bssid)
{
    int ret = 0;
    struct private_data *private_data;
    struct scan_bssid *entry, *scan_bssid_list;

    if (g_wiphy)
    {
        private_data = wiphy_priv(g_wiphy);

        scan_bssid_list = &private_data->adapter->scan_bssid_list;
        if (scan_bssid_list == NULL)
        {
            ERROR_PRINT("scan_bssid_list == NULL\n");
            return 0;
        }

        spin_lock(&private_data->adapter->scan_lock);

        if (!list_empty(&scan_bssid_list->list))
        {
            entry = list_first_entry(&scan_bssid_list->list, struct scan_bssid, list);
            memcpy(bssid, entry->bssid, ETH_ALEN);
            list_del(&entry->list);
            kfree(entry);
            ret = 1;
        }

        spin_unlock(&private_data->adapter->scan_lock);
    }

    return ret;
}

void priv_scan_bssid_list_delete(void)
{
    struct private_data *private_data;
    struct scan_bssid *entry, *tmp, *scan_bssid_list;

    TRACE_FUNC_ENTRY();

    if (g_wiphy)
    {
        private_data = wiphy_priv(g_wiphy);

        scan_bssid_list = &private_data->adapter->scan_bssid_list;
        if (scan_bssid_list == NULL)
        {
            ERROR_PRINT("scan_bssid_list == NULL\n");
            return;
        }

        spin_lock(&private_data->adapter->scan_lock);

        list_for_each_entry_safe(entry, tmp, &scan_bssid_list->list, list)
        {
            list_del(&entry->list);
            kfree(entry);
        }

        spin_unlock(&private_data->adapter->scan_lock);
    }
    
    TRACE_FUNC_EXIT();
}

struct net_device *priv_netdev_get(void)
{
    struct private_data *private_data;
    struct net_device * netdev = NULL;

    if (!g_wiphy)
    {
        return NULL;
    }
        
    private_data = wiphy_priv(g_wiphy);
    if (!private_data || !private_data->adapter || !private_data->adapter->net_dev)
    {
        return NULL;
    }
    
    netdev = private_data->adapter->net_dev;

    return netdev;
}

void priv_data_unregister(void)
{
    TRACE_FUNC_ENTRY();
    
    g_wiphy = NULL;

    TRACE_FUNC_EXIT();
}
