#include <linux/module.h>
#include <linux/ieee80211.h>
#include <net/cfg80211.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include "network_device.h"
#include "model_cfg80211.h"
#include "esp32_cfg80211.h"
#include "bss_info.h"
#include "event.h"
#include "transceiver.h"
#include "ieee80211_mlme.h"
#include "common.h"
#include "spi_ctrl.h"
#include "ring_buff.h"
#include "wifi_adapter.h"

#define WIFI_NET_DEV_NAME     "esp32_wlan0"

struct wireless_adapter wifi_adapter;

__inline static int wifi_adapter_thread_init(void)
{
    int ret;

    ret = event_handler_init();
    if (ret != 0)
    {
        return ret;
    }

    ret = recv_loop_init();
    if (ret != 0)
    {
        event_handler_deinit();
        return ret;
    }

    return 0;
}

__inline static void wifi_adapter_thread_deinit(void)
{
    recv_loop_deinit();
    event_handler_deinit();
}

static int __init wifi_adapter_init(void)
{
    struct net_device *net_dev;
    struct wireless_dev *wdev;
    struct wiphy *wiphy;
    int ret;

    uint8_t mac_addr[ETH_ALEN] = {0xc8, 0xc9, 0xa3, 0xc9, 0x27, 0x6c};

    TRACE_FUNC_ENTRY();
    
    spin_lock_init(&wifi_adapter.scan_lock);
    INIT_LIST_HEAD(&wifi_adapter.scan_bssid_list.list);

    /* SPI init */
    ret = spi_init("wifi-spi-driver", MAX_SPEED_HZ, SPI_BUS_NUM, 0, SPI_MODE0);
    if (ret != 0)
    {
        return -ENOMEM;
    } 

    memcpy(wifi_adapter.mac_addr, mac_addr, ETH_ALEN);

    /* register for CFG80211 */
    wiphy = CFG80211_INIT(&wifi_adapter);
    if (wiphy == NULL)
    {
        return ret;
    }

    /* net device alloc */
    net_dev = net_dev_alloc(WIFI_NET_DEV_NAME);
    if (net_dev == NULL)
    {
        CFG80211_DEINIT(wiphy);
        return -ENOMEM;
    }

    /* wdev alloc */
    wdev = kzalloc(sizeof(struct wireless_dev), GFP_KERNEL);
    if (!wdev)
    {
        CFG80211_DEINIT(wiphy);
        return -ENOMEM;
    }

    /* wdev setup */
    wdev->wiphy  = wiphy;
    wdev->netdev = net_dev;

    wdev->iftype = NL80211_IFTYPE_STATION;
    net_dev->ieee80211_ptr = wdev;

    /* register for net device */
    ret = net_dev_register(net_dev, wifi_adapter.mac_addr);
    if (ret != 0)
    {
        CFG80211_DEINIT(wiphy);
    }

    wifi_adapter.wdev       = wdev;
    wifi_adapter.net_dev    = net_dev;
    wifi_adapter.wiphy      = wiphy;

    scan_bss_info_entry_init();
    buffer_init();

    if (wifi_adapter_thread_init() != 0)
    {
        net_dev_delete(wifi_adapter.net_dev);
        CFG80211_DEINIT(wifi_adapter.wiphy);
        return -ENOMEM;
    }

    TRACE_FUNC_EXIT();

    return 0;
}

static void __exit wifi_adapter_exit(void)
{
    TRACE_FUNC_ENTRY();

    wifi_adapter_thread_deinit();
    scan_bss_info_entry_delete();

    net_dev_delete(wifi_adapter.net_dev);
    CFG80211_DEINIT(wifi_adapter.wiphy);
    
    spi_deinit();
    buffer_deinit();

    TRACE_FUNC_EXIT();
}

module_init(wifi_adapter_init);
module_exit(wifi_adapter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bsoh");
MODULE_DESCRIPTION("wifi adapter driver");
