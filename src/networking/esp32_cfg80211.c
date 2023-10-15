#include <linux/ieee80211.h>
#include <net/cfg80211.h>
#include <net/mac80211.h>
#include <linux/delay.h>

#include "common.h"
#include "event.h"
#include "priv.h"
#include "wifi_adapter.h"
#include "bss_info.h"
#include "esp32_cfg80211.h"
#include "cfg80211_vendor_cmd.h"


#define RATETAB_ENT(_rate, _rateid, _flags) \
{                                       \
    .bitrate    = (_rate),              \
    .hw_value   = (_rateid),            \
    .flags      = (_flags),             \
}

#define CHAN2G(_channel, _freq, _flags)     \
{                                           \
    .band           = NL80211_BAND_2GHZ,    \
    .center_freq    = (_freq),              \
    .hw_value       = (_channel),           \
    .flags          = (_flags),             \
    .max_antenna_gain   = 0,                \
    .max_power          = 30,               \
}

#define CHAN5G(_channel, _flags)                    \
{                                                   \
    .band           = NL80211_BAND_5GHZ,            \
    .center_freq    = 5000 + (5 * (_channel)),      \
    .hw_value       = (_channel),                   \
    .flags          = (_flags),                     \
    .max_antenna_gain = 0,                          \
    .max_power        = 30,                         \
}


static struct wiphy *g_wiphy;

static const u32 esp32_cipher_suites[] =
{
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_CCMP,
};

static int esp32_cfg80211_change_iface(struct wiphy *wiphy, struct net_device *net_dev, enum nl80211_iftype type, struct vif_params *params)
{
	switch (type)
    {
        case NL80211_IFTYPE_STATION:
		DEBUG_PRINT("station !!!\n");
            break;

        case NL80211_IFTYPE_AP:
		DEBUG_PRINT("ap !!!\n");
            break;

        default:
		DEBUG_PRINT("change iface failed !!!\n");
            return -EOPNOTSUPP;
	}

    return 0;
}

static int esp32_cfg80211_add_key(struct wiphy *wiphy, struct net_device *net_dev, u8 key_index,
                                    bool pairwise, const u8 *mac_addr, struct key_params *params)
{
    return 0;
}

static int esp32_cfg80211_get_key(struct wiphy *wiphy, struct net_device *net_dev, u8 key_index,
                                 bool pairwise, const u8 *mac_addr, void *cookie,
                                 void (*callback)(void *cookie, struct key_params *))
{
	return 0;
}

static int esp32_cfg80211_del_key(struct wiphy *wiphy, struct net_device *net_dev, u8 key_index, bool pairwise, const u8 *mac_addr)
{
	return 0;
}

static int esp32_cfg80211_set_default_key(struct wiphy *wiphy, struct net_device *net_dev, u8 key_index, bool unicast, bool multicast)
{
    return 0;
}

static int esp32_cfg80211_get_station(struct wiphy *wiphy, struct net_device *net_dev, const u8 *mac, struct station_info *sinfo)
{
    return 0;
}

struct ieee80211_channel *ch_num_ieee80211_channel(struct wiphy *wiphy, u8 channel_num)
{
    int band, i;

    for (band = 0; band < NUM_NL80211_BANDS; band++)
    {
        struct ieee80211_supported_band *sband = wiphy->bands[band];
        if (!sband)
            continue;

        for (i = 0; i < sband->n_channels; i++)
        {
            if (sband->channels[i].hw_value == channel_num)
                return &sband->channels[i];
        }
    }

    return NULL;
}

__inline static int inform_scan_result(struct wiphy *wiphy)
{
    struct ieee80211_channel *ch;
    struct bss_info_entry *bss_entry;
    struct event_msg evt_msg = {0};
    struct cfg80211_bss *bss;
    u8 bssid[ETH_ALEN] = {0};
    s32 notify_signal;
    int err = 1;

    if (priv_scan_status_get() != EVENT_SCAN_READY_CMD)
    {   
        ERROR_PRINT("can_status != EVENT_SCAN_READY_CMD\n");
        return -1;
    }

    /* scan start */
    evt_msg.cmd = EVENT_SCAN_START_CMD;
    if (wait_for_scan_event(evt_msg, 2000))
    {
        while (priv_scan_bssid_get(bssid))
        {
            /* get bss_entry : key - bssid */
            bss_entry = scan_bss_info_get(bssid);
            if (bss_entry != NULL)
            {
                notify_signal = -4600;
                /* get iee80211 channel */
                ch = ch_num_ieee80211_channel(wiphy, bss_entry->bss_info->channel);
                if (ch == NULL)
                {
                    ERROR_PRINT("ch == NULL\n");
                    goto exit;
                }
                
                /* inform bss frame */
                bss = cfg80211_inform_bss_frame(wiphy, ch, (struct ieee80211_mgmt *)bss_entry->bss_info->mgmt_frame,
                                                        bss_entry->bss_info->mgmt_len, notify_signal, GFP_ATOMIC);
                if (unlikely(!bss))
                {
                    ERROR_PRINT("bss null !\n");
                    goto exit;
                }
                cfg80211_put_bss(wiphy, bss);
                err = 0;
            }
        }
    }
    else
    {
        //DEBUG_PRINT("scan time out\n");
    }
exit:
    return err;
}

static int esp32_cfg80211_scan(struct wiphy *wiphy, struct cfg80211_scan_request *request)
{
    struct cfg80211_scan_info scan_info = {0};
    int ret;

    TRACE_FUNC_ENTRY();

    ret = inform_scan_result(wiphy);
    if (ret == 0)
    {
        scan_info.aborted = 0;
    }
    else
    {
        scan_info.aborted = 1;
    }
    cfg80211_scan_done(request, &scan_info);

    priv_scan_status_set(EVENT_SCAN_READY_CMD);
    
    TRACE_FUNC_EXIT();

    return 0;
}

static int esp32_cfg80211_set_wiphy_params(struct wiphy *wiphy, u32 changed)
{
	return 0;
}

static int esp32_cfg80211_connect(struct wiphy *wiphy, struct net_device *net_dev, struct cfg80211_connect_params *sme)
{
    return 0;
}

static int esp32_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *net_dev, u16 reason_code)
{
    return 0;
}

static int esp32_cfg80211_join_ibss(struct wiphy *wiphy, struct net_device *net_dev, struct cfg80211_ibss_params *params)
{
    return 0;
}

static int esp32_cfg80211_leave_ibss(struct wiphy *wiphy, struct net_device *net_dev)
{
    return 0;
}

static int esp32_cfg80211_set_txpower(struct wiphy *wiphy, struct wireless_dev *wdev, enum nl80211_tx_power_setting type, int mbm)
{
	DEBUG_PRINT("set tx power\n");
    return 0;
}

static int esp32_cfg80211_get_txpower(struct wiphy *wiphy, struct wireless_dev *wdev, int *dbm)
{
    *dbm = 20;

    return 0;
}

static int esp32_cfg80211_set_power_mgmt(struct wiphy *wiphy, struct net_device *net_dev, bool enabled, int timeout)
{
    return 0;
}

static int esp32_cfg80211_set_pmksa(struct wiphy *wiphy, struct net_device *net_dev, struct cfg80211_pmksa *pmksa)
{
    return 0;
}

static int esp32_cfg80211_del_pmksa(struct wiphy *wiphy, struct net_device *net_dev, struct cfg80211_pmksa *pmksa)
{
    return 0;
}

static int esp32_cfg80211_flush_pmksa(struct wiphy *wiphy, struct net_device *net_dev)
{
    return 0;
}

static struct cfg80211_ops esp32_cfg80211_ops =
{
    .change_virtual_intf = esp32_cfg80211_change_iface,
    .add_key = esp32_cfg80211_add_key,
    .get_key = esp32_cfg80211_get_key,
    .del_key = esp32_cfg80211_del_key,
    .set_default_key = esp32_cfg80211_set_default_key,
    .get_station = esp32_cfg80211_get_station,
    .scan = esp32_cfg80211_scan,
    .set_wiphy_params = esp32_cfg80211_set_wiphy_params,
    .connect = esp32_cfg80211_connect,
    .disconnect = esp32_cfg80211_disconnect,
    .join_ibss = esp32_cfg80211_join_ibss,
    .leave_ibss = esp32_cfg80211_leave_ibss,
    .set_tx_power = esp32_cfg80211_set_txpower,
    .get_tx_power = esp32_cfg80211_get_txpower,
    .set_power_mgmt = esp32_cfg80211_set_power_mgmt,
    .set_pmksa = esp32_cfg80211_set_pmksa,
    .del_pmksa = esp32_cfg80211_del_pmksa,
    .flush_pmksa = esp32_cfg80211_flush_pmksa,
};

static struct ieee80211_channel esp32_2ghz_channels[] =
{
    CHAN2G(1, 2412, 0),
    CHAN2G(2, 2417, 0),
    CHAN2G(3, 2422, 0),
    CHAN2G(4, 2427, 0),
    CHAN2G(5, 2432, 0),
    CHAN2G(6, 2437, 0),
    CHAN2G(7, 2442, 0),
    CHAN2G(8, 2447, 0),
    CHAN2G(9, 2452, 0),
    CHAN2G(10, 2457, 0),
    CHAN2G(11, 2462, 0),
    CHAN2G(12, 2467, 0),
    CHAN2G(13, 2472, 0),
    CHAN2G(14, 2484, 0),
};

static struct ieee80211_channel esp32_5ghz_channels[] =
{
	CHAN5G(36, 0),	CHAN5G(40, 0),	CHAN5G(44, 0),	CHAN5G(48, 0),

	CHAN5G(52, 0),	CHAN5G(56, 0),	CHAN5G(60, 0),	CHAN5G(64, 0),

	CHAN5G(100, 0),	CHAN5G(104, 0),	CHAN5G(108, 0),	CHAN5G(112, 0),
	CHAN5G(116, 0),	CHAN5G(120, 0),	CHAN5G(124, 0),	CHAN5G(128, 0),
	CHAN5G(132, 0),	CHAN5G(136, 0),	CHAN5G(140, 0),	CHAN5G(144, 0),

	CHAN5G(149, 0),	CHAN5G(153, 0),	CHAN5G(157, 0),	CHAN5G(161, 0),
	CHAN5G(165, 0),	CHAN5G(169, 0),	CHAN5G(173, 0),	CHAN5G(177, 0),
};

static struct ieee80211_rate esp32_rates[] =
{
    RATETAB_ENT(10,  0x1,   0),
    RATETAB_ENT(20,  0x2,   0),
    RATETAB_ENT(55,  0x4,   0),
    RATETAB_ENT(110, 0x8,   0),
    RATETAB_ENT(60,  0x10,  0),
    RATETAB_ENT(90,  0x20,  0),
    RATETAB_ENT(120, 0x40,  0),
    RATETAB_ENT(180, 0x80,  0),
    RATETAB_ENT(240, 0x100, 0),
    RATETAB_ENT(360, 0x200, 0),
    RATETAB_ENT(480, 0x400, 0),
    RATETAB_ENT(540, 0x800, 0),
};

static struct ieee80211_supported_band esp32_band_2ghz =
{
	.band = NL80211_BAND_2GHZ,
    .channels = esp32_2ghz_channels,
    .n_channels = ARRAY_SIZE(esp32_2ghz_channels),
    .bitrates = esp32_rates,
    .n_bitrates = ARRAY_SIZE(esp32_rates),
};

static struct ieee80211_supported_band esp32_band_5ghz =
{
    .band = NL80211_BAND_5GHZ,
    .channels = esp32_5ghz_channels,
    .n_channels = ARRAY_SIZE(esp32_5ghz_channels),
    .bitrates = esp32_rates,
    .n_bitrates = ARRAY_SIZE(esp32_rates),
};

//static struct wiphy *wiphy;

void esp32_cfg80211_setup(struct wiphy *p_wiphy)
{
    p_wiphy->max_scan_ssids = 9;
    p_wiphy->max_scan_ie_len = 2304;
    p_wiphy->max_num_pmkids = 4;

    /* signal */
    p_wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;

    /* interface mode */
    p_wiphy->interface_modes = BIT(NL80211_IFTYPE_STATION) | BIT(NL80211_IFTYPE_AP);

    /* bands */
    p_wiphy->bands[NL80211_BAND_2GHZ] = &esp32_band_2ghz;
    p_wiphy->bands[NL80211_BAND_5GHZ] = &esp32_band_5ghz;

    /* cipher suites */
    p_wiphy->cipher_suites = esp32_cipher_suites;
    p_wiphy->n_cipher_suites = ARRAY_SIZE(esp32_cipher_suites);

    p_wiphy->flags |= WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL;
    p_wiphy->flags |= WIPHY_FLAG_HAVE_AP_SME;

}

struct wiphy *esp32_cfg80211_init(struct wireless_adapter *adapter)
{
    struct wiphy *wiphy;
    int ret;

    TRACE_FUNC_ENTRY();

    wiphy = wiphy_new(&esp32_cfg80211_ops, sizeof(private_data));
    if (!wiphy)
    {
        ERROR_PRINT("wiphy new error\n");
        return NULL;
    }

    priv_data_register(wiphy, adapter);

    /* register for vendor command */
    vendor_cmd_attach(wiphy);

    /* cfg80211 setup */
    esp32_cfg80211_setup(wiphy);

    /* register for wiphy */
    ret = wiphy_register(wiphy);
    if (ret < 0)
    {
        ERROR_PRINT("wiphy_error [%d]\n", ret);
        goto error_wiphy_free;
    }

    g_wiphy = wiphy;
    return wiphy;

error_wiphy_free:
    wiphy_free(wiphy);

    TRACE_FUNC_EXIT();

    return NULL;
}

void esp32_cfg80211_deinit(struct wiphy *wiphy)
{
    TRACE_FUNC_ENTRY();

    if (wiphy)
    {
        vendor_cmd_detach(wiphy);
        wiphy_unregister(wiphy);
        wiphy_free(wiphy);
        wiphy = NULL;
    }
    priv_data_unregister();

    TRACE_FUNC_EXIT();
}

