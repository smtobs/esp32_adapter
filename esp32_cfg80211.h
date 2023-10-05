#ifndef _ESP32_CFG80211_H
#define _ESP32_CFG80211_H

struct wiphy;
struct wireless_adapter;

struct wiphy *esp32_cfg80211_init(struct wireless_adapter *);
void esp32_cfg80211_deinit(struct wiphy *);
struct ieee80211_channel *ch_num_ieee80211_channel(struct wiphy *, u8);

#endif
