#ifndef _IEEE80211_MAC_LAYER_H
#define _IEEE80211_MAC_LAYER_H

#define MAX_SSID_LEN     32

typedef struct ieee80211_mgmt_frame
{
    uint len;
    struct ieee80211_mgmt *frame;
} ieee80211_mgmt_frame;

typedef u8 TBD;

int probe_req_send(u8 *sa_mac_addr, u8 *da_mac_addr, u8* bssid);
void recv_frame_handler(TBD *frame, int frame_len);

#endif