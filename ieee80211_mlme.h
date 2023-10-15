#ifndef _IEEE80211_MAC_LAYER_H
#define _IEEE80211_MAC_LAYER_H

#define MAX_SSID_LEN     32

struct sk_buff;

typedef struct ieee80211_mgmt_frame
{
    uint len;
    struct ieee80211_mgmt *frame;
} ieee80211_mgmt_frame;

struct llc_snap_header
{
    u8 dsap;
    u8 ssap;
    u8 control;
    u8 oui[3];
    u16 ethertype;
}__attribute__((packed));

int probe_req_send(u8 *, u8 *, u8*);
void deauth_send(u8 *, u8 *);
int data_frame_send(u8 *, int);
void recv_frame_handler(struct sk_buff *);

#endif