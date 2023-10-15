#ifndef _CFG80211_VENDOR_CMD_H
#define _CFG80211_VENDOR_CMD_H

struct wiphy;

int vendor_cmd_attach(struct wiphy *);
int vendor_cmd_detach(struct wiphy *);

#endif