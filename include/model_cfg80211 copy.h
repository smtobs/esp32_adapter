#ifndef _MODEL_CFG80211_H
#define _MODEL_CFG80211_H

#include "config.h"

#ifdef MODEL_NAME_ESP32
 #include "esp32_cfg80211.h"

 #define CFG80211_INIT(x)    esp32_cfg80211_init(x)
 #define CFG80211_DEINIT(x)  esp32_cfg80211_deinit(x)

#else
// Todo
#endif

#endif /* _MODEL_CFG80211_H */

