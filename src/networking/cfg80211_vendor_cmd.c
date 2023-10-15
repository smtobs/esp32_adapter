#include <net/rtnetlink.h>
#include <net/cfg80211.h>

#include "cfg80211_vendor_cmd.h"
#include "common.h"
#include "ieee80211_mlme.h"

/* OUI */
#define OUI_BSOH                 0x001A12

/* SUB CMD */
enum VENDOR_SUB_CMD
{
    BSOH_VENDOR_SCMD_DEAUTH = 0x1018,
    BSOH_VENDOR_SCMD_BEACON,
    BSOH_VENDOR_SCMD_TEST_MODE,
};


/* Policy */
enum deauth_policy2
{
    DEAUTH_ATTR_DATA2 = 6,
    DEAUTH_ATTR_MAX2,
};

static const struct nla_policy vendor_cmd_deauth_policy2[DEAUTH_ATTR_MAX2 + 1] =
{
    [0] = { .len = ETH_ALEN },
    [1] = { .len = ETH_ALEN },
    [2] = { .len = ETH_ALEN },
    [3] = { .len = ETH_ALEN },
    [4] = { .len = ETH_ALEN },
    [5] = { .len = ETH_ALEN }
};


enum deauth_policy
{
    DEAUTH_ATTR_SA = 0,
    DEAUTH_ATTR_DA,
    DEAUTH_ATTR_MAX,
};

static const struct nla_policy vendor_cmd_deauth_policy[] =
{
    // [DEAUTH_ATTR_SA] = { .type = NLA_UNSPEC, .len = ETH_ALEN },
    // [DEAUTH_ATTR_DA] = { .type = NLA_UNSPEC, .len = ETH_ALEN },
    [DEAUTH_ATTR_SA] = { .type = NLA_UNSPEC, .len = ETH_ALEN },
    [DEAUTH_ATTR_DA] = { .type = NLA_UNSPEC, .len = ETH_ALEN },
};

static int vendor_cmd_test_mode(struct wiphy *wiphy, struct wireless_dev *wdev, const void  *data, int len)
{

    static u8 sa[] = {0x80, 0xCA, 0x4B, 0x85, 0x1E, 0xE6}; //AP
    static u8 da[] = {0xf0, 0x9e, 0x4a, 0x5b, 0xda, 0x01}; // da

    TRACE_FUNC_ENTRY();
    if (!wiphy || !wdev || !data || len < 0) 
    {
        ERROR_PRINT("Invalid parameters\n");
        return -EINVAL;
    }

    deauth_send(sa, da);

    TRACE_FUNC_EXIT();

    return 0;
}

static int vendor_cmd_deauth_send(struct wiphy *wiphy, struct wireless_dev *wdev, const void  *data, int len)
{
    int i;
    u8 *sa, *da;
    struct nlattr *tb[DEAUTH_ATTR_MAX];

    if (!wiphy || !wdev || !data) 
    {
        ERROR_PRINT("Invalid parameters\n");
        return -EINVAL;
    }

    if (len < (2 * ETH_ALEN))
    {
        ERROR_PRINT("Invalid parameters\n");
        return -EINVAL;
    }
    else
    {
        INFO_PRINT("len = [%d]\n", len);
    }

    nla_parse(tb, DEAUTH_ATTR_MAX, nlmsg_attrdata(data, 0), nlmsg_attrlen(data, 0), vendor_cmd_deauth_policy, NULL);
    if (tb[DEAUTH_ATTR_SA] && tb[DEAUTH_ATTR_DA])
    {
        sa = nla_data(tb[DEAUTH_ATTR_SA]);
        da = nla_data(tb[DEAUTH_ATTR_DA]);
        
        if (!sa || !da) 
        {
            ERROR_PRINT("NULL sa or da data retrieved\n");
            return -EINVAL;
        }
        
        INFO_PRINT("sa = ");
        for (i = 0; i < ETH_ALEN; i++)
        {
            INFO_PRINT("%u ", sa[i]);
        }

        INFO_PRINT("\t\tda = ");
        for (i = 0; i < ETH_ALEN; i++)
        {
            INFO_PRINT("%u ", da[i]);
        }
        INFO_PRINT("\n");

        deauth_send(sa, da);

        return 0;
    }
    else
    {
        ERROR_PRINT("nla parse fail\n");
        return -EINVAL;
    }
}

static const struct wiphy_vendor_command vendor_cmds[] =
{
    {
        {
            .vendor_id = OUI_BSOH,
            .subcmd = BSOH_VENDOR_SCMD_DEAUTH
        },
        .flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
        .doit = vendor_cmd_deauth_send,
#if (0)
         //.policy = vendor_cmd_deauth_policy2,
         //.maxattr = ARRAY_SIZE(vendor_cmd_deauth_policy2),
#else
         .policy = vendor_cmd_deauth_policy2, //VENDOR_CMD_RAW_DATA,
         .maxattr = 6,
#endif
    },
    {
        {
            .vendor_id = OUI_BSOH,
            .subcmd = BSOH_VENDOR_SCMD_TEST_MODE
        },
        .flags = WIPHY_VENDOR_CMD_NEED_WDEV | WIPHY_VENDOR_CMD_NEED_NETDEV,
        .doit = vendor_cmd_test_mode,
        .policy = VENDOR_CMD_RAW_DATA,
        .maxattr = 1,
    }
};

static const struct  nl80211_vendor_cmd_info vendor_events[] =
{
};

int vendor_cmd_attach(struct wiphy *wiphy)
{
    TRACE_FUNC_ENTRY();

    wiphy->vendor_commands	= vendor_cmds;
    wiphy->n_vendor_commands = ARRAY_SIZE(vendor_cmds);

    INFO_PRINT("wiphy->n_vendor_commands %d", wiphy->n_vendor_commands);

    // wiphy->vendor_events	= vendor_events;
    // wiphy->n_vendor_events	= ARRAY_SIZE(vendor_events);

    TRACE_FUNC_EXIT();
	
    return 0;
}

int vendor_cmd_detach(struct wiphy *wiphy)
{
	TRACE_FUNC_ENTRY();

	wiphy->vendor_commands  = NULL;
	wiphy->n_vendor_commands = 0;

    // wiphy->vendor_events    = NULL;
	// wiphy->n_vendor_events  = 0;

    TRACE_FUNC_EXIT();

	return 0;
}
