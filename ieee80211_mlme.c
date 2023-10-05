#include <linux/ieee80211.h>

#include "ieee80211_mlme.h"
#include "bss_info.h"
#include "event.h"
#include "utils.h"
#include "priv.h"

//#define GET_FRAME_TYPE(pbuf)        (le16_to_cpu(*(unsigned short *)(pbuf)) & (BIT(3) | BIT(2)))
#define GET_FRAME_TYPE(pbuf)        ((le16_to_cpu(*(unsigned short *)(pbuf)) & (BIT(3) | BIT(2))) >> 2)
#define GET_FRAME_SUB_TYPE(pbuf)    ((le16_to_cpu(*(unsigned short *)(pbuf)) & (BIT(7) | BIT(6) | BIT(5) | BIT(4))) >> 4)
#define GET_FRAME_RETRY(pbuf)       ((le16_to_cpu(*(unsigned short *)(pbuf)) & BIT(11)) >> 11)

#define GET_BSSID(pbuf)	            ((unsigned char *)(pbuf) + 16)
#define IE_OFFSET                   12


static u8 *ie_set(u8 *, int, uint, u8 *, uint *);
static struct ieee80211_mgmt_frame *probe_req_create(u8 *sa_mac_addr, u8 *da_mac_addr, u8* bssid);
static int reserved(TBD *, int frame_len);
static int probe_resp_analyze(TBD *, int frame_len);


typedef struct management_frame_handler
{
	char *str;
	int (*func)(TBD *recv_frame, int frame_len);
} management_frame_handler;

struct management_frame_handler mgmt_handl_tbl[] =
{
	{"assoc_req",     &reserved}, /* Todo */
	{"assoc_resp",    &reserved}, /* Todo */
	{"re_assoc_req",  &reserved}, /* Todo */
	{"re_assoc_resp", &reserved}, /* Todo */
	{"probe_req",     &reserved}, /* Todo */
	{"probe_resp",    &probe_resp_analyze},
	{"reserved",      &reserved},
	{"reserved",      &reserved},
	{"beacon",        &reserved}, /* Todo */
	{"ATIM",          &reserved}, /* Todo */
	{"disassoc",      &reserved}, /* Todo */
	{"auth",          &reserved}, /* Todo */
	{"deauth",        &reserved}, /* Todo */
	{"action",        &reserved}, /* Todo */
	{"action_no_ack", &reserved}, /* Todo */
};

static u8 bc_addr[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static u8 *ie_get(const u8 *ies, int element_id, int *element_len, int limit)
{
	int tmp, i;
	const u8 *p_ies;

	if (limit < 1)
    {
        ERROR_PRINT("limit < 1 \n");
		return NULL;
	}

	p_ies = ies;
	i = 0;
	*element_len = 0;
	while (1)
    {
		if (*p_ies == element_id)
        {
			*element_len = *(p_ies + 1);
			return (u8 *)p_ies;
		}
        else
        {
			tmp = *(p_ies + 1);
			p_ies += (tmp + 2);
			i += (tmp + 2);
		}

		if (i >= limit)
        {
            break;
        }
	}
    
    DEBUG_PRINT("IE id(%d) Not Found\n", element_id);
	return NULL;
}

static u8 *ie_set(u8 *ie, int elem_id, uint elem_len, u8 *elem_value, uint *frame_len)
{
    /* Element ID */
	*ie = (u8)elem_id;

    /* Element length */
	*(ie + 1) = (u8)elem_len;

    /* Element Value */
	if (elem_len > 0)
    {
        memcpy((void *)(ie + 2), (void *)elem_value, elem_len);
    }
		
	*frame_len = *frame_len + (elem_len + 2);

	return ie + elem_len + 2;
}

static struct ieee80211_mgmt_frame *probe_req_create(u8 *sa_mac_addr, u8 *da_mac_addr, u8* bssid)
{
    struct ieee80211_mgmt_frame *mgmt = NULL;
    struct ieee80211_mgmt *frame = NULL;
    u8 support_rate[] = {0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    u8 *ie;

    TRACE_FUNC_ENTRY();

    mgmt = kzalloc(sizeof(ieee80211_mgmt_frame), GFP_KERNEL);
    if (!mgmt)
    {
        ERROR_PRINT("Failed to allocate mgmt\n");
        goto exit;
    }

    frame = kzalloc(sizeof(struct ieee80211_mgmt) + 1000, GFP_KERNEL);
    if (!frame)
    {
        ERROR_PRINT("mgmt == NULL\n");
        goto exit;
    }

    if (!is_valid_ether_addr(sa_mac_addr))
    {
        ERROR_PRINT("Invalid sa_mac_addr %s\n", sa_mac_addr);
        goto exit;
    }

    memset(frame, 0x0, sizeof(struct ieee80211_mgmt) + 1000);

    /* MAC Header begin */
    mgmt->len = sizeof(struct ieee80211_hdr_3addr);

    /* Frame Control */
    frame->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_REQ);
    /* MAC Address */
    ether_addr_copy(frame->sa, sa_mac_addr);

    if (da_mac_addr == NULL)
    {
        ether_addr_copy(frame->da, bc_addr);
        ether_addr_copy(frame->bssid, bc_addr);
    }
    else
    {
        if (!is_valid_ether_addr(da_mac_addr))
        {
            ERROR_PRINT("Invalid da_mac_addr %s\n", da_mac_addr);
            goto exit;
        }
        else
        {
            ether_addr_copy(frame->da, da_mac_addr);
            ether_addr_copy(frame->bssid, da_mac_addr);
        }
    }

    /* Frame Body */
    ie = frame->u.probe_req.variable;

    /* SSID */
    ie_set(ie, WLAN_EID_SSID, 0, NULL, &(mgmt->len));

    /* support_rate */
    ie_set(ie, WLAN_EID_SUPP_RATES, sizeof(support_rate), support_rate, &(mgmt->len));

    mgmt->frame = frame;

    TRACE_FUNC_EXIT();

    return mgmt;

exit:
    if (frame)
    {
        SAFE_FREE(frame);
    }

    if (mgmt)
    {
        SAFE_FREE(mgmt);
    }

    TRACE_FUNC_EXIT();

    return NULL;

}

int probe_req_send(u8 *sa_mac_addr, u8 *da_mac_addr, u8* bssid)
{
    //u8 buffer[1024] = {0};
    struct ieee80211_mgmt_frame *mgmt;
    int i=0;
    TRACE_FUNC_ENTRY();

    mgmt = probe_req_create(sa_mac_addr, da_mac_addr, bssid);
    if (!mgmt)
    {
        ERROR_PRINT("mgmt == NULL\n");
        return 0;
    }

    //프로브 리퀘스트를 이벤트 루프에게 전달하여 실제 H/W 인터페이스로 모듈에게 프레임
    if (mgmt->frame)
    {
        SAFE_FREE(mgmt->frame);
    }

    if (mgmt)
    {
        SAFE_FREE(mgmt->frame);
    }

    TRACE_FUNC_EXIT();

    return 1;
}

static void data_frame_handler(TBD *frame, int frame_len)
{

}

static void ctrl_frame_handler(TBD *frame, int frame_len)
{

}

static int reserved(TBD *frame, int frame_len)
{
    INFO_PRINT("reserved packet\n");
    return 0;
}

static int probe_resp_analyze(TBD *frame, int frame_len)
{
    struct event_msg send_msg = {0};
    struct bss_info bss_info = {0};
    int ieee80211_hdr_len, ie_len, ie_offset;
    int element_len = 0, ret = 0;
    u8 *element_val;

    TRACE_FUNC_ENTRY();

    ieee80211_hdr_len = sizeof(struct ieee80211_hdr_3addr);
    ie_len = frame_len - ieee80211_hdr_len;
    ie_offset = ie_len - IE_OFFSET;
    
    /* Cheking Frame length */
    if (frame_len < (ieee80211_hdr_len + 1))
    {
        ret = -1;
        ERROR_PRINT("Invalid frame length.\n");
        goto invalid_frame;
    }

	/* Checking SSID */
	element_val = ie_get(frame + ieee80211_hdr_len + IE_OFFSET, WLAN_EID_SSID, &element_len, ie_offset);
	if (element_val == NULL)
    {
        ret = -1;
        ERROR_PRINT("ie : ssid Not found\n");
		goto invalid_frame;
	}

	if (*(element_val + 1))
    {
		if (element_len > MAX_SSID_LEN)
        {
            ret = -1;
			ERROR_PRINT("ssid too long (%d)\n", element_len);
            goto invalid_frame;
		}
	}

    /* Checking for DS */
	element_val = ie_get(frame + ieee80211_hdr_len + IE_OFFSET, WLAN_EID_DS_PARAMS, &element_len, ie_offset);
	if (element_val)
    {
        bss_info.channel = *(element_val + 2);
    }
    else
    {
        bss_info.channel = 36;
    }

    /* Update bss info */
    bss_info.sub_type =  IEEE80211_STYPE_PROBE_RESP;
    bss_info.mgmt_frame = frame;
    bss_info.mgmt_len = frame_len;
    memcpy(bss_info.bssid, GET_BSSID(frame), ETH_ALEN);

    ret = bss_info_insert(&bss_info);

    priv_scan_bssid_set(bss_info.bssid);

    if (priv_scan_status_get() == EVENT_SCAN_START_CMD)
    {
        /* scan done message send */
        send_msg.cmd = EVENT_SCAN_DONE_CMD;
        send_msg.data_len = ETH_ALEN;
        memcpy(send_msg.data, bss_info.bssid, ETH_ALEN);

        event_send(send_msg);
    }
    else
    {
        INFO_PRINT("Fail to event_send message : reson scan status != EVENT_SCAN_START_CMD\n");
    }
    
invalid_frame:
    
    TRACE_FUNC_EXIT();

    return ret;
}

static void mgmt_frame_handler(TBD *frame, int frame_len)
{
    struct management_frame_handler *mgmt_handl;
    u16 sub_type = GET_FRAME_SUB_TYPE(frame);

    if (sub_type >= (sizeof(mgmt_handl_tbl) / sizeof(struct management_frame_handler)))
    {
        ERROR_PRINT("Invalid sub type [%u]\n", sub_type);
		return;
	}

    mgmt_handl = &mgmt_handl_tbl[sub_type];
    if (mgmt_handl->func)
    {
        mgmt_handl->func(frame, frame_len);
    }
    
    if (mgmt_handl->str)
    {
        INFO_PRINT("%s frame recv \n", mgmt_handl->str);
    }
}

void recv_frame_handler(TBD *frame, int frame_len)
{
    u8 frame_type;

    frame_type = GET_FRAME_TYPE(frame);
    switch (frame_type)
    {
        case IEEE80211_FTYPE_MGMT:
            mgmt_frame_handler(frame, frame_len);
            break;

        case IEEE80211_FTYPE_CTL:
            ctrl_frame_handler(frame, frame_len);
            break;

        case IEEE80211_FTYPE_DATA:
            data_frame_handler(frame, frame_len);
            break;
        
        default:
            INFO_PRINT("Invalid frame type [%u]\n", frame_type);
            break;
    }
}

