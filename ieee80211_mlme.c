#include <linux/ieee80211.h>
#include <linux/if_arp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/atomic.h>

#include "ieee80211_mlme.h"
#include "bss_info.h"
#include "event.h"
#include "utils.h"
#include "priv.h"
#include "ring_buff.h"


#define MAX_DEAUTH_LEN              (30 + 1)
#define SEQ_NUM_UPDATE              (true)
#define SEQ_NUM_CHECK               (false)
#define IS_FROMDS(fc)               ((fc) & IEEE80211_FCTL_FROMDS)
#define IS_TODS(fc)                 ((fc) & IEEE80211_FCTL_TODS)
#define IS_FRAME_PROTECTED(fc)      (((fc) & IEEE80211_FCTL_PROTECTED) != 0)
#define GET_FRAME_TYPE(pbuf)        ((le16_to_cpu(*(unsigned short *)(pbuf)) & (BIT(3) | BIT(2))))
#define GET_FRAME_SUB_TYPE(pbuf)    ((le16_to_cpu(*(unsigned short *)(pbuf)) & (BIT(7) | BIT(6) | BIT(5) | BIT(4))))
#define GET_FRAME_RETRY(pbuf)       ((le16_to_cpu(*(unsigned short *)(pbuf)) & BIT(11)))
#define GET_BSSID(pbuf)	            ((unsigned char *)(pbuf) + 16)
#define IE_OFFSET                   12

static u8 *ie_set(u8 *, int, uint, u8 *, uint *);
static struct ieee80211_mgmt_frame *probe_req_create(u8 *sa_mac_addr, u8 *da_mac_addr, u8* bssid);
static int reserved(u8 *, int frame_len);
static int probe_resp_analyze(u8 *, int frame_len);

typedef struct management_frame_handler
{
	char *str;
	int (*func)(u8 *recv_frame, int frame_len);
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
static u8 rfc1042_oui[] = {0x00, 0x00, 0x00};

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
    struct ieee80211_mgmt_frame *mgmt;
    
    TRACE_FUNC_ENTRY();

    mgmt = probe_req_create(sa_mac_addr, da_mac_addr, bssid);
    if (!mgmt)
    {
        ERROR_PRINT("mgmt == NULL\n");
        return 0;
    }

    tx_buffer_critical_section_lock();
    if (tx_buffer_enqueue((u8 *)mgmt->frame, mgmt->len) == BUFFER_FULL)
    {
        ERROR_PRINT("tx_buffer FULL\n");
    }
    tx_buffer_critical_section_unlock();

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

__inline static bool deauth_create(u8 *mgmt, int *mgmt_len, u8 *sa, u8 *da)
{
    struct ieee80211_hdr_3addr hdr = {0};
    u16 reason_code = cpu_to_le16(3);
    int len;

    hdr.frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_DEAUTH);

    /* Set SA and BSSID  */
    if (!is_valid_ether_addr(sa))
    {
        ERROR_PRINT("Invalid sa %s\n", sa);
        goto exit;
    }
    else
    {
        ether_addr_copy(hdr.addr2, sa); //sa
        ether_addr_copy(hdr.addr3, sa); //bssid
    }

    /* Set DA */
    if (da == NULL || !is_valid_ether_addr(da))
    {
        ERROR_PRINT("Invalid da %s\n", da);
        goto exit;
    }
    else
    {
        ether_addr_copy(hdr.addr1, da);
    }
    
    /* WiFi MAC Header */
    len = sizeof(struct ieee80211_hdr_3addr);
    memcpy(mgmt, &hdr, len);

    /* WiFi Body */
    memcpy(mgmt + len, &reason_code, sizeof(reason_code));
    len += sizeof(reason_code);
    
    if (len > MAX_DEAUTH_LEN)
    {
        ERROR_PRINT("len > MAX_DEAUTH_LEN = %d\n", len);
    }
    else
    {
        *mgmt_len = len;
        return true;
    }

exit:
    return false;
}

void deauth_send(u8 *sa, u8 *da)
{
    u8 mgmt[MAX_DEAUTH_LEN] = {0};
    int mgmt_len = 0;

    if (deauth_create(mgmt, &mgmt_len, sa, da) == true)
    {
        tx_buffer_critical_section_lock();
        if (tx_buffer_enqueue(mgmt, mgmt_len) == BUFFER_FULL)
        {
            ERROR_PRINT("tx_buffer FULL\n");
        }
        tx_buffer_critical_section_unlock();
    }
    else
    {
        ERROR_PRINT("Fail deauth_create\n");
    }
}

__inline static u8 *data_frame_create(u8 *ra, u8 *buf, int *buf_len)
{
    int len;
    u16 proto;
    struct llc_snap_header snap_hdr = {0};
    struct ieee80211_hdr_3addr hdr = {0};
    static u8 data_frame[MAX_BUFFER_SIZE] = {0};
    int hdr_len = sizeof(struct ieee80211_hdr_3addr);

    if (!buf || (*buf_len > MAX_BUFFER_SIZE) || (*buf_len < 0))
    {
        INFO_PRINT("buf NULL or Invalid buf_len = [%d]\n", *buf_len);
        return NULL;
    }

    memset(data_frame, 0x0, sizeof(data_frame));

    /* Frame Control */
    hdr.frame_control = cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_STYPE_DATA | IEEE80211_FCTL_TODS);
    
    if (ra)
    {
        ether_addr_copy(hdr.addr1, ra);
    }

    memcpy(hdr.addr3, buf, ETH_ALEN);              //da
    memcpy(hdr.addr2, buf + ETH_ALEN, ETH_ALEN);   //ta
    proto = *(u16 *)&buf[ETH_ALEN + ETH_ALEN];     //protocol type

    /* Wifi Mac Header */
    memcpy(data_frame, &hdr, hdr_len);
    len = hdr_len;

    /* WiFi Body Start */

    /* LLC Header */
    snap_hdr.dsap = 0xaa;
    snap_hdr.ssap = 0xaa;
    snap_hdr.control = 0x03;
    snap_hdr.ethertype = le16_to_cpu(proto);
    memcpy(snap_hdr.oui, rfc1042_oui, 3);
    memcpy(data_frame + len, &snap_hdr, sizeof(struct llc_snap_header));
    len += sizeof(struct llc_snap_header);

    /* IP */
    memcpy(data_frame + len, buf + 14, (*buf_len) - 14);
    *buf_len = (*buf_len) + len - 14;
    
    return data_frame;
}

int data_frame_send(u8 *buf, int buf_len)
{
    u8 *data_frame;
    int data_frame_len;
    static u8 ra[] = {0x80, 0xCA, 0x4B, 0x85, 0x1E, 0xE6};

    data_frame_len = buf_len;
    data_frame = data_frame_create(ra, buf, &data_frame_len);
    if (!data_frame)
    {
        ERROR_PRINT("Received frame or its data frame is NULL\n");
        return 0;
    }

    tx_buffer_critical_section_lock();
    if (tx_buffer_enqueue(data_frame, data_frame_len) == BUFFER_FULL)
    {
        ERROR_PRINT("tx_buffer is FULL\n");
        tx_buffer_critical_section_unlock();

        return 0;
    }
    tx_buffer_critical_section_unlock();

    return 1;
}

static bool seq_num_chk_or_update(u16 new_seq_num, bool is_update)
{
    static atomic_t prv_seq_num = ATOMIC_INIT(0xffff);

    TRACE_FUNC_ENTRY();

    if (is_update)
    {
        atomic_set(&prv_seq_num, new_seq_num);
        return true;
    }
    else
    {
        if (new_seq_num == atomic_read(&prv_seq_num))
        {
            return false;
        }
    }

    TRACE_FUNC_EXIT();
    return true;
}

__inline static bool validate_eth_frame_for_rx(struct sk_buff *eth_frame)
{
    struct iphdr *ip_header = NULL;
    struct icmphdr *icmp_header = NULL;
    static u16 last_icmp_seq = 0xFFFF;
    unsigned int ip_total_len;

    TRACE_FUNC_ENTRY();

    /* Check if there's enough data for the IP header */
    if (unlikely(skb_linearize(eth_frame))) 
    {
        return false; // if failed to linearize, return false
    }
        
    if (skb_network_header_len(eth_frame) < sizeof(struct iphdr))
    {
        return false; /* if IP header size is not sufficient, return false */
    }
    
    /* Preferred way to get the IP header */
    ip_header = ip_hdr(eth_frame);  
    if (ip_header->protocol != IPPROTO_ICMP)
    {   
        return true; /* if it's not ICMP, we've already checked the IP header, so return true */
    }

    ip_total_len = ntohs(ip_header->tot_len);

    /* Check if there's enough data for the ICMP header */
    if ((ip_header->ihl << 2) + sizeof(struct icmphdr) > ip_total_len)
    {
        return false; /* if ICMP header size is not sufficient, return false */
    }

    /* Preferred way to get the ICMP header */
    icmp_header = icmp_hdr(eth_frame);

    /* Check sequence number */
    if (ntohs(icmp_header->un.echo.sequence) == last_icmp_seq)
    {
        ERROR_PRINT("Duplicated ICMP sequence number: %u.\n", ntohs(icmp_header->un.echo.sequence));
        return false;
    }

    last_icmp_seq = ntohs(icmp_header->un.echo.sequence);

    DEBUG_PRINT("ICMP sequence number: %u.\n", ntohs(icmp_header->un.echo.sequence));

    TRACE_FUNC_EXIT();
    
    return true;
}

__inline static bool frame_report(struct sk_buff *eth_frame)
{
    int ret;
    struct net_device *netdev = NULL;

    TRACE_FUNC_ENTRY();

    if (!eth_frame || eth_frame->data == NULL)
    {
        ERROR_PRINT("Received frame or its eth_frame is NULL\n");
        return false;
    }

    INFO_PRINT("eth_frame->len %d\n", eth_frame->len);
    
    /* Get netdevice */
    netdev = priv_netdev_get();
    if (netdev == NULL)
    {
        return false;
    }
   
    eth_frame->protocol  = eth_type_trans(eth_frame, netdev); 
    if (validate_eth_frame_for_rx(eth_frame) == false)
    {
        return false;
    }

    eth_frame->dev = netdev;
    eth_frame->ip_summed = CHECKSUM_NONE;

    ret = netif_rx(eth_frame);
    if (ret == NET_RX_SUCCESS)
    {
        DEBUG_PRINT("NET_RX_SUCCESS\n");
        return true;
    }
    else
    {
        dev_kfree_skb(eth_frame);
        INFO_PRINT("Unknown return value from netif_rx: %d.\n", ret);
        return false;
    }

    TRACE_FUNC_EXIT();
}

static u8 network_bssid[] = {0x80, 0xCA, 0x4B, 0x85, 0x1E, 0xE6};

__inline struct sk_buff *wifi_data_frame_to_eth_frame(struct sk_buff *recv_frame, u16 type)
{
    struct ethhdr *eh = NULL;
    struct ieee80211_qos_hdr *qos_w_hdr = NULL;
    struct ieee80211_hdr_3addr *w_hdr = NULL;
    struct sk_buff *eth_frame = NULL;
    u8 *llc = NULL, *addr1 = NULL, *addr2 = NULL;
    int eth_frame_len, fcs_len = 4, w_hdr_len;
    int llc_hdr_len = sizeof(struct llc_snap_header);
    int eth_hdr_len = sizeof(struct ethhdr);
    
    TRACE_FUNC_ENTRY();

    /* data frame sub type */
    if (type == IEEE80211_STYPE_QOS_DATA)
    {
        w_hdr_len = sizeof(struct ieee80211_qos_hdr);
        qos_w_hdr = (struct ieee80211_qos_hdr *)recv_frame->data;
        if (!qos_w_hdr)
        {
            return NULL;
        }
        addr1 = qos_w_hdr->addr1;
        addr2 = qos_w_hdr->addr2;
    }
    else if (type == IEEE80211_STYPE_DATA)
    {
        w_hdr_len = sizeof(struct ieee80211_hdr_3addr);
        w_hdr = (struct ieee80211_hdr_3addr *)recv_frame->data;
        if (!w_hdr)
        {
            return NULL;
        }
        addr1 = w_hdr->addr1;
        addr2 = w_hdr->addr2;
    }
    else
    {
        return NULL;
    }

    /* Check addr1 and addr NULL */
    if (addr1 == NULL || addr2 == NULL)
    {
        return NULL;
    }

    llc = recv_frame->data + w_hdr_len;

    /* Check Frame length */
    if (recv_frame->len < w_hdr_len + llc_hdr_len)
    {   
        ERROR_PRINT("Invalid LLC/SNAP header\n");
        return NULL;
    }

    /* ethernet frame length */
    eth_frame_len = recv_frame->len - w_hdr_len - llc_hdr_len + eth_hdr_len;

    /* alloc eth frame */
    eth_frame = dev_alloc_skb(eth_frame_len + 2);
    if (!eth_frame)
    {
        ERROR_PRINT("Failed to allocate skb for ethernet frame.\n");
        return NULL;
    }

    memset(eth_frame->data, 0, eth_frame_len + 2);
    //INFO_PRINT("eth_frame_len %d,\t recv_frame->len %d,\t eth_hdr_len %d \n", eth_frame_len, recv_frame->len, eth_hdr_len);

    /* Set Ethernet Hedaer */
    eh = (struct ethhdr *)skb_put(eth_frame, eth_hdr_len);
    memcpy(eh->h_dest, addr1, ETH_ALEN);
    memcpy(eh->h_source, addr2, ETH_ALEN);
    eh->h_proto = le16_to_cpu(*(u16 *)(llc + 6));

    /* copy */
    memcpy(skb_put(eth_frame, eth_frame_len - eth_hdr_len - fcs_len),
                    llc + llc_hdr_len, 
                    eth_frame_len - eth_hdr_len - fcs_len);

    TRACE_FUNC_EXIT();

    return eth_frame;
}

__inline static bool ap_to_station_frame_handler(struct sk_buff *recv_frame, u8 *ta, const u16 type, const u16 seq_num)
{
    struct sk_buff *eth_frame;

    TRACE_FUNC_ENTRY();

    if (memcmp(ta, network_bssid, ETH_ALEN) != 0)
    {
        INFO_PRINT("Mismatched TA. Expected: %pM, Got: %pM\n", network_bssid, ta);
        return false;
    }

    if (!seq_num_chk_or_update(seq_num, SEQ_NUM_CHECK))
    {
        INFO_PRINT("Duplicate sequence number detected\n");
        return false;
    }

    eth_frame = wifi_data_frame_to_eth_frame(recv_frame, type);
    if (eth_frame)
    {
        return frame_report(eth_frame);
    }

    TRACE_FUNC_EXIT();

    return false;
}

/* ToDS    FromDS  A1(RA)  A2(TA)  A3      A4      Use
* -----------------------------------------------------------------
*  0       0       DA      SA      BSSID   -       IBSS/DLS
*  0       1       DA      BSSID   SA      -       AP -> STA
*  1       0       BSSID   SA      DA      -       AP <- STA
*  1       1       RA      TA      DA      SA      unspecified (WDS)
*/
static void data_frame_handler(struct sk_buff *recv_frame)
{
    u16 type, fc, seq_num;
    struct ieee80211_hdr_3addr *w_hdr = NULL;

    TRACE_FUNC_ENTRY();

    if (!recv_frame || !recv_frame->data)
    {
        ERROR_PRINT("Received frame or its data is NULL\n");
        return;
    }

    if (recv_frame->len < sizeof(struct ieee80211_hdr_3addr) + 1)
    {
        ERROR_PRINT("Invalid recv frame length %d\n", recv_frame->len);
        return;
    }

    w_hdr = (struct  ieee80211_hdr_3addr *)recv_frame->data;
    
    /* Todo : Only  Sub Frame data and qos data Support */
    type = GET_FRAME_SUB_TYPE(recv_frame->data);
    if ((type != IEEE80211_STYPE_DATA) && (type != IEEE80211_STYPE_QOS_DATA))
    {
        DEBUG_PRINT("Todo : Not Supoort Data Frame Sube Type [%04x]\n", type);
        return;
    }

    fc = le16_to_cpu(w_hdr->frame_control);
    seq_num = le16_to_cpu(w_hdr->seq_ctrl);

    /* Check Frame encryption */
    if (IS_FRAME_PROTECTED(fc))
    {
        INFO_PRINT("Todo : Not Supoort Data Frame protected\n");
        return;
    }

    /* AP -> STA */
    if (IS_FROMDS(fc) && !IS_TODS(fc))
    {
        if (ap_to_station_frame_handler(recv_frame, w_hdr->addr2, type, seq_num))
        {
            seq_num_chk_or_update(seq_num, SEQ_NUM_UPDATE);
        }
    }
    else
    {
        INFO_PRINT("Todo : Not Supoort Data Frame DS (Only AP->Station)\n");
        return;
    }

    TRACE_FUNC_EXIT();
}

static void ctrl_frame_handler(u8 *frame, int frame_len)
{

}

static int reserved(u8 *frame, int frame_len)
{
    INFO_PRINT("reserved packet\n");
    return 0;
}

static int probe_resp_analyze(u8 *frame, int frame_len)
{
    struct event_msg send_msg = {0};
    struct bss_info bss_info = {0};
    int ieee80211_hdr_len, ie_len, ie_offset;
    int element_len = 0, ret = 0;
    u8 *element_val;

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

    return ret;
}

static void mgmt_frame_handler(u8 *frame, int frame_len)
{
    struct management_frame_handler *mgmt_handl;
    u16 sub_type = GET_FRAME_SUB_TYPE(frame) >> 4;

    TRACE_FUNC_ENTRY();

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

    TRACE_FUNC_EXIT();
}

void recv_frame_handler(struct sk_buff *recv_buff)
{
    u16 frame_type;
    u8 *frame;
    int frame_len;

    TRACE_FUNC_ENTRY();

    if (!recv_buff || !recv_buff->data || recv_buff->len < sizeof(struct ieee80211_hdr_3addr))
    {
        ERROR_PRINT("!recv_buff || !recv_buff->data || recv_buff->len < 25\n");
        return;
    }

    frame     = recv_buff->data;
    frame_len = recv_buff->len;

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
            data_frame_handler(recv_buff);
            break;
        
        default:
            INFO_PRINT("Invalid frame type [%x]\n", frame_type);
            break;
    }

    TRACE_FUNC_EXIT();
}

