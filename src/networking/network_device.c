#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/spinlock.h>

#include "common.h"
#include "network_device.h"
#include "ieee80211_mlme.h"

static int net_dev_open(struct net_device *);
static int net_dev_stop(struct net_device *);
static int net_dev_set_mac_address(struct net_device *, void *);
static struct net_device_stats *net_dev_get_stats(struct net_device *);
static int net_dev_ioctl(struct net_device *, struct ifreq *, int);
static void setup_net_dev(struct net_device *, u8 *);
static netdev_tx_t net_xmit_entry(struct sk_buff *pkt, struct net_device *pnetdev);

static DEFINE_SPINLOCK(xmit_lock);

static struct net_device_stats net_dev_stats;
static const struct net_device_ops netdev_ops =
{
    .ndo_open = net_dev_open,
    .ndo_stop = net_dev_stop,
    .ndo_start_xmit = net_xmit_entry,
    .ndo_set_mac_address = net_dev_set_mac_address,
    .ndo_get_stats = net_dev_get_stats,
    .ndo_do_ioctl = net_dev_ioctl,
};

static int net_dev_open(struct net_device *net_dev)
{
	printk("net_dev_open_start!\n");
    netif_start_queue(net_dev);
	printk("net_dev_open_stop!\n");
    return 0;
}

netdev_tx_t net_xmit_entry(struct sk_buff *pkt, struct net_device *pnetdev)
{	
    u8 *buf;
    int len;

    if (pkt)
    {
        buf = pkt->data;
        len = pkt->len;
    
        spin_lock(&xmit_lock);
        if ((pkt->data) && (pkt->len > 0) && (data_frame_send(buf, len)))
        {
            dev_kfree_skb(pkt);
            spin_unlock(&xmit_lock);
            return NETDEV_TX_OK;
        }
        dev_kfree_skb(pkt);
        spin_unlock(&xmit_lock);
    }

    return NETDEV_TX_BUSY;
}

static int net_dev_set_mac_address(struct net_device *net_dev, void *addr)
{
    struct sockaddr *sa = addr;

    if (!is_valid_ether_addr(sa->sa_data))
    {
        ERROR_PRINT("Is Invalid sa data.\n");
        return -EADDRNOTAVAIL;
    }
        
    memcpy(net_dev->dev_addr, sa->sa_data, ETH_ALEN);
    INFO_PRINT("MAC address configuration successful.\n");

    return 0;
}

static struct net_device_stats *net_dev_get_stats(struct net_device *net_dev)
{
    net_dev_stats.tx_packets = 11;
    net_dev_stats.rx_packets = 12;
    net_dev_stats.tx_dropped = 13;
    net_dev_stats.rx_dropped = 14;
    net_dev_stats.tx_bytes = 15;
    net_dev_stats.rx_bytes = 16;

    return &net_dev_stats;
}

static int net_dev_ioctl(struct net_device *net_dev, struct ifreq *ifr, int cmd)
{
    return 0;
}

static int net_dev_stop(struct net_device *net_dev)
{
    netif_stop_queue(net_dev);
    return 0;
}

struct net_device *net_dev_alloc(const char *net_dev_name)
{
    struct net_device *net_dev;
    int ret;

    net_dev = alloc_etherdev(0);
    if (!net_dev)
    {
        ERROR_PRINT("Failed to alloc etherdev.\n");
        return NULL;
    }
    
    ret = dev_alloc_name(net_dev, net_dev_name);
    if (ret < 0)
    {
        ERROR_PRINT("Failed to allocate name for net device.\n");
        free_netdev(net_dev);
        return NULL;
    }

    return net_dev;
}

static void setup_net_dev(struct net_device *net_dev, u8 *mac_addr)
{
    ether_setup(net_dev);
    net_dev->netdev_ops = &netdev_ops;

    memcpy(net_dev->dev_addr, mac_addr, ETH_ALEN);
}

int net_dev_register(struct net_device *net_dev, u8 *mac_addr)
{
    if (net_dev == NULL)
    {
        ERROR_PRINT("net_dev == NULL\n");
        return -ENOMEM;
    }

     setup_net_dev(net_dev, mac_addr);

    if (register_netdev(net_dev))
    {
        ERROR_PRINT("Failed to register net device\n");
        free_netdev(net_dev);
        return -ENODEV;
    }

    return 0;
}

void net_dev_delete(struct net_device *net_dev)
{
    TRACE_FUNC_ENTRY();

    if (net_dev)
    {
        unregister_netdev(net_dev);
        free_netdev(net_dev);
        net_dev = NULL;
    }

    TRACE_FUNC_EXIT();
}

