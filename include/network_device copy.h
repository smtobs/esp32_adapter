#ifndef _NETWORK_DEVICE_H
#define _NETWORK_DEVICE_H

struct net_device;

struct net_device *net_dev_alloc(const char *net_dev_name);
int net_dev_register(struct net_device *, u8 *);
void net_dev_delete(struct net_device *);

#endif
