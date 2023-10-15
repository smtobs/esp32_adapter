#include <linux/spinlock.h>

#include "ring_buff.h"
#include "common.h"

static struct ring_buffer tx_ring_buff;
static struct ring_buffer rx_ring_buff;

void buffer_init(void)
{
    int i;

    /* TX */
    memset(&tx_ring_buff, 0x0, sizeof(struct ring_buffer));
    spin_lock_init(&tx_ring_buff.lock);
    mutex_init(&tx_ring_buff.mutex);
    
    for (i = 0; i < BUFFER_COUNT; i++)
    {
        tx_ring_buff.buffers[i] = alloc_skb(MAX_BUFFER_SIZE, GFP_KERNEL);
        if (!tx_ring_buff.buffers[i])
        {
            DEBUG_PRINT("Failed to allocate buff\n");
            goto buffer_init_fail;
        }
    }

    /* RX */
    memset(&rx_ring_buff, 0x0, sizeof(struct ring_buffer));
    spin_lock_init(&rx_ring_buff.lock);
    mutex_init(&rx_ring_buff.mutex);

    for (i = 0; i < BUFFER_COUNT; i++)
    {
        rx_ring_buff.buffers[i] = alloc_skb(MAX_BUFFER_SIZE, GFP_KERNEL);
        if (!rx_ring_buff.buffers[i])
        {
            DEBUG_PRINT("Failed to allocate buff\n");
            goto buffer_init_fail;
        }
    }

    return;

buffer_init_fail:
    buffer_deinit();  
}

__inline static int is_buffer_empty(struct ring_buffer *ring_buff)
{
    return (ring_buff->count <= 0);
}

__inline static int is_buffer_full(struct ring_buffer *ring_buff)
{
    return (ring_buff->count >= BUFFER_COUNT);
}

__inline int buffer_enqueue(struct ring_buffer *ring_buff, u8 *buf, int len)
{
    struct sk_buff *buffer;

    if (is_buffer_full(ring_buff))
    {
        //DEBUG_PRINT("ring buff count[%d]\n", ring_buff->count);
        return BUFFER_FULL;
    }

    buffer = ring_buff->buffers[ring_buff->tail];
    if (!buffer)
    {
        DEBUG_PRINT("No sk_buff available\n");
        return -ENOMEM;
    }

    skb_trim(buffer, 0);
    if (skb_tailroom(buffer) < len) 
    {
        DEBUG_PRINT("Not enough tailroom for data\n");
        return -ENOMEM;
    }

    memcpy(skb_put(buffer, len), buf, len);

    ring_buff->tail = (ring_buff->tail + 1) % BUFFER_COUNT;
    ring_buff->count++;

    return 0;
}

__inline struct sk_buff *buffer_dequeue(struct ring_buffer *ring_buff)
{
    struct sk_buff *buf;

    if (is_buffer_empty(ring_buff))
    {
        return NULL;
    }
        
    buf = ring_buff->buffers[ring_buff->head];
    ring_buff->head = (ring_buff->head + 1) % BUFFER_COUNT;
    ring_buff->count--;

    return buf;
}

/* Tx Ring buff */
int is_tx_buffer_empty(void)
{
    return is_buffer_empty(&tx_ring_buff);
}

int is_tx_buffer_full(void)
{
    return is_buffer_full(&tx_ring_buff);
}

int tx_buffer_enqueue(u8 *buf, int len)
{
    return buffer_enqueue(&tx_ring_buff, buf, len);
}

struct sk_buff *tx_buffer_dequeue(void)
{
    return buffer_dequeue(&tx_ring_buff);
}

void tx_buffer_critical_section_lock(void)
{
    spin_lock(&tx_ring_buff.lock);
}

void tx_buffer_critical_section_unlock(void)
{
    spin_unlock(&tx_ring_buff.lock);
}


/* RX Ring buff */
int is_rx_buffer_empty(void)
{
    return is_buffer_empty(&rx_ring_buff);
}

int is_rx_buffer_full(void)
{
    return is_buffer_full(&rx_ring_buff);
}

int rx_buffer_enqueue(u8 *buf, int len)
{
    return buffer_enqueue(&rx_ring_buff, buf, len);
}

struct sk_buff *rx_buffer_dequeue(void)
{
    struct sk_buff *buff;
    buff = buffer_dequeue(&rx_ring_buff);
    if (buff == NULL)
    {
        //DEBUG_PRINT("ring buff empty\n");
        return NULL;
    }
    else
    {
        return buff;
    }
}

void rx_buffer_critical_section_lock(void)
{
    mutex_lock(&rx_ring_buff.mutex);
}

void rx_buffer_critical_section_unlock(void)
{
    mutex_unlock(&rx_ring_buff.mutex);
}

void buffer_deinit(void)
{
    int i;

    /* TX */
    spin_lock(&tx_ring_buff.lock);

    for (i = 0; i < BUFFER_COUNT; i++)
    {
        if (tx_ring_buff.buffers[i])
        {
            dev_kfree_skb(tx_ring_buff.buffers[i]);
            tx_ring_buff.buffers[i] = NULL;
        }
    }
    tx_ring_buff.head = 0;
    tx_ring_buff.tail = 0;
    tx_ring_buff.count = 0;

    spin_unlock(&tx_ring_buff.lock);

    /* RX */
    spin_lock(&rx_ring_buff.lock);

    for (i = 0; i < BUFFER_COUNT; i++)
    {
        if (rx_ring_buff.buffers[i])
        {
            dev_kfree_skb(rx_ring_buff.buffers[i]);
            rx_ring_buff.buffers[i] = NULL;
        }
    }
    rx_ring_buff.head = 0;
    rx_ring_buff.tail = 0;
    rx_ring_buff.count = 0;

    spin_unlock(&rx_ring_buff.lock);
}
