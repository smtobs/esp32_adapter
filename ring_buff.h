#ifndef _TX_RING_BUFF_H
#define _TX_RING_BUFF_H

#include <linux/skbuff.h>

//#define MAX_BUFFER_SIZE          (1500)
#define MAX_BUFFER_SIZE          (512)
#define BUFFER_COUNT            (20)
#define BUFFER_FULL             (-1)
#define BUFFER_EMPTY            (NULL)
#define BUFFER_ENQUEUE_SUCESS   (0)

typedef struct ring_buffer
{
    struct sk_buff *buffers[BUFFER_COUNT];
    int head;
    int tail;
    u8 count;
    spinlock_t lock;
    struct mutex mutex;
} ring_buffer;

void buffer_init(void);
void buffer_deinit(void);

int is_tx_buffer_empty(void);
int is_tx_buffer_full(void);
int tx_buffer_enqueue(u8 *, int);
struct sk_buff *tx_buffer_dequeue(void);
void tx_buffer_critical_section_lock(void);
void tx_buffer_critical_section_unlock(void);

int is_rx_buffer_empty(void);
int is_rx_buffer_full(void);
int rx_buffer_enqueue(u8 *, int);
struct sk_buff *rx_buffer_dequeue(void);
void rx_buffer_critical_section_lock(void);
void rx_buffer_critical_section_unlock(void);

#endif
