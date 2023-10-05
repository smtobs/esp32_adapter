#ifndef _EVENT_H
#define _EVENT_H

enum EVENT_CMD
{
    EVENT_SCAN_READY_CMD = 0,
    EVENT_SCAN_START_CMD,
    EVENT_SCAN_DONE_CMD,
};

typedef struct event_msg
{
    int cmd;
    u8 data[256];
    int data_len;
} __attribute__((packed)) event_msg;

int event_send(struct event_msg);
int event_recv(struct event_msg *, unsigned long);
long wait_for_scan_event(struct event_msg, unsigned long);
int event_handler_init(void);
void event_handler_deinit(void);

#endif
