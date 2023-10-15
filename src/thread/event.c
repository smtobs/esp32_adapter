#include <linux/kfifo.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#include "ieee80211_mlme.h"
#include "priv.h"
#include "event.h"
#include "common.h"
#include "ring_buff.h"

#define MSG_SIZE         sizeof(struct event_msg)
#define MSG_QUEUE_NUM    8
#define FIFO_SIZE        MSG_QUEUE_NUM * MSG_SIZE

typedef struct scan_wait
{
    wait_queue_head_t wait_queue;
    bool scan_complete;
} scan_wait;

DEFINE_MUTEX(fifo_lock);
static struct kfifo msg_fifo             = {0};
static wait_queue_head_t event_msg_queue = {0};
static scan_wait scan_event              = {0};
static struct task_struct *event_thread  = NULL;


int event_send(struct event_msg msg)
{
    int ret = 0;

    mutex_lock(&fifo_lock);
    ret = kfifo_in(&msg_fifo, &msg, MSG_SIZE);
    mutex_unlock(&fifo_lock);

    wake_up_all(&event_msg_queue);

    return ret ? 0 : -ENOMEM;
}

int event_recv(struct event_msg *msg, unsigned long timeout)
{
    unsigned long timeout_jiffies;
    int ret;

    if (timeout)
    {
        timeout_jiffies = msecs_to_jiffies(timeout);

        timeout_jiffies = wait_event_timeout(event_msg_queue, !kfifo_is_empty(&msg_fifo), timeout_jiffies);
        if (!timeout_jiffies)
        {
            //DEBUG_PRINT("Timeout waiting for message\n");
            return -ETIMEDOUT;
        }
    }
    else
    {
        wait_event(event_msg_queue, !kfifo_is_empty(&msg_fifo));
    }

    mutex_lock(&fifo_lock);
    ret = kfifo_out(&msg_fifo, msg, MSG_SIZE);
    if (ret != MSG_SIZE)
    {
        ERROR_PRINT("ret != MSG_SIZE\n");
    }
    mutex_unlock(&fifo_lock);

    return 0;
}

long wait_for_scan_event(struct event_msg send_msg, unsigned long timeout)
{
    if (event_send(send_msg) == 0)
    {
        return wait_event_timeout(scan_event.wait_queue, scan_event.scan_complete, msecs_to_jiffies(timeout));
    }
    else
    {
        ERROR_PRINT("Faild to event_send");
        return 0;
    }
}

static void notify_scan_complete(scan_wait *data)
{
    data->scan_complete = true;
    wake_up_all(&data->wait_queue);
}

static void scan_process(struct event_msg recv_msg)
{
    int curr_scan_status;
    int cmd = recv_msg.cmd;

    curr_scan_status = priv_scan_status_get();

    if ((cmd == EVENT_SCAN_START_CMD) && (curr_scan_status == EVENT_SCAN_READY_CMD))
    {
        priv_scan_status_set(EVENT_SCAN_START_CMD);
        probe_req_send(priv_mac_addr_get(), NULL, NULL);
    }
    else if ((cmd == EVENT_SCAN_DONE_CMD) &&(curr_scan_status == EVENT_SCAN_START_CMD))
    {
        priv_scan_status_set(EVENT_SCAN_DONE_CMD);
        notify_scan_complete(&scan_event);
    }
    else if ((cmd == EVENT_SCAN_READY_CMD) && (curr_scan_status == EVENT_SCAN_DONE_CMD))
    {
        priv_scan_status_set(EVENT_SCAN_READY_CMD);
    }
    else
    {
        DEBUG_PRINT("cmd = [%d], curr_scan_status = [%d]\n", cmd, curr_scan_status);
        DEBUG_PRINT("scan_handler cmd error\n");
    }
}

static int event_handler_run(void *data)
{
    struct event_msg msg = {0};
    struct sk_buff *rx_buf = {0};
    int cmd;

    while (!kthread_should_stop()) 
    {
        if (event_recv(&msg, 1000) == 0) 
        {
            cmd = msg.cmd;
            switch (cmd)
            {
                case EVENT_SCAN_START_CMD:
                case EVENT_SCAN_DONE_CMD:
                case EVENT_SCAN_READY_CMD:

                    scan_process(msg);
                    break;

                case EVENT_RECV_HANDLE_CMD:
                    rx_buffer_critical_section_lock();

                    rx_buf = rx_buffer_dequeue();
                    while (rx_buf != BUFFER_EMPTY)
                    {
                        recv_frame_handler(rx_buf);
                        rx_buf = rx_buffer_dequeue();
                    }

                    rx_buffer_critical_section_unlock();
                    break;

                default:
                    break;
            }
        }

        msleep(1);
    }
    return 0;
}

int event_handler_init(void)
{
    int ret;

    TRACE_FUNC_ENTRY();

    init_waitqueue_head(&event_msg_queue);
    init_waitqueue_head(&scan_event.wait_queue);
    mutex_init(&fifo_lock);

    ret = kfifo_alloc(&msg_fifo, FIFO_SIZE, GFP_KERNEL);
    if (ret) 
    {
        ERROR_PRINT("Failed to create fifo, ret : [%d], FIFO_SIZE = [%ld]\n", ret, FIFO_SIZE);
        return ret;
    }

    event_thread = kthread_run(event_handler_run, NULL, "event_handler_thread");
    if (IS_ERR(event_thread)) 
    {
        ERROR_PRINT("Failed to create event_handler_thread\n");
        kfifo_free(&msg_fifo);
        return PTR_ERR(event_thread);
    }

    TRACE_FUNC_EXIT();
    return 0;
}

void event_handler_deinit(void)
{
    TRACE_FUNC_ENTRY();

    kthread_stop(event_thread);
    DEBUG_PRINT("kthread_stop ok\n");
    kfifo_free(&msg_fifo);

    TRACE_FUNC_EXIT();
}

