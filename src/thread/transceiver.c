#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>

#include "ieee80211_mlme.h"
#include "event.h"
#include "transceiver.h"
#include "common.h"
#include "spi_ctrl.h"
#include "ring_buff.h"

static struct task_struct *recv_thread = NULL;

static int recv_loop_run(void *data)
{
    struct sk_buff *tx_buf = NULL;
    struct event_msg send_msg = {0};
    int recv_buf_len = 0, ret;

    u8 *recv_buf = NULL;
    recv_buf = kmalloc(MAX_SPI_DATA_LEN, GFP_KERNEL);
    if (!recv_buf)
    {
        ERROR_PRINT("Failed to allocate memory for recv_buf\n");
        return -ENOMEM;
    }

    while (!kthread_should_stop()) 
    {
        if (CHECK_READY_SPI())
        {
            /* Send Frame */
            tx_buffer_critical_section_lock();
            
            tx_buf = tx_buffer_dequeue();
            if (tx_buf == BUFFER_EMPTY)
            {
                recv_buf_len = spi_full_duplex_transfer(NULL, 0, recv_buf, MAX_SPI_DATA_LEN);
            }
            else
            {
                recv_buf_len = spi_full_duplex_transfer(tx_buf->data, tx_buf->len, recv_buf, MAX_SPI_DATA_LEN);
            }
            tx_buffer_critical_section_unlock();

            /* Recv Frame */
            if (recv_buf_len > 0)
            {
                //INFO_PRINT("rx_buffer_enqueue\n");
                rx_buffer_critical_section_lock();
                ret = rx_buffer_enqueue(&recv_buf[SPI_DATA_INDEX], recv_buf_len);
                rx_buffer_critical_section_unlock();
                
                if (ret == BUFFER_ENQUEUE_SUCESS)
                {
                    send_msg.cmd = EVENT_RECV_HANDLE_CMD;
                    event_send(send_msg);
                }
            }
        }
        msleep(1);
    }
    return 0;
}

int recv_loop_init(void)
{
    TRACE_FUNC_ENTRY();

    recv_thread = kthread_run(recv_loop_run, NULL, "recv_loop_thread");
    if (IS_ERR(recv_thread)) 
    {
        ERROR_PRINT("Failed to create recv_loop_thread\n");
        return PTR_ERR(recv_thread);
    }

    TRACE_FUNC_EXIT();
    return 0;
}

void recv_loop_deinit(void)
{
    TRACE_FUNC_ENTRY();

    kthread_stop(recv_thread);
    
    TRACE_FUNC_EXIT();
}
