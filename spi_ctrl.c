#include <linux/spi/spi.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>

#include "spi_ctrl.h"
#include "utils.h"

#define GPIO_HANDSHAKE             27
#define GPIO_HANDSHAKE_DEBOUNCE    10 //ms

atomic_t is_spi_ready = ATOMIC_INIT(0);
static struct spi_device *spi_device;
extern atomic_t is_spi_ready;
static int irq_number;
static int gpio_initialized = 0;

static irqreturn_t spi_handshake_gpio_irq_handler(int irq, void *dev_id)
{
    if (gpio_get_value(GPIO_HANDSHAKE))
    {
        atomic_set(&is_spi_ready, 1);
    }
    else
    {
        atomic_set(&is_spi_ready, 0);
    }

    return IRQ_HANDLED;
}

__inline static int spi_handshake_gpio_init(void)
{
    int result;

    result = gpio_request(GPIO_HANDSHAKE, "sysfs");
    if (result)
    {
        ERROR_PRINT("Failed to request GPIO.\n");
        return result;
    }

    /* Set GPIO INPUT */
    result = gpio_direction_input(GPIO_HANDSHAKE);
    if (result)
    {
        ERROR_PRINT("Failed to set GPIO direction.\n");
        gpio_free(GPIO_HANDSHAKE);
        return result;
    }

    /* Set debounce */
    gpio_set_debounce(GPIO_HANDSHAKE, GPIO_HANDSHAKE_DEBOUNCE);  // Assuming this call doesn't fail, or if it fails, it's non-critical

    result = gpio_export(GPIO_HANDSHAKE, false);
    if (result)
    {
        ERROR_PRINT("Failed to export GPIO.\n");
        gpio_free(GPIO_HANDSHAKE);
        return result;
    }

    irq_number = gpio_to_irq(GPIO_HANDSHAKE);
    if (irq_number < 0)
    {
        ERROR_PRINT("Failed to get IRQ number.\n");
        gpio_unexport(GPIO_HANDSHAKE);
        gpio_free(GPIO_HANDSHAKE);
        return irq_number;
    }

    result = request_irq(irq_number, (irq_handler_t) spi_handshake_gpio_irq_handler, IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING, "gpio_irq_handler", NULL);
    if (result)
    {
        ERROR_PRINT("Failed to request IRQ.\n");
        gpio_unexport(GPIO_HANDSHAKE);
        gpio_free(GPIO_HANDSHAKE);
    }
    else
    {
        gpio_initialized = 1;
    }

    return result;
}

int spi_init(char *modalias, unsigned long max_speed, int bus, int chip_select, int mode)
{
    int ret;
    struct spi_master *master;
    struct spi_board_info spi_info = 
    {
        .max_speed_hz = max_speed,
        .bus_num      = bus,
        .chip_select  = chip_select,
        .mode         = mode
    };

    strlcpy(spi_info.modalias, modalias, strlen(modalias));

    INFO_PRINT("modalias [%s]\n", spi_info.modalias);
    INFO_PRINT("max speed [%d]\n", spi_info.max_speed_hz);
    INFO_PRINT("bus num [%d]\n", spi_info.bus_num);
    INFO_PRINT("chip [%d]\n", spi_info.chip_select);
    INFO_PRINT("mode [%d]\n", spi_info.mode);

    if (spi_handshake_gpio_init() != 0)
    {
        return -1;
    }
    
    master = spi_busnum_to_master(spi_info.bus_num);
    if (master == NULL)
    {
        ERROR_PRINT("SPI Master not found.\n");
        return -1;
    }
   
    /* create a new slave device, given the master and device info */
    spi_device = spi_new_device(master, &spi_info);
    if (spi_device == NULL) 
    {
        ERROR_PRINT("Failed to create slave.\n");
        return -1;
    }
  
    /* 8-bits in a word */
    spi_device->bits_per_word = 8;

    /* setup the SPI slave device */
    ret = spi_setup(spi_device);
    if (ret)
    {
        ERROR_PRINT("spi set up failed\n");
        spi_unregister_device(spi_device);
        return -1;
    }
    return 0;
}

int spi_full_duplex_transfer(u8 *send_buf, int send_buf_len, u8 *recv_buf, int recv_buf_len)
{
    struct spi_transfer tr = {0};
    u8 *actual_send_buf = NULL;
    int actual_send_buf_len = 0;
    bool send_flag = false;
    int ret = -1;
  
    if (spi_device)
    {   
        if (send_buf != NULL)
        {
#if (0)
            for (i=0; i<send_buf_len; i++)
            {
                INFO_PRINT("send_buf[%d]=[%u]\n", i, send_buf[i]);
            }
            INFO_PRINT("\n\n\n");
#endif
            actual_send_buf_len = send_buf_len;
            actual_send_buf = hw_frame_assemble(send_buf, &actual_send_buf_len);
            if (actual_send_buf != NULL)
            {
                send_flag = true;
#if (0)
                for (i=0; i<actual_send_buf_len; i++)
                {
                    INFO_PRINT("actual_send_buf[%d]=[%u]\n", i, actual_send_buf[i]);
                }
                INFO_PRINT("\n\n\n");
#endif
            }
        }

        tr.tx_buf = send_flag == true ? actual_send_buf : NULL;
        tr.rx_buf = recv_buf;
        tr.len = MAX_SPI_DATA_LEN;

        ret = spi_sync_transfer(spi_device, &tr, 1);
        if (ret < 0)
        {
            ERROR_PRINT("SPI receive failed: %d\n", ret);
        }
        else
        {
            ret = is_valid_hw_frame(recv_buf);
        }
    }
    else
    {
        ERROR_PRINT("spi_device is NULL\n");
    }
 
    return ret;
}

void spi_deinit(void)
{ 
    if (gpio_initialized)
    {
        free_irq(irq_number, NULL);
        gpio_unexport(GPIO_HANDSHAKE);
        gpio_free(GPIO_HANDSHAKE);
    }

    if (spi_device)
    {
        spi_unregister_device(spi_device);
    }
}
