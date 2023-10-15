#ifndef _SPI_CTRL_H_
#define _SPI_CTRL_H_

#include <linux/atomic.h>
#include "hw_link_ctrl_protocol.h"

extern atomic_t is_spi_ready;

#define SPI_MODE0     (0)
#define SPI_MODE1     (1)
#define SPI_MODE2     (2)
#define SPI_MODE3     (3)

#define MAX_SPEED_HZ      (2000000)
#define SPI_BUS_NUM       (1)
//#define MAX_SPI_DATA_LEN  (1500 + 16)
#define MAX_SPI_DATA_LEN  (512)

#define CHECK_READY_SPI()  (atomic_read(&is_spi_ready))
#define SPI_DATA_INDEX     PAYLOAD_FIELD

int spi_init(char *, unsigned long, int, int, int);
int spi_full_duplex_transfer(u8 *, int, u8 *, int);
void spi_deinit(void);

#endif
