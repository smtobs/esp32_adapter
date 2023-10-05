#ifndef _UTILS_H
#define _UTILS_H

#include <linux/slab.h>
#include <linux/kernel.h>

#define PRINT_LOGO_NAME     "esp32_adapter"     

#define SAFE_FREE(ptr) \
    do \
    { \
        kfree(ptr); \
        (ptr) = NULL; \
    } while (0)

#define TRACE_FUNC_ENTRY() \
    printk("[%s] - [%s] : start\n", PRINT_LOGO_NAME, __func__)

#define TRACE_FUNC_EXIT() \
    printk("[%s] - [%s] : exit\n", PRINT_LOGO_NAME, __func__)



#define DEBUG_PRINT(fmt, ...) \
    printk("[%s] - [%s] (DEBUG) : " fmt, PRINT_LOGO_NAME, __func__, ##__VA_ARGS__)

#define INFO_PRINT(fmt, ...) \
    printk("[%s] - [%s] (INFO) : " fmt, PRINT_LOGO_NAME, __func__, ##__VA_ARGS__)

#define ERROR_PRINT(fmt, ...) \
    printk("[%s] - [%s] (ERROR) : " fmt, PRINT_LOGO_NAME, __func__, ##__VA_ARGS__)

#endif
