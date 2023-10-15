#ifndef _COMMON_H
#define _COMMON_H

#include <linux/slab.h>
#include <linux/kernel.h>

#define PRINT_LOGO_NAME     "esp32_adapter"

#define LOG_LEVEL_NONE      0
#define LOG_LEVEL_ERROR     1
#define LOG_LEVEL_INFO      2
#define LOG_LEVEL_DEBUG     3
#define LOG_LEVEL_TRACE     4

#define SAFE_FREE(ptr) \
    do \
    { \
        kfree(ptr); \
        (ptr) = NULL; \
    } while (0)

#define CURRENT_LOG_LEVEL   LOG_LEVEL_TRACE

#if CURRENT_LOG_LEVEL >= LOG_LEVEL_TRACE
#define TRACE_FUNC_ENTRY() \
    printk("[%s] - [%s] : start\n", PRINT_LOGO_NAME, __func__)
#define TRACE_FUNC_EXIT() \
    printk("[%s] - [%s] : exit\n", PRINT_LOGO_NAME, __func__)
#else
#define TRACE_FUNC_ENTRY()
#define TRACE_FUNC_EXIT()
#endif

#if CURRENT_LOG_LEVEL >= LOG_LEVEL_DEBUG
#define DEBUG_PRINT(fmt, ...) \
    printk("[%s] - [%s] (DEBUG) : " fmt, PRINT_LOGO_NAME, __func__, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...)
#endif

#if CURRENT_LOG_LEVEL >= LOG_LEVEL_INFO
#define INFO_PRINT(fmt, ...) \
    printk("[%s] - [%s] (INFO) : " fmt, PRINT_LOGO_NAME, __func__, ##__VA_ARGS__)
#else
#define INFO_PRINT(fmt, ...)
#endif

#if CURRENT_LOG_LEVEL >= LOG_LEVEL_ERROR
#define ERROR_PRINT(fmt, ...) \
    printk("[%s] - [%s] (ERROR) : " fmt, PRINT_LOGO_NAME, __func__, ##__VA_ARGS__)
#else
#define ERROR_PRINT(fmt, ...)
#endif

#endif
