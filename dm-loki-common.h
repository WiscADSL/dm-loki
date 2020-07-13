#ifndef __dm_loki_common_h

#define __dm_loki_common_h

#define _LOG(level, msg, ...) do {\
    printk(level "dm_loki: %s:%d " msg "\n", \
            __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } while(0);

#define LOG(msg, ...) _LOG(KERN_INFO, msg, ##__VA_ARGS__);
#define LOG_INFO(msg, ...) _LOG(KERN_INFO, msg, ##__VA_ARGS__);
#define LOG_EROR(msg, ...) _LOG(KERN_ERR, msg, ##__VA_ARGS__);
#define LOG_WARN(msg, ...) _LOG(KERN_WARNING, msg, ##__VA_ARGS__);

#endif
