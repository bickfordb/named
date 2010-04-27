#include <stdio.h>

#ifndef __LOG_H__
#define __LOG_H__


typedef enum {
    LogDebugLevel = 1,
    LogInfoLevel, 
    LogErrorLevel
} LogLevel;

extern LogLevel log_level;

#define LOG_DEBUG(FMT, ...) LOG(LogDebugLevel, "DEBUG", FMT, ##__VA_ARGS__)
#define LOG_INFO(FMT, ...) LOG(LogInfoLevel, "INFO", FMT, ##__VA_ARGS__)
#define LOG_ERROR(FMT, ...) LOG(LogErrorLevel, "ERROR", FMT, ##__VA_ARGS__)
#define LOG(LOG_LEVEL, LEVEL_NAME, FMT, ...) { \
    if (LOG_LEVEL >= log_level) {\
        fprintf(stderr, "%s:%d\t%s\t" FMT "\n", __FILE__, __LINE__, LEVEL_NAME, ##__VA_ARGS__);\
    }\
}
#endif // __LOG_H__
