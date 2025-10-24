#include "logger.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

static void _log(const char * level, const char * m, va_list args) {
    struct tm* tm_info;

    time_t timer = time(NULL);
    char time_buffer[64];
    tm_info = localtime(&timer);
    if (tm_info == NULL) {
        return;
    }
    strftime(time_buffer, sizeof(time_buffer), "%H:%M:%S %d-%m-%Y", tm_info);

    char *msg = malloc(strlen(m) + 1024);
    if (msg == NULL)
    {
        return;
    }
    snprintf(msg, strlen(m) + 1024, "%s -- %s: %s", time_buffer, level, m);

    vprintf(msg, args);
    fflush(stdout);
    free(msg);
}

void log_info(const char *m, ...) {
    va_list args;
    va_start(args, m);
    _log("INFO", m, args);
    va_end(args);
}

void log_debug(const char *m, ...) {
    va_list args;
    va_start(args, m);
    _log("DEBUG", m, args);
    va_end(args);
}

void log_error(const char *m, ...) {
    va_list args;
    va_start(args, m);
    _log("ERROR", m, args);
    va_end(args);
}

void log_warn(const char *m, ...) {
    va_list args;
    va_start(args, m);
    _log("WARN", m, args);
    va_end(args);
}
