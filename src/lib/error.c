#include "include/error.h"

#include <string.h>
#include <errno.h>
#include <stdio.h>

void est_error_update(ESTError_t *err, const char *new_message, ...) {
    va_list args;
    va_start(args, new_message);

    char new_human[EST_ERROR_MSG_LEN];
    vsnprintf(new_human, EST_ERROR_MSG_LEN - 1, new_message, args);
    va_end(args);

    size_t current_len = strlen(err->human);
    size_t new_len = strlen(new_human);
    size_t separator_len = 2; // ". "
    
    // Check if result fits
    if (current_len + separator_len + new_len >= EST_ERROR_MSG_LEN) {
        return;
    }

    // Safe append
    strcat(err->human, ". ");
    strcat(err->human, new_human);
}

void est_error_set(ESTError_t *err, int8_t subsystem, int16_t code, const char *message, ...) {
    va_list args;
    va_start(args, message);

    vsnprintf(err->human, EST_ERROR_MSG_LEN - 1, message, args);

    err->code = code;
    err->native = errno;

    va_end(args);
}

void est_error_set_custom(ESTError_t *err, int8_t subsystem, int16_t code, int native, const char *message, ...) {
    va_list args;
    va_start(args, message);

    vsnprintf(err->human, EST_ERROR_MSG_LEN - 1, message, args);

    err->code = code;
    err->native = native;

    va_end(args);
}
