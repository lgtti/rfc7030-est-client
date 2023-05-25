#include "include/error.h"

#include <string.h>
#include <errno.h>
#include <stdio.h>

void est_error_update(ESTError_t *err, const char *new_message, ...) {
    va_list args;
    va_start(args, new_message);

    char new_human[EST_ERROR_MSG_LEN];
    vsprintf(new_human, new_message, args);

    size_t concat_len = strlen(err->human) + strlen(new_human) + strlen(". ");
    size_t avail_len = EST_ERROR_MSG_LEN - strlen(err->human);
    if(concat_len > EST_ERROR_MSG_LEN) {
        return;
    }

    strcat(err->human, ". ");
    strncat(err->human, new_human, avail_len);

    va_end(args);
}

void est_error_set(ESTError_t *err, int8_t subsystem, int16_t code, const char *message, ...) {
    va_list args;
    va_start(args, message);

    vsprintf(err->human, message, args);

    strncpy(err->human, message, EST_ERROR_MSG_LEN - 1);
    err->code = code;
    err->native = errno;

    va_end(args);
}

void est_error_set_custom(ESTError_t *err, int8_t subsystem, int16_t code, int native, const char *message, ...) {
    va_list args;
    va_start(args, message);

    vsprintf(err->human, message, args);

    strncpy(err->human, message, EST_ERROR_MSG_LEN - 1);
    err->code = code;
    err->native = native;

    va_end(args);
}