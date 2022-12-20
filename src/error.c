#include "include/error.h"

#include <string.h>
#include <errno.h>
#include <stdio.h>

void est_error_update(ESTError_t *err, const char *new_message) {
    char new_human[EST_ERROR_MSG_LEN];
    strcpy(new_human, err->human);
    strcat(new_human, ". ");
    strncat(new_human, new_message, EST_ERROR_MSG_LEN);
}

void est_error_set(ESTError_t *err, int8_t subsystem, const char *message, int16_t code) {
    strncpy(err->human, message, EST_ERROR_MSG_LEN - 1);
    err->code = code;
    err->native = errno;
}

void est_error_set_custom(ESTError_t *err, int8_t subsystem, const char *message, int16_t code) {
    strncpy(err->human, message, EST_ERROR_MSG_LEN - 1);
    err->code = code;
    err->native = 0;
}