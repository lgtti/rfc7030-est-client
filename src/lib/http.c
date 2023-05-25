#include "http_internal.h"
#include "est.h"

#include <string.h>

HTTP_VERIFY_HEADER_ENUM http_verify_response_header(const char *name, const char *value, ESTHttp_Header_t *check) {
    // ignore case in header name
    if(strcasecmp(check->name, name) == 0) {

        // but no in header value
        if(strcmp(check->value, value) != 0) {
            return HTTP_VERIFY_HEADER_VALUE_KO;
        }

        // header and value are ok
        return HTTP_VERIFY_HEADER_VALUE_OK;
    }

    // no header found
    return HTTP_VERIFY_HEADER_NOTFOUND;
}

bool_t http_verify_response_compliance(ESTHttp_RespMetadata_t *respMetadata, VerifyState_t *states, size_t states_len, ESTError_t *err) {
    int h_found = 0;

    // We MUST stop the loop if we have finished the headers or we CAN stop the loop
    // when we have found all requested headers.
    for(int j = 0; j < states_len; j++) {
        VerifyState_t *s_current = &states[j];
        // Check all states to match the header
        
        for(int i = 0; i < respMetadata->headers_len || (h_found == states_len); i++) {
            ESTHttp_Header_t *h_to_check = &respMetadata->headers[i];
        
            HTTP_VERIFY_HEADER_ENUM res = http_verify_response_header(s_current->header.name, s_current->header.value, h_to_check);
            switch(res) {
                case HTTP_VERIFY_HEADER_NOTFOUND:
                    LOG_DEBUG(("Search %s, skip this %s\n", s_current->header.name, h_to_check->name))
                    break;
                case HTTP_VERIFY_HEADER_VALUE_KO:
                    // retry with the alternative if exists
                    if(strlen(s_current->alternative) > 0) {
                        res = http_verify_response_header(s_current->header.name, s_current->alternative, h_to_check);
                        if(res == HTTP_VERIFY_HEADER_VALUE_OK) {
                            s_current->found = EST_TRUE;
                            h_found++;
                            break;
                        }
                    }
                    est_error_set(err, ERROR_SUBSYSTEM_EST, EST_HTTP_ERROR_BAD_HEADERS, 
                        "Invalid header %s value %s found in response", 
                        s_current->header.name, h_to_check->value);
                    return EST_FALSE;
                case HTTP_VERIFY_HEADER_VALUE_OK:
                    s_current->found = EST_TRUE;
                    h_found++;
                    break;
            }

            if(s_current->found) {
                break;
            }
        }

        if(!s_current->found) {
            LOG_ERROR(("Missing mandatory header %s with value %s\n", s_current->header.name, s_current->header.value))
        }
    }

    // One or more of the mandatory headers is missing. Return error
    if(h_found != states_len) {
        est_error_set(err, ERROR_SUBSYSTEM_EST, EST_HTTP_ERROR_BAD_HEADERS, 
                "Missing some mandatory headers in response");
        return EST_FALSE;
    }

    return EST_TRUE;
}
