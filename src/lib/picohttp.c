#include "picohttp.h"
#include "picohttpparser.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "est.h"
#include "http_internal.h"

// Note the ' ' at the END!!!!
#define PICO_HTTP_GET "GET "
#define PICO_HTTP_POST "POST "

typedef struct PicoHttp_Ctx {
    TransportInterface_t *tint;
    ESTHttp_Header_t *headers;
    const ESTBasicAuth_t *auth;
}PicoHttp_Ctx_t;

ESTHttp_Ctx_t * picohttp_initialize(TransportInterface_t *tint, const ESTAuthData_t *auth, ESTError_t *err) {
    LOG_INFO(("http init\n"))

    PicoHttp_Ctx_t *ctx = (PicoHttp_Ctx_t *)malloc(sizeof(PicoHttp_Ctx_t));
    if (ctx == NULL)
    {
        LOG_ERROR(("Failed to allocate memory for PicoHttp_Ctx_t\n"))
        return NULL;
    }
    memset(ctx, 0, sizeof(PicoHttp_Ctx_t));
    ctx->tint = tint;

    // Set basic auth only if we have requested it.
    if(auth->type == EST_AUTH_TYPE_BASIC) {
        ctx->auth = &auth->basicAuth;
    }

    return (ESTHttp_Ctx_t *)ctx;
}

static bool_t parse_response(char *resp, size_t resp_current_len, PicoHttp_Ctx_t *pico_ctx, ESTHttp_RespMetadata_t *response_metadata, ESTError_t *err) {
    int min_ver = 0;
    int status = 0;
    const char *msg;
    size_t msg_len = 0;
    struct phr_header headers[HTTP_MAX_HEADERS_NUM];
    size_t num_headers = HTTP_MAX_HEADERS_NUM; 

    // Parse the HTTP Response
    int ret = phr_parse_response(resp, resp_current_len, 
        &min_ver, 
        &status,
        &msg, 
        &msg_len,
        headers,
        &num_headers,
        0);

    if(ret == -1) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_HTTP, EST_ERROR_HTTP_RESP_PARSE, 0, "Failed to parse http received response");
        err->native = ret;
        return EST_FALSE;
    }

    if(ret == -2) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_HTTP, EST_ERROR_HTTP_RESP_PARSE_INC, 0, "Failed to parse http incomplete received response");
        err->native = ret;
        return EST_FALSE;
    }

    response_metadata->status = status;

    if(status < 200 || status >= 300) {
        // Stop execution, wrong status code
        return EST_TRUE;
    }

    LOG_DEBUG(("Response body content %s\n", resp + ret))
    LOG_DEBUG(("Response body len %d\n", (int)(resp_current_len - ret)))

    response_metadata->headers_len = num_headers;
    response_metadata->headers = (ESTHttp_Header_t *)malloc(sizeof(ESTHttp_Header_t) * num_headers);
    memset(response_metadata->headers, 0, sizeof(sizeof(ESTHttp_Header_t) * num_headers));

    // Store received body with a manual copy
    response_metadata->body_len = resp_current_len - ret;
    response_metadata->body = malloc(response_metadata->body_len);

    /* Pico library uses pointers to store location of data (see their docs!!)
        This means that msg points to a single character of the orginal "resp"
        buffer.
        We store the msg value in out context but we don't need to free it. */
    memcpy(response_metadata->body, (resp + ret), response_metadata->body_len);

    for(int i = 0; i < num_headers; i++) {
        memcpy(response_metadata->headers[i].name, headers[i].name, headers[i].name_len);
        response_metadata->headers[i].name[headers[i].name_len] = '\0';
        memcpy(response_metadata->headers[i].value, headers[i].value, headers[i].value_len);
        response_metadata->headers[i].value[headers[i].value_len] = '\0';
    }

    return EST_TRUE;
}

bool_t picohttp_send(ESTHttp_Ctx_t *ctx, ESTHttp_ReqMetadata_t *request_metadata, byte_t *body, size_t body_len, ESTHttp_RespMetadata_t *response_metadata, ESTError_t *err) {
    LOG_DEBUG(("send http data\n"))
    PicoHttp_Ctx_t *pico_ctx = (PicoHttp_Ctx_t *)ctx;
    
    char op[32];
    char *http_ver = " HTTP/1.1\r\n";
    char *connection = "Connection: close\r\n";
    char *content_len = "Content-Length: %d\r\n";
    char *authorization = "Authorization: Basic ";
    char content[64];

    char req[HTTP_REQ_MAX_LEN];

    // Create initial http request part - method
    snprintf(op, sizeof(op), "%s", request_metadata->operation == HTTP_POST ? PICO_HTTP_POST : PICO_HTTP_GET);
    
    // Start creation of the request
    strncpy(req, op, sizeof(req) - 1);
    strncat(req, request_metadata->path, sizeof(req) - strlen(req) - 1);
    strncat(req, http_ver, sizeof(req) - strlen(req) - 1);
    strncat(req, connection, sizeof(req) - strlen(req) - 1);

    // Add all headers (its ok to have the last header terminating with \r\n)
    for(int i = 0; i < request_metadata->headers_len; i++) {
        strncat(req, request_metadata->headers[i].name, sizeof(req) - strlen(req) - 1);
        strncat(req, ": ", sizeof(req) - strlen(req) - 1);
        strncat(req, request_metadata->headers[i].value, sizeof(req) - strlen(req) - 1);;
        strncat(req, "\r\n", sizeof(req) - strlen(req) - 1);
    }

    // Configure basic auth for this request
    if(pico_ctx->auth != NULL) {
        strncat(req, authorization, sizeof(req) - strlen(req) - 1);
        strncat(req, pico_ctx->auth->b64secret, sizeof(req) - strlen(req) - 1);
        strncat(req, "\r\n", sizeof(req) - strlen(req) - 1);
    }

    /* We have some body in the request, so add the correct header plus the body itself. */
    if(body_len > 0) {
        snprintf(content, sizeof(content), content_len, (int)body_len);
        strncat(req, content, sizeof(req) - strlen(req) - 1);
        // add trailing last \r\n as requested by http;
        strncat(req, "\r\n", sizeof(req) - strlen(req) - 1);
        strncat(req, body, sizeof(req) - strlen(req) - 1);
    } else {
        // add trailing last \r\n as requested by http; no body
        strncat(req, "\r\n", sizeof(req) - strlen(req) - 1);
    }
    req[sizeof(req) - 1] = '\0';

    // Remove C string terminator
    size_t req_len_raw = strlen(req);

    LOG_DEBUG(("HTTP req real len %d\n", (int)req_len_raw))
    LOG_DEBUG(("HTTP req to send :\n%s\n", req))
    
    /* Send the http request. */
    size_t write_res = pico_ctx->tint->send(pico_ctx->tint->pNetworkContext, req, req_len_raw);
    bool_t result = write_res >= 0;

    if(result) {
        // Allocated max size for complete response
        size_t resp_avail_size = HTTP_RESP_CHUNK_LEN;
        // Current index to last filled byte in response
        size_t resp_current_len = 0;
        // Response data
        char *resp = (char *)malloc(resp_avail_size);
        memset(resp, 0, resp_avail_size);
        
        char current_resp_data[HTTP_RESP_CHUNK_LEN];
        memset(current_resp_data, 0, sizeof(HTTP_RESP_CHUNK_LEN));

        int32_t recv_bytes = 0;
        while((recv_bytes = pico_ctx->tint->recv(pico_ctx->tint->pNetworkContext, current_resp_data, HTTP_RESP_CHUNK_LEN)) > 0) {
            LOG_DEBUG(("Received bytes from response %d\n", recv_bytes))

            if(resp_current_len + recv_bytes > resp_avail_size) {
                LOG_DEBUG(("Resize response buffer with greater size\n"))

                /* Response is too big, realloc response content to fit new size*/
                char *tmp = resp;
                // Double the current size 
                resp_avail_size = resp_avail_size * 2;
                // Realloc
                resp = (char *)malloc(resp_avail_size);
                // Copy the buffer to the new location
                memcpy(resp, tmp, resp_current_len);
                // Clear the previous allocated memory
                free(tmp);
            }

            memcpy(resp + resp_current_len, current_resp_data, recv_bytes);
            resp_current_len = resp_current_len + recv_bytes;
        
            memset(current_resp_data, 0, HTTP_RESP_CHUNK_LEN);
        }

        LOG_DEBUG(("Response total bytes %d\n", (int)resp_current_len))

        if(recv_bytes < 0) {
            /* Server has closed the connection, so free the response and return error. */
            free(resp);
            est_error_set(err, ERROR_SUBSYSTEM_HTTP, EST_ERROR_HTTP_RECV, "HTTP Server recv returns negative number");
            return EST_FALSE;
        }

        LOG_DEBUG(("Recv response: %s\n", resp))
        if(!parse_response(resp, resp_current_len, pico_ctx, response_metadata, err)) {
            free(resp);
            return EST_FALSE;
        }

        free(resp);

    } else {
        est_error_set_custom(err, ERROR_SUBSYSTEM_HTTP, EST_ERROR_HTTP_SEND, write_res, "Send http request failed");
    }

    return result;
}

void picohttp_send_free(ESTHttp_Ctx_t *ctx, ESTHttp_RespMetadata_t *response_metadata) {
    if(response_metadata->body_len > 0) {
        free(response_metadata->body);
        response_metadata->body = NULL;
    }
    if(response_metadata->headers) {
        free(response_metadata->headers);
        response_metadata->headers = NULL;
    }
}

void picohttp_free(ESTHttp_Ctx_t *ctx) {
    LOG_DEBUG(("http pico free\n"))

    PicoHttp_Ctx_t *pico_ctx = (PicoHttp_Ctx_t *)ctx;
    free(ctx);
}