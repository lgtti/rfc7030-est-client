#ifndef AEA9002D_774F_43DC_B9C0_2B9B4A66F081
#define AEA9002D_774F_43DC_B9C0_2B9B4A66F081

#include "types.h"
#include "error.h"
#include "transport_interface.h"
#include "config.h"
#include "auth.h"

/* Generic header definition name:value */
typedef struct ESTHttp_Header {
    char name[EST_HTTP_HEADER_NAME_LEN];
    char value[EST_HTTP_HEADER_VALUE_LEN];
}ESTHttp_Header_t;

/* HTTP request needs some configuration data. */
typedef struct ESTHttp_ReqMetadata {

    ESTHttp_Header_t headers[EST_HTTP_REQ_HEADERS_NUM];

    /* Current number of headers */
    size_t headers_len;

    /* Requested GET/POST */
    int8_t operation;

    const char *path;

    const char *host;
}ESTHttp_ReqMetadata_t;

/* Response informations. 
*/
typedef struct ESTHttp_RespMetadata {
    /* This field must be allocated
        by the HTTP library implementation and cleaned
        using the specific http library function.
    */
    ESTHttp_Header_t *headers;

    /* Current number of headers in thr response. */
    size_t headers_len;

    // HTTP status code
    uint8_t status;

    /* This field must be allocated
        by the HTTP library implementation and cleaned
        using the specific http library function.
    */
    char *body;

    size_t body_len;
}ESTHttp_RespMetadata_t;

typedef struct ESTHttp_Ctx ESTHttp_Ctx_t;

/* Initialize any library-specific data/function. The input parameter tint (TransportInterface_t) must be populated
    with the correct information.

    auth parameter can be used to check if the HTTP basic auth is required.
*/
typedef ESTHttp_Ctx_t * (*EST_http_initialize)(TransportInterface_t *tint, const ESTAuthData_t *auth, ESTError_t *err);

/* Use the specific-implementation HTTP send to request EST Server operation.
  Use response metadata to retrive the body.
  Body can be NULL if not body is requested (as GET for example). 
  Control this behavior setting "body_len" parameter to 0. 
*/
typedef bool_t (*EST_http_send)(ESTHttp_Ctx_t *ctx, ESTHttp_ReqMetadata_t *request_metadata, byte_t *body, size_t body_len, ESTHttp_RespMetadata_t *response_metadata, ESTError_t *err);

/* Free response body allocated memory */
typedef void (*EST_http_send_free)(ESTHttp_Ctx_t *ctx, ESTHttp_RespMetadata_t *response_metadata);

/* Free allocated memory*/
typedef void (*EST_http_free)(ESTHttp_Ctx_t *ctx);

typedef struct ESTHttpInterface {
    EST_http_initialize initialize;
    EST_http_send send;
    EST_http_send_free send_free;
    EST_http_free free;
}ESTHttpInterface_t;


#endif /* AEA9002D_774F_43DC_B9C0_2B9B4A66F081 */
