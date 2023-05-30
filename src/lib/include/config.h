#ifndef A4E4D3A2_2BF0_4D00_A756_F321CCAFF5BE
#define A4E4D3A2_2BF0_4D00_A756_F321CCAFF5BE

/* HTTP Basic Auth username bytes len (ANSI) */
#define EST_BASIC_AUTH_LEN 1024

/* Standard EST Error human message bytes len */
#define EST_ERROR_MSG_LEN 1024

/* EST client path <label> bytes len (see RFC 7030, 3.2.2. HTTP URIs for Control */
#define EST_CLIENT_LABEL_LEN 64

/* Max len of HTTP header value. 
    Please note that this value is used to set the Host header also.*/
#define EST_HTTP_HEADER_VALUE_LEN 128

/* Max len of HTTP header name. */
#define EST_HTTP_HEADER_NAME_LEN 64

/* Max len of host */
#define EST_HTTP_HOST_LEN 48

/* Max len of initial cachain */
#define EST_CLIENT_CHAIN_LEN 10000

/* Max len of host:port */
#define EST_HTTP_HOST_PORT_LEN (EST_HTTP_HOST_LEN + 10)

/* Max request headers allowed */
#define EST_HTTP_REQ_HEADERS_NUM 5

/* Max len for the stack allocated buffer used to compose the http request*/
#define HTTP_REQ_MAX_LEN 2048

/* Standard port defined by RFC 7030. */
#define EST_TCP_PORT 443

/* TLS unique len (usually 256bytes) */
#define EST_TLS_UNIQUE_LEN 256

/* Len of CSR must be smaller than the HTTP Request max size */
#define EST_CSR_MAX_LEN (HTTP_REQ_MAX_LEN / 2)

/* Read max N bytes from the HTTP response (allocating the buffer) */
#define HTTP_RESP_CHUNK_LEN 1024

/* Max number of headers in the http response */
#define HTTP_MAX_HEADERS_NUM 100

/* Enable/Disable EST client feature define in the EST specification at 
    4.1.3.  CA Certificates Response
    specifically for the OldWithOld management.
    Enable this feature can result in a lower client performance */
//#define EST_CLIENT_CHECK_TA_REKEY_ENABLED

#include "log.h"

/* Include user custom defined config file to override standard values */
#ifdef EST_CONFIG_CUSTOM_FILE
#include EST_CONFIG_CUSTOM_FILE
#endif

#endif /* A4E4D3A2_2BF0_4D00_A756_F321CCAFF5BE */
