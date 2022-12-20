#ifndef A4E4D3A2_2BF0_4D00_A756_F321CCAFF5BE
#define A4E4D3A2_2BF0_4D00_A756_F321CCAFF5BE

/* HTTP Basic Auth username bytes len (ANSI) */
#define EST_BASIC_AUTH_ID_LEN 128

/* HTTP Basic Auth password bytes len (ANSI) */
#define EST_BASIC_AUTH_SECRET_LEN 256

/* Standard EST Error human message bytes len */
#define EST_ERROR_MSG_LEN 1024

/* EST client path <label> bytes len (see RFC 7030, 3.2.2. HTTP URIs for Control */
#define EST_CLIENT_LABEL_LEN 64

/* Max len of HTTP header value. 
    Please note that this value is used to set the Host header also.*/
#define EST_HTTP_HEADER_VALUE_LEN 128

/* Max len of HTTP header name. */
#define EST_HTTP_HEADER_NAME_LEN 64

/* Max len of host:port */
#define EST_HTTP_HOST_PORT_LEN 64

/* Max request headers allowed */
#define EST_HTTP_REQ_HEADERS_NUM 5

/* Max len for the stack allocated buffer used to compose the http request*/
#define HTTP_REQ_MAX_LEN 2048

/* Standard port defined by RFC 7030. */
#define EST_TCP_PORT 443

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
