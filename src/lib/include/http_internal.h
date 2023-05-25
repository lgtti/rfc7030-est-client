#ifndef AEA9002D_774F_43DC_B9C0_2B9B4A66F078
#define AEA9002D_774F_43DC_B9C0_2B9B4A66F078

#include "http.h"

#define HTTP_GET    0x1
#define HTTP_POST   0x2

#define HTTP_HEADER_CONTENT_TYPE                    "Content-Type"
#define HTTP_HEADER_CONTENT_ENC                     "Content-Transfer-Encoding"
#define HTTP_HEADER_RETRY                           "Retry-After"
#define HTTP_HEADER_CONTENT_TYPE_VAL                "application/pkcs7-mime"
#define HTTP_HEADER_CONTENT_TYPE_VAL_ENROLL         "application/pkcs7-mime; smime-type=certs-only"
#define HTTP_HEADER_CONTENT_TYPE_VAL_ENROLL_ALT     "application/pkcs7-mime;smime-type=certs-only"
#define HTTP_HEADER_CONTENT_ENC_VAL                 "base64"

typedef char HTTP_VERIFY_HEADER_ENUM;
#define HTTP_VERIFY_HEADER_NOTFOUND 0
#define HTTP_VERIFY_HEADER_VALUE_KO 1
#define HTTP_VERIFY_HEADER_VALUE_OK 2

/*
    This function is used internally o check the presence of a particular header
    and its value.
    The function returns:
    HTTP_VERIFY_HEADER_NOTFOUND if the header is not the requested one
    HTTP_VERIFY_HEADER_VALUE_KO if the headers is ok but the value is different
    HTTP_VERIFY_HEADER_VALUE_OK if header and value are same as requested
*/
HTTP_VERIFY_HEADER_ENUM http_verify_response_header(const char *name, const char *value, ESTHttp_Header_t *check);

typedef struct VerifyState {
    ESTHttp_Header_t header;
    bool_t found;
    char alternative[EST_HTTP_HEADER_VALUE_LEN];
}VerifyState_t;

/*
    This function verify if the response contains all requested standard headers.
*/
bool_t http_verify_response_compliance(ESTHttp_RespMetadata_t *respMetadata, VerifyState_t *states, size_t states_len, ESTError_t *err);

#endif