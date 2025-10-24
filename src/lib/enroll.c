#include "est.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include "ctx.h"
#include "http_internal.h"

/*
RFC:
An EST server MAY provide service for multiple CAs as indicated by an
OPTIONAL additional path segment between the registered application
name and the operation path.  To avoid conflict, the CA label MUST
NOT be the same as any defined operation path segment.  The EST
server MUST provide services regardless of whether the additional
path segment is present.  The following are three example valid URIs:

1.  https://www.example.com/.well-known/est/cacerts

2.  https://www.example.com/.well-known/est/arbitraryLabel1/cacerts
*/
#define EST_HTTP_PATH_SIMPLEENROLL              "/.well-known/est/%s/simpleenroll"
#define EST_HTTP_PATH_SIMPLEENROLL_NOLABEL      "/.well-known/est/simpleenroll"
#define EST_HTTP_PATH_SIMPLEREENROLL            "/.well-known/est/%s/simplereenroll"
#define EST_HTTP_PATH_SIMPLEREENROLL_NOLABEL    "/.well-known/est/simplereenroll"

#define ENROLL_VERIFY_STATE_NUM 2
#define ENROLL_VERIFY_STATE_NUM_RFC8251 1

/*
Send a new http request for /simpleenroll and /simplereenroll endpoints.
*/
static ESTPKCS7_t * make_http_request(ESTClient_Ctx_t *ctx, ESTHttp_ReqMetadata_t *httpReq, byte_t *body, size_t body_len, ESTError_t *err) {
    LOG_DEBUG(("get cacerts PKCS7 from server\n"))

    ESTHttpInterface_t *http = &ctx->httpInterface;    
    ESTX509Interface_t *x509 = ctx->options.x509Interface; 
    
    ESTHttp_RespMetadata_t respMetadata;
    memset(&respMetadata, 0, sizeof(ESTHttp_RespMetadata_t));

    /* Execute HTTP command. 
        Response metadata wil contains the allocated memory with the http body response.
        Remember to free it with the specific function.
        HTTP status code != 200 is not an error, see status field of the response.
    */
    if(!http->send(ctx->http, httpReq, body, body_len, &respMetadata, err)) {
        est_error_update(err, "Failed to send enroll http request");
        return NULL;
    }

    LOG_DEBUG(("http send completed\n"))

    if(respMetadata.status != 200) {

        /*
        RFC: 
        If the server responds with an HTTP [RFC2616] 202, this indicates
        that the request has been accepted for processing but that a response
        is not yet available.  The server MUST include a Retry-After header
        as defined for HTTP 503 responses
        */
        if(respMetadata.status == 202) {
            LOG_DEBUG(("Received http 202, check retry-after header value\n"))

            for(int i = 0; i < respMetadata.headers_len; i++) {
                if(strcasecmp(respMetadata.headers[i].name, HTTP_HEADER_RETRY) == 0) {
                    int retry = 0;
                    if(sscanf(respMetadata.headers[i].value, "%d", &retry) == EOF) {
                        // Ignore retry after case because header value is not compliant
                        break;
                    }
                    
                    // Stop execution retuning error with the retry informaton
                    est_error_set_custom(err, ERROR_SUBSYSTEM_EST, EST_ERROR_ENROLL_RETRY, retry,
                        "Server requests retry after delay %d", retry);
                    return NULL;
                }
            }
        } else {
            est_error_set_custom(err, ERROR_SUBSYSTEM_EST, EST_ERROR_CACERTS_HTTP_KO, 0,
                "Invalid http status code %d", respMetadata.status);
            return NULL;
        }
    }

    /*
        Check header compliance.
        There variables are used to ignore the check if the header is already ok (performance improvement)
    */

    

    if(ctx->options.strict8951) {
        LOG_DEBUG(("RFC 8951 strict mode enabled with flag=%d\n", ctx->options.strict8951))
        /*
        RFC: 
            The HTTP content-type of "application/pkcs7-mime" with an
                smime-type parameter "certs-only" is used, as specified in [RFC5273].
            ---> (The Simple PKI Response is sent with a Content-Transfer-Encoding of "base64")
                This requirements has been deprecated by RFC 8951 (see 
                https://github.com/lgtti/rfc7030-est-client/issues/1)
        */
        
        VerifyState_t states[ENROLL_VERIFY_STATE_NUM_RFC8251];
        memset(states, 0, sizeof(states));
        strcpy(states[0].header.name, HTTP_HEADER_CONTENT_TYPE);
        strcpy(states[0].header.value, HTTP_HEADER_CONTENT_TYPE_VAL_ENROLL_RFC8951);
        strcpy(states[0].alternative, HTTP_HEADER_CONTENT_TYPE_VAL_ENROLL_ALTRFC8951);

        if(!http_verify_response_compliance(&respMetadata, states, ENROLL_VERIFY_STATE_NUM_RFC8251, err)) {
            return EST_FALSE;
        }
    } else { 
        LOG_DEBUG(("RFC 8951 strict mode disabled\n"))

        VerifyState_t states[ENROLL_VERIFY_STATE_NUM];
        memset(states, 0, sizeof(states));
        strcpy(states[0].header.name, HTTP_HEADER_CONTENT_TYPE);
        strcpy(states[0].header.value, HTTP_HEADER_CONTENT_TYPE_VAL_ENROLL);
        strcpy(states[0].alternative, HTTP_HEADER_CONTENT_TYPE_VAL_ENROLL_ALT);
        strcpy(states[1].header.name, HTTP_HEADER_CONTENT_ENC);
        strcpy(states[1].header.value, HTTP_HEADER_CONTENT_ENC_VAL);

        if(!http_verify_response_compliance(&respMetadata, states, ENROLL_VERIFY_STATE_NUM, err)) {
            return EST_FALSE;
        }
    }

    /* No body returned and this is an error. Enrollment always returns a valid PKCS7 single-certificate response
    */
    if(respMetadata.body_len == 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, EST_ERROR_NOBODY, 0, "No bytes found in HTTP response");
        return NULL;
    }

    LOG_DEBUG(("body data found %d\n", (int)respMetadata.body_len))
    LOG_DEBUG(("body is retrieved, now parse it as pkcs7\n"))

    // /enroll MUST return a valid PKCS7 body response. */
    ESTPKCS7_t *p7 = x509->pkcs7_parse(respMetadata.body, respMetadata.body_len, err);
    if(!p7) {
        est_error_update(err, "Failed to parse http request body in pkcs7 form");
        return NULL;
    }

    LOG_DEBUG(("pkcs7 parse completed\n"))

    /* Free body response memory */
    http->send_free(ctx->http, &respMetadata);

    return p7;
}

ESTCertificate_t * est_enroll(ESTClient_Ctx_t *ctx, byte_t *req, size_t req_len, bool_t renew, ESTError_t *err) {
    ESTHttpInterface_t *http = &ctx->httpInterface;    
    ESTX509Interface_t *x509 = ctx->options.x509Interface;

    ESTHttp_RespMetadata_t respMetadata;
    memset(&respMetadata, 0, sizeof(ESTHttp_RespMetadata_t));

    // prepare http path using label if provided
    size_t path_max_len = EST_HTTP_PATH_LEN + EST_CLIENT_LABEL_LEN;
    char path[EST_HTTP_PATH_LEN + EST_CLIENT_LABEL_LEN];

    bool_t use_label = EST_FALSE;

    if(strlen(ctx->options.label) > 0) {
        use_label = EST_TRUE; 
    }
    
    if(renew) {
        snprintf(path, path_max_len,
            use_label ? EST_HTTP_PATH_SIMPLEREENROLL : EST_HTTP_PATH_SIMPLEREENROLL_NOLABEL, 
            ctx->options.label);
    } else {
        snprintf(path, path_max_len,
            use_label ? EST_HTTP_PATH_SIMPLEENROLL : EST_HTTP_PATH_SIMPLEENROLL_NOLABEL, 
            ctx->options.label);
    }

    ESTHttp_ReqMetadata_t httpReq;
    httpReq.host = ctx->host;
    httpReq.operation = HTTP_POST;
    httpReq.path = (char *)path;

    /* simpleenroll is a little bit complex than cacerts. We need the host header but we must configure
        the content type (p10) and the base64 encoding as specified in the rfc.
    */
    httpReq.headers_len = 5;

    snprintf(httpReq.headers[0].name, sizeof(httpReq.headers[0].name), "%s", "User-Agent");  
    snprintf(httpReq.headers[0].value, sizeof(httpReq.headers[0].value), "%s", EST_LIB_VERSION);  

    snprintf(httpReq.headers[1].name, sizeof(httpReq.headers[1].name), "%s", "Host");  
    snprintf(httpReq.headers[1].value, sizeof(httpReq.headers[1].value), "%s", ctx->host);

    /* set simpleenroll request type
    RFC: 
    The HTTP content-type of "application/pkcs10" is used here.  The
    format of the message is as specified in [RFC5967] with a Content-
    Transfer-Encoding of "base64" [RFC2045].
    */
    snprintf(httpReq.headers[2].name, sizeof(httpReq.headers[2].name), "%s", "Content-Type");  
    snprintf(httpReq.headers[2].value, sizeof(httpReq.headers[2].value), "%s", "application/pkcs10");  

    snprintf(httpReq.headers[3].name, sizeof(httpReq.headers[3].name), "%s", "Content-Transfer-Encoding");  
    snprintf(httpReq.headers[3].value, sizeof(httpReq.headers[3].value), "%s", "base64");  

    snprintf(httpReq.headers[4].name, sizeof(httpReq.headers[4].name), "%s", "Accept");  
    snprintf(httpReq.headers[4].value, sizeof(httpReq.headers[4].value), "%s", "*/*");


    ESTPKCS7_t *p7 = make_http_request(ctx, &httpReq, req, req_len, err);
    if(!p7) {
        return NULL;
    }

    LOG_DEBUG(("Try to parse received certificate\n"))

    size_t p7certificates_len_found = 0;
    ESTCertificate_t *crt = x509->pkcs7_get_first_certificate(p7, &p7certificates_len_found, err);

    LOG_DEBUG(("Found %d certificates\n", p7certificates_len_found))

    // Release pkcs7 memory because we only need certificates.
    x509->pkcs7_free(p7);

    /* PKCS7 must contains some certificates. Here we have received an error during
        the extracting phase of these certifcates.*/
    if(crt == NULL) {
        est_error_update(err, "Failed to extract pkcs7 certificate list for request certificate");
        return NULL;
    }

    /* No certificates found in a valid PKCS7 response. EST /simpleenroll MUST contains 
        at most one certificate so this is an error. */
    if(p7certificates_len_found == 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, EST_ERROR_EMPTY, 0, "No certificates found in PKCS7 response for request certificate");
        return NULL;
    }

    /* Too many certificates...strange response. Error. */
    if(p7certificates_len_found > 1) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, EST_ERROR_ENROLL_TOOMANY, 0, "Too many certificates found in PKCS7 response for request certificate");
        return NULL;
    }

    LOG_DEBUG(("Library enroll completed\n"))

    return crt;
}

void est_enroll_free(ESTClient_Ctx_t *ctx, ESTCertificate_t *crt) {
    if(crt) {
        ctx->options.x509Interface->certificate_free(crt);
    }
}
