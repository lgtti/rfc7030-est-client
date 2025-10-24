#include "est.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "ctx.h"
#include "http_internal.h"

#define EST_HTTP_PATH_CACERTS               "/.well-known/est/%s/cacerts"
#define EST_HTTP_PATH_CACERTS_NOLABEL       "/.well-known/est/cacerts"
#define CACERTS_VERIFY_STATE_NUM 1

/*
Send a new http request for /cacerts endpoint.
*/
static ESTPKCS7_t * make_http_request(ESTClient_Ctx_t *ctx, ESTHttp_ReqMetadata_t *httpReq, ESTError_t *err) {
    LOG_DEBUG(("get cacerts PKCS7 from server\n"))

    ESTHttpInterface_t *http = &ctx->httpInterface;    
    ESTX509Interface_t *x509 = ctx->options.x509Interface; 
    
    ESTHttp_RespMetadata_t respMetadata;
    memset(&respMetadata, 0, sizeof(ESTHttp_RespMetadata_t));

    /* Execute HTTP command. 
        Response metadata wil contains the allocated memory with the http body response.
        Remember to free it with the specific function.
        If no error is implicit HTTP status >= 200 <= 299
    */
    if(!http->send(ctx->http, httpReq, NULL, 0, &respMetadata, err)) {
        est_error_update(err, "Failed to send cacerts http request");
        http->send_free(ctx->http, &respMetadata);
        return NULL;
    }

    LOG_DEBUG(("http send completed\n"))

    /* Only HTTP 200 is accepted in cacerts response. If server requires retry this is not
    recognized because rfc says it is only valid for enroll operations. 
    LibEST manages the retry for all requests but the specification is clear. 

    RFC:
        If successful, the server response MUST have an HTTP 200 response
        code.  Any other response code indicates an error and the client MUST
        abort the protocol.
    */
    if(respMetadata.status != 200) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, EST_ERROR_CACERTS_HTTP_KO, 0,
            "Invalid http status code %d", respMetadata.status);
        http->send_free(ctx->http, &respMetadata);
        return NULL;
    }

    /*
        Check header compliance.
        There variables are used to ignore the check if the header is already ok (performance improvement)
    RFC: 
        The HTTP content-type of "application/pkcs7-mime" is used.  
        
        ---> (The Simple PKI Response is sent with a Content-Transfer-Encoding of "base64")
            This requirements has been deprecated by RFC 8951 (see 
            https://github.com/lgtti/rfc7030-est-client/issues/1)
    */
    
    VerifyState_t states[CACERTS_VERIFY_STATE_NUM];
    memset(states, 0, sizeof(states));

    snprintf(states[0].header.name, sizeof(states[0].header.name), "%s", HTTP_HEADER_CONTENT_TYPE);
    snprintf(states[0].header.value, sizeof(states[0].header.value), "%s", HTTP_HEADER_CONTENT_TYPE_VAL);
    snprintf(states[0].alternative, sizeof(states[0].alternative), "%s", HTTP_HEADER_CONTENT_TYPE_VAL_ENROLL_RFC8951);

    if(!http_verify_response_compliance(&respMetadata, states, CACERTS_VERIFY_STATE_NUM, err)) {
        return EST_FALSE;
    }

    /* No body returned and this is an error. EST cacerts always returns a PKCS7. 
    RFC:
    The EST server MUST include the current root CA certificate in the
    response.
    */
    if(respMetadata.body_len == 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, EST_ERROR_NOBODY, 0, "No bytes found in HTTP response");
        http->send_free(ctx->http, &respMetadata);
        return NULL;
    }

    LOG_DEBUG(("body data found %d\n", (int)respMetadata.body_len))
    LOG_DEBUG(("body is retrieved, now parse it as pkcs7\n"))

    // /cacerts MUST return a valid PKCS/ body response. */
    ESTPKCS7_t *p7 = x509->pkcs7_parse(respMetadata.body, respMetadata.body_len, err);
    if(!p7) {
        est_error_update(err, "Failed to parse http request body in pkcs7 form");
        http->send_free(ctx->http, &respMetadata);
        return NULL;
    }

    LOG_DEBUG(("pkcs7 parse completed\n"))

    /* Free body response memory */
    http->send_free(ctx->http, &respMetadata);

    return p7;
}

static bool_t verify_cacerts_chain(ESTX509Interface_t *x509, ESTCaCerts_Info_t *output, ESTError_t *err) {
    /*
    Here we put all self signed certificate. These are the only trusted certificate we have.
    They are trusted because we are connected to the EST Server using the explicit TA.
    */
    ESTCertificateStore_t *trusted_store = x509->certificate_store_create(err);
    if(!trusted_store) {
        est_error_update(err, "CAcerts trust store creation failed");
        return EST_FALSE;
    }

    for(int i = 0; i < output->chain_len; i++) {
        ESTCertificate_t *crt = output->chain[i];

        bool_t self_signed = EST_FALSE;
        if(!x509->certificate_is_self_signed(crt, &self_signed, err)) {
            x509->certificate_store_free(&trusted_store);
            est_error_update(err, "CAcerts failure during validate self sign");
            return EST_FALSE;
        }

        if(self_signed) {
            // Self signed can be added to the trusted store
            if(!x509->certificate_store_add(trusted_store, crt, err)) {
                x509->certificate_store_free(&trusted_store);
                est_error_update(err, "CAcerts failure during implicit TA creation");
                return EST_FALSE;
            }
        }
    }

    // Now verify every certificate with the composed trusted and untrusted stores
    for(int i = 0; i < output->chain_len; i++) {
        ESTCertificate_t *crt = output->chain[i];

        bool_t verified = EST_FALSE;
        if(!x509->certificate_verify(trusted_store, output->chain, output->chain_len, crt, &verified, err)) {
            x509->certificate_store_free(&trusted_store);
            est_error_update(err, "CAcerts failure during implicit TA creation");
            return EST_FALSE;
        }

        if(!verified) {
            // Verification failed so the cacerts response is invalid. Return error.
            x509->certificate_store_free(&trusted_store);
            est_error_set_custom(err, ERROR_SUBSYSTEM_EST, EST_ERROR_CACERTS_INVALID, 0,
                "CAcerts failure during implicit TA creation. Some certificates are not valid");
            return EST_FALSE;
        }
    }

    x509->certificate_store_free(&trusted_store);
    return EST_TRUE;
}

/* Request /cacerts.
    Flow is:
    0. est_connect without authentication
    1. Make HTTP GET Request without body
    2. Parse received pkcs7 formatted payload 
    3. Extract all certificates from pkcs7
*/
bool_t est_cacerts(ESTClient_Ctx_t *ctx, ESTCaCerts_Info_t *output, ESTError_t *err) {
    ESTHttpInterface_t *http = &ctx->httpInterface;    
    ESTX509Interface_t *x509 = ctx->options.x509Interface; 

    /* 
    prepare http path using label if provided
    */
    size_t path_max_len = EST_HTTP_PATH_LEN + EST_CLIENT_LABEL_LEN;
    char path[EST_HTTP_PATH_LEN + EST_CLIENT_LABEL_LEN];
    bool_t use_label = EST_FALSE;

    if(strlen(ctx->options.label) > 0) {
        use_label = EST_TRUE; 
    }

    snprintf(path, path_max_len, 
        use_label ? EST_HTTP_PATH_CACERTS : EST_HTTP_PATH_CACERTS_NOLABEL, 
        ctx->options.label);

    /* /cacerts request is simple, only one header (host) is required. */
    ESTHttp_ReqMetadata_t req;
    req.host = ctx->host;
    req.operation = HTTP_GET;
    req.path = (char *)path;

    req.headers_len = 3;

    snprintf(req.headers[0].name, sizeof(req.headers[0].name), "%s", "User-Agent");  
    snprintf(req.headers[0].value, sizeof(req.headers[0].value), "%s", EST_LIB_VERSION);  

    snprintf(req.headers[1].name, sizeof(req.headers[1].name), "%s", "Host");  
    snprintf(req.headers[1].value, sizeof(req.headers[1].value), "%s", ctx->host);  

    snprintf(req.headers[2].name, sizeof(req.headers[2].name), "%s", "Accept");  
    snprintf(req.headers[2].value, sizeof(req.headers[2].value), "%s", "*/*");
    
    ESTPKCS7_t *p7 = make_http_request(ctx, &req, err);
    if(!p7) {
        // no override error messaege, is managed by the called function
        return EST_FALSE;
    }

    // Retrieve certificates from pkcs7
    ESTCertificate_t **p7certificates;
    int p7certificates_len = x509->pkcs7_get_certificates(p7, &p7certificates, err);

    // Release pkcs7 memory because we only need certificates.
    x509->pkcs7_free(p7);

    /* PKCS7 must contains some certificates. Here we have received an error during
        the extracting phase of these certifcates.
        err is expected populated by the function in error*/
    if(p7certificates_len < 0) {
        est_error_update(err, "Failed to extract pkcs7 certificate list for cacerts");
        return EST_FALSE;
    }

    /* No certificates found in a valid PKCS7 response. EST /cacerts MUST contains 
        at least the EST TA so this is an error. 
        
    RFC:
        The EST server MUST include the current root CA certificate in the
        response.
    */
    if(p7certificates_len == 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, EST_ERROR_EMPTY, 0, "No certificates found in PKCS7 response for cacerts");
        return EST_FALSE;
    }
    /* Now we will store all received certificates.
        We add all certificates to the master cacerts implicit TA.
        Important note for memory deallocation. This instruction makes a pointer-copy
        of the chain. It is ownership of the called (client) to release the memory for the cacert result
        calling est_cacert_free function. Don't manually deallocate p7certificates. */
    output->chain = p7certificates;
    output->chain_len = p7certificates_len;

    /* 
    CACerts certificates must be valid and the response must contains all the chain 
    used to make the verify.

    RFC:
    After out-of-band validation occurs, all the other certificates MUST
    be validated using normal [RFC5280] certificate path validation
    (using the most recent CA certificate as the TA) before they can be
    used to build certificate paths during certificate validation.
    */
    if(!verify_cacerts_chain(x509, output, err)) {
        est_error_update(err, "Failed to verify cacerts received chain");
        return EST_FALSE;
    }

#ifdef EST_CLIENT_CHECK_TA_REKEY_ENABLED
        /* Here we check the existence of CA Rekey. 
            First step is to check if the current certificate is self signed. */
        
        // Actually not implemented
#endif

    return EST_TRUE;
}

void est_cacerts_free(ESTClient_Ctx_t *ctx, ESTCaCerts_Info_t *cacerts) {
    for(int i = 0; i < cacerts->chain_len; i++) {
        ctx->options.x509Interface->certificate_free(cacerts->chain[i]);
    }

    free(cacerts->chain);
    cacerts->chain = NULL;
}
