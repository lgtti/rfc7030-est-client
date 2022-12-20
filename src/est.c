#include "include/est.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "transport_interface.h"

#define EST_LIB_VERSION  "InfoCert.MIDPKI.EST-1.0.0"

#define HTTP_HEADER_HOST_IDX                        0
#define HTTP_HEADER_CONTENT_TYPE_IDX                1
#define HTTP_HEADER_CONTENT_TRANSFER_ENC_IDX        2
#define HTTP_HEADER_UA_IDX                          3

#define EST_HTTP_PATH_CACERTS               "/.well-known/est/%s/cacerts"
#define EST_HTTP_PATH_CACERTS_NOLABEL       "/.well-known/est/cacerts"
#define EST_HTTP_PATH_SIMPLEENROLL          "/.well-known/est/%s/simpleenroll"
#define EST_HTTP_PATH_SIMPLEENROLL_NOLABEL  "/.well-known/est/simpleenroll"
#define EST_HTTP_PATH_SIMPLEREENROLL          "/.well-known/est/%s/simplereenroll"
#define EST_HTTP_PATH_SIMPLEREENROLL_NOLABEL  "/.well-known/est/simplereenroll"

#define EST_HTTP_PATH_LEN 32

/* EST internal definition of the incomplete type defined in the est.h header.
 It contains all data used by internal client logic.*/
typedef struct ESTClient_Ctx {
    ESTClient_Options_t options;

    /* Interface with raw transport layer.
        For example, if you are in an embedded world, this interface
        can point to a hw-oriented driver that write socket data.
    */
    TransportInterface_t transport;

    /* Context for HTTP layer */
    ESTHttp_Ctx_t *http;

    /* Hostname without port, usually used in HTTP commands
        as SNI parameter. */
    char host[EST_HTTP_HOST_PORT_LEN];
}ESTClient_Ctx_t;

/* Initialize est client library. */
ESTClient_Ctx_t * est_initialize(const ESTClient_Options_t *opts, ESTError_t *err) {
    LOG_INFO(("Init est library\n"))

    assert(opts != NULL);

    ESTClient_Ctx_t *ctx = malloc(sizeof(ESTClient_Ctx_t));
    assert(ctx != NULL);

    memset(ctx, 0, sizeof(ESTClient_Ctx_t));
    memcpy(&ctx->options, opts, sizeof(ESTClient_Options_t));

    return ctx;
}

/* Delete context.
    This method stops the TLS connection and
    frees the HTTP implementation.
*/
void est_free(ESTClient_Ctx_t **ctx) {
    LOG_INFO(("Free est library\n"))

    assert(ctx != NULL);
    assert(*ctx != NULL);

    ESTClient_Ctx_t *c = *ctx;

    c->options.httpInterface->free(c->http);
    c->options.tlsInterface->free(&c->transport);
    
    free(*ctx);
    *ctx = NULL;
}

/* Host is composed by hostname:port. If port is not defined we 
    will use the default port specified in the config header file.
*/
static void create_host(const char *host, int port, char *out) {
    if(port == 0) {
        port = EST_TCP_PORT;
    }

    sprintf(out, "%s:%d", host, port);
}

/* Initialize TLS backend and all ncessary HTTP resources.
    Pay attention to auth parameter. EST authentication methods may differ and the 
    specification only says that mTLS, HTTP Basic Auth and Certificate-Less suites are
    possible.
    On the tehnical view, if we want to start a new mTLS channel, we need to make this 
    during the channel creation, differently than the HTTP Basic auth that can be done in the HTTP
    command itself.
    So in this function we must check if we have the mTLS authentication and call the correct TLS init method.
    In addition, we pass the auth parameters to HTTP init function to manage HTTP Basic auth or Certificate Less.
 */
bool_t est_connect(ESTClient_Ctx_t *ctx, const char *host, int port, const ESTAuthData_t *auth, ESTError_t *err) {
    LOG_INFO(("Connect to est server %s %d\n", host, port))

    char host_port[EST_HTTP_HOST_PORT_LEN];
    create_host(host, port, host_port);

    /* Save host (without port) to the context, 
    we must reuse IT in the Host HTTP Header. */
    strcpy(ctx->host, host);

    LOG_INFO(("Connect to real est server %s\n", host_port))
    
    if(auth->type == EST_AUTH_TYPE_NONE) {
        //Open tcp/ip connection with TLS tunneling without authentication. This is valid for /cacerts or /csrattrs endpoints.
        if(!ctx->options.tlsInterface->initialize(host_port, 
                                                    host, 
                                                    ctx->options.chain,
                                                    ctx->options.chain_len,
                                                    ctx->options.skip_tls_verify,
                                                    &ctx->transport,
                                                    err)) {
            est_error_update(err, "Failed to init tls transport\n");
            return EST_FALSE;
        }
    } else {
        //Open tcp/ip connection with TLS tunneling using authentication (required by non-cacerts endpoints).
        if(!ctx->options.tlsInterface->initialize_auth(host_port, 
                                                    host, 
                                                    auth, 
                                                    ctx->options.chain,
                                                    ctx->options.chain_len,
                                                    ctx->options.skip_tls_verify,
                                                    &ctx->transport,
                                                    err)) {
            est_error_update(err, "Failed to init tls transport with authentication\n");
            return EST_FALSE;
        }
    }

    // Second step: initialize http layer using tcp/ip TLS tunnel
    ctx->http = ctx->options.httpInterface->initialize(&ctx->transport, auth, err);
    if(!ctx->http) {
        est_error_update(err, "Failed to init http layer\n");
        return EST_FALSE;
    }

    return EST_TRUE;
}

/* Makes an HTTP request to a specific EST endpoint and parse the expected PCKS7 body response.
    NOTE: please free the memory with x509->pkcs7_free after calling this function. 
    Input:
        ctx: current EST client context
        httpReq: details for the requested HTTP operation
        body: if HTTP POST, set this parameter with the body of the request. Ignored if body_len is 0
        body_len: len in bytes of the body parameter. If set to 0, body is ignored
        err: error
*/
static ESTPKCS7_t * est_execute_pkcs7_http(ESTClient_Ctx_t *ctx, ESTHttp_ReqMetadata_t *httpReq, byte_t *body, size_t body_len, ESTError_t *err) {
    LOG_DEBUG(("get PKCS7 from server\n"))

    ESTHttpInterface_t *http = ctx->options.httpInterface;    
    ESTX509Interface_t *x509 = ctx->options.x509Interface; 
    
    ESTHttp_RespMetadata_t respMetadata;
    memset(&respMetadata, 0, sizeof(ESTHttp_RespMetadata_t));

    /* Execute HTTP command. 
        Response metadata wil contains the allocated memory with the http body response.
        Remembed to free it with the specific function.
        If no error is implicit HTTP status >= 200 <= 299
    */
    if(!http->send(ctx->http, httpReq, body, body_len, &respMetadata, err)) {
        est_error_update(err, "Failed to send http request");
        return NULL;
    }

    LOG_DEBUG(("http send completed\n"))

    /* No body returned and this is an error. EST always returns a PKCS7. */
    if(respMetadata.body_len == 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, "No bytes found in HTTP response", EST_ERROR_NOBODY);
        return NULL;
    }

    LOG_DEBUG(("body data found %d\n", (int)respMetadata.body_len))
    LOG_DEBUG(("body is retrieved, now parse it as pkcs7\n"))

    // /cacerts MUST return a valid PKCS/ body response. */
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

static void compose_path(const char *path_label, const char *path_nolabel, const char *label, char *output) {
    if(strlen(label) > 0) {
        // User selected label
        sprintf(output, path_label, label);
    } else {
        strcpy(output, path_nolabel);
    }
}

/* Request /cacerts.
    Flow is:
    0. est_connect without authentication
    1. Make HTTP GET Request without body
    2. Parse received pkcs7 formatted payload 
    3. Extract all certificates from pkcs7
*/
bool_t est_cacerts(ESTClient_Ctx_t *ctx, ESTCaCerts_Info_t *output, ESTError_t *err) {
    ESTHttpInterface_t *http = ctx->options.httpInterface;    
    ESTX509Interface_t *x509 = ctx->options.x509Interface; 

    // prepare http path using label if provided
    char path[EST_HTTP_PATH_LEN + EST_CLIENT_LABEL_LEN];
    compose_path(EST_HTTP_PATH_CACERTS, EST_HTTP_PATH_CACERTS_NOLABEL, ctx->options.label, path);

    /* /cacerts request is simple, only one header (host) is required. */
    ESTHttp_ReqMetadata_t req;
    req.host = ctx->host;
    req.operation = HTTP_GET;
    req.path = (char *)path;

    req.headers_len = 2;

    strcpy(req.headers[0].name, "User-Agent");
    strcpy(req.headers[0].value, EST_LIB_VERSION);
    strcpy(req.headers[1].name, "Host");
    strcpy(req.headers[1].value, ctx->host);
    
    ESTPKCS7_t *p7 = est_execute_pkcs7_http(ctx, &req, NULL, 0, err);
    if(!p7) {
        // no override error messaege, is managed by the called function
        return EST_FALSE;
    }

    ESTCertificate_t **p7certificates;
    size_t p7certificates_len = x509->pkcs7_get_certificates(p7, &p7certificates, err);

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
        at least the EST TA so this is an error. */
    if(p7certificates_len == 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, "No certificates found in PKCS7 response for cacerts", EST_ERROR_EMPTY);
        return EST_FALSE;
    }
    /* Now we will analyze all received certificates.
        We add all certificates to the master cacerts implicit TA.
        Important note for memory deallocation. This instruction makes a pointer-copy
        of the chain. It is ownership of the called (client) to release the memory for the cacert result
        calling est_cacert_free function. Do not deallocate manually p7certificates. */
    output->chain = p7certificates;
    output->chain_len = p7certificates_len;

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

static ESTCertificate_t * request_certificate(ESTClient_Ctx_t *ctx, 
                                                byte_t *req, 
                                                size_t req_len, 
                                                const char *pathlabel, 
                                                const char *pathnolabel, 
                                                ESTError_t *err) {

    ESTHttpInterface_t *http = ctx->options.httpInterface;    
    ESTX509Interface_t *x509 = ctx->options.x509Interface;

    ESTHttp_RespMetadata_t respMetadata;
    memset(&respMetadata, 0, sizeof(ESTHttp_RespMetadata_t));

    // prepare http path using label if provided
    char path[EST_HTTP_PATH_LEN + EST_CLIENT_LABEL_LEN];
    compose_path(pathlabel, pathnolabel, ctx->options.label, path);

    ESTHttp_ReqMetadata_t httpReq;
    httpReq.host = ctx->host;
    httpReq.operation = HTTP_POST;
    httpReq.path = (char *)path;

    /* simpleentoll is a little bit complex than cacerts. We need the host header but we must configure
        the content type (p10) and the base64 encoding as specified in the rfc.
    */
    httpReq.headers_len = 4;

    strcpy(httpReq.headers[0].name, "User-Agent");
    strcpy(httpReq.headers[0].value, EST_LIB_VERSION);

    strcpy(httpReq.headers[1].name, "Host");
    strcpy(httpReq.headers[1].value, ctx->host);
    // set simpleenroll request type
    strcpy(httpReq.headers[2].name, "Content-Type");
    strcpy(httpReq.headers[2].value, "application/pkcs10");
    // set simpleenroll request encoding type
    strcpy(httpReq.headers[3].name, "Content-Transfer-Encoding");
    strcpy(httpReq.headers[3].value, "base64");


    ESTPKCS7_t *p7 = est_execute_pkcs7_http(ctx, &httpReq, req, req_len, err);
    if(!p7) {
        return EST_FALSE;
    }

    ESTCertificate_t **p7certificates;
    size_t p7certificates_len = x509->pkcs7_get_certificates(p7, &p7certificates, err);

    // Release pkcs7 memory because we only need certificates.
    x509->pkcs7_free(p7);

    /* PKCS7 must contains some certificates. Here we have received an error during
        the extracting phase of these certifcates.*/
    if(p7certificates_len < 0) {
        est_error_update(err, "Failed to extract pkcs7 certificate list for request certificate");
        return EST_FALSE;
    }

    /* No certificates found in a valid PKCS7 response. EST /simpleenroll MUST contains 
        at most one certificate so this is an error. */
    if(p7certificates_len == 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, "No certificates found in PKCS7 response for request certificate", EST_ERROR_EMPTY);
        return EST_FALSE;
    }

    /* Too many certificates...strange response. Error. */
    if(p7certificates_len > 1) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_EST, "Too many certificates found in PKCS7 response for request certificate", EST_ERROR_ENROLL_TOOMANY);
        return EST_FALSE;
    }

    ESTCertificate_t *crt = p7certificates[0];

    /* Release allocated memory. Different that cacerts, here we only need the certicate, not the entire chain.
        Obviously, the client must take care of the certificate memory decallocation using the
        appropriate function est_simpleenroll_free.
    */
    free(p7certificates);
    return crt;
}

/* Request /simpleenroll.
    Flow is:
    0. est_connect with authentication
    1. Make HTTP POST Request with body as csr
    2. Parse received pkcs7 formatted payload 
    3. Extract the single certificate
*/
ESTCertificate_t * est_simpleenroll(ESTClient_Ctx_t *ctx, byte_t *req, size_t req_len, ESTError_t *err) {
    return request_certificate(ctx, req, req_len, EST_HTTP_PATH_SIMPLEENROLL, EST_HTTP_PATH_SIMPLEENROLL_NOLABEL, err);
}

/* Request /simplereenroll.
    Flow is:
    0. est_connect with authentication
    1. Make HTTP POST Request with body as csr
    2. Parse received pkcs7 formatted payload 
    3. Extract the single certificate
*/
ESTCertificate_t * est_simplereenroll(ESTClient_Ctx_t *ctx, byte_t *req, size_t req_len, ESTError_t *err) {
    return request_certificate(ctx, req, req_len, EST_HTTP_PATH_SIMPLEREENROLL, EST_HTTP_PATH_SIMPLEREENROLL_NOLABEL, err);
}

void est_simpleenroll_free(ESTClient_Ctx_t *ctx, ESTCertificate_t *crt) {
    if(crt) {
        ctx->options.x509Interface->certificate_free(crt);
    }
}