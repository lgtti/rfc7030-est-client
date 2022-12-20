#include "est_client.h"
#include <string.h>


static bool_t enroll(const ESTClient_Options_t *opts, 
                            const ESTAuthData_t *auth, 
                            const char *host, 
                            int port, 
                            byte_t *csr,
                            size_t csr_len,
                            EST_client_enroll_event event,
                            bool_t renew, 
                            ESTError_t *err) {

    ESTAuthData_t cacert_auth;

    /* Initialize authentication configuration to default 0-value.
        For the first step (cacerts) no auth is required.
    */
    memset(&cacert_auth, 0, sizeof(cacert_auth));

    /* Creates the EST client context with the options 
        configured during the client setup.
    */
    LOG_INFO(("Initialize est client.\n"))
    ESTClient_Ctx_t *est = est_initialize(opts, err);
    if(!est) {
        return EST_FALSE;
    }

    /* Start a new TLS connection with the EST Server
    */
    if(!est_connect(est, host, port, &cacert_auth, err)) {
        return EST_FALSE;
    }

    /* Request cacerts informations.
    */
    ESTCaCerts_Info_t cacerts;
    memset(&cacerts, 0, sizeof(cacerts));
    if(!est_cacerts(est, &cacerts, err)) {
        return EST_FALSE;
    }

    /* Replace implicit TA chain with explicit TA from cacerts (or, if this is a renew,
        update it with a fresh version of cacerts). 
        To make this op safe (caller needs to clear all allocated memory for 
        the input structure) we make a copy working on it.
    */
    ESTClient_Options_t override_opts;
    override_opts.x509Interface = opts->x509Interface;
    override_opts.tlsInterface = opts->tlsInterface;
    override_opts.httpInterface = opts->httpInterface;
    override_opts.skip_tls_verify = opts->skip_tls_verify;
    strcpy(override_opts.label, opts->label);
    
    override_opts.chain = cacerts.chain;
    override_opts.chain_len = cacerts.chain_len;

    /* Clear all previously used EST configuration.
        Once updated the Explicit TA database, we need to close the
        TLS connection reopening it using the mutual authentication with the client certificate
    */
    est_free(&est);

    /* Initialize a new EST context using the new Explicit TA */
    est = est_initialize(opts, err);
    if(!est) {
        return EST_FALSE;
    }

    /* Reconnect using the authentication credentials 
    */
    if(!est_connect(est, host, port, auth, err)) {
        return EST_FALSE;
    }

    /* Request the certificate! */
    ESTCertificate_t *crt = NULL;
    
    if(renew) {
        est_simplereenroll(est, csr, csr_len, err);
    } else {
        est_simpleenroll(est, csr, csr_len, err);
    }

    if(!crt) {
        return EST_FALSE;
    }

    // Invoke the caller event code with cacerts response and the obtained certificate
    event(&cacerts, crt);

    // Free all resources
    est_cacerts_free(est, &cacerts);
    est_simpleenroll_free(est, crt);
    est_free(&est);

    return EST_TRUE;
}


bool_t enroll_certificate(const ESTClient_Options_t *opts, 
                            const ESTAuthData_t *auth, 
                            const char *host, 
                            int port, 
                            byte_t *csr,
                            size_t csr_len,
                            EST_client_enroll_event event,
                            ESTError_t *err) {

    return enroll(opts, auth, host, port, csr, csr_len, event, EST_FALSE, err);
}

bool_t reenroll_certificate(const ESTClient_Options_t *opts, 
                            const ESTAuthData_t *auth, 
                            const char *host, 
                            int port, 
                            byte_t *csr,
                            size_t csr_len,
                            EST_client_enroll_event event,
                            ESTError_t *err) {

    return enroll(opts, auth, host, port, csr, csr_len, event, EST_TRUE, err);
}
