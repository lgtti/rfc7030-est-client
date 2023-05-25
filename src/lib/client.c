#include "est.h"
#include "ctx.h"

#include <string.h>
#include <stdlib.h>

bool_t est_client_cacerts(const ESTClient_Options_t *opts, const char *host, int port, ESTClientCacerts_Ctx_t *output, ESTError_t *err) {
    output->ctx = est_initialize(opts, err);
    if(!output->ctx) {
        return EST_FALSE;
    }

    ESTAuthData_t none;
    memset(&none, 0, sizeof(none));
    none.type = EST_AUTH_TYPE_NONE;

    if(!est_connect(output->ctx, host, port, &none, err)) {
        return EST_FALSE;
    }

    if(!est_cacerts(output->ctx, &output->cacerts, err)) {
        est_free(&output->ctx);
        return EST_FALSE;
    }

    return EST_TRUE;
}

void est_client_cacerts_free(ESTClientCacerts_Ctx_t *cacerts_ctx) {
    est_cacerts_free(cacerts_ctx->ctx, &cacerts_ctx->cacerts);
    est_free(&cacerts_ctx->ctx);
}

static bool_t est_client_enroll_internal(const ESTClient_Options_t *opts, 
    const char *host, 
    int port, 
    ESTAuthData_t *auth,
    void *csr_ctx,
    bool_t renew, 
    ESTClientEnroll_Ctx_t *output,
    ESTError_t *err) {

    ESTClientCacerts_Ctx_t cacerts_ctx;
    memset(&cacerts_ctx, 0, sizeof(cacerts_ctx));

    if(!est_client_cacerts(opts, host, port, &cacerts_ctx, err)) {
        return EST_FALSE;
    }

    output->cacerts.chain = cacerts_ctx.cacerts.chain;
    output->cacerts.chain_len = cacerts_ctx.cacerts.chain_len;

    // create new client options to avoid change to the input one
    ESTClient_Options_t auth_opts;
    auth_opts.x509Interface = opts->x509Interface;
    auth_opts.tlsInterface = opts->tlsInterface;
    auth_opts.skip_tls_verify = opts->skip_tls_verify;
    auth_opts.use_pop = opts->use_pop;
    auth_opts.get_csr = opts->get_csr;
    strcpy(auth_opts.label, opts->label);
    // replace explicit TA with the new implicit TA
    auth_opts.chain = cacerts_ctx.cacerts.chain;
    auth_opts.chain_len = cacerts_ctx.cacerts.chain_len;

    /* We MUST free the old context to reopen a new tls auth channel. Don't free
    the cacerts response because we need to share it to the caller. We will free it 
    in the related free function. */
    est_free(&cacerts_ctx.ctx);

    // Reopen tls channel and re-initialize the client
    output->ctx = est_initialize(&auth_opts, err);
    if(!output->ctx) {
        return EST_FALSE;
    }

    if(!est_connect(output->ctx, host, port, auth, err)) {
        est_free(&output->ctx);
        return EST_FALSE;
    }

    // Obtain the CSR from the caller
    char csr[EST_CSR_MAX_LEN];
    size_t csr_len = EST_CSR_MAX_LEN;

    if(!opts->get_csr(csr_ctx, output->ctx->tlsunique, output->ctx->tlsunique_len, csr, &csr_len, err)) {
        return EST_FALSE;
    }

    output->enrolled = est_enroll(output->ctx, csr, csr_len, renew, err);
    return output->enrolled != NULL;
}

bool_t est_client_simpleenroll(const ESTClient_Options_t *opts, 
    const char *host, 
    int port, 
    ESTAuthData_t *auth,
    void *csr_ctx, 
    ESTClientEnroll_Ctx_t *output,
    ESTError_t *err) {
    return est_client_enroll_internal(opts, host, port, auth, csr_ctx, EST_FALSE, output, err);
}

bool_t est_client_simplereenroll(const ESTClient_Options_t *opts, 
    const char *host, 
    int port, 
    ESTAuthData_t *auth,
    void *csr_ctx, 
    ESTClientEnroll_Ctx_t *output,
    ESTError_t *err) {
    return est_client_enroll_internal(opts, host, port, auth, csr_ctx, EST_TRUE, output, err);
}

void est_client_enroll_free(ESTClientEnroll_Ctx_t *enroll_ctx) {
    if(!enroll_ctx || !enroll_ctx->ctx) {
        return;
    }

    est_cacerts_free(enroll_ctx->ctx, &enroll_ctx->cacerts);
    est_enroll_free(enroll_ctx->ctx, enroll_ctx->enrolled);
    est_free(&enroll_ctx->ctx);
}
