#include "est.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "transport_interface.h"
#include "ctx.h"
#include "picohttp.h"

/* 
Initialize est client library. 
Don't dereference any memory allocated to construct client options (such as cachain)
before terminate the est invocation.
*/
ESTClient_Ctx_t * est_initialize(const ESTClient_Options_t *opts, ESTError_t *err) {
    LOG_INFO(("Init est library\n"))

    assert(err != NULL);
    assert(opts != NULL);

    ESTClient_Ctx_t *ctx = calloc(1, sizeof(ESTClient_Ctx_t));
    if(!ctx) {
        est_error_set(err, ERROR_SUBSYSTEM_EST, 0, "Memory allocation failed");
        return NULL;
    }

    // Copy all content of client options
    memcpy(&ctx->options, opts, sizeof(ESTClient_Options_t));

    return ctx;
}

/* Delete context.
    This method stops the TLS connection and
    frees the HTTP implementation.
*/
void est_free(ESTClient_Ctx_t **ctx) {
    LOG_INFO(("Free est library\n"))

    if(!ctx || !*ctx) {
        return;
    }

    ESTClient_Ctx_t *c = *ctx;

    if(c->http) {
        c->httpInterface.free(c->http);
    }

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

        LOG_DEBUG(("Use default header specified port %d\n", port))
    }

    sprintf(out, "%s:%d", host, port);
}

/* 
Initialize TLS backend and all ncessary HTTP resources.
This function starts the http connection with the EST server and initialize the internal HTTP state with function pointers.
Here we can retrive the TLS Unique value from the TLS channel, the caller can use it to generate a CSR with the challengePassword field as described in the RFC.
*/
bool_t est_connect(ESTClient_Ctx_t *ctx, const char *host, int port, const ESTAuthData_t *auth, ESTError_t *err) {
    assert(auth != NULL);
    assert(host != NULL);

    LOG_INFO(("Connect to est server %s %d\n", host, port))

    char host_port[EST_HTTP_HOST_PORT_LEN];
    create_host(host, port, host_port);

    /* Save host (without port) to the context, 
    we must reuse it in the Host HTTP Header. */
    strcpy(ctx->host, host);

    if(!ctx->options.tlsInterface->initialize(host_port, host, auth, ctx->options.chain, ctx->options.chain_len, 
        ctx->options.skip_tls_verify, &ctx->transport, err)) {

        est_error_update(err, "Failed to init tls transport with authentication\n");
        return EST_FALSE;
    }

    /* If authentication is mTLS and tls_unique POP management is requested
    inform the caller with the generated value.
    RFC: 
    The client generating the CSR obtains the tls-unique value from the
    TLS subsystem as described in Channel Bindings for TLS
    */
    if(ctx->options.use_pop) {
        if(!ctx->options.tlsInterface->get_unique(&ctx->transport, ctx->tlsunique, &ctx->tlsunique_len, err)) {
            LOG_WARN(("No TLS unique POP implementation, skip it\n"))
        }
    }

    // Second step: initialize http layer using tcp/ip TLS tunnel
    ctx->httpInterface.initialize = picohttp_initialize;
    ctx->httpInterface.free = picohttp_free;
    ctx->httpInterface.send = picohttp_send;
    ctx->httpInterface.send_free = picohttp_send_free;

    ctx->http = ctx->httpInterface.initialize(&ctx->transport, auth, err);
    if(!ctx->http) {
        est_error_update(err, "Failed to init http layer\n");
        return EST_FALSE;
    }

    LOG_INFO(("EST client connected\n"))

    return EST_TRUE;
}

