#include "internal.h"

typedef struct OpenSSL_NetworkContext {
    SSL *ssl;  
    SSL_CTX *ctx;
    BIO *conn;
    char tlsunique[EST_TLS_UNIQUE_LEN];
}OpenSSL_NetworkContext_t;

bool_t tls_unique(TransportInterface_t  *tint, char *output, size_t *len, ESTError_t *err) {
    OpenSSL_NetworkContext_t *oss_ctx = (OpenSSL_NetworkContext_t *)tint->pNetworkContext;
    strcpy(output, oss_ctx->tlsunique);
    *len = strlen(oss_ctx->tlsunique);
    return EST_TRUE;
}

int32_t tls_recv( NetworkContext_t * pNetworkContext, void * pBuffer, size_t bytesToRecv ) {
    OpenSSL_NetworkContext_t *octx = (OpenSSL_NetworkContext_t *)pNetworkContext;

    int32_t rb = 0;
    int32_t total = 0; 
    char *tmp = (char *)pBuffer;
    size_t to_read = bytesToRecv / 2;

    do {
        rb = BIO_read(octx->conn, tmp, to_read);

        if(rb != -1) {
            tmp = tmp + rb;
            total = total + rb;

            LOG_DEBUG(("Read %d\n", rb))
            LOG_DEBUG(("Total %d\n", total))   
        }
    }while((rb > 0 || BIO_should_read(octx->conn)) && (total + to_read) < bytesToRecv );

    return total;
}

int32_t tls_send( NetworkContext_t * pNetworkContext, const void * pBuffer, size_t bytesToSend ) {
    OpenSSL_NetworkContext_t *octx = (OpenSSL_NetworkContext_t *)pNetworkContext;
    return BIO_write(octx->conn, pBuffer, bytesToSend);
}

bool_t tls_init(const char *host, const char *tls_host, const ESTAuthData_t *auth, ESTCertificate_t **chain, size_t chain_len, bool_t skip_verify, TransportInterface_t *tint, ESTError_t *err) {
    LOG_INFO(("init tls channel with openssl\n"))

    const SSL_METHOD *method = TLS_client_method(); /* Create new client-method instance */
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_SSL_CTX, ERR_get_error(), "Failed to init tls, fail to create SSL CTX");
        oss_print_error();
        return EST_FALSE;
    }

    /* As described by est rfc, min required is tls 1.1 
    RFC:
    TLS 1.1 [RFC4346] (or a later version) MUST be
    used for all EST communications
    */
    SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);

    /*+ Configure the Trusted chain registry 
        used to validate EST Server certificate. 
    */
    LOG_DEBUG(("open openssl cert store\n"))
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);
    // TODO capire cosa fare qui X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

    for(int i = 0; i < chain_len; i++) {
        X509 *chain_crt = (X509 *)chain[i];
        LOG_DEBUG(("add cert chain to cert store\n"))

        if(!X509_STORE_add_cert(store, chain_crt)) {
            est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_STORE_CA_CERT, ERR_get_error(), "Failed to init tls, fail setup certificate chain");
            oss_print_error();
            SSL_CTX_free(ctx);
            return EST_FALSE;
        }
    }

    if(skip_verify) {
        LOG_DEBUG(("Skip verify trust chain integrity\n"))
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    } else {
        LOG_DEBUG(("Verify trust chain integrity\n"))
        LOG_DEBUG(("configure verify options with chain_len %d\n", (int)chain_len))
        SSL_CTX_set_verify_depth(ctx, chain_len);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }

    if(auth != NULL && auth->type == EST_AUTH_TYPE_CERT) {
        // if auth requests mTLS, set certificate and private key
        SSL_CTX_use_certificate(ctx, (X509 *)auth->certAuth.certificate);
        SSL_CTX_use_PrivateKey(ctx, (EVP_PKEY *)auth->certAuth.privateKey);
    }
    
    LOG_DEBUG(("Prepare connect\n"))
    BIO *conn = BIO_new_ssl_connect(ctx);
    if(!conn) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_CONNECT, ERR_get_error(), "Failed to init tls, fail connect ssl");
        oss_print_error();
        SSL_CTX_free(ctx);
        return EST_FALSE;
    }

    LOG_DEBUG(("set openssl hostname %s\n", host))   
    BIO_set_conn_hostname(conn, host);

    SSL *ssl = NULL;
    BIO_get_ssl(conn, &ssl);
    if (!ssl) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_GET_TUNNEL_REF, ERR_get_error(), "Failed to init tls, fail to create SSL");
        oss_print_error();
        BIO_free_all(conn);
        SSL_CTX_free(ctx);
        return EST_FALSE;
    }

    LOG_DEBUG(("set openssl tls hostname %s\n", tls_host))
    SSL_set_tlsext_host_name(ssl, tls_host);

    LOG_DEBUG(("Try connect...\n"))
    if(BIO_do_connect(conn) <= 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_START_HANDSHAKE, ERR_get_error(), "Failed to start tls handshake");
        oss_print_error();
        BIO_free_all(conn);
        SSL_CTX_free(ctx);
        return EST_FALSE;
    }

    LOG_DEBUG(("Collect tls unique information...\n"))

    byte_t tlsunique_output[EST_TLS_UNIQUE_LEN];
    memset(tlsunique_output, 0, sizeof(tlsunique_output));

    byte_t buf[EST_TLS_UNIQUE_LEN];
    size_t buf_len = SSL_get_finished(ssl, buf, EST_TLS_UNIQUE_LEN);
    if(buf_len > 0) {
        BIO *b64 = BIO_new(BIO_f_base64());
        if (b64 != NULL) {
            BIO *bio = BIO_new(BIO_s_mem());
            if (bio == NULL) {
                BIO_free(b64);
            } else {
                bio = BIO_push(b64, bio);
                BIO_write(bio, buf, strlen(buf));
                (void)BIO_flush(bio);

                BUF_MEM *bptr = NULL;
                BIO_get_mem_ptr(bio, &bptr);

                size_t l = 0;
                if (bptr->data[bptr->length - 1] == '\n') {
                    l = bptr->length - 1;
                } else {
                    l = bptr->length;
                }

                memcpy(tlsunique_output, bptr->data, l);
                tlsunique_output[l] = '\0';
                BIO_free_all(b64);
            }
        }
    }
   
    LOG_DEBUG(("Retrive peer certificate\n"))
    X509 *server_crt = SSL_get_peer_certificate(ssl);
    if(!server_crt) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_SERVERCERT_MISSING, ERR_get_error(), "Failed to init tls, server do not present a certificate");
        oss_print_error();
        BIO_free_all(conn);
        SSL_CTX_free(ctx);
        return EST_FALSE;
    } else {
        X509_free(server_crt);
    }

    if(!skip_verify) {
        LOG_DEBUG(("Verify peer certificate validity\n"))
        if(SSL_get_verify_result(ssl) != X509_V_OK ) {
            est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_SERVERCERT_INVALID, ERR_get_error(), "Failed to init tls, server certificate is not verified");
            oss_print_error();
            BIO_free_all(conn);
            SSL_CTX_free(ctx);
            return EST_FALSE;
        }
    }

    SSL_SESSION *session = SSL_get_session(ssl);

    LOG_DEBUG(("Configure internal openssl saved context\n"))

    OpenSSL_NetworkContext_t *nctx = (OpenSSL_NetworkContext_t *)malloc(sizeof(OpenSSL_NetworkContext_t));
    nctx->ctx = ctx;
    nctx->ssl = ssl; 
    nctx->conn = conn;
    strcpy(nctx->tlsunique, tlsunique_output);

    /* In this client implementation openssl is the network low-level layer of the stack.
        If your HTTP library owns the TLS management and the socket management, 
        you can return an empty structure.
    */
    tint->pNetworkContext = (NetworkContext_t *)nctx; 
    tint->recv = tls_recv;
    tint->send = tls_send;
    return EST_TRUE;
}

void tls_free(TransportInterface_t *ctx) {
    if(ctx->pNetworkContext) {
        OpenSSL_NetworkContext_t *octx = (OpenSSL_NetworkContext_t *)ctx->pNetworkContext;
        if(octx->conn) {
            BIO_free_all(octx->conn);
        }

        if(octx->ctx) {
            SSL_CTX_free(octx->ctx);
        }

        free(octx);
    }
}
