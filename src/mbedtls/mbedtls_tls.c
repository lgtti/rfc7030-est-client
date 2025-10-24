#include "internal.h"

typedef struct mbedTLS_NetworkContext
{
    mbedtls_ssl_context *ssl;  
    mbedtls_ssl_config *ctx;
    mbedtls_net_context conn;
    char tlsunique[EST_TLS_UNIQUE_LEN];
}mbedTLS_NetworkContext_t;

bool_t tls_unique(TransportInterface_t  *tint, char *output, size_t *len, ESTError_t *err)
{
    if (tint == NULL || tint->pNetworkContext == NULL || output == NULL || len == NULL || err == NULL) 
    {
        LOG_DEBUG(("Invalid input parameters\n"));
        return EST_FALSE;
    }
    mbedTLS_NetworkContext_t *oss_ctx = (mbedTLS_NetworkContext_t *)tint->pNetworkContext;
    snprintf(output, EST_TLS_UNIQUE_LEN, "%s", oss_ctx->tlsunique);
    *len = strnlen(output, EST_TLS_UNIQUE_LEN - 1);
    return EST_TRUE;
}

int32_t tls_recv( NetworkContext_t * pNetworkContext, void * pBuffer, size_t bytesToRecv )
{
    if (pBuffer == NULL || bytesToRecv == 0 || pNetworkContext == NULL) 
    {
        LOG_DEBUG(("Invalid input parameters\n"));
        return EST_FALSE;
    }
    mbedTLS_NetworkContext_t *octx = (mbedTLS_NetworkContext_t *)pNetworkContext;
    if (octx->ssl->private_state != MBEDTLS_SSL_HANDSHAKE_OVER) 
    {
        LOG_DEBUG(("TLS handshake not completed\n"));
        return EST_FALSE;
    }
    int32_t bytesRead = 0;
    int32_t totalBytesRead = 0; 
    char *bufferPtr = (char *)pBuffer;
    size_t bytesToReadEachIteration = bytesToRecv / 2;

    while (totalBytesRead < bytesToRecv) 
    {
        bytesRead = mbedtls_ssl_read(octx->ssl, ( const unsigned char *)bufferPtr, bytesToReadEachIteration);
        
        if (bytesRead <= 0) 
        {
            if (bytesRead == 0) 
            {
                LOG_DEBUG(("Connection closed by peer.\n"));
            } 
            else 
            {
                char error_buf[100];
                mbedtls_strerror(bytesRead, error_buf, sizeof(error_buf));
                LOG_DEBUG(("Return Code during mbedtls_ssl_read: %s\n", error_buf));
            }
            break;
        }
        
        totalBytesRead += bytesRead;
        bufferPtr += bytesRead;
    }
    return totalBytesRead;
}

int32_t tls_send( NetworkContext_t * pNetworkContext, const void * pBuffer, size_t bytesToSend )
{
    if (pBuffer == NULL || bytesToSend == 0 || pNetworkContext == NULL) 
    {
        LOG_DEBUG(("Invalid input parameters\n"));
        return EST_FALSE;
    }
    mbedTLS_NetworkContext_t *octx = (mbedTLS_NetworkContext_t *)pNetworkContext;
    if (octx->ssl->private_state != MBEDTLS_SSL_HANDSHAKE_OVER) 
    {
        LOG_DEBUG(("TLS handshake not completed\n"));
        return EST_FALSE;
    }
    return mbedtls_ssl_write(octx->ssl, (const unsigned char *)pBuffer, bytesToSend);
}

bool_t tls_init(const char *host_port, const char *host, const ESTAuthData_t *auth, ESTCertificate_t **chain, size_t chain_len, bool_t skip_verify, TransportInterface_t *tint, ESTError_t *err)
{
    if (host_port == NULL || host == NULL || chain == NULL || chain_len == 0 || tint == NULL || auth == NULL || err == NULL) 
    {
        LOG_DEBUG(("Invalid input parameters\n"));
        return EST_FALSE;
    }
    int ret;    
    LOG_INFO(("init tls channel with mbedTLS\n"));

    // init neccesary mbedtls context
    mbedtls_entropy_context mbed_ssl_entropy_;
    mbedtls_ctr_drbg_context mbed_ssl_ctr_drbg_;
    mbedtls_ssl_config *mbed_ssl_config_ = (mbedtls_ssl_config *)malloc(sizeof(mbedtls_ssl_config));
    if (mbed_ssl_config_ == NULL)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_SSL_CTX, 0, "Failed to init tls, fail to create SSL config");
        return EST_FALSE;
    }

    mbedtls_entropy_init(&mbed_ssl_entropy_);
    mbedtls_ctr_drbg_init(&mbed_ssl_ctr_drbg_);
    mbedtls_ssl_config_init(mbed_ssl_config_);

    /*+ Configure the Trusted chain registry 
        used to validate EST Server certificate. 
    */
    mbedtls_x509_crt *cert_store = (mbedtls_x509_crt *)chain[0];;

    // mbedtls rand number init
    const char *pers = "ssl_client";
    if(mbedtls_ctr_drbg_seed(&mbed_ssl_ctr_drbg_, mbedtls_entropy_func, &mbed_ssl_entropy_, (const unsigned char *) pers, strlen(pers)) != 0) 
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_SSL_CTX, 0, "Failed to init tls, fail to seed random number generator");
        mbedtls_ctr_drbg_free(&mbed_ssl_ctr_drbg_);
        mbedtls_entropy_free(&mbed_ssl_entropy_);
        mbedtls_ssl_config_free(mbed_ssl_config_);
        free(mbed_ssl_config_);
        return EST_FALSE;
    }

    // mbedtls client config
    if(mbedtls_ssl_config_defaults(mbed_ssl_config_, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) 
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_SSL_CTX, 0, "Failed to init tls, fail to set ssl config defaults");
        mbedtls_ctr_drbg_free(&mbed_ssl_ctr_drbg_);
        mbedtls_entropy_free(&mbed_ssl_entropy_);
        mbedtls_ssl_config_free(mbed_ssl_config_);
        free(mbed_ssl_config_);
        return EST_FALSE;
    }

    // check if we need to skip verify
    if (skip_verify) 
    {
        LOG_DEBUG(("Skip verify trust chain integrity\n"))
        mbedtls_ssl_conf_authmode(mbed_ssl_config_, MBEDTLS_SSL_VERIFY_NONE);
    }
    else
    {
        LOG_DEBUG(("Verify trust chain integrity\n"))
        mbedtls_ssl_conf_authmode(mbed_ssl_config_, MBEDTLS_SSL_VERIFY_REQUIRED);
    }

    // Add cachain to ssl configuration
    mbedtls_ssl_conf_ca_chain(mbed_ssl_config_, cert_store, NULL);

    // Certificate and Key Auth
    if (auth != NULL && auth->type == EST_AUTH_TYPE_CERT)
    {
        // if auth requests mTLS, set certificate and private key
        mbedtls_ssl_conf_own_cert(mbed_ssl_config_, (mbedtls_x509_crt *)auth->certAuth.certificate, (mbedtls_pk_context *)auth->certAuth.privateKey);
    }


    // TODO: Set max TLS version to 1.3
    // since mbedTLS 3.6.0 has some issues with connection using TLS1.3, we need to set max version to TLS1.2
    // will set back to 1.3 is there is any update from mbedTLS

    // set max tls version tls1.2
    mbedtls_ssl_conf_max_tls_version(mbed_ssl_config_, MBEDTLS_SSL_VERSION_TLS1_2); 
    mbedtls_ssl_conf_rng(mbed_ssl_config_, mbedtls_ctr_drbg_random, &mbed_ssl_ctr_drbg_);

    // MBEDTLS CONNECT
    mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)malloc(sizeof(mbedtls_ssl_context));
    if (ssl == NULL)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_CONNECT, 0, "Failed to init tls, fail to create SSL");
        mbedtls_ctr_drbg_free(&mbed_ssl_ctr_drbg_);
        mbedtls_entropy_free(&mbed_ssl_entropy_);
        mbedtls_ssl_free(ssl);
        mbedtls_ssl_config_free(mbed_ssl_config_);
        free(ssl);
        free(mbed_ssl_config_);
        return EST_FALSE;
    }

    mbedtls_net_context server_fd_; //!< File descriptor for the server
    mbedtls_ssl_init(ssl);
    mbedtls_net_init(&server_fd_);

    // set the network context
    mbedTLS_NetworkContext_t *nctx = (mbedTLS_NetworkContext_t *)malloc(sizeof(mbedTLS_NetworkContext_t));
    if (nctx == NULL)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_CONNECT, 0, "Failed to init tls, fail to create network context");
        mbedtls_ctr_drbg_free(&mbed_ssl_ctr_drbg_);
        mbedtls_entropy_free(&mbed_ssl_entropy_);
        mbedtls_net_free(&server_fd_);
        mbedtls_ssl_free(ssl);
        mbedtls_ssl_config_free(mbed_ssl_config_);
        free(ssl);
        free(mbed_ssl_config_);
        return EST_FALSE;
    }
    nctx->ssl = ssl;
    nctx->ctx = mbed_ssl_config_;
    nctx->conn = server_fd_;

    // extract port from host_port
    char *port;
    char *colon_pos = strchr(host_port, ':');
    if(colon_pos == NULL)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_CONNECT, 0, "Failed to init tls, invalid host:port");
        mbedtls_ctr_drbg_free(&mbed_ssl_ctr_drbg_);
        mbedtls_entropy_free(&mbed_ssl_entropy_);
        mbedtls_net_free(&server_fd_);
        mbedtls_ssl_free(ssl);
        mbedtls_ssl_config_free(mbed_ssl_config_);
        free(ssl);
        free(mbed_ssl_config_);
        free(nctx);
        return EST_FALSE;
    }
    port = colon_pos + 1;

    // Connect TCP Socket to the server
    ret = mbedtls_net_connect(&nctx->conn, host, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_CONNECT, ret, "Failed to init tls, fail to connect to server");
        oss_print_error(ret);
        mbedtls_ctr_drbg_free(&mbed_ssl_ctr_drbg_);
        mbedtls_entropy_free(&mbed_ssl_entropy_);
        mbedtls_net_free(&server_fd_);
        mbedtls_ssl_free(ssl);
        mbedtls_ssl_config_free(mbed_ssl_config_);
        free(mbed_ssl_config_);
        free(ssl);
        free(nctx);
        return EST_FALSE;
    }
    // Setup SSL
    ret = mbedtls_ssl_setup(nctx->ssl, nctx->ctx);
    if (ret != 0)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_CONNECT, ret, "Failed to init tls, fail to setup SSL");
        oss_print_error(ret);
        mbedtls_ctr_drbg_free(&mbed_ssl_ctr_drbg_);
        mbedtls_entropy_free(&mbed_ssl_entropy_);
        mbedtls_net_free(&server_fd_);
        mbedtls_ssl_free(ssl);
        mbedtls_ssl_config_free(mbed_ssl_config_);
        free(mbed_ssl_config_);
        free(ssl);
        free(nctx);
        return EST_FALSE;
    }
    // Set up the I/O callbacks
    mbedtls_ssl_set_bio(nctx->ssl, &nctx->conn, mbedtls_net_send, mbedtls_net_recv, NULL);
    // Perform the SSL/TLS handshake
    ret = mbedtls_ssl_handshake(nctx->ssl);
    if (ret != 0)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_START_HANDSHAKE, ret, "Failed to start tls handshake");
        oss_print_error(ret);
        mbedtls_ctr_drbg_free(&mbed_ssl_ctr_drbg_);
        mbedtls_entropy_free(&mbed_ssl_entropy_);
        mbedtls_net_free(&server_fd_);
        mbedtls_ssl_free(ssl);
        mbedtls_ssl_config_free(mbed_ssl_config_);
        free(mbed_ssl_config_);
        free(ssl);
        free(nctx);
        return EST_FALSE;
    }

    LOG_DEBUG(("Retrive peer certificate\n"))
    mbedtls_x509_crt *server_crt = mbedtls_ssl_get_peer_cert(nctx->ssl);
    if (server_crt == NULL)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_SERVERCERT_MISSING, 0, "Failed to init tls, fail to retrive server certificate");
        mbedtls_ctr_drbg_free(&mbed_ssl_ctr_drbg_);
        mbedtls_entropy_free(&mbed_ssl_entropy_);
        mbedtls_net_free(&server_fd_);
        mbedtls_ssl_free(ssl);
        mbedtls_ssl_config_free(mbed_ssl_config_);
        free(mbed_ssl_config_);
        free(ssl);
        free(nctx);
        return EST_FALSE;
    }

    LOG_DEBUG(("Server certificate retrieved\n"))
    mbedtls_x509_crt_free(server_crt);

    if (!skip_verify)
    {
        LOG_DEBUG(("Verify server certificate\n"))
        ret = mbedtls_ssl_get_verify_result(nctx->ssl);
        if (ret != 0)
        {
            est_error_set_custom(err, ERROR_SUBSYSTEM_TLS, EST_ERROR_TLS_SERVERCERT_INVALID, ret, "Failed to init tls, server certificate is invalid");
            oss_print_error(ret);
            mbedtls_ctr_drbg_free(&mbed_ssl_ctr_drbg_);
            mbedtls_entropy_free(&mbed_ssl_entropy_);
            mbedtls_net_free(&server_fd_);
            mbedtls_ssl_free(ssl);
            mbedtls_ssl_config_free(mbed_ssl_config_);
            free(mbed_ssl_config_);
            free(ssl);
            free(nctx);
            return EST_FALSE;
        }
    }

    // clean up randomness resource allocation
    mbedtls_ctr_drbg_free(&mbed_ssl_ctr_drbg_);
    mbedtls_entropy_free(&mbed_ssl_entropy_);

    // set the network context to transport interface
    tint->pNetworkContext = (NetworkContext_t *)nctx;
    tint->recv = tls_recv;
    tint->send = tls_send;
    
    return EST_TRUE;
}

void tls_free(TransportInterface_t *ctx) 
{
    if(ctx != NULL && ctx->pNetworkContext != NULL) 
    {
        mbedTLS_NetworkContext_t *octx = (mbedTLS_NetworkContext_t *)ctx->pNetworkContext;
        if(octx->ssl != NULL) 
        {
            mbedtls_ssl_free(octx->ssl);
            free(octx->ssl);
        }

        if(octx->conn.fd > 0) 
        {
            mbedtls_net_free(&octx->conn);
        }

        if(octx->ctx != NULL)
        {
            mbedtls_ssl_config_free(octx->ctx);
            free(octx->ctx);
        }

        free(octx);
    }
}
