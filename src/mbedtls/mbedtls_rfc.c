#include "internal.h"

static bool_t load_csr(void *ctx, const char *tlsunique, size_t tlsunique_len, byte_t *csr, size_t *csr_len, ESTError_t *err)
{
    if (ctx == NULL || csr == NULL || csr_len == NULL) {
        LOG_ERROR(("Invalid parameters: ctx, csr, or csr_len is NULL\n"))
        return EST_FALSE;
    }
    
    char *csr_ctx = (char *)ctx;
    // Use strnlen to safely bound length check, avoiding unterminated string scan
    size_t csr_ctx_len = strnlen(csr_ctx, EST_CSR_MAX_LEN);
    
    if (csr_ctx_len >= EST_CSR_MAX_LEN) {
        LOG_ERROR(("CSR length exceeds maximum allowed size or not null-terminated\n"))
        return EST_FALSE;
    }
    
    memcpy(csr, csr_ctx, csr_ctx_len);
    csr[csr_ctx_len] = '\0';
    *csr_len = csr_ctx_len;
    return EST_TRUE;
}

bool_t parse_p12(const char *p12, size_t p12_len, const char *password, ESTAuthData_t *auth, ESTError_t *err)
{
    LOG_INFO(("parse_p12 - PKCS12 feature unavailable in MbedTLS\n"))
    est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_P12, -1,
                        "PKCS12 parsing is not supported with MbedTLS backend");
    return EST_FALSE;
}

/**
 * @brief Copies a PEM buffer adding the null terminator required by MbedTLS.
 *
 * MbedTLS detects the PEM format checking that the last byte of the input
 * buffer is a null terminator, and the terminator must be counted in the
 * buffer length. The caller can't be forced to respect this convention, so
 * the buffer is copied and terminated here.
 *
 * @param pem The PEM buffer to copy.
 * @param pem_len The length of the PEM buffer, without the null terminator.
 * @param out_len The length of the returned buffer, including the null terminator.
 *
 * @return The null terminated copy of the input buffer, NULL on allocation failure.
 *         The caller MUST free it.
 */
static unsigned char * pem_terminated_copy(const char *pem, size_t pem_len, size_t *out_len)
{
    unsigned char *buf = (unsigned char *)malloc(pem_len + 1);
    if (buf == NULL)
    {
        return NULL;
    }

    memcpy(buf, pem, pem_len);
    buf[pem_len] = '\0';
    *out_len = pem_len + 1;

    return buf;
}

bool_t parse_pem(const char *key, size_t key_len, const char *cert, size_t cert_len, ESTAuthData_t *auth, ESTError_t *err)
{
    if (key == NULL || key_len == 0 || cert == NULL || cert_len == 0 || auth == NULL || err == NULL)
    {
        LOG_ERROR(("Invalid parameters: key, cert, auth or err is NULL\n"))
        return EST_FALSE;
    }

    LOG_INFO(("Prepare enroll with PEM key len=%d cert len=%d\n", (int)key_len, (int)cert_len))

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    /* MbedTLS requires a random number generator to parse the private key. */
    const char *pers = "parse_pem";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_P12, ret, "Failed to seed random number generator");
        oss_print_error(ret);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return EST_FALSE;
    }

    mbedtls_pk_context *pkey = (mbedtls_pk_context *)malloc(sizeof(mbedtls_pk_context));
    mbedtls_x509_crt *crt = (mbedtls_x509_crt *)malloc(sizeof(mbedtls_x509_crt));
    if (pkey == NULL || crt == NULL)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_P12, 0, "Failed to allocate PEM key or certificate");
        free(pkey);
        free(crt);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return EST_FALSE;
    }

    mbedtls_pk_init(pkey);
    mbedtls_x509_crt_init(crt);

    /* Load private key from PEM */
    size_t buf_len = 0;
    unsigned char *buf = pem_terminated_copy(key, key_len, &buf_len);
    if (buf == NULL)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_P12, 0, "Failed to allocate PEM private key buffer");
        goto error;
    }

    ret = mbedtls_pk_parse_key(pkey, buf, buf_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    free(buf);

    if (ret != 0)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_P12, ret, "Failed to parse PEM private key");
        oss_print_error(ret);
        goto error;
    }

    /* Load certificate from PEM */
    buf = pem_terminated_copy(cert, cert_len, &buf_len);
    if (buf == NULL)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_P12, 0, "Failed to allocate PEM certificate buffer");
        goto error;
    }

    ret = mbedtls_x509_crt_parse(crt, buf, buf_len);
    free(buf);

    if (ret != 0)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_CERT_PARSE, ret, "Failed to parse PEM certificate");
        oss_print_error(ret);
        goto error;
    }

    /* Check that the private key matches the certificate public key. */
    ret = mbedtls_pk_check_pair(&crt->pk, pkey, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_P12, ret, "PEM private key doesn't match the certificate public key");
        oss_print_error(ret);
        goto error;
    }

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    /* Configure auth structure to use Certificate type authentication */
    auth->type = EST_AUTH_TYPE_CERT;
    auth->certAuth.certificate = (ESTCertificate_t *)crt;
    auth->certAuth.privateKey = (ESTPrivKey_t *)pkey;

    LOG_INFO(("PEM key and certificate loaded correctly, mTLS authentication configured\n"))
    return EST_TRUE;

error:
    mbedtls_pk_free(pkey);
    mbedtls_x509_crt_free(crt);
    free(pkey);
    free(crt);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return EST_FALSE;
}

bool_t parse_basicauth(const char *userpassword, ESTAuthData_t *auth, ESTError_t *err) {
    if (userpassword == NULL) {
        LOG_ERROR(("User password is NULL\n"))
        return EST_FALSE;
    }

    size_t userpassword_len = strlen(userpassword);
    size_t olen = 0;
    
    if(mbedtls_base64_encode((unsigned char *)auth->basicAuth.b64secret, 
                             sizeof(auth->basicAuth.b64secret), 
                             &olen,
                             (const unsigned char *)userpassword, 
                             userpassword_len) != 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_B64, 0, "Failed to convert basic auth to base64 format");
        return EST_FALSE;
    }

    auth->type = EST_AUTH_TYPE_BASIC;
    return EST_TRUE;
}

/**
 * @brief Initializes the RFC7030 subsystem.
 *
 * This function initializes the RFC7030 subsystem.
 * It logs an informational message to indicate the initialization.
 */
void rfc7030_init()
{
    LOG_INFO(("RFC_7030 Init\n"))
}

/**
 * @brief Free the RFC7030 subsystem.
 *
 * This function free the RFC7030 subsystem.
 * It logs an informational message to indicate the freeing.
 */
void rfc7030_free()
{
    LOG_INFO(("RFC_7030 Free\n"))
}

/**
 * @brief Structure representing the EST TLS interface.
 *
 * This structure defines the interface for the EST TLS operations.
 * It contains function pointers to the initialization, freeing, and
 * unique identifier retrieval functions.
 * 
 * @param initialize Function pointer to the TLS initialization function.
 * @param free Function pointer to the TLS freeing function.
 * @param get_unique Function pointer to the TLS unique identifier retrieval function.
 */
static ESTTLSInterface_t tls = {
    .initialize = tls_init,
    .free = tls_free,
    .get_unique = tls_unique
};

/**
 * @brief Structure representing the EST X.509 interface.
 * 
 * This structure defines the interface for the EST X.509 operations.
 * 
 * @param pkcs7_parse Function pointer to the PKCS7 parsing function.
 * @param pkcs7_free Function pointer to the PKCS7 freeing function.
 * @param pkcs7_get_certificates Function pointer to the PKCS7 certificate retrieval function.
 * @param pkcs7_get_first_certificate Function pointer to the PKCS7 first certificate retrieval function.
 * @param certificate_parse Function pointer to the certificate parsing function.
 * @param certificate_is_self_signed Function pointer to the certificate self-signed verification function.
 * @param certificate_free Function pointer to the certificate freeing function.
 * @param certificate_verify Function pointer to the certificate verification function.
 * @param certificate_store_create Function pointer to the certificate store creation function.
 * @param certificate_store_free Function pointer to the certificate store freeing function.
 * @param certificate_store_add Function pointer to the certificate store addition function. 
 * 
*/
static ESTX509Interface_t x509 = {
    .pkcs7_parse = x509_pkcs7_parse,
    .pkcs7_free = x509_pkcs7_free,
    .pkcs7_get_certificates = x509_pkcs7_get_certificates,
    .pkcs7_get_first_certificate = x509_pkcs7_get_first_certificate,
    .certificate_parse = x509_certificate_parse,
    .certificate_is_self_signed = x509_certificate_is_self_signed,
    .certificate_free = x509_certificate_free,
    .certificate_verify = x509_certificate_verify,
    .certificate_store_create = x509_certificate_store_create,
    .certificate_store_free = x509_certificate_store_free,
    .certificate_store_add = x509_certificate_store_add,
    .csr_parse = x509_csr_parse,
    .csr_free = x509_csr_free,
    .verify_cert_csr_pubkey = x509_verify_cert_csr_pubkey,
    .verify_cert_csr_subject = x509_verify_cert_csr_subject
};

/**
 * @brief Configuration structure for RFC7030 subsystem.
 *
 * This structure holds the configuration settings for the RFC7030 subsystem.
 * It includes function pointers for parsing basic authentication, parsing p12 files,
 * TLS configuration, X.509 certificate configuration, and loading CSR (Certificate Signing Request).
 * 
 * @param parse_basicauth Function pointer to the basic authentication parsing function.
 * @param parse_p12 Function pointer to the p12 parsing function.
 * @param parse_pem Function pointer to the PEM key and certificate parsing function.
 * @param tls Pointer to the EST TLS interface.
 * @param x509 Pointer to the EST X.509 interface.
 * @param get_csr Function pointer to the CSR loading function.
 * 
 */
static RFC7030_Subsystem_Config_t rfcConfig = {
    .parse_basicauth = parse_basicauth,
    .parse_p12 = parse_p12,
    .parse_pem = parse_pem,
    .tls = &tls,
    .x509 = &x509,
    .get_csr = load_csr
};

/**
 * @brief Retrieves the configuration settings for the RFC7030 subsystem.
 *
 * This function retrieves the configuration settings for the RFC7030 subsystem.
 * 
 * @return Pointer to the configuration structure for the RFC7030 subsystem.
 */
RFC7030_Subsystem_Config_t * rfc7030_get_config() 
{
    return &rfcConfig;
}

/**
 * @brief Requests the CA chain from the EST server.
 *
 * This function requests the CA chain from the EST server.
 * It uses the EST client library to perform the operation.
 * 
 * @param config Pointer to the RFC7030 options structure.
 * @param ca Pointer to the buffer to store the CA chain.
 * @param ca_len Length of the buffer to store the CA chain.
 * @param err Pointer to the EST error structure.
 * 
 * @return EST_TRUE if the operation is successful, EST_FALSE otherwise.
 */
bool_t rfc7030_request_cachain(RFC7030_Options_t *config, 
    char *ca, 
    size_t ca_len, 
    ESTError_t *err
) {
    if (config == NULL || ca == NULL || ca_len == 0 || err == NULL) 
    {
        LOG_ERROR(("Invalid input parameters\n"))
        return EST_FALSE;
    }
    ESTClient_Options_t est_opts;
    memset(&est_opts, 0, sizeof(est_opts));

    est_opts.get_csr = rfcConfig.get_csr;
    est_opts.use_pop = tls.get_unique != NULL;
    est_opts.tlsInterface = &tls;
    est_opts.x509Interface = &x509;

    if(config->label) 
    {
        snprintf(est_opts.label, EST_CLIENT_LABEL_LEN, "%s", config->label);
    }
    
    if(config->cachain) 
    {
        oss_load_implicit_ta(config->cachain, &est_opts);
    } 
    else 
    {
        est_opts.skip_tls_verify = EST_TRUE;
    }

    ESTClientCacerts_Ctx_t cacerts_response;
    memset(&cacerts_response, 0, sizeof(cacerts_response));

    if(!est_client_cacerts(&est_opts, config->host, config->port, &cacerts_response, err)) 
    {
        oss_free_implicit_ta(&est_opts);
        est_client_cacerts_free(&cacerts_response);
        return EST_FALSE;
    }

    oss_free_implicit_ta(&est_opts);

    int ca_idx_pt = 0;
    ca[0] = '\0';
    for(int i = 0; i < cacerts_response.cacerts.chain_len; i++) 
    {
        char buf[5000];
        ca_idx_pt = oss_crt2pem_noterminator((mbedtls_x509_crt *)cacerts_response.cacerts.chain[i], buf, ca_len); 
        buf[ca_idx_pt] = '\0';
        strncat(ca, buf, ca_len - strlen(ca) - 1);
    }

    est_client_cacerts_free(&cacerts_response);
    
    return EST_TRUE;
}

/**
 * @brief Requests a certificate from the EST server.
 *
 * This function requests a certificate from the EST server.
 * It uses the EST client library to perform the operation.
 * 
 * @param config Pointer to the RFC7030 enroll options structure.
 * @param ca Pointer to the buffer to store the CA chain.
 * @param ca_len Length of the buffer to store the CA chain.
 * @param enrolled Pointer to the buffer to store the enrolled certificate.
 * @param enrolled_len Length of the buffer to store the enrolled certificate.
 * @param err Pointer to the EST error structure.
 * 
 * @return EST_TRUE if the operation is successful, EST_FALSE otherwise.
 */
static bool_t request_certificate_inner(RFC7030_Enroll_Options_t *config, 
    bool_t renew,
    char *ca,
    size_t ca_len,
    char *enrolled,
    size_t enrolled_len,
    ESTError_t *err) 
{
    if (config == NULL || ca == NULL || ca_len == 0 || enrolled == NULL || enrolled_len == 0 || err == NULL) 
    {
        LOG_ERROR(("Invalid input parameters\n"))
        return EST_FALSE;
    }
    ESTClient_Options_t est_opts;
    memset(&est_opts, 0, sizeof(est_opts));

    est_opts.get_csr = rfcConfig.get_csr;
    est_opts.use_pop = tls.get_unique != NULL;
    est_opts.tlsInterface = &tls;
    est_opts.x509Interface = &x509;

    if(config->opts.disable_rfc8951) {
        est_opts.strict8951 = EST_FALSE;
    } else {
        est_opts.strict8951 = EST_TRUE;
    }
    
    if(config->opts.label) 
    {
        snprintf(est_opts.label, EST_CLIENT_LABEL_LEN, "%s", config->opts.label);
    }
    
    if(config->opts.cachain) 
    {
        oss_load_implicit_ta(config->opts.cachain, &est_opts);
    } 
    else 
    {
        est_opts.skip_tls_verify = EST_TRUE;
    }

    ESTClientEnroll_Ctx_t enroll_output;
    memset(&enroll_output, 0, sizeof(enroll_output));

    if(renew) 
    {
        if(!est_client_simplereenroll(&est_opts, 
            config->opts.host, 
            config->opts.port, 
            &config->auth, 
            config->csr_ctx, 
            &enroll_output, err)) 
        {
            LOG_DEBUG(("ReEnroll completed with error\n"))
            est_client_enroll_free(&enroll_output);
            oss_free_implicit_ta(&est_opts);
            return EST_FALSE;
        }
    } 
    else 
    {
        if(!est_client_simpleenroll(&est_opts, 
            config->opts.host, 
            config->opts.port, 
            &config->auth, 
            config->csr_ctx, 
            &enroll_output, err))
        {

            LOG_DEBUG(("Enroll completed with error\n"))
            est_client_enroll_free(&enroll_output);
            oss_free_implicit_ta(&est_opts);
            return EST_FALSE;
        }
    }

    LOG_DEBUG(("EST Operation completed\n"))

    oss_free_implicit_ta(&est_opts);
    int len = oss_crt2pem_noterminator((mbedtls_x509_crt *)enroll_output.enrolled, enrolled, enrolled_len);
    if (len < 0) 
    { 
        est_client_enroll_free(&enroll_output); return EST_FALSE; 
    }
    enrolled[len] = '\0';

    int ca_idx_pt = 0;
    ca[0] = '\0';
    for(int i = 0; i < enroll_output.cacerts.chain_len; i++) 
    {
        char buf[5000];
        ca_idx_pt = oss_crt2pem_noterminator((mbedtls_x509_crt *)enroll_output.cacerts.chain[i], buf, ca_len); 
        buf[ca_idx_pt] = '\0';
        strncat(ca, buf, ca_len - strlen(ca) - 1);
    }


    est_client_enroll_free(&enroll_output);
    return EST_TRUE;
}

/**
 * @brief Requests a certificate from the EST server.
 *
 * This function requests a certificate from the EST server.
 * It uses the EST client library to perform the operation.
 * 
 * @param config Pointer to the RFC7030 enroll options structure.
 * @param ca Pointer to the buffer to store the CA chain.
 * @param ca_len Length of the buffer to store the CA chain.
 * @param enrolled Pointer to the buffer to store the enrolled certificate.
 * @param enrolled_len Length of the buffer to store the enrolled certificate.
 * @param err Pointer to the EST error structure.
 * 
 * @return EST_TRUE if the operation is successful, EST_FALSE otherwise.
 */
bool_t rfc7030_request_certificate(RFC7030_Enroll_Options_t *config, 
    char *ca,
    size_t ca_len,
    char *enrolled,
    size_t enrolled_len,
    ESTError_t *err
) {
    return request_certificate_inner(config, EST_FALSE, ca, ca_len, enrolled, enrolled_len, err);
}

/**
 * @brief Renews a certificate from the EST server.
 *
 * This function renews a certificate from the EST server.
 * It uses the EST client library to perform the operation.
 * 
 * @param config Pointer to the RFC7030 enroll options structure.
 * @param ca Pointer to the buffer to store the CA chain.
 * @param ca_len Length of the buffer to store the CA chain.
 * @param enrolled Pointer to the buffer to store the enrolled certificate.
 * @param enrolled_len Length of the buffer to store the enrolled certificate.
 * @param err Pointer to the EST error structure.
 * 
 * @return EST_TRUE if the operation is successful, EST_FALSE otherwise.
 */
bool_t rfc7030_renew_certificate(RFC7030_Enroll_Options_t *config, 
    char *ca,
    size_t ca_len,
    char *enrolled,
    size_t enrolled_len,
    ESTError_t *err
) {
    return request_certificate_inner(config, EST_TRUE, ca, ca_len, enrolled, enrolled_len, err);
}