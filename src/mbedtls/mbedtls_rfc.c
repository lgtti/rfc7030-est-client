#include "internal.h"

static bool_t load_csr(void *ctx, const char *tlsunique, size_t tlsunique_len, byte_t *csr, size_t *csr_len, ESTError_t *err)
{
    if (ctx == NULL || csr == NULL || csr_len == NULL)
    {
        LOG_ERROR(("Invalid input parameters\n"))
        return EST_FALSE;
    }
    char *csr_ctx = (char *)ctx;
    *csr_len = strlen(csr_ctx);
    snprintf(csr, *csr_len + 1, "%s", csr_ctx);
    return EST_TRUE;
}

bool_t parse_p12(const char *p12, size_t p12_len, const char *password, ESTAuthData_t *auth, ESTError_t *err)
{
    LOG_INFO(("parse_p12 - Feature unavailable\n"))
    return EST_FEATURE_NOT_SUPPORTED;
}

bool_t parse_basicauth(const char *userpassword, ESTAuthData_t *auth, ESTError_t *err) {
    LOG_INFO(("parse_basicAUTH - Feature unavailable\n"))
    return EST_FEATURE_NOT_SUPPORTED;
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
    .certificate_store_add = x509_certificate_store_add
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
 * @param tls Pointer to the EST TLS interface.
 * @param x509 Pointer to the EST X.509 interface.
 * @param get_csr Function pointer to the CSR loading function.
 * 
 */
static RFC7030_Subsystem_Config_t rfcConfig = {
    .parse_basicauth = parse_basicauth,
    .parse_p12 = parse_p12,
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
        snprintf(est_opts.label, sizeof(est_opts.label), "%s", config->label);
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
        snprintf(est_opts.label, sizeof(est_opts.label), "%s", config->opts.label);
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