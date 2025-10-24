#include "internal.h"

#define CSR_MAX_LEN 4096

static bool_t load_csr(void *ctx, const char *tlsunique, size_t tlsunique_len, byte_t *csr, size_t *csr_len, ESTError_t *err) {
    char *csr_ctx = (char *)ctx;
    snprintf(csr, CSR_MAX_LEN, "%s", csr_ctx);
    *csr_len = strlen(csr_ctx);

    return EST_TRUE;
}

bool_t parse_p12(const char *p12, size_t p12_len, const char *password, ESTAuthData_t *auth, ESTError_t *err) {
    LOG_INFO(("Prepare enroll with p12 len=%d\n", (int)p12_len))

    // Load P12 pre enrollment certificate

    BIO *mem = BIO_new(BIO_s_mem());
    BIO_write(mem, p12, p12_len);

    PKCS12 *p12ssl = d2i_PKCS12_bio(mem, NULL);
    EVP_PKEY *pkey = EVP_PKEY_new();
    X509 *cert = X509_new();
    if(PKCS12_parse(p12ssl, password, &pkey, &cert, NULL) == 0) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_P12, ERR_get_error(), "Failed to prepare enrollment, failed to parse P12");
        oss_print_error();
        return EST_FALSE;
    }

    PKCS12_free(p12ssl);
    BIO_free(mem);

    // Configure auth structure to use Certificate type authentication
    auth->type = EST_AUTH_TYPE_CERT;
    auth->certAuth.certificate = (ESTCertificate_t *)cert;
    auth->certAuth.privateKey = (ESTPrivKey_t *)pkey;

    LOG_INFO(("P12 loaded correctly and authentication mTLS configured with pkey and cert\n"))
    return EST_TRUE;
}

bool_t parse_basicauth(const char *userpassword, ESTAuthData_t *auth, ESTError_t *err) {
    if(!EVP_EncodeBlock((unsigned char *)auth->basicAuth.b64secret, (const unsigned char *)userpassword, 16)) {
        est_error_set_custom(err, ERROR_SUBSYSTEM_X509, EST_ERROR_X509_B64, ERR_get_error(), "Failed to convert basic auth to base64 format");
        oss_print_error();
        return EST_FALSE;
    }

    auth->type = EST_AUTH_TYPE_BASIC;
    return EST_TRUE;
}

void rfc7030_init() {
    OpenSSL_add_all_digests();
    SSL_load_error_strings();
    ERR_load_crypto_strings();

    load_legacy_module();
}

// Free crypto Library modules resources
void rfc7030_free() {
    free_legacy_module();
}

static ESTTLSInterface_t tls = {
    .initialize = tls_init,
    .free = tls_free,
    .get_unique = tls_unique
};

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

static RFC7030_Subsystem_Config_t rfcConfig = {
    .parse_basicauth = parse_basicauth,
    .parse_p12 = parse_p12,
    .tls = &tls,
    .x509 = &x509,
    .get_csr = load_csr
};

RFC7030_Subsystem_Config_t * rfc7030_get_config() {
    return &rfcConfig;
}

bool_t rfc7030_request_cachain(RFC7030_Options_t *config, 
    char *ca, 
    size_t ca_len, 
    ESTError_t *err
) {
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
    
    if(config->cachain) {
        oss_load_implicit_ta(config->cachain, &est_opts);
    } else {
        est_opts.skip_tls_verify = EST_TRUE;
    }

    ESTClientCacerts_Ctx_t cacerts_response;
    memset(&cacerts_response, 0, sizeof(cacerts_response));

    if(!est_client_cacerts(&est_opts, config->host, config->port, &cacerts_response, err)) {
        oss_free_implicit_ta(&est_opts);
        est_client_cacerts_free(&cacerts_response);
        return EST_FALSE;
    }

    oss_free_implicit_ta(&est_opts);

    int ca_idx_pt = 0;
    ca[0] = '\0';
    for(int i = 0; i < cacerts_response.cacerts.chain_len; i++) {
        char buf[5000];
        ca_idx_pt = oss_crt2pem_noterminator((X509 *)cacerts_response.cacerts.chain[i], buf, ca_len); 
        buf[ca_idx_pt] = '\0';
        strncat(ca, buf, ca_len - strlen(ca) - 1);
    }

    est_client_cacerts_free(&cacerts_response);
    free_legacy_module();
    
    return EST_TRUE;
}

static bool_t request_certificate_inner(RFC7030_Enroll_Options_t *config, 
    bool_t renew,
    char *ca,
    size_t ca_len,
    char *enrolled,
    size_t enrolled_len,
    ESTError_t *err) {

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
    
    if(config->opts.cachain) {
        oss_load_implicit_ta(config->opts.cachain, &est_opts);
    } else {
        est_opts.skip_tls_verify = EST_TRUE;
    }

    ESTClientEnroll_Ctx_t enroll_output;
    memset(&enroll_output, 0, sizeof(enroll_output));

    if(renew) {
        if(!est_client_simplereenroll(&est_opts, 
            config->opts.host, 
            config->opts.port, 
            &config->auth, 
            config->csr_ctx, 
            &enroll_output, err)) {
            
            LOG_DEBUG(("ReEnroll completed with error\n"))
            est_client_enroll_free(&enroll_output);
            oss_free_implicit_ta(&est_opts);
            return EST_FALSE;
        }
    } else {
        if(!est_client_simpleenroll(&est_opts, 
            config->opts.host, 
            config->opts.port, 
            &config->auth, 
            config->csr_ctx, 
            &enroll_output, err)) {

            LOG_DEBUG(("Enroll completed with error\n"))
            est_client_enroll_free(&enroll_output);
            oss_free_implicit_ta(&est_opts);
            return EST_FALSE;
        }
    }

    LOG_DEBUG(("EST Operation completed\n"))

    oss_free_implicit_ta(&est_opts);
    int len = oss_crt2pem_noterminator((X509 *)enroll_output.enrolled, enrolled, enrolled_len);
    enrolled[len] = '\0';

    int ca_idx_pt = 0;
    ca[0] = '\0';
    for(int i = 0; i < enroll_output.cacerts.chain_len; i++) {
        char buf[5000];
        ca_idx_pt = oss_crt2pem_noterminator((X509 *)enroll_output.cacerts.chain[i], buf, ca_len); 
        buf[ca_idx_pt] = '\0';
        strncat(ca, buf, ca_len - strlen(ca) - 1);
    }

    est_client_enroll_free(&enroll_output);
    return EST_TRUE;
}

bool_t rfc7030_request_certificate(RFC7030_Enroll_Options_t *config, 
    char *ca,
    size_t ca_len,
    char *enrolled,
    size_t enrolled_len,
    ESTError_t *err
) {
    return request_certificate_inner(config, EST_FALSE, ca, ca_len, enrolled, enrolled_len, err);
}

bool_t rfc7030_renew_certificate(RFC7030_Enroll_Options_t *config, 
    char *ca,
    size_t ca_len,
    char *enrolled,
    size_t enrolled_len,
    ESTError_t *err
) {
    return request_certificate_inner(config, EST_TRUE, ca, ca_len, enrolled, enrolled_len, err);
}
