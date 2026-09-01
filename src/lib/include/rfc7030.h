#ifndef CLIENT_RFC_7030_H
#define CLIENT_RFC_7030_H

#include "est.h"

typedef bool_t (*parse_p12_t)(const char *p12, size_t p12_len, const char *password, ESTAuthData_t *auth, ESTError_t *err);
typedef bool_t (*parse_basicauth_t)(const char *userpassword, ESTAuthData_t *auth, ESTError_t *err);
typedef bool_t (*parse_pem_t)(const char *key, size_t key_len, const char *cert, size_t cert_len, ESTAuthData_t *auth, ESTError_t *err);

typedef struct RFC7030_Subsystem_Config {
    const ESTTLSInterface_t *tls;
    const ESTX509Interface_t *x509;
    parse_p12_t parse_p12;
    parse_basicauth_t parse_basicauth;
    parse_pem_t parse_pem;
    est_get_csr_t get_csr;
}RFC7030_Subsystem_Config_t;

typedef struct RFC7030_Options {
    int port;
    const char *host;
    const char *label;
    const char *cachain;
    bool_t disable_rfc8951;
}RFC7030_Options_t;

typedef struct CstCtx CsrCtx_t;

typedef struct RFC7030_Enroll_Options {
    RFC7030_Options_t opts;
    ESTAuthData_t auth;
    CsrCtx_t *csr_ctx;
}RFC7030_Enroll_Options_t;

/**
 * @brief Initializes the RFC7030 subsystem.
 *
 * This function initializes the RFC7030 subsystem.
 * It logs an informational message to indicate the initialization.
 */
void rfc7030_init(void);
/**
 * @brief Frees the RFC7030 subsystem.
 *
 * This function frees the RFC7030 subsystem.
 * It logs an informational message to indicate the freeing.
 */
void rfc7030_free(void);

/**
 * @brief Retrieves the configuration settings for the RFC7030 subsystem.
 *
 * This function retrieves the configuration settings for the RFC7030 subsystem.
 * 
 * @return Pointer to the configuration structure for the RFC7030 subsystem.
 */
RFC7030_Subsystem_Config_t * rfc7030_get_config(void);

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
);

/*! @brief EST Enrollment 
 *
 * @param config: Pointer to Enrollment Configuration
 * @param ca: placeholder for caCert
 * @param ca_len: ca placeholder size
 * @param enrolled: placeholder for certificate
 * @param enrolled_len: enrolled certificate placeholder size
 * @param err: pointer to error
 * 
 *
 * @retval EST_TRUE (1)
 * @retval EST_FALSE (0)
 */
bool_t rfc7030_request_certificate(RFC7030_Enroll_Options_t *config, 
    char *ca,
    size_t ca_len,
    char *enrolled,
    size_t enrolled_len,
    ESTError_t *err
);

/*! @brief EST Reenrollment 
 *
 * @param config: Pointer to Enrollment Configuration
 * @param ca: placeholder for caCert
 * @param ca_len: ca placeholder size
 * @param enrolled: placeholder for certificate
 * @param enrolled_len: enrolled certificate placeholder size
 * @param err: pointer to error
 * 
 *
 * @retval EST_TRUE (1)
 * @retval EST_FALSE (0)
 */
bool_t rfc7030_renew_certificate(RFC7030_Enroll_Options_t *config, 
    char *ca,
    size_t ca_len,
    char *enrolled,
    size_t enrolled_len,
    ESTError_t *err
);

#endif